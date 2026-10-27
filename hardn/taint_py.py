"""Intra-procedural taint analysis for Python, built on the stdlib `ast` module.

Tracks request data (Flask/Django/FastAPI/Starlette) through assignments, f-strings, concatenation
and method calls into dangerous sinks, across multiple lines. Known sanitizers stop propagation.
"""
from __future__ import annotations

import ast

from .code_rules import RULES
from .models import Finding
from .walker import is_test_path

REQUEST_NAMES = {"request", "req"}
SOURCE_ATTRS = {
    "args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST", "FILES",
    "COOKIES", "body", "query_params", "path_params",
}
SOURCE_METHODS = {"get_json", "get_data", "json", "form", "body"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket"}
NON_INPUT_PARAMS = {"self", "cls", "request", "req", "db", "session", "response", "background_tasks", "current_user", "user"}
SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "quote", "escape", "secure_filename", "basename",
    "UUID", "Decimal", "ip_address", "ip_network", "clean", "sanitize", "literal_eval", "safe_join",
}

_FIX = {r.id: r.fix for r in RULES}

# (rule id, title, severity, cwe, matcher(dotted call name) -> bool, rule whose fix text applies)
SINKS = [
    ("PYT001", "SQL injection: request data reaches a SQL query", "high", "CWE-89",
     lambda n: n.rsplit(".", 1)[-1] in {"execute", "executemany", "executescript", "raw"} or n in {"text", "sqlalchemy.text"}, "PY004"),
    ("PYT002", "Command injection: request data reaches a shell command", "critical", "CWE-78",
     lambda n: n in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}, "PY003"),
    ("PYT003", "Code injection: request data reaches eval/exec", "critical", "CWE-95",
     lambda n: n in {"eval", "exec", "compile"}, "PY001"),
    ("PYT004", "SSRF: request data controls an outbound request URL", "high", "CWE-918",
     lambda n: n.startswith(("requests.", "httpx.", "urllib.request.")) or n in {"urlopen", "aiohttp.request"}, "PY012"),
    ("PYT005", "Path traversal: request data reaches a filesystem path", "high", "CWE-22",
     lambda n: n in {"open", "send_file", "os.remove", "os.unlink", "shutil.rmtree", "shutil.copy", "shutil.move",
                     "Path", "pathlib.Path", "FileResponse", "io.open"}, "PY013"),
    ("PYT006", "Open redirect: request data controls a redirect target", "medium", "CWE-601",
     lambda n: n.rsplit(".", 1)[-1] in {"redirect", "HttpResponseRedirect", "RedirectResponse"}, "PY014"),
    ("PYT007", "Unsafe deserialization of request data", "critical", "CWE-502",
     lambda n: n in {"pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.loads", "dill.loads",
                     "jsonpickle.decode", "shelve.open"}, "PY005"),
    ("PYT008", "Server-side template injection", "critical", "CWE-1336",
     lambda n: n.rsplit(".", 1)[-1] in {"render_template_string", "from_string"} or n in {"Template", "jinja2.Template"},
     None),
    ("PYT009", "XSS: request data marked as safe HTML", "high", "CWE-79",
     lambda n: n.rsplit(".", 1)[-1] in {"Markup", "mark_safe"}, "PY015"),
]
SHELL_CALLS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}
SSTI_FIX = ("Never build templates from user input. Render a fixed template file and pass user data as context "
            "variables: render_template('page.html', name=name).")


def dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(dotted(node.func) + "()")
    return ".".join(reversed(parts))


class _Function:
    def __init__(self, path: str, lines: list):
        self.path, self.lines = path, lines
        self.env = {}  # var name -> chain [(label, line)]

    def taint(self, node):
        """Return the source chain if `node` carries request data, else None."""
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name) and base.id in REQUEST_NAMES and node.attr in SOURCE_ATTRS:
                return [(f"{base.id}.{node.attr}", node.lineno)]
            if isinstance(base, ast.Attribute) and base.attr == "request" and node.attr in SOURCE_ATTRS:
                return [(f"request.{node.attr}", node.lineno)]
            return self.taint(base)
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            last = name.rsplit(".", 1)[-1]
            if last in SANITIZERS or name in ("os.path.basename", "shlex.quote", "html.escape"):
                return None
            parts = name.split(".")
            if len(parts) >= 2 and parts[-2] in REQUEST_NAMES and last in SOURCE_METHODS:
                return [(f"{parts[-2]}.{last}()", node.lineno)]
            for child in [node.func, *node.args, *(k.value for k in node.keywords)]:
                chain = self.taint(child)
                if chain:
                    return chain
            return None
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        for child in ast.iter_child_nodes(node):
            chain = self.taint(child)
            if chain:
                return chain
        return None

    def bind(self, target, chain, line) -> bool:
        if isinstance(target, ast.Name):
            if target.id not in self.env:
                self.env[target.id] = chain + [(target.id, line)]
                return True
        elif isinstance(target, (ast.Tuple, ast.List)):
            return any([self.bind(t, chain, line) for t in target.elts])
        elif isinstance(target, ast.Starred):
            return self.bind(target.value, chain, line)
        return False

    def run(self, body_nodes: list) -> list:
        nodes = [n for stmt in body_nodes for n in _walk_local(stmt)]
        for _ in range(4):  # fixed point over assignments (handles loops / out-of-order flows)
            changed = False
            for n in nodes:
                if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    chain = self.taint(n.value)
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    if chain:
                        changed |= any([self.bind(t, chain, n.lineno) for t in targets])
                elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                    chain = self.taint(n.iter)
                    if chain:
                        changed |= self.bind(n.target, chain, getattr(n, "lineno", chain[-1][1]))
                elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                    chain = self.taint(n.context_expr)
                    if chain:
                        changed |= self.bind(n.optional_vars, chain, chain[-1][1])
            if not changed:
                break
        return [f for n in nodes if isinstance(n, ast.Call) for f in self.check_sink(n)]

    def check_sink(self, call: ast.Call) -> list:
        name = dotted(call.func)
        if not name:
            return []
        out = []
        for rid, title, sev, cwe, match, fix_rule in SINKS:
            if not match(name):
                continue
            if rid == "PYT007" and name == "yaml.load" and any(
                    "Safe" in dotted(k.value) for k in call.keywords if k.arg == "Loader"):
                continue
            args = call.args[:1] or [k.value for k in call.keywords if k.arg in ("url", "sql", "statement", "path", "file")]
            out += self._report(rid, title, sev, cwe, name, call, args, _FIX.get(fix_rule) if fix_rule else SSTI_FIX)
        if name in SHELL_CALLS and any(k.arg == "shell" and getattr(k.value, "value", False) is True for k in call.keywords):
            out += self._report("PYT002", SINKS[1][1], "critical", "CWE-78", name, call, call.args[:1], _FIX["PY002"])
        return out

    def _report(self, rid, title, sev, cwe, name, call, args, fix) -> list:
        for arg in args:
            chain = self.taint(arg)
            if chain:
                flow = _compact(chain + [(name + "()", call.lineno)])
                line = self.lines[call.lineno - 1].strip() if call.lineno <= len(self.lines) else ""
                return [Finding(
                    rule_id=rid, title=title, severity=sev, category="code", file=self.path, line=call.lineno,
                    snippet=line[:240], cwe=cwe, fix=fix or "",
                    extra={"flow": " → ".join(f"{label} (L{ln})" for label, ln in flow)},
                )]
        return []


def _compact(chain: list) -> list:
    out = []
    for item in chain:
        if not out or out[-1] != item:
            out.append(item)
    return out


def _walk_local(node):
    """ast.walk that does not descend into nested function/class definitions."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for child in ast.iter_child_nodes(n):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                stack.append(child)


def _route_params(fn) -> list:
    """Parameters of Flask/FastAPI route handlers are attacker-controlled (path/query params)."""
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
            params = fn.args.args + fn.args.kwonlyargs
            return [a for a in params if a.arg not in NON_INPUT_PARAMS
                    and (a.annotation is None or dotted(a.annotation) in ("str", "Any", "bytes"))]
    return []


def scan(files: list) -> list:
    findings = []
    for f in files:
        if not f.path.endswith(".py") or is_test_path(f.path):
            continue
        try:
            tree = ast.parse(f.text, filename=f.path)
        except (SyntaxError, ValueError):
            continue
        module_body = [s for s in tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        findings += _Function(f.path, f.lines).run(module_body)
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                an = _Function(f.path, f.lines)
                for p in _route_params(fn):
                    an.env[p.arg] = [(f"route param `{p.arg}`", fn.lineno)]
                findings += an.run(fn.body)
    return findings
