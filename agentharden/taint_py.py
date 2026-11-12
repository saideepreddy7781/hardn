"""Taint analysis for Python, built on the stdlib `ast` module.

Follows request data (Flask, Django, FastAPI, Starlette, Tornado) through assignments, f-strings, concatenation,
`.format`, containers and method calls into dangerous sinks. Each function is walked once in statement order, so a
reassignment clears taint and a sink that runs before the taint arrives stays quiet. Branches are merged, simple
validation guards (`isdigit`, allowlists, `re.fullmatch`, a resolved-path prefix check) clear a value, and each
sanitizer clears only the sinks it actually protects. Import aliases are resolved, client objects such as
`requests.Session()` are tracked, and functions defined in the same file are summarised, so a helper that runs the
query or returns request data is followed. Analysis stays inside one file.
"""
from __future__ import annotations

import ast
import re

from .code_rules import RULES, is_suppressed
from .models import Finding
from .walker import is_test_path

_FIX = {r.id: r.fix for r in RULES}
SSTI_FIX = ("Never build templates from user input. Render a fixed template file and pass user data as context "
            "variables: render_template('page.html', name=name).")
XSS_FIX = ("Return HTML through a template with auto-escaping, or escape every value (markupsafe.escape / "
           "django.utils.html.escape) before building the response. Return JSON for data.")

REQUEST_NAMES = {"request", "req"}
REQUEST_TYPES = {"Request", "HttpRequest", "WSGIRequest", "ASGIRequest", "HTTPConnection", "WebSocket"}
SOURCE_ATTRS = {
    "args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST", "FILES", "COOKIES",
    "body", "query_params", "path_params", "url", "base_url", "path", "full_path", "query_string", "referrer",
    "host", "host_url", "url_root", "environ", "view_args", "stream", "META", "user_agent", "authorization",
    "match_info", "query", "rel_url", "raw_path", "content", "uri", "arguments", "body_arguments",
    "query_arguments", "remote_user",
}
SOURCE_METHODS = {"get_json", "get_data", "json", "form", "body", "text", "get_full_path", "build_absolute_uri",
                  "get_host", "get_raw_uri", "read", "post", "multipart", "get_argument", "get_arguments",
                  "get_query_argument", "get_body_argument"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket", "head", "options"}
SKIP_PARAMS = {"self", "cls", "db", "session", "background_tasks", "response"}
VALIDATED_TYPES = {"int", "float", "bool", "UUID", "UUID1", "UUID3", "UUID4", "UUID5", "datetime", "date", "time",
                   "timedelta", "Decimal", "PositiveInt", "NegativeInt", "NonNegativeInt", "NonPositiveInt",
                   "PositiveFloat", "conint", "confloat", "condecimal", "IPv4Address", "IPv6Address",
                   "IPvAnyAddress", "StrictInt", "StrictBool", "StrictFloat", "Literal", "EmailStr"}
NON_INPUT_TYPES = {"Response", "BackgroundTasks", "Session", "AsyncSession", "Connection", "Settings", "Depends",
                   "Security", "SecurityScopes"}
CLIENT_CTORS = {"requests.Session", "requests.session", "requests.sessions.Session", "httpx.Client",
                "httpx.AsyncClient", "aiohttp.ClientSession", "urllib3.PoolManager", "urllib3.HTTPConnectionPool",
                "tornado.httpclient.AsyncHTTPClient", "tornado.httpclient.HTTPClient"}
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "fetch"}

ALL = frozenset({"sql", "cmd", "code", "ssrf", "path", "redirect", "deser", "ssti", "xss"})
# The request's own path, or a host Django already checked against ALLOWED_HOSTS, sends the user back to this site.
SAME_SITE = frozenset({"redirect"})
SANITIZERS = {
    # type conversions and lookups: nothing attacker-shaped survives them
    **dict.fromkeys(("int", "float", "bool", "len", "abs", "round", "ord", "hash", "UUID", "uuid.UUID", "Decimal", "decimal.Decimal", "ip_address", "ipaddress.ip_address", "ip_network", "ipaddress.ip_network", "isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha", "startswith", "endswith", "isinstance", "callable", "count", "index", "find"), ALL),
    **{n: frozenset({"xss"}) for n in ("escape", "html.escape", "markupsafe.escape", "cgi.escape", "conditional_escape",
                                       "django.utils.html.escape", "bleach.clean", "nh3.clean", "strip_tags",
                                       "escape_html", "xml.sax.saxutils.escape", "jinja2.escape", "escapejs",
                                       "flask.escape")},
    **{n: frozenset({"xss", "cmd", "sql", "code", "ssti", "ssrf"}) for n in (
        "quote", "quote_plus", "urllib.parse.quote", "urllib.parse.quote_plus", "urlencode", "urllib.parse.urlencode")},
    **{n: frozenset({"cmd"}) for n in ("shlex.quote", "pipes.quote", "shlex.join")},
    **{n: frozenset({"path"}) for n in ("secure_filename", "werkzeug.utils.secure_filename", "basename",
                                        "os.path.basename", "safe_join", "werkzeug.utils.safe_join",
                                        "werkzeug.security.safe_join", "flask.safe_join")},
    **{n: frozenset({"sql"}) for n in ("quote_name", "quote_ident", "escape_string", "sql.Identifier", "sql.Literal",
                                       "psycopg2.sql.Identifier", "psycopg2.sql.Literal", "bindparam",
                                       "sqlalchemy.bindparam", "literal")},
    **{n: frozenset({"redirect", "ssrf"}) for n in ("url_for", "flask.url_for", "reverse", "django.urls.reverse",
                                                    "resolve_url")},
    **{n: frozenset({"code", "deser", "ssti"}) for n in ("literal_eval", "ast.literal_eval")},
    **{n: frozenset({"sql", "cmd", "code", "path", "deser", "ssti", "ssrf"}) for n in ("json.dumps",)},
}
GENERIC_SANITIZER = re.compile(r"^(?:sanitize\w*|clean\w*|escape\w*|validate\w*|safe_\w+)$")
SQL_SAFE_METHODS = {"where", "filter", "filter_by", "bindparams", "params", "values", "order_by", "having", "exclude",
                    "get_or_none", "get", "Q", "F", "Value", "select", "update", "delete", "insert"}
STRING_FUNCS = {"str", "format", "join", "replace", "strip", "lstrip", "rstrip", "lower", "upper", "title", "split",
                "rsplit", "splitlines", "decode", "encode", "os.path.join", "posixpath.join", "urljoin",
                "urllib.parse.urljoin", "f", "repr", "bytes", "bytearray", "list", "tuple", "set", "dict", "sorted",
                "reversed", "dict.get", "get", "getlist", "pop", "items", "keys", "values", "copy", "unquote",
                "urllib.parse.unquote", "base64.b64decode", "b64decode", "loads", "json.loads", "BytesIO",
                "io.BytesIO", "StringIO", "io.StringIO", "Path", "pathlib.Path", "PurePath", "realpath",
                "os.path.realpath", "abspath", "os.path.abspath", "normpath", "os.path.normpath", "resolve",
                "expanduser", "os.path.expanduser", "casefold", "zfill", "center", "ljust", "rjust", "partition",
                "translate", "removeprefix", "removesuffix", "read", "getvalue", "next", "iter", "map", "filter",
                "zip", "enumerate", "min", "max", "sum", "any", "all", "dumps", "urlparse", "urllib.parse.urlparse"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/zsh", "cmd", "cmd.exe",
          "powershell", "pwsh", "powershell.exe"}
SQL_TEXT = re.compile(r"(?i)\b(select|insert|update|delete|create|drop|alter|replace)\b.*\b(from|into|set|table|"
                      r"where|values)\b|\bpragma\b")
SOURCE_HINT = re.compile(r"\brequest\b|\breq\b|Request\b|\.kwargs\b|\.route\(|get_argument|"
                         r"@\w+\.(?:get|post|put|patch|delete|api_route|websocket)\(")


def dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = dotted(node.func)
        if not inner:
            return ""
        parts.append(inner + "()")
    else:
        return ""
    return ".".join(reversed(parts))


def _const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


# ---- taint values -------------------------------------------------------------------------------------------------
# A taint is (chain, safe, origins): chain is ((label, line), ...); safe is the set of sink classes it was sanitised
# for; origins holds "src" for request data and parameter indices while a function summary is being computed.

def _choose(*taints):
    taints = [t for t in taints if t]
    if not taints:
        return None
    if len(taints) == 1:
        return taints[0]
    best = min(taints, key=lambda t: (len(t[1]), "src" not in t[2]))
    safe = frozenset.intersection(*(t[1] for t in taints))
    origins = frozenset().union(*(t[2] for t in taints))
    return (best[0], safe, origins)


def _with_safe(t, classes):
    if not t:
        return None
    safe = t[1] | classes
    return None if safe >= ALL else (t[0], safe, t[2])


def _extend(t, label, line):
    if not t:
        return None
    chain = t[0] if t[0] and t[0][-1] == (label, line) else t[0] + ((label, line),)
    return (chain, t[1], t[2])


def _merge_env(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = _choose(out.get(k), v)
    return out


# ---- sinks --------------------------------------------------------------------------------------------------------

SINK_INFO = {
    "sql": ("PYT001", "SQL injection: request data reaches a SQL query", "high", "CWE-89", "PY004"),
    "cmd": ("PYT002", "Command injection: request data reaches a shell command", "critical", "CWE-78", "PY003"),
    "code": ("PYT003", "Code injection: request data reaches eval/exec", "critical", "CWE-95", "PY001"),
    "ssrf": ("PYT004", "SSRF: request data controls an outbound request URL", "high", "CWE-918", "PY012"),
    "path": ("PYT005", "Path traversal: request data reaches a filesystem path", "high", "CWE-22", "PY013"),
    "redirect": ("PYT006", "Open redirect: request data controls a redirect target", "medium", "CWE-601", "PY014"),
    "deser": ("PYT007", "Unsafe deserialization of request data", "critical", "CWE-502", "PY005"),
    "ssti": ("PYT008", "Server-side template injection", "critical", "CWE-1336", None),
    "markup": ("PYT009", "XSS: request data marked as safe HTML", "high", "CWE-79", "PY015"),
    "xss": ("PYT010", "Reflected XSS: request data written into an HTML response", "high", "CWE-79", None),
}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "mogrify"}
SQL_AMBIGUOUS = {"fetch", "fetchrow", "fetchval", "fetch_all", "fetch_one", "fetch_val", "query", "execute_many",
                 "iterate", "exec_driver_sql"}
SQL_FUNCS = {"text", "sqlalchemy.text", "sqlalchemy.sql.text", "RawSQL", "django.db.models.expressions.RawSQL",
             "pandas.read_sql", "pandas.read_sql_query", "read_sql", "read_sql_query", "pd.read_sql"}
CMD_FUNCS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput",
             "asyncio.create_subprocess_shell", "pty.spawn", "platform.popen"}
SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
              "subprocess.Popen"}
CODE_FUNCS = {"eval", "exec", "compile", "builtins.eval", "builtins.exec"}
SSRF_MODULES = ("requests", "httpx", "requests.api")
PATH_FUNCS = {"open", "io.open", "codecs.open", "os.open", "builtins.open", "os.remove", "os.unlink", "os.rmdir",
              "os.removedirs", "os.listdir", "os.scandir", "os.makedirs", "os.mkdir", "os.stat", "os.chmod",
              "os.chown", "os.walk", "os.truncate", "tarfile.open", "zipfile.ZipFile", "aiofiles.open",
              "send_file", "flask.send_file", "FileResponse", "starlette.responses.FileResponse",
              "fastapi.responses.FileResponse", "django.http.FileResponse"}
PATH_TWO_ARGS = {"os.rename", "os.replace", "os.link", "os.symlink", "shutil.copy", "shutil.copy2", "shutil.copyfile",
                 "shutil.copytree", "shutil.move", "shutil.rmtree", "shutil.copyfileobj"}
PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink", "rmdir", "mkdir", "touch",
                "rename", "replace", "iterdir", "symlink_to", "chmod"}
REDIRECTS = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"}
DESER_FUNCS = {"pickle.loads", "pickle.load", "pickle.Unpickler", "cPickle.loads", "cPickle.load", "_pickle.loads",
               "dill.loads", "dill.load", "jsonpickle.decode", "marshal.loads", "marshal.load", "shelve.open",
               "yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all", "joblib.load",
               "torch.load", "numpy.load", "pandas.read_pickle"}
SSTI_FUNCS = {"jinja2.Template", "Template", "django.template.Template", "mako.template.Template",
              "jinja2.Environment().from_string", "flask.render_template_string", "render_template_string"}
MARKUP_FUNCS = {"Markup", "markupsafe.Markup", "mark_safe", "django.utils.safestring.mark_safe", "flask.Markup",
                "jinja2.Markup", "SafeString"}
HTML_RESPONSES = {"HttpResponse", "django.http.HttpResponse", "HTMLResponse", "fastapi.responses.HTMLResponse",
                  "starlette.responses.HTMLResponse", "make_response", "flask.make_response", "flask.Response",
                  "werkzeug.wrappers.Response", "werkzeug.Response", "starlette.responses.Response",
                  "fastapi.responses.Response", "fastapi.Response", "Response"}
NON_HTML = re.compile(r"(?i)json|plain|csv|octet|javascript|xml|image|pdf|zip|event-stream")
TERMINATORS = {"abort", "flask.abort", "exit", "sys.exit", "quit", "os._exit"}


class _Summary:
    __slots__ = ("ret", "sinks", "params", "is_method")

    def __init__(self, params, is_method):
        self.ret = None  # taint of the return value, with parameter origins
        self.sinks = []  # (origins, safe, kind, line, chain)
        self.params = params
        self.is_method = is_method


class _Module:
    def __init__(self, path: str, lines: list, tree: ast.Module):
        self.path, self.lines, self.tree = path, lines, tree
        self.aliases = {}
        self.request_imports = set()
        self.flask = self.fastapi = False
        self.functions, self.classes, self.summaries = {}, {}, {}
        self.findings = {}
        self.collect = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                    self._note_framework(a.name)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                self._note_framework(node.module)
                for a in node.names:
                    full = f"{node.module}.{a.name}"
                    self.aliases[a.asname or a.name] = full
                    if a.name == "request" and node.module.split(".")[0] in ("flask", "quart", "bottle", "sanic"):
                        self.request_imports.add(a.asname or a.name)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
            elif isinstance(node, ast.ClassDef):
                self.classes[node.name] = {n.name: n for n in node.body
                                           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def _note_framework(self, module: str):
        top = module.split(".")[0]
        if top in ("flask", "quart", "werkzeug"):
            self.flask = True
        elif top in ("fastapi", "starlette"):
            self.fastapi = True

    def canonical(self, name: str) -> str:
        if not name:
            return name
        head, _, rest = name.partition(".")
        call = head.endswith("()")
        base = head[:-2] if call else head
        if base in self.aliases:
            head = self.aliases[base] + ("()" if call else "")
        return head + ("." + rest if rest else "")

    def report(self, kind, line, chain, sink_label):
        rid, title, sev, cwe, fix_rule = SINK_INFO[kind]
        key = (rid, line)
        if not self.collect or key in self.findings:
            return
        if 0 < line <= len(self.lines) and is_suppressed(self.lines[line - 1]):
            return  # the same inline markers that silence line rules
        flow, prev = [], None
        for item in tuple(chain) + ((sink_label, line),):
            if item != prev:
                flow.append(f"{item[0]} (L{item[1]})")
            prev = item
        snippet = self.lines[line - 1].strip()[:240] if 0 < line <= len(self.lines) else ""
        fix = _FIX.get(fix_rule, "") if fix_rule else (SSTI_FIX if kind == "ssti" else XSS_FIX)
        self.findings[key] = Finding(rule_id=rid, title=title, severity=sev, category="code", file=self.path,
                                     line=line, snippet=snippet, cwe=cwe, fix=fix,
                                     extra={"flow": " → ".join(flow)})

    def run(self) -> list:
        targets = [(fn, None) for fn in self.functions.values()]
        for cname, methods in self.classes.items():
            targets += [(fn, cname) for fn in methods.values()]
        for round_no in range(3):
            self.collect = round_no == 2
            for fn, cname in targets:
                try:
                    _Func(self, fn, cname).analyse()
                except RecursionError:
                    continue
        try:
            _Func(self, None, None).analyse()
        except RecursionError:
            pass
        return list(self.findings.values())


class _Func:
    def __init__(self, module: _Module, fn, cname, env=None, req_names=None):
        self.m, self.fn, self.cname = module, fn, cname
        self.env = dict(env or {})
        self.types = {}
        self.resolved = set()  # names holding a realpath()/abspath() result, for prefix guards
        self.sqlish = set()
        self.req = set(req_names) if req_names is not None else set(module.request_imports)
        self.returns = []
        self.route = None
        self.summary = None
        if fn is not None:
            self._init_params()

    # ---- parameters ----------------------------------------------------------------------------------------------

    def _init_params(self):
        fn = self.fn
        a = fn.args
        positional = list(getattr(a, "posonlyargs", [])) + list(a.args)
        is_method = self.cname is not None and positional and positional[0].arg in ("self", "cls")
        callable_params = positional[1:] if is_method else positional
        defaults = dict(zip([p.arg for p in positional][-len(a.defaults):], a.defaults)) if a.defaults else {}
        defaults.update({p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})
        names = [p.arg for p in callable_params] + [p.arg for p in a.kwonlyargs]
        self.summary = _Summary(names, bool(is_method))
        route = self._route_info()
        params = callable_params + list(a.kwonlyargs)
        for p in params:
            if self._is_request_param(p):
                self.req.add(p.arg)
        first = callable_params[0].arg if callable_params else None
        django_view = first in REQUEST_NAMES or (callable_params and self._is_request_param(callable_params[0]))
        for idx, p in enumerate(params):
            if p.arg in self.req:
                continue
            source = False
            if route is not None:
                source = self._route_param_tainted(p, defaults.get(p.arg), route)
            elif django_view and idx > 0 and p.arg not in SKIP_PARAMS and not a.kwonlyargs.count(p):
                source = self._annotation_tainted(p.annotation) if p.annotation is not None else True
            if source:
                self.env[p.arg] = ((f"route param `{p.arg}`", fn.lineno),), frozenset(), frozenset({"src"})
            else:
                self.env[p.arg] = ((f"param `{p.arg}`", fn.lineno),), frozenset(), frozenset({idx})

    def _is_request_param(self, p) -> bool:
        if p.annotation is not None:
            ann = dotted(p.annotation).rsplit(".", 1)[-1]
            return ann in REQUEST_TYPES
        return p.arg in REQUEST_NAMES

    def _route_info(self):
        for dec in self.fn.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            if dec.func.attr not in ROUTE_DECORATORS:
                continue
            path = _const_str(dec.args[0]) if dec.args else None
            if path is None:
                path = next((_const_str(k.value) for k in dec.keywords if k.arg in ("path", "rule")), None)
            if path is None or (path and not path.startswith("/")):
                continue
            html = any(k.arg == "response_class" and "HTML" in dotted(k.value) for k in dec.keywords)
            flask_style = "<" in path or (dec.func.attr == "route" and not self.m.fastapi)
            converters = {m.group(2): (m.group(1) or "string") for m in re.finditer(r"<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>", path)}
            return {"path": path, "flask": flask_style, "converters": converters, "html": html}
        return None

    def _route_param_tainted(self, p, default, route) -> bool:
        if p.arg in SKIP_PARAMS:
            return False
        if route["flask"]:
            conv = route["converters"].get(p.arg)
            return conv is not None and conv not in ("int", "float", "uuid")
        if isinstance(default, ast.Call) and dotted(default.func).rsplit(".", 1)[-1] in ("Depends", "Security"):
            return False
        return self._annotation_tainted(p.annotation)

    def _annotation_tainted(self, ann) -> bool:
        if ann is None:
            return True
        for _ in range(6):
            if isinstance(ann, ast.Subscript):
                head = dotted(ann.value).rsplit(".", 1)[-1]
                inner = ann.slice.value if isinstance(ann.slice, getattr(ast, "Index", ())) else ann.slice
                elts = inner.elts if isinstance(inner, ast.Tuple) else [inner]
                if head == "Annotated":
                    if any(isinstance(e, ast.Call) and dotted(e.func).rsplit(".", 1)[-1] in ("Depends", "Security")
                           for e in elts[1:]):
                        return False
                    ann = elts[0]
                elif head in ("Optional", "List", "list", "Sequence", "Set", "set", "FrozenSet", "Tuple", "tuple",
                              "Iterable"):
                    ann = elts[0]
                elif head == "Union":
                    ann = next((e for e in elts if not (isinstance(e, ast.Constant) and e.value is None)
                                and dotted(e) != "None"), elts[0])
                elif head == "Literal":
                    return False
                else:
                    break
            elif isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
                ann = ann.right if (isinstance(ann.left, ast.Constant) and ann.left.value is None) else ann.left
            else:
                break
        name = dotted(ann).rsplit(".", 1)[-1] if not isinstance(ann, ast.Constant) else str(ann.value)
        if name in VALIDATED_TYPES or name in NON_INPUT_TYPES or name in REQUEST_TYPES:
            return False
        return True

    # ---- driver ---------------------------------------------------------------------------------------------------

    def analyse(self):
        body = self.fn.body if self.fn is not None else [
            s for s in self.m.tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        self.exec_block(body)
        if self.fn is not None:
            self.m.summaries[self.fn] = self.summary
            ret = _choose(*self.returns)
            self.summary.ret = ret

    def exec_block(self, stmts):
        for s in stmts:
            self.exec_stmt(s)

    def exec_stmt(self, s):
        if isinstance(s, ast.Assign):
            t = self.eval(s.value)
            for target in s.targets:
                self.assign(target, t, s.value, s.lineno)
        elif isinstance(s, ast.AnnAssign):
            if s.value is not None:
                self.assign(s.target, self.eval(s.value), s.value, s.lineno)
        elif isinstance(s, ast.AugAssign):
            t = _choose(self.eval(s.target), self.eval(s.value))
            self.assign(s.target, t, None, s.lineno)
        elif isinstance(s, ast.Expr):
            self.eval(s.value)
        elif isinstance(s, ast.Return):
            if s.value is not None:
                t = self.eval(s.value)
                if t:
                    self.returns.append(t)
                    self._check_return_xss(s, t)
        elif isinstance(s, ast.If):
            self._exec_if(s)
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            before = dict(self.env)
            t = self.eval(s.iter)
            for _ in range(2):
                self.assign(s.target, t, None, s.lineno)
                self.exec_block(s.body)
            self.env = _merge_env(before, self.env)
            self.exec_block(s.orelse)
        elif isinstance(s, ast.While):
            before = dict(self.env)
            self.eval(s.test)
            for _ in range(2):
                self.exec_block(s.body)
            self.env = _merge_env(before, self.env)
            self.exec_block(s.orelse)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                t = self.eval(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, t, item.context_expr, s.lineno)
            self.exec_block(s.body)
        elif isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
            before = dict(self.env)
            self.exec_block(s.body)
            after = dict(self.env)
            merged = _merge_env(before, after)
            for h in s.handlers:
                self.env = dict(merged)
                self.exec_block(h.body)
                after = _merge_env(after, self.env)
            self.env = after
            self.exec_block(s.orelse)
            self.exec_block(s.finalbody)
        elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if self.fn is not None:  # a closure or a route defined inside an app factory
                inner = _Func(self.m, s, None, env=self.env, req_names=self.req)
                inner.exec_block(s.body)
        elif isinstance(s, ast.Delete):
            for target in s.targets:
                if isinstance(target, ast.Name):
                    self.env.pop(target.id, None)
        elif isinstance(s, (ast.Import, ast.ImportFrom)):
            pass
        else:
            for field in ("body", "orelse", "finalbody"):
                block = getattr(s, field, None)
                if isinstance(block, list):
                    self.exec_block(block)
            for case in getattr(s, "cases", []) or []:
                self.exec_block(case.body)

    def _exec_if(self, s):
        self.eval(s.test)
        clean_true, clean_false = self._guard(s.test)
        base = self.env
        self.env = {k: v for k, v in base.items() if k not in clean_true}
        self.exec_block(s.body)
        env_true = self.env
        self.env = {k: v for k, v in base.items() if k not in clean_false}
        self.exec_block(s.orelse)
        env_false = self.env
        if _terminates(s.body) and not _terminates(s.orelse):
            self.env = env_false
        elif _terminates(s.orelse) and s.orelse and not _terminates(s.body):
            self.env = env_true
        else:
            self.env = _merge_env(env_true, env_false)

    def _guard(self, test):
        """Names proven safe when `test` is true, and when it is false."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            t, f = self._guard(test.operand)
            return f, t
        if isinstance(test, ast.BoolOp):
            parts = [self._guard(v) for v in test.values]
            if isinstance(test.op, ast.And):
                return set().union(*(p[0] for p in parts)), set.intersection(*(set(p[1]) for p in parts))
            return set.intersection(*(set(p[0]) for p in parts)), set().union(*(p[1] for p in parts))
        if isinstance(test, ast.Call):
            name = dotted(test.func)
            last = name.rsplit(".", 1)[-1]
            if isinstance(test.func, ast.Attribute) and last in ("isdigit", "isnumeric", "isdecimal", "isalnum",
                                                                  "isalpha", "isidentifier"):
                n = _name(test.func.value)
                return ({n} if n else set()), set()
            if isinstance(test.func, ast.Attribute) and last == "startswith":
                n = _name(test.func.value)
                return ({n} if n and n in self.resolved else set()), set()
            if last in ("fullmatch", "match") and test.args:
                pattern = _const_str(test.args[0]) if len(test.args) > 1 else None
                subject = test.args[1] if len(test.args) > 1 else test.args[0]
                n = _name(subject)
                if n and (last == "fullmatch" or pattern is None or pattern.endswith(("$", "\\Z"))):
                    return {n}, set()
            if last == "isinstance" and test.args:
                n = _name(test.args[0])
                return ({n} if n else set()), set()
            if last in ("is_safe_url", "url_has_allowed_host_and_scheme") and test.args:
                n = _name(test.args[0])
                return ({n} if n else set()), set()
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            n = _name(test.left)
            op = test.ops[0]
            if n and isinstance(op, (ast.In, ast.Eq)):
                return {n}, set()
            if n and isinstance(op, (ast.NotIn, ast.NotEq)):
                return set(), {n}
        return set(), set()

    # ---- binding ---------------------------------------------------------------------------------------------------

    def assign(self, target, t, value, line):
        if isinstance(target, ast.Name):
            name = target.id
            if value is not None:
                self._track(name, value)
            if t:
                self.env[name] = _extend(t, name, line)
            else:
                self.env.pop(name, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts) \
                    and not any(isinstance(e, ast.Starred) for e in target.elts):
                for sub, val in zip(target.elts, value.elts):
                    self.assign(sub, self.eval_quiet(val), val, line)
            else:
                for sub in target.elts:
                    self.assign(sub, t, None, line)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, t, None, line)
        elif isinstance(target, ast.Attribute):
            key = dotted(target)
            if key:
                if t:
                    self.env[key] = _extend(t, key, line)
                else:
                    self.env.pop(key, None)
        elif isinstance(target, ast.Subscript):
            base = dotted(target.value)
            if base and t:  # weak update: the container now holds request data
                self.env[base] = _choose(self.env.get(base), _extend(t, base, line))

    def _track(self, name, value):
        """Remember what kind of object a name holds: request alias, HTTP client, resolved path, SQL text."""
        self.req.discard(name)
        self.types.pop(name, None)
        self.resolved.discard(name)
        self.sqlish.discard(name)
        if isinstance(value, ast.Name) and value.id in self.req:
            self.req.add(name)
            return
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(value, ast.Call):
            canon = self.m.canonical(dotted(value.func))
            if canon in CLIENT_CTORS:
                self.types[name] = canon
            elif canon.rsplit(".", 1)[-1] in ("Path", "PurePath", "PosixPath") or canon.endswith(".resolve"):
                self.types[name] = "pathlib.Path"
            if canon.rsplit(".", 1)[-1] in ("realpath", "abspath", "normpath", "resolve"):
                self.resolved.add(name)
        elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
            self.types[name] = "pathlib.Path"
        if _sql_text(value):
            self.sqlish.add(name)

    # ---- expressions -------------------------------------------------------------------------------------------------

    def eval_quiet(self, node):
        return self.eval(node)

    def is_request(self, node) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.req
        return isinstance(node, ast.Attribute) and node.attr == "request" and isinstance(node.value, ast.Name) \
            and node.value.id in ("self", "cls", "ctx", "context", "info")

    def eval(self, node):
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Attribute):
            key = dotted(node)
            if key and key in self.env:
                return self.env[key]
            if self.is_request(node.value) and node.attr in SOURCE_ATTRS:
                return ((f"{dotted(node.value) or 'request'}.{node.attr}", node.lineno),), \
                    SAME_SITE if node.attr in ("path", "full_path", "path_info") else frozenset(), frozenset({"src"})
            if node.attr == "kwargs" and isinstance(node.value, ast.Name) and node.value.id == "self":
                return (("self.kwargs", node.lineno),), frozenset(), frozenset({"src"})
            return self.eval(node.value)
        if isinstance(node, ast.Subscript):
            return self.eval(node.value)
        if isinstance(node, ast.Call):
            return self.eval_call(node)
        if isinstance(node, ast.BinOp):
            return self._eval_binop(node)
        if isinstance(node, ast.JoinedStr):
            return _choose(*(self.eval(v.value) for v in node.values if isinstance(v, ast.FormattedValue)))
        if isinstance(node, ast.FormattedValue):
            return self.eval(node.value)
        if isinstance(node, ast.BoolOp):
            return _choose(*(self.eval(v) for v in node.values))
        if isinstance(node, ast.IfExp):
            self.eval(node.test)
            return _choose(self.eval(node.body), self.eval(node.orelse))
        if isinstance(node, ast.Compare):
            self.eval(node.left)
            for c in node.comparators:
                self.eval(c)
            return None
        if isinstance(node, ast.UnaryOp):
            t = self.eval(node.operand)
            return None if isinstance(node.op, ast.Not) else t
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return _choose(*(self.eval(e) for e in node.elts))
        if isinstance(node, ast.Dict):
            return _choose(*(self.eval(v) for v in node.values))
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._eval_comp(node)
        if isinstance(node, (ast.Starred, ast.Await)):
            return self.eval(node.value)
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return self.eval(node.value) if node.value is not None else None
        if isinstance(node, ast.NamedExpr):
            t = self.eval(node.value)
            self.assign(node.target, t, node.value, node.lineno)
            return t
        if isinstance(node, ast.Lambda):
            saved = dict(self.env)
            self.eval(node.body)  # sinks inside the lambda see the enclosing values
            self.env = saved
            return None
        return None

    def _eval_binop(self, node):
        """Iterative, so a generated 4000-term concatenation cannot exhaust the stack."""
        leaves, stack = [], [node]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.BinOp):
                stack.append(n.right)
                stack.append(n.left)
            else:
                leaves.append(n)
        if isinstance(node.op, ast.Mod) and _const_str(node.left) is None and not isinstance(node.left, ast.JoinedStr):
            pass  # numeric modulo still carries the operands
        return _choose(*(self.eval(leaf) for leaf in leaves if not isinstance(leaf, ast.Constant)))

    def _eval_comp(self, node):
        saved = dict(self.env)
        for gen in node.generators:
            t = self.eval(gen.iter)
            self.assign(gen.target, t, None, getattr(gen.iter, "lineno", node.lineno))
            for cond in gen.ifs:
                self.eval(cond)
        if isinstance(node, ast.DictComp):
            out = _choose(self.eval(node.key), self.eval(node.value))
        else:
            out = self.eval(node.elt)
        self.env = saved
        return out

    def eval_call(self, node: ast.Call):
        name = dotted(node.func)
        recv_node = node.func.value if isinstance(node.func, ast.Attribute) else None
        if recv_node is not None and isinstance(recv_node, ast.Name) and recv_node.id in self.types:
            name = self.types[recv_node.id] + "()." + node.func.attr
        canon = self.m.canonical(name)
        last = canon.rsplit(".", 1)[-1] if canon else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
        recv = self.eval(recv_node) if recv_node is not None and not self.is_request(recv_node) else None
        args = [self.eval(a) for a in node.args]
        kwargs = {k.arg: self.eval(k.value) for k in node.keywords}
        self._check_sinks(node, canon, last, args, kwargs, recv)

        if recv_node is not None and self.is_request(recv_node) and node.func.attr in SOURCE_METHODS:
            return ((f"{dotted(recv_node) or 'request'}.{node.func.attr}()", node.lineno),), \
                SAME_SITE if node.func.attr in ("get_full_path", "get_host") else frozenset(), frozenset({"src"})
        if recv_node is not None and isinstance(recv_node, ast.Name) and recv_node.id == "self" and \
                last in ("get_argument", "get_arguments", "get_query_argument", "get_body_argument"):
            return ((f"self.{last}()", node.lineno),), frozenset(), frozenset({"src"})
        if last in ("get", "getlist") and any(k.arg == "type" and dotted(k.value) in ("int", "float", "bool", "UUID")
                                              for k in node.keywords):
            return None
        everything = _choose(recv, *args, *(v for v in kwargs.values()))
        if not everything and not self._summary_for(node):
            return None
        summary_fn = self._summary_for(node)
        if summary_fn is not None:
            return self._apply_summary(node, summary_fn, args, kwargs, name)
        if canon in SANITIZERS or last in SANITIZERS and (canon == last or canon.endswith("." + last)):
            classes = SANITIZERS.get(canon) or SANITIZERS[last]
            return _with_safe(everything, classes)
        if GENERIC_SANITIZER.match(last) and not isinstance(node.func, ast.Attribute):
            return None
        if last in SQL_SAFE_METHODS and isinstance(node.func, ast.Attribute):
            return _choose(recv, _with_safe(_choose(*args, *kwargs.values()), frozenset({"sql"})))
        if canon in STRING_FUNCS or last in STRING_FUNCS:
            return everything
        if recv is not None:  # a method on request data keeps it (`.strip()`, `.split(":")`)
            return _choose(recv, _with_safe(_choose(*args, *kwargs.values()), frozenset({"xss"})))
        return _with_safe(everything, frozenset({"xss"}))  # unknown function: still data, no longer HTML-shaped

    # ---- same-file functions -------------------------------------------------------------------------------------

    def _summary_for(self, node):
        func = node.func
        if isinstance(func, ast.Name) and func.id in self.m.functions:
            return self.m.functions[func.id]
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in ("self", "cls") \
                and self.cname and func.attr in self.m.classes.get(self.cname, {}):
            return self.m.classes[self.cname][func.attr]
        return None

    def _apply_summary(self, node, fn, args, kwargs, name):
        summary = self.m.summaries.get(fn)
        if summary is None:  # not analysed yet (first round): assume it passes data through
            return _with_safe(_choose(*args, *kwargs.values()), frozenset({"xss"}))
        bound = {}
        for i, t in enumerate(args):
            if t and i < len(summary.params):
                bound[i] = t
        for k, t in kwargs.items():
            if t and k in summary.params:
                bound[summary.params.index(k)] = t
        label = f"{name.rsplit('.', 1)[-1]}()"
        for origins, safe, kind, line, chain in summary.sinks:
            for idx in origins:
                arg = bound.get(idx) if isinstance(idx, int) else None
                if arg is None:
                    continue
                cls = "xss" if kind in ("xss", "markup") else kind
                if cls in arg[1] or cls in safe:
                    continue
                full = arg[0] + ((label, node.lineno),) + tuple(chain[1:])
                self._sink_hit(kind, line, (full, arg[1] | safe, arg[2]), "", direct=True)
        out = []
        ret = summary.ret
        if ret:
            if "src" in ret[2]:
                out.append(_extend(((ret[0]), ret[1], frozenset({"src"})), label, node.lineno))
            for idx in ret[2]:
                if isinstance(idx, int) and idx in bound:
                    arg = bound[idx]
                    out.append((arg[0] + ((label, node.lineno),), arg[1] | ret[1], arg[2]))
        return _choose(*out)

    # ---- sinks ---------------------------------------------------------------------------------------------------

    def _sink_hit(self, kind, line, t, sink_label, direct=False):
        cls = "xss" if kind in ("xss", "markup") else kind
        if not t or cls in t[1]:
            return
        if "src" in t[2]:
            self.m.report(kind, line, t[0], sink_label or "sink")
        params = frozenset(o for o in t[2] if isinstance(o, int))
        if params and self.summary is not None:
            entry = (params, t[1], kind, line, t[0] if not direct else t[0])
            if entry not in self.summary.sinks:
                self.summary.sinks.append(entry)

    def _check_sinks(self, node, canon, last, args, kwargs, recv):
        line = node.lineno
        label = canon + "()" if canon else "call"

        def arg(i, *kw):
            t = args[i] if i < len(args) else None
            for k in kw:
                t = _choose(t, kwargs.get(k))
            return t

        def node_arg(i, *kw):
            if i < len(node.args):
                return node.args[i]
            return next((k.value for k in node.keywords if k.arg in kw), None)

        # SQL
        if last in SQL_METHODS and isinstance(node.func, ast.Attribute):
            self._sink_hit("sql", line, arg(0, "sql", "query", "statement", "operation"), label)
        elif last == "extra" and isinstance(node.func, ast.Attribute):
            self._sink_hit("sql", line, _choose(*(kwargs.get(k) for k in ("where", "select", "tables", "order_by"))),
                           label)
        elif canon in SQL_FUNCS or last in ("RawSQL", "read_sql", "read_sql_query"):
            self._sink_hit("sql", line, arg(0, "sql", "text"), label)
        elif last in SQL_AMBIGUOUS and isinstance(node.func, ast.Attribute):
            target = node_arg(0, "query", "sql")
            if target is not None and (_sql_text(target) or _name(target) in self.sqlish):
                self._sink_hit("sql", line, arg(0, "query", "sql"), label)
        # command execution
        if canon in CMD_FUNCS:
            self._sink_hit("cmd", line, arg(0, "cmd", "command"), label)
        elif canon in SUBPROCESS or canon == "asyncio.create_subprocess_exec":
            shell = any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in node.keywords)
            first = node_arg(0, "args")
            if shell:
                self._sink_hit("cmd", line, arg(0, "args"), label)
            elif canon == "asyncio.create_subprocess_exec":
                self._exec_family(node.args, args, line, label, program_index=0)
            elif isinstance(first, (ast.List, ast.Tuple)):
                elt_taints = [self.eval(e) for e in first.elts]
                self._exec_family(first.elts, elt_taints, line, label, program_index=0)
        elif canon.startswith(("os.exec", "os.spawn", "os.posix_spawn")):
            program_index = 1 if canon.startswith("os.spawn") else 0
            flat_nodes, flat_taints = [], []
            for a, t in zip(node.args, args):
                if isinstance(a, (ast.List, ast.Tuple)):
                    flat_nodes += a.elts
                    flat_taints += [self.eval(e) for e in a.elts]
                else:
                    flat_nodes.append(a)
                    flat_taints.append(t)
            self._exec_family(flat_nodes, flat_taints, line, label, program_index=program_index)
        # code
        if canon in CODE_FUNCS:
            self._sink_hit("code", line, arg(0, "source", "expression"), label)
        # SSRF
        ssrf = None
        if canon.startswith(tuple(m + "." for m in SSRF_MODULES)) and last in HTTP_VERBS | {"request", "stream"} \
                and canon.count(".") <= 2:
            ssrf = (1 if last in ("request", "stream") else 0)
        elif canon in ("urllib.request.urlopen", "urllib.request.Request", "urllib.urlopen", "urllib2.urlopen",
                       "http.client.HTTPConnection", "http.client.HTTPSConnection", "urlopen"):
            ssrf = 0
        elif canon in ("aiohttp.request",):
            ssrf = 1
        elif "()." in canon and canon.split("().", 1)[0] in CLIENT_CTORS and last in HTTP_VERBS | {"request", "stream"}:
            ssrf = 1 if last in ("request", "stream") and "urllib3" not in canon and "tornado" not in canon else 0
            if "urllib3" in canon and last == "request":
                ssrf = 1
        if ssrf is not None:
            target = node_arg(ssrf, "url")
            if not _fixed_host(target):
                self._sink_hit("ssrf", line, arg(ssrf, "url"), label)
        # filesystem paths
        if canon in PATH_FUNCS or last in ("send_file", "FileResponse"):
            self._sink_hit("path", line, arg(0, "file", "path", "filename", "path_or_file", "name"), label)
        elif canon in PATH_TWO_ARGS:
            self._sink_hit("path", line, _choose(arg(0, "src"), arg(1, "dst")), label)
        elif last in PATH_METHODS and isinstance(node.func, ast.Attribute) and recv is not None \
                and self._pathish(node.func.value):
            self._sink_hit("path", line, recv, label)
        # redirects
        if last in REDIRECTS:
            target = node_arg(0, "location", "url", "to", "redirect_to")
            if not _same_site(target):
                self._sink_hit("redirect", line, arg(0, "location", "url", "to", "redirect_to"), label)
        # deserialization
        if canon in DESER_FUNCS:
            safe_loader = any("Safe" in dotted(a) or "BaseLoader" in dotted(a) for a in node.args[1:]) or any(
                k.arg == "Loader" and ("Safe" in dotted(k.value) or "BaseLoader" in dotted(k.value))
                for k in node.keywords)
            numpy_ok = canon == "numpy.load" and not any(k.arg == "allow_pickle" for k in node.keywords)
            if not (canon.startswith("yaml.load") and safe_loader) and not numpy_ok:
                self._sink_hit("deser", line, arg(0, "data", "file", "stream"), label)
        # templates
        if (canon in SSTI_FUNCS or last in ("render_template_string", "from_string")) and canon != "string.Template":
            self._sink_hit("ssti", line, arg(0, "source"), label)
        # XSS
        if canon in MARKUP_FUNCS or last in ("Markup", "mark_safe"):
            self._sink_hit("markup", line, arg(0), label)
        elif self._html_response(canon, last, node):
            self._sink_hit("xss", line, arg(0, "content", "response", "body"), label)

    def _exec_family(self, nodes, taints, line, label, program_index):
        consts = [_const_str(n) for n in nodes]
        if program_index < len(nodes):
            prog = consts[program_index]
            if prog is not None and prog.rsplit("/", 1)[-1] in SHELLS | {"sh", "bash"} and "-c" in consts:
                self._sink_hit("cmd", line, _choose(*taints[consts.index("-c") + 1:]), label)
                return
            if prog is None:
                self._sink_hit("cmd", line, taints[program_index], label)

    def _pathish(self, recv_node) -> bool:
        if isinstance(recv_node, ast.Name):
            return self.types.get(recv_node.id) == "pathlib.Path"
        if isinstance(recv_node, ast.BinOp) and isinstance(recv_node.op, ast.Div):
            return True
        if isinstance(recv_node, ast.Call):
            return self.m.canonical(dotted(recv_node.func)).rsplit(".", 1)[-1] in ("Path", "PurePath", "resolve",
                                                                                    "joinpath")
        return False

    def _html_response(self, canon, last, node) -> bool:
        if canon not in HTML_RESPONSES and last not in ("HttpResponse", "HTMLResponse", "make_response"):
            return False
        if last == "Response" and not (canon.startswith(("flask", "werkzeug", "starlette", "fastapi"))
                                       or self.m.flask):
            return False
        if canon.startswith("rest_framework"):
            return False
        for k in node.keywords:
            if k.arg in ("content_type", "mimetype", "media_type", "headers"):
                text = _const_str(k.value) or ""
                if NON_HTML.search(text) or k.arg == "headers" and NON_HTML.search(ast.dump(k.value)):
                    return False
        if last == "make_response" and node.args and isinstance(node.args[0], ast.Call):
            return False  # make_response(render_template(...)) / make_response(jsonify(...))
        return True

    def _check_return_xss(self, s, t):
        """Flask returns a str as text/html; FastAPI only does when the route says response_class=HTMLResponse."""
        if self.fn is None:
            return
        route = self._route_info()
        if route is None:
            return
        html = route["html"] or (route["flask"] and (self.m.flask or not self.m.fastapi))
        if not html or isinstance(s.value, (ast.Dict, ast.List, ast.Tuple)):
            return
        if isinstance(s.value, ast.Call):
            last = dotted(s.value.func).rsplit(".", 1)[-1]
            if last in ("jsonify", "render_template", "redirect", "make_response", "send_file", "Response",
                        "HTMLResponse", "abort", "url_for", "dumps"):
                return
        self._sink_hit("xss", s.lineno, t, "returned HTML")


def _name(node):
    return node.id if isinstance(node, ast.Name) else (dotted(node) if isinstance(node, ast.Attribute) else None)


def _terminates(stmts) -> bool:
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        return dotted(last.value.func).rsplit(".", 1)[-1] in {t.rsplit(".", 1)[-1] for t in TERMINATORS}
    return False


def _leading_literal(node):
    """The constant text an expression starts with, for f-strings, concatenation, `%` and `.format`."""
    for _ in range(50):
        if node is None:
            return None
        s = _const_str(node)
        if s is not None:
            return s
        if isinstance(node, ast.JoinedStr):
            first = node.values[0] if node.values else None
            return _const_str(first) if first is not None else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            node = node.left
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            node = node.func.value
            continue
        return None
    return None


def _same_site(node) -> bool:
    prefix = _leading_literal(node)
    return bool(prefix) and prefix.startswith("/") and len(prefix) > 1 and prefix[1] not in "/\\" \
        and _const_str(node) is None


def _fixed_host(node) -> bool:
    prefix = _leading_literal(node)
    return bool(prefix) and _const_str(node) is None and bool(re.match(r"(?i)^https?://[^/?#@]+[/?#]", prefix))


def _sql_text(node) -> bool:
    if node is None:
        return False
    for n in ast.walk(node):
        s = _const_str(n)
        if s and SQL_TEXT.search(s):
            return True
    return False


def scan(files: list) -> list:
    findings = []
    for f in files:
        if not f.path.endswith(".py") or is_test_path(f.path):
            continue
        if not SOURCE_HINT.search(f.text):
            continue  # no request object, route or view anywhere: nothing can be tainted
        try:
            tree = ast.parse(f.text, filename=f.path)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        try:
            findings += _Module(f.path, f.lines, tree).run()
        except Exception:  # noqa: BLE001 - one odd file must not end the scan of the whole repository
            continue
    return findings
