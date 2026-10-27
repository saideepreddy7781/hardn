"""Lightweight multi-line taint tracking for JavaScript/TypeScript.

There is no JS parser in the Python stdlib, so this is a careful line-oriented approximation:
it follows request data through `const/let/var` assignments (including destructuring) within a
file and flags it when it reaches a dangerous sink. Line rules in code_rules.py catch the
single-line cases; this catches the `const q = "..." + name; db.query(q)` style flows.
"""
from __future__ import annotations

import re

from .code_rules import RULES
from .models import Finding
from .walker import is_test_path

JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
SOURCE = re.compile(
    r"\b(?:req|request|ctx\.request)\.(?:query|body|params|headers|cookies)\b|\bctx\.(?:query|params)\b"
    r"|\b(?:location\.(?:search|hash)|document\.(?:URL|referrer)|window\.location\.(?:search|hash))\b"
    r"|\bsearchParams\.get\s*\(|\bawait\s+request\.(?:json|formData|text)\s*\("
)
ASSIGN = re.compile(
    r"^\s*(?:export\s+)?(?:(?:const|let|var)\s+)?(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]|, ]+)?\s*=(?![=>])\s*(.+)$"
)
SANITIZER = re.compile(
    r"\b(?:parseInt|parseFloat|Number|Boolean|encodeURIComponent|escape|escapeHtml|DOMPurify\.sanitize|sanitize\w*|"
    r"validator\.\w+|path\.basename|z\.\w+|\w+Schema\.parse)\s*\("
)

_FIX = {r.id: r.fix for r in RULES}
# (rule, title, severity, cwe, regex locating the call; group 'args' starts right after "(" , fix rule, bare-identifier-only)
SINKS = [
    ("JST001", "SQL injection: request data reaches a SQL query", "high", "CWE-89",
     r"\.(?:query|raw|execute|whereRaw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(", "JS003", False),
    ("JST002", "Command injection: request data reaches a shell command", "critical", "CWE-78",
     r"(?<![\w$.])(?:child_process\.|cp\.)?(?:exec|execSync)\s*\(", "JS002", False),
    ("JST003", "Code injection: request data reaches eval", "critical", "CWE-95",
     r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn\w*\s*\(", "JS001", False),
    ("JST004", "SSRF: request data controls an outbound request URL", "high", "CWE-918",
     r"\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|got(?:\.\w+)?|https?\.(?:get|request))\s*\(", "JS013", False),
    ("JST005", "Path traversal: request data reaches a filesystem path", "high", "CWE-22",
     r"\b(?:readFile|readFileSync|createReadStream|sendFile|unlink|unlinkSync|writeFile|writeFileSync|download)\s*\(", "JS012", False),
    ("JST006", "Open redirect: request data controls a redirect target", "medium", "CWE-601",
     r"\.redirect\s*\(", "JS011", False),
    ("JST007", "NoSQL injection: request object used as a query", "high", "CWE-943",
     r"\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(", "JS015", True),
    ("JST008", "Prototype pollution: request data deep-merged into an object", "medium", "CWE-1321",
     r"\b(?:_\.merge|_\.mergeWith|_\.defaultsDeep|deepmerge|merge\.recursive)\s*\(", None, False),
]
XSS_ASSIGN = re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*(.+)|dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)")
PROTO_FIX = ("Never deep-merge untrusted objects. Pick known fields explicitly, validate with a schema, or merge into "
             "Object.create(null) and reject __proto__/constructor/prototype keys.")


def first_arg(text: str, all_args: bool = False) -> str:
    """Text of the first call argument (or of all arguments), given the text right after '('."""
    depth, quote, out = 0, None, []
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\":
                out.append(text[i + 1: i + 2])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
            out.append(ch)
        elif ch in "([{":
            depth += 1
            out.append(ch)
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
            out.append(ch)
        elif ch == "," and depth == 0 and not all_args:
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).strip()


def _names(lhs: str) -> list:
    lhs = lhs.strip()
    if lhs[0] in "{[":
        names = []
        for part in lhs[1:-1].split(","):
            part = part.split("=")[0].strip().lstrip(".")
            if ":" in part:
                part = part.split(":", 1)[1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
                names.append(part)
        return names
    return [lhs]


def _identifiers_outside_strings(expr: str) -> set:
    """Identifiers in code positions, including `${...}` interpolations, excluding plain string text."""
    code, i, quote = [], 0, None
    while i < len(expr):
        ch = expr[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if quote == "`" and expr.startswith("${", i):
                end = expr.find("}", i)
                code.append(" " + expr[i + 2: end if end != -1 else len(expr)] + " ")
                i = end + 1 if end != -1 else len(expr)
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        else:
            code.append(ch)
        i += 1
    return set(re.findall(r"(?<![\w$.])[A-Za-z_$][\w$]*", "".join(code)))


class _File:
    def __init__(self, path: str, lines: list):
        self.path, self.lines = path, lines
        self.env = {}

    def chain_for(self, expr: str):
        if SANITIZER.search(expr) and not SOURCE.search(SANITIZER.split(expr)[0]):
            return None
        m = SOURCE.search(expr)
        if m:
            return [(m.group(0).rstrip("( "), None)]
        for ident in _identifiers_outside_strings(expr):
            if ident in self.env:
                return self.env[ident]
        return None

    def run(self) -> list:
        code_lines = [(i, ln) for i, ln in enumerate(self.lines, 1)
                      if len(ln) < 1000 and not ln.lstrip().startswith(("//", "* ", "/*"))]
        for _ in range(2):
            for lineno, line in code_lines:
                m = ASSIGN.match(line)
                if not m:
                    continue
                chain = self.chain_for(m.group(2))
                if not chain:
                    continue
                for name in _names(m.group(1)):
                    if name not in self.env:
                        src = [(chain[0][0], chain[0][1] or lineno)] + chain[1:]
                        self.env[name] = src + [(name, lineno)]
        out = []
        for lineno, line in code_lines:
            out += self.check(lineno, line)
        return out

    def check(self, lineno: int, line: str) -> list:
        found = []
        for rid, title, sev, cwe, rx, fix_rule, bare_only in SINKS:
            for m in re.finditer(rx, line):
                arg = first_arg(line[m.end():], all_args=rid == "JST008")
                if rid == "JST006" and re.match(r"^\d+$", arg):  # res.redirect(302, url)
                    rest = line[m.end():]
                    arg = first_arg(rest[rest.find(",") + 1:])
                if bare_only and not re.fullmatch(r"[\w$.]+", arg):
                    continue
                if not arg or re.fullmatch(r"(['\"])[^'\"]*\1", arg):
                    continue
                chain = self.chain_for(arg)
                if chain:
                    found.append(self._finding(rid, title, sev, cwe, lineno, line, chain, m.group(0).rstrip("( "),
                                               _FIX.get(fix_rule) if fix_rule else PROTO_FIX))
                    break
        m = XSS_ASSIGN.search(line)
        if m:
            chain = self.chain_for(m.group(1) or m.group(2) or "")
            if chain:
                found.append(self._finding("JST009", "XSS: request data written into HTML", "high", "CWE-79",
                                           lineno, line, chain, "innerHTML", _FIX["JS004"]))
        return found

    def _finding(self, rid, title, sev, cwe, lineno, line, chain, sink, fix) -> Finding:
        chain = [(label, ln or lineno) for label, ln in chain] + [(sink.lstrip("."), lineno)]
        flow, prev = [], None
        for item in chain:
            if item != prev:
                flow.append(f"{item[0]} (L{item[1]})")
            prev = item
        return Finding(rule_id=rid, title=title, severity=sev, category="code", file=self.path, line=lineno,
                       snippet=line.strip()[:240], cwe=cwe, fix=fix, extra={"flow": " → ".join(flow)})


def scan(files: list) -> list:
    out = []
    for f in files:
        if f.path.lower().endswith(JS_EXT) and not is_test_path(f.path) and ".min." not in f.path:
            out += _File(f.path, f.lines).run()
    return out
