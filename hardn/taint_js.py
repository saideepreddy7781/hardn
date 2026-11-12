"""Taint tracking for JavaScript and TypeScript without a parser.

There is no JS parser in the Python stdlib, so this works on statements. Comments are removed, then the text is
split into statements at `;` and line ends outside brackets, and into blocks at `{` where a block can start, so a
call or template literal spread over several lines is one statement and object literals stay whole. Each block has
its own scope: `const`/`let` shadow, a later assignment kills taint, and changes made inside an `if` or a loop are
merged on the way out. Functions defined in the same file are summarised, so a helper that runs the query, or one
that returns request data, is followed.

Known limits: no type information (a method called `execute` is assumed to be a database call when its argument
looks like SQL), no flow across files, guards are recognised only in the `if (!check(x)) return` shape, and code
built by unusual syntax (labels, `with`, deeply nested template literals) is approximated.
"""
from __future__ import annotations

import bisect
import re

from .code_rules import _C_TOKENS, RULES, is_bundle, is_suppressed, views
from .models import Finding
from .walker import is_test_path

JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_FIX = {r.id: r.fix for r in RULES}
PROTO_FIX = ("Never deep-merge untrusted objects. Pick known fields explicitly, validate with a schema, or merge into "
             "Object.create(null) and reject __proto__/constructor/prototype keys.")
XSS_FIX = ("Send data as JSON (res.json) or render it through a template that escapes by default. If you must build "
           "HTML, escape every value first.")
SSTI_FIX = "Never compile templates from user input. Render a fixed template and pass user data as variables."
DESER_FIX = "Never deserialize untrusted input with node-serialize or similar; parse JSON and validate it with a schema."

ALL = frozenset({"sql", "cmd", "code", "ssrf", "path", "redirect", "nosql", "proto", "xss", "ssti", "deser"})
BROWSER_SAFE = frozenset({"sql", "cmd", "path", "nosql", "deser", "ssti", "xss"})
PAGE_URL_SAFE = BROWSER_SAFE | {"ssrf", "redirect"}
INFO = {
    "sql": ("JST001", "SQL injection: request data reaches a SQL query", "high", "CWE-89", "JS003"),
    "cmd": ("JST002", "Command injection: request data reaches a shell command", "critical", "CWE-78", "JS002"),
    "code": ("JST003", "Code injection: request data reaches eval", "critical", "CWE-95", "JS001"),
    "ssrf": ("JST004", "SSRF: request data controls an outbound request URL", "high", "CWE-918", "JS013"),
    "path": ("JST005", "Path traversal: request data reaches a filesystem path", "high", "CWE-22", "JS012"),
    "redirect": ("JST006", "Open redirect: request data controls a redirect target", "medium", "CWE-601", "JS011"),
    "nosql": ("JST007", "NoSQL injection: request data used as a query object", "high", "CWE-943", "JS015"),
    "proto": ("JST008", "Prototype pollution: request data deep-merged into an object", "medium", "CWE-1321", None),
    "dom": ("JST009", "XSS: request data written into HTML", "high", "CWE-79", "JS004"),
    "xss": ("JST010", "Reflected XSS: request data written into an HTML response", "high", "CWE-79", None),
    "deser": ("JST011", "Unsafe deserialization of request data", "critical", "CWE-502", None),
    "ssti": ("JST012", "Server-side template injection", "critical", "CWE-1336", None),
}
FIXES = {"proto": PROTO_FIX, "xss": XSS_FIX, "ssti": SSTI_FIX, "deser": DESER_FIX}

REQ_PROPS = (r"query|body|params|headers|cookies|signedCookies|url|originalUrl|path|hostname|host|file|files|"
             r"baseUrl|subdomains|rawBody|querystring|header")
STRING_PROPS = {"params", "headers", "cookies", "signedCookies", "url", "originalUrl", "path", "hostname", "host",
                "baseUrl", "querystring", "header", "file"}
FIXED_SOURCES = re.compile(
    r"\b(?:ctx\.request|ctx)\.(?:query|params|querystring|headers|header|body|url|path|host|hostname|files?)\b"
    r"|\bctx\.(?:get|cookies\.get)\s*\(|\bctx\.request\.(?:get)\s*\("
    r"|\b(?:window\.)?location\.(?:search|hash|href)\b|\bdocument\.(?:URL|documentURI|referrer|cookie|baseURI)\b"
    r"|\bwindow\.name\b|\bsearchParams\.get\s*\(|\bawait\s+(?:req|request|ctx\.request)\.(?:json|formData|text)\s*\(\s*\)"
)
SANITIZERS = [
    (re.compile(r"\b(?:parseInt|parseFloat|Number|Boolean|Math\.\w+|BigInt|isNaN|validator\.to(?:Int|Float|Boolean)|"
                r"z\.\w+(?:\.\w+)*\.parse|\w+Schema\.parse|uuidValidate|Number\.parseInt)\s*\("), ALL),
    (re.compile(r"(?<![\w$.])String\s*\("), frozenset({"nosql", "proto"})),
    (re.compile(r"\b(?:escapeHtml|escape|he\.(?:encode|escape)|_\.escape|validator\.escape|DOMPurify\.sanitize|"
                r"sanitizeHtml|xss|encodeHTML|htmlEscape|purify\.sanitize)\s*\("), frozenset({"xss", "dom"})),
    (re.compile(r"\bencodeURIComponent\s*\("), frozenset({"xss", "dom", "redirect", "ssrf", "path", "cmd", "code"})),
    (re.compile(r"\bpath\.basename\s*\("), frozenset({"path"})),
    (re.compile(r"\b(?:mysql\.escape|connection\.escape|pool\.escape|db\.escape|sqlstring\.escape|"
                r"SqlString\.escape|pgFormat|format\.literal|escapeLiteral|escapeIdentifier)\s*\("), frozenset({"sql"})),
    (re.compile(r"\b(?:shellEscape|shellQuote\.quote|quote)\s*\("), frozenset({"cmd"})),
    (re.compile(r"\bsanitize\w*\s*\("), ALL),
]

ASSIGN = re.compile(r"^(?:export\s+)?(?:declare\s+)?(const|let|var)\s+(.+)$", re.DOTALL)
REASSIGN = re.compile(r"^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*(\+=|\|\|=|\?\?=|=)(?![=>])\s*(.+)$", re.DOTALL)
FUNC_HEADER = re.compile(
    r"(?:\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)?\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?::[^{=]+)?$"
    r"|(?:\b([A-Za-z_$][\w$]*)\s*[:=]\s*)?(?:async\s+)?\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?::[^{=]+)?=>\s*$"
    r"|(?:\b([A-Za-z_$][\w$]*)\s*[:=]\s*)?(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>\s*$"
    r"|^\s*(?:(?:public|private|protected|static|async|get|set)\s+)*([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?::[^{]+)?$)",
    re.DOTALL)
KEYWORDS = {"if", "for", "while", "switch", "catch", "with", "return", "function", "else", "do", "try", "finally",
            "typeof", "new", "await", "yield", "case", "default", "throw", "delete", "void", "in", "of", "instanceof",
            "const", "let", "var", "this", "true", "false", "null", "undefined", "async", "class", "extends",
            "super", "import", "export", "from", "as"}
ROUTE_CALL = re.compile(r"\b[\w$]*(?:app|router|server|api|route|routes|Router)\s*\.\s*(?:get|post|put|patch|delete|"
                        r"all|use|options|head|route)\s*\(")
NEXT_HANDLER = re.compile(r"export\s+(?:default\s+)?(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|"
                          r"handler|middleware)\b|export\s+default\s+(?:async\s+)?function\b")
GUARD = re.compile(r"^if\s*\(\s*!\s*(?:\(?\s*)?(?:[\w$.\[\]]+\.(?:includes|has|test)\s*\(\s*([\w$.]+)\s*\)|"
                   r"/(?:\\.|[^/\n])+/[gimsuy]*\.test\s*\(\s*([\w$.]+)\s*\)|"
                   r"(?:validator\.is\w+|Number\.isInteger|Number\.isSafeInteger|isValid\w*|is[A-Z]\w*)\s*\(\s*([\w$.]+)"
                   r"|([\w$.]+)\.startsWith\s*\(|([\w$.]+)\.match\s*\(\s*/\^)")

SINKS = [
    ("sql", re.compile(r"\.(?:query|raw|whereRaw|orWhereRaw|havingRaw|\$queryRawUnsafe|\$executeRawUnsafe|"
                       r"unsafe)\s*\("), "first"),
    ("sql_exec", re.compile(r"\.execute\s*\("), "first"),
    ("cmd", None, "cmd"),
    ("code", re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w*|compileFunction)\s*\(|"
                        r"\bnew\s+vm\.Script\s*\(|\b(?:math|mathjs)\.(?:eval|evaluate)\s*\("), "first"),
    ("code_timer", re.compile(r"(?<![\w$.])(?:window\.)?set(?:Timeout|Interval)\s*\("), "first"),
    ("ssrf", re.compile(r"(?<![\w$.])(?:fetch|got|ky|axios)\s*\(|\b(?:axios|got|ky|superagent|undici)\.(?:get|post|"
                        r"put|patch|delete|head|request|stream|fetch)\s*\(|\bhttps?\.(?:get|request)\s*\("), "url"),
    ("ssrf_needle", re.compile(r"\bneedle(?:\.(?:get|post|put|patch|delete|head|request))?\s*\("), "needle"),
    ("path", re.compile(r"(?:\b(?:fs|fsp|fse|fsPromises|fs\.promises|promises)\.|(?<![\w$.]))(?:readFile|readFileSync|"
                        r"createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|"
                        r"unlinkSync|readdir|readdirSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|stat|statSync|"
                        r"access|accessSync|open|openSync|copyFile|copyFileSync|rename|renameSync|existsSync)\s*\("),
     "two"),
    ("path_send", re.compile(r"\.(?:sendFile|download)\s*\("), "send"),
    ("redirect", re.compile(r"\.redirect\s*\(|\bres\.location\s*\(|\blocation\.(?:assign|replace)\s*\(|"
                            r"\bwindow\.open\s*\("), "redirect"),
    ("nosql", re.compile(r"\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndRemove|updateOne|updateMany|"
                         r"deleteOne|deleteMany|countDocuments|count|aggregate|where|exists|distinct)\s*\("), "nosql"),
    ("proto", re.compile(r"\b(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)\s*\(|"
                         r"(?<![\w$.])(?:deepmerge|mergeDeep|deepExtend|merge\.recursive|defaultsDeep)\s*\(|"
                         r"(?:\$|jQuery)\.extend\s*\(\s*true\s*,"), "all"),
    ("dom", re.compile(r"\bdocument\.write(?:ln)?\s*\(|\.(?:html|append|prepend|after|before|replaceWith)\s*\(|"
                       r"(?<![\w$.])(?:\$|jQuery)\s*\("), "first"),
    ("dom_insert", re.compile(r"\.insertAdjacentHTML\s*\("), "second"),
    ("xss", re.compile(r"\bres\.(?:status\s*\(\s*\d+\s*\)\s*\.)?(?:send|write|end)\s*\("), "response"),
    ("deser", re.compile(r"\b(?:serialize|nodeSerialize|serializer)\.unserialize\s*\(|(?<![\w$.])unserialize\s*\("),
     "first"),
    ("ssti", re.compile(r"\b(?:ejs|pug|jade|Handlebars|handlebars|nunjucks|dot|doT|mustache|Mustache)\."
                        r"(?:render|compile|renderString|template)\s*\(|\b_\.template\s*\("), "first"),
]
ASSIGN_SINKS = [
    ("dom", re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*(.+)$", re.DOTALL)),
    ("dom", re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(.+?)\}\}", re.DOTALL)),
    ("redirect", re.compile(r"(?:^|[^\w$.])(?:window\.|document\.)?location(?:\.href)?\s*=(?!=)\s*(.+)$", re.DOTALL)),
    ("xss", re.compile(r"\bctx\.(?:response\.)?body\s*=(?!=)\s*(.+)$", re.DOTALL)),
]
SINK_HINT = re.compile(r"query|raw|Raw|Unsafe|unsafe|execute|exec|spawn|eval|Function|vm\.|math|set(?:Timeout|Interval)|"
                       r"fetch|got|ky|axios|superagent|undici|https?\.|needle|fs|File|Stream|unlink|readdir|rm|mkdir|"
                       r"stat|access|open|copy|rename|exists|sendFile|download|redirect|location|find|update|delete|"
                       r"count|aggregate|where|distinct|merge|set|extend|zipObject|document\.write|html|append|"
                       r"prepend|after|before|replaceWith|\$|jQuery|insertAdjacent|send|write|end|body|unserialize|"
                       r"render|compile|template|innerHTML|outerHTML|dangerously")
SOURCE_HINT = ("req", "request", "ctx", "location", "document.", "searchParams", "addEventListener", "params",
               "window.name", "query", "body")


def split_args(text: str) -> list:
    """Top-level arguments of a call, given the text right after '('."""
    depth, quote, cur, out, i = 0, None, [], [], 0
    while i < len(text):
        ch = text[i]
        if quote:
            cur.append(ch)
            if ch == "\\":
                cur.append(text[i + 1: i + 2])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    last = "".join(cur).strip()
    if last or out:
        out.append(last)
    return out


def first_arg(text: str, all_args: bool = False) -> str:
    args = split_args(text)
    if not args:
        return ""
    return ", ".join(args) if all_args else args[0]


def _balanced_end(text: str, start: int) -> int:
    """Index just past the ')' that closes the '(' at text[start - 1]."""
    depth, quote, i = 0, None, start
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i + 1
            depth -= 1
        i += 1
    return len(text)


def _code_identifiers(expr: str) -> list:
    """Identifier chains in code positions, including `${...}`, minus string text and object-literal keys."""
    code, i, quote = [], 0, None
    while i < len(expr):
        ch = expr[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if quote == "`" and expr.startswith("${", i):
                end = _balanced_end(expr, i + 2) - 1
                code.append(" " + expr[i + 2: end] + " ")
                i = end + 1
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            code.append(" ")
        else:
            code.append(ch)
        i += 1
    text = re.sub(r"(?<=[{,])\s*[A-Za-z_$][\w$]*\s*:(?!:)", " ", "".join(code))
    return re.findall(r"(?<![\w$.])[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*", text)


def _choose(*taints):
    taints = [t for t in taints if t]
    if not taints:
        return None
    if len(taints) == 1:
        return taints[0]
    best = min(taints, key=lambda t: (len(t[1]), "src" not in t[2]))
    return (best[0], frozenset.intersection(*(t[1] for t in taints)), frozenset().union(*(t[2] for t in taints)))


def _with_safe(t, classes):
    if not t:
        return None
    safe = t[1] | classes
    return None if safe >= ALL else (t[0], safe, t[2])


def _merge_scope(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        old = out.get(k, _MISSING)
        if old is v:
            continue
        out[k] = v if old is _MISSING else _choose(old, v)
    return out


_MISSING = object()


class _Block:
    __slots__ = ("header", "line", "items", "params", "name", "kind", "route", "msg_param")

    def __init__(self, header: str, line: int):
        self.header, self.line, self.items = header, line, []
        self.params, self.name, self.kind, self.route, self.msg_param = [], None, "block", False, None


class _Stmt:
    __slots__ = ("text", "start", "line")

    def __init__(self, text: str, start: int, line: int):
        self.text, self.start, self.line = text, start, line


class _File:
    def __init__(self, path: str, text: str, lines: list):
        self.path, self.lines = path, lines
        self.nc, self.code = views(text, "c")
        self.newlines = [i for i, ch in enumerate(text) if ch == "\n"]
        self.findings = {}
        self.collect = False
        self.summaries = {}
        self.functions = {}
        self.cmd_aliases = {m.group(1) for m in re.finditer(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"](?:node:)?child_process['\"]\s*\)", text)}
        self.cmd_aliases |= {m.group(1) for m in re.finditer(
            r"import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['\"](?:node:)?child_process['\"]", text)}
        prefix = "|".join(re.escape(a) + r"\." for a in sorted(self.cmd_aliases | {"child_process", "cp"}))
        self.cmd_rx = re.compile(r"(?:" + prefix + r"|require\(\s*['\"](?:node:)?child_process['\"]\s*\)\.|(?<![\w$.]))"
                                 r"(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(")
        self.req_aliases = {"req", "request"}

    def line_of(self, offset: int) -> int:
        return bisect.bisect_left(self.newlines, offset) + 1

    # ---- structure -------------------------------------------------------------------------------------------------

    def _structural(self) -> str:
        """The code view with line breaks inside multi-line strings blanked, so a template literal stays whole."""
        chars = None
        for m in _C_TOKENS.finditer(self.nc):
            if m.lastgroup == "s" and "\n" in m.group(0):
                if chars is None:
                    chars = list(self.code)
                for i, ch in enumerate(m.group(0)):
                    if ch == "\n":
                        chars[m.start() + i] = " "
        return "".join(chars) if chars is not None else self.code

    def parse(self) -> _Block:
        code, nc = self._structural(), self.nc
        root = _Block("", 1)
        root.kind = "root"
        frames = [(root, [])]
        start = 0

        def flush(end):
            nonlocal start
            text = nc[start:end]
            if text.strip():
                lead = len(text) - len(text.lstrip())
                frames[-1][0].items.append(_Stmt(text.strip(), start + lead, self.line_of(start + lead)))
            start = end + 1

        for m in re.finditer(r"[;{}()\[\]\n]", code):
            ch, pos = m.group(0), m.start()
            block, parens = frames[-1]
            if ch in "([":
                parens.append(ch)
            elif ch in ")]":
                if parens and parens[-1] != "{":
                    parens.pop()
            elif ch == "{":
                before = code[start:pos].rstrip()
                if self._is_block(before):
                    header = nc[start:pos]
                    hstart = start + len(header) - len(header.lstrip())
                    child = _Block(header.strip(), self.line_of(hstart))
                    self._classify(child, parens)
                    if header.strip():
                        block.items.append(_Stmt(header.strip(), hstart, child.line))
                    block.items.append(child)
                    frames.append((child, []))
                    start = pos + 1
                else:
                    parens.append("{")
            elif ch == "}":
                if parens and parens[-1] == "{":
                    parens.pop()
                elif len(frames) > 1:
                    flush(pos)
                    frames.pop()
                    start = pos + 1
            elif ch == ";":
                if not parens:
                    flush(pos)
            elif ch == "\n" and not parens:
                prev = code[start:pos].rstrip()
                if not prev:
                    start = pos + 1
                    continue
                nxt = code[pos + 1: pos + 200].lstrip()[:2]
                if prev[-1] in "+-*/%=&|^!~?:,.(<>[{" or prev.endswith(("=>",)) or (nxt and (nxt[0] in ".+-*/%&|^?:,)]="
                                                                                        or nxt == "=>")):
                    continue
                if re.search(r"(?:^|[^\w$])(?:if|for|while|else|do)\s*(?:\(.*\))?$", prev):
                    continue  # `if (x)` newline `stmt;`: keep them together
                flush(pos)
        flush(len(nc))
        return root

    @staticmethod
    def _is_block(before: str) -> bool:
        if not before:
            return True
        if before.endswith(("=>", ")", "else", "try", "finally", "do", ";", "{", "}")):
            return True
        return bool(re.search(r"\bclass\s+[\w$]+(?:\s+extends\s+[\w$.]+)?(?:\s+implements\s+[\w$., ]+)?$|"
                              r"\b(?:static|get|set)$|:\s*[\w$<>\[\]|, ]+$", before)) and "=" not in before[-3:]

    def _classify(self, block: _Block, parens):
        header = block.header
        m = FUNC_HEADER.search(header)
        if m and not (m.group(7) and m.group(7) in KEYWORDS):
            block.kind = "function"
            params = m.group(2) or m.group(4) or m.group(6) or m.group(8) or ""
            block.name = m.group(1) or m.group(3) or m.group(5) or m.group(7)
            block.params = self._param_names(params)
            next_file = bool(re.search(r"(?:^|/)(?:pages/api/|app/.*\broute\.[jt]sx?$|(?:src/)?middleware\.[jt]s$)",
                                       self.path))
            if ROUTE_CALL.search(header) or (next_file and NEXT_HANDLER.search(header)) or re.search(
                    r"\bexport\s+(?:const|let)\s+(?:GET|POST|PUT|PATCH|DELETE)\b", header):
                block.route = True
            if re.search(r"addEventListener\(\s*['\"]message['\"]", header) and block.params \
                    and isinstance(block.params[0], str):
                block.msg_param = block.params[0]
            if block.name in KEYWORDS:
                block.name = None
        elif re.match(r"^(?:\}\s*)?(?:if|else|for|while|switch|catch|do)\b", header):
            block.kind = "cond"
        elif header.startswith(("try", "finally")):
            block.kind = "plain"
        else:
            block.kind = "plain"

    @staticmethod
    def _param_names(params: str) -> list:
        names = []
        for part in split_args(params + ")") if params.strip() else []:
            part = part.strip()
            if not part:
                continue
            part = re.sub(r"^\.\.\.", "", part)
            if part.startswith("{"):
                inner = part[1:part.rfind("}")]
                names.append(("{", [_strip_default(x) for x in split_args(inner + ")")]))
                continue
            names.append(re.split(r"[?:=]", part, maxsplit=1)[0].strip())
        return names

    # ---- reporting --------------------------------------------------------------------------------------------------

    def report(self, kind, line, chain, sink):
        rid, title, sev, cwe, fix_rule = INFO[kind]
        key = (rid, line)
        if not self.collect or key in self.findings:
            return
        if 0 < line <= len(self.lines) and is_suppressed(self.lines[line - 1]):
            return
        flow, prev = [], None
        for item in tuple(chain) + ((sink, line),):
            if item != prev:
                flow.append(f"{item[0]} (L{item[1]})")
            prev = item
        snippet = self.lines[line - 1].strip()[:240] if 0 < line <= len(self.lines) else ""
        fix = _FIX.get(fix_rule, "") if fix_rule else FIXES.get(kind, "")
        self.findings[key] = Finding(rule_id=rid, title=title, severity=sev, category="code", file=self.path, line=line,
                                     snippet=snippet, cwe=cwe, fix=fix, extra={"flow": " → ".join(flow)})

    def run(self) -> list:
        root = self.parse()
        self._index(root)
        for round_no in range(3):
            self.collect = round_no == 2
            if round_no < 2:
                for fn in self.functions.values():
                    _Analysis(self, fn).run_function()
            else:
                _Analysis(self, root).run_root()
        return list(self.findings.values())

    def _index(self, block):
        for item in block.items:
            if isinstance(item, _Block):
                if item.kind == "function" and item.name and not item.route:
                    self.functions.setdefault(item.name, item)
                self._index(item)


def _strip_default(part: str) -> str:
    part = part.strip().lstrip(".")
    part = part.split("=")[0].strip()
    if ":" in part:
        part = part.split(":", 1)[1].strip()
    return part


class _Analysis:
    def __init__(self, f: _File, block: _Block):
        self.f, self.block = f, block
        self.scopes = [{}]
        self.req = [set()]
        self.msg = [set()]
        self.returns = []
        self.sinks = []

    # ---- scopes ------------------------------------------------------------------------------------------------------

    def lookup(self, name):
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def declare(self, name, t):
        self.scopes[-1][name] = t

    def assign(self, name, t):
        root = name.split(".", 1)[0]
        for scope in reversed(self.scopes):
            if name in scope or root in scope:
                scope[name] = t
                return
        self.scopes[0][name] = t

    def is_req(self, name: str) -> bool:
        return name in self.f.req_aliases or any(name in s for s in self.req)

    # ---- drivers -----------------------------------------------------------------------------------------------------

    def run_root(self):
        self.exec_items(self.block.items)

    def run_function(self):
        self.enter_function(self.block, summary=True)
        self.exec_items(self.block.items)
        ret = _choose(*self.returns)
        self.f.summaries[self.block.name] = (self.block.params, ret, self.sinks)

    def enter_function(self, block, summary=False):
        self.scopes.append({})
        self.req.append(set())
        self.msg.append(set())
        for idx, p in enumerate(block.params):
            if isinstance(p, tuple):  # destructured parameter, e.g. Next.js `{ params }`
                for name in p[1]:
                    if block.route and idx >= 1 and name in ("params", "searchParams", "query"):
                        self.declare(name, (((f"route {name}", block.line),), frozenset(), frozenset({"src"})))
                    elif block.route and idx == 0 and name in ("query", "params", "body", "headers", "cookies"):
                        self.declare(name, (((f"req.{name}", block.line),), frozenset(), frozenset({"src"})))
                    else:
                        self.declare(name, (((f"param `{name}`", block.line),), frozenset(), frozenset({idx})))
                continue
            if block.route and idx == 0:
                self.req[-1].add(p)
                continue
            if p in ("req", "request", "ctx") or not p:
                continue
            self.declare(p, (((f"param `{p}`", block.line),), frozenset(), frozenset({idx})))
        if block.msg_param:
            self.msg[-1].add(block.msg_param)

    def exec_items(self, items):
        i = 0
        while i < len(items):
            item = items[i]
            if isinstance(item, _Stmt):
                nxt = items[i + 1] if i + 1 < len(items) else None
                if isinstance(nxt, _Block) and nxt.header and item.text == nxt.header:
                    self.exec_header(item, nxt)
                    self.exec_block(nxt)
                    i += 2
                    continue
                self.exec_stmt(item)
            else:
                self.exec_block(item)
            i += 1

    def exec_header(self, stmt, block):
        text = stmt.text
        m = re.match(r"^(?:\}\s*)?for\s*(?:await\s*)?\(\s*(?:const|let|var)?\s*(.+?)\s+(?:of|in)\s+(.+)\)\s*$", text, re.DOTALL)
        if m:
            block.params = []
            self._pending_for = (m.group(1), self.chain_for(m.group(2), stmt), stmt.line)
        else:
            self._pending_for = None
        self.check_sinks(stmt, text)  # `db.query(q, function (err) {` carries its sink in the header

    def exec_block(self, block):
        snapshot = [dict(s) for s in self.scopes]
        pending = getattr(self, "_pending_for", None)
        self._pending_for = None
        if block.kind == "function":
            self.enter_function(block)
        else:
            self.scopes.append({})
            self.req.append(set())
            self.msg.append(set())
        if pending:
            for name in _names(pending[0]):
                self.declare(name, _extend(pending[1], name, pending[2]))
        rounds = 2 if pending or re.match(r"^(?:while|do)\b", block.header) else 1
        for _ in range(rounds):
            self.exec_items(block.items)
        self.scopes.pop()
        self.req.pop()
        self.msg.pop()
        guard = GUARD.match(block.header)
        if block.kind == "function" or block.kind == "cond":
            for scope, before in zip(self.scopes, snapshot):
                merged = _merge_scope(before, scope)
                scope.clear()
                scope.update(merged)
        if guard and block.items and isinstance(block.items[-1], _Stmt) and \
                re.match(r"^(?:return|throw)\b", block.items[-1].text):
            self._kill_guarded(guard)

    def _kill_guarded(self, m):
        for name in filter(None, m.groups()):
            if m.group(4) == name:  # startsWith on a resolved path: safe for paths only
                t = self.lookup(name)
                self.assign(name, _with_safe(t, frozenset({"path"})))
            else:
                self.assign(name, None)

    # ---- statements ------------------------------------------------------------------------------------------------

    def exec_stmt(self, stmt):
        text = stmt.text
        guard = GUARD.match(text)
        if guard and re.search(r"\)\s*(?:\{\s*)?(?:return|throw)\b", text):
            self.check_sinks(stmt, text)
            self._kill_guarded(guard)
            return
        body = re.sub(r"^(?:export\s+(?:default\s+)?|await\s+)", "", text)
        if self.f.summaries and re.match(r"^[A-Za-z_$][\w$]*\s*\(", body) and \
                body.split("(", 1)[0].strip() in self.f.summaries:
            self.chain_for(body, stmt)  # a bare helper call: follow request data into the helper's sinks
        m = re.match(r"^return\b\s*(.*)$", body, re.DOTALL)
        if m:
            t = self.chain_for(m.group(1), stmt) if m.group(1) else None
            if t:
                self.returns.append(t)
        m = ASSIGN.match(body)
        if m:
            for decl in _split_top(m.group(2)):
                lhs, eq, rhs = _split_assign(decl)
                if not eq:
                    for name in _names(lhs):
                        self.declare(name, None)
                    continue
                if re.fullmatch(r"\s*[\w$]+\s*", rhs) and self.is_req(rhs.strip()):
                    for name in _names(lhs):
                        self.req[-1].add(name)
                    continue
                t = self.chain_for(rhs, stmt)
                for name in _names(lhs):
                    self.declare(name, _extend(t, name, stmt.line))
        else:
            m = REASSIGN.match(body)
            if m and not body.startswith(("ctx.body", "ctx.response.body")) and \
                    not re.search(r"\.(?:innerHTML|outerHTML|href)$|^(?:window\.)?location$", m.group(1)):
                name, op, rhs = m.group(1), m.group(2), m.group(3)
                t = self.chain_for(rhs, stmt)
                if op != "=":
                    t = _choose(self.lookup(name), t)
                if re.fullmatch(r"\s*[\w$]+\s*", rhs) and self.is_req(rhs.strip()):
                    self.req[-1].add(name)
                self.assign(name, _extend(t, name, stmt.line))
        self.check_sinks(stmt, text)

    # ---- expressions -------------------------------------------------------------------------------------------------

    def chain_for(self, expr: str, stmt=None):
        if not expr or not expr.strip():
            return None
        expr = re.sub(r"\bnew\s+URL\s*\(\s*(['\"`])[^'\"`]*\1\s*,\s*[\w$.]+\s*\)", "0", expr)
        temps = {}
        expr = self._fold_calls(expr, temps, stmt)
        taints = []
        for m in self._source_matches(expr):
            taints.append(m)
        for ident in _code_identifiers(expr):
            if ident in temps:
                taints.append(temps[ident])
                continue
            parts = ident.replace("?.", ".").split(".")
            for k in range(len(parts), 0, -1):
                t = self.lookup(".".join(parts[:k]))
                if t is not None or any(".".join(parts[:k]) in s for s in self.scopes):
                    if t:
                        taints.append(t)
                    break
            if len(parts) >= 2 and parts[0] in set().union(*self.msg) and parts[1] == "data":
                line = stmt.line if stmt else 0
                taints.append((((f"{parts[0]}.data", line),), frozenset(), frozenset({"src"})))
        out = _choose(*taints)
        if out and re.search(r"\.replace(?:All)?\(\s*(?:/<\/g?\w*|['\"]<['\"])\s*,\s*['\"]&lt;['\"]", expr):
            out = _with_safe(out, frozenset({"dom", "xss"}))  # hand-written entity escaping
        return out

    def _source_matches(self, expr):
        out = []
        line = None
        aliases = self.f.req_aliases | set().union(*self.req)
        alt = "|".join(sorted(re.escape(a) for a in aliases))
        rx = re.compile(r"\b(?:" + alt + r")\??\.(" + REQ_PROPS + r")\b(?!\s*\()|\b(?:" + alt +
                        r")\.(get|header|param)\s*\(")
        for m in rx.finditer(expr):
            prop = m.group(1) or m.group(2)
            if prop == "url" and m.group(0).startswith("request.") and "new URL" not in expr:
                pass
            label = m.group(0).rstrip("( ")
            safe = frozenset({"nosql"}) if prop in STRING_PROPS or m.group(2) else frozenset()
            out.append((((label, line),), safe, frozenset({"src"})))
        for m in FIXED_SOURCES.finditer(expr):
            label = m.group(0).rstrip("( ")
            string_only = not re.search(r"\.(?:query|body)\b|json|formData", label)
            safe = frozenset({"nosql"}) if string_only else frozenset()
            if re.match(r"(?:window\.)?location\.href|document\.(?:URL|documentURI|baseURI)", label):
                safe = PAGE_URL_SAFE  # the page's own address: same origin, so neither SSRF nor an open redirect
            elif re.match(r"(?:window\.)?location|document\.|window\.name", label):
                safe = BROWSER_SAFE  # browser data reaches DOM, redirect, eval and client-side fetch, not the server
            out.append((((label, line),), safe, frozenset({"src"})))
        return out

    def _fold_calls(self, expr, temps, stmt):
        """Replace sanitizer calls and same-file helper calls by placeholders that carry their result taint."""
        for _ in range(20):
            best = None
            for rx, classes in SANITIZERS:
                m = rx.search(expr)
                if m and (best is None or m.start() < best[0].start()):
                    best = (m, classes)
            helper = None
            if self.f.summaries:
                for m in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", expr):
                    if m.group(1) in self.f.summaries and m.group(1) not in KEYWORDS:
                        helper = m
                        break
            if helper is not None and (best is None or helper.start() < best[0].start()):
                end = _balanced_end(expr, helper.end())
                result = self._call_helper(helper.group(1), expr[helper.end():end], stmt)
                key = f"__t{len(temps)}"
                temps[key] = result
                expr = expr[:helper.start()] + key + expr[end:]
                continue
            if best is None:
                return expr
            m, classes = best
            end = _balanced_end(expr, m.end())
            inner = self.chain_for(expr[m.end():end - 1], stmt)
            key = f"__t{len(temps)}"
            temps[key] = _with_safe(inner, classes)
            expr = expr[:m.start()] + key + expr[end:]
        return expr

    def _call_helper(self, name, args_text, stmt):
        params, ret, sinks = self.f.summaries[name]
        args = split_args(args_text + ")") if args_text.strip() else []
        taints = [self.chain_for(a, stmt) for a in args]
        line = stmt.line if stmt else 0
        label = f"{name}()"
        for origins, safe, kind, sink_line, chain, sink in sinks:
            for idx in origins:
                if isinstance(idx, int) and idx < len(taints) and taints[idx]:
                    arg = taints[idx]
                    cls = _cls(kind)
                    if cls in arg[1] or cls in safe:
                        continue
                    full = tuple((lbl, ln or line) for lbl, ln in arg[0]) + ((label, line),) + tuple(chain[1:])
                    self.hit(kind, sink_line, (full, arg[1] | safe, arg[2]), sink)
        out = []
        if ret:
            if "src" in ret[2]:
                out.append((tuple((lbl, ln or line) for lbl, ln in ret[0]) + ((label, line),), ret[1],
                            frozenset({"src"})))
            for idx in ret[2]:
                if isinstance(idx, int) and idx < len(taints) and taints[idx]:
                    arg = taints[idx]
                    out.append((arg[0] + ((label, line),), arg[1] | ret[1], arg[2]))
        return _choose(*out)

    # ---- sinks -------------------------------------------------------------------------------------------------------

    def hit(self, kind, line, t, sink):
        if not t or _cls(kind) in t[1]:
            return
        chain = tuple((lbl, ln or line) for lbl, ln in t[0])
        if "src" in t[2]:
            self.f.report(kind, line, chain, sink)
        params = frozenset(o for o in t[2] if isinstance(o, int))
        if params:
            entry = (params, t[1], kind, line, chain, sink)
            if entry not in self.sinks:
                self.sinks.append(entry)

    def check_sinks(self, stmt, text):
        if not SINK_HINT.search(text):
            return
        for kind, rx in ASSIGN_SINKS:
            m = rx.search(text)
            if m:
                rhs = m.group(1)
                if kind == "xss" and not _html_like(rhs, self):
                    continue
                if kind == "redirect" and _same_site(rhs):
                    continue
                self.hit(kind, self.f.line_of(stmt.start + m.start()), self.chain_for(rhs, stmt),
                         "innerHTML" if kind == "dom" else ("ctx.body" if kind == "xss" else "location"))
        for kind, rx, mode in SINKS:
            if kind == "cmd":
                matches = list(self.f.cmd_rx.finditer(text))
            else:
                matches = list(rx.finditer(text))
            for m in matches:
                args = split_args(text[m.end():])
                line = self.f.line_of(stmt.start + m.start())
                sink = m.group(0).rstrip("( ").lstrip(".")
                self._check_one(kind, mode, m, args, text, stmt, line, sink)

    def _check_one(self, kind, mode, m, args, text, stmt, line, sink):
        if not args:
            return
        first = args[0]
        if _literal(first) and mode not in ("needle", "cmd", "nosql", "all", "second", "two", "response", "redirect"):
            return
        if kind == "sql_exec":
            receiver = text[:m.start()]
            if not (re.search(r"(?i)(?:db|conn|connection|client|pool|knex|sequelize|cursor|trx|tx|sql|database|mysql|"
                              r"pg|stmt|statement|session|manager|queryRunner)\s*$", receiver) or _sqlish(first)):
                return
            kind = "sql"
        if kind == "sql":
            if text[m.start():m.start() + 7] == ".query(" and re.search(r"\b(?:req|request|ctx)\s*$", text[:m.start()]):
                return
            self.hit("sql", line, self.chain_for(first, stmt), sink)
        elif kind == "cmd":
            name = m.group(1)
            rest = ", ".join(args[1:])
            if name in ("exec", "execSync") or re.search(r"\bshell\s*:\s*true", rest):
                self.hit("cmd", line, self.chain_for(first, stmt), sink)
            else:
                prog = _literal_value(first)
                if prog is not None and prog.rsplit("/", 1)[-1] in ("sh", "bash", "zsh", "dash", "cmd", "cmd.exe",
                                                                     "powershell", "pwsh") and len(args) > 1 \
                        and re.search(r"['\"](?:-c|/c|-Command)['\"]", args[1]):
                    self.hit("cmd", line, self.chain_for(args[1], stmt), sink)
                elif prog is None:
                    self.hit("cmd", line, self.chain_for(first, stmt), sink)
        elif kind == "code":
            self.hit("code", line, self.chain_for(first, stmt), sink)
        elif kind == "code_timer":
            if re.match(r"^\s*(?:function\b|\(|async\b|[\w$]+\s*=>)", first) or re.fullmatch(r"[\w$.]+", first):
                return
            self.hit("code", line, self.chain_for(first, stmt), sink)
        elif kind in ("ssrf", "ssrf_needle"):
            target = first
            if kind == "ssrf_needle" and _literal_value(first) and re.fullmatch(r"(?i)get|post|put|patch|delete|head",
                                                                                _literal_value(first) or ""):
                target = args[1] if len(args) > 1 else ""
            if target.startswith("{"):
                prop = re.search(r"(?:^|[{,])\s*(?:url|baseURL|uri|href)\s*(?::\s*([^,}]+)|(?=[,}]))", target)
                if not prop:
                    return
                target = prop.group(1) or "url"
            if _literal(target) or _fixed_host(target):
                return
            self.hit("ssrf", line, self.chain_for(target, stmt), sink)
        elif kind == "path":
            self.hit("path", line, _choose(self.chain_for(first, stmt),
                                           self.chain_for(args[1], stmt) if len(args) > 1 and
                                           re.search(r"copyFile|rename", sink) else None), sink)
        elif kind == "path_send":
            if re.search(r"\broot\s*:(?!\s*['\"`]/['\"`])", ", ".join(args[1:])):
                return
            self.hit("path", line, self.chain_for(first, stmt), sink)
        elif kind == "redirect":
            target = args[1] if re.fullmatch(r"\d+", first) and len(args) > 1 else first
            if _literal(target) or _same_site(target):
                return
            self.hit("redirect", line, self.chain_for(target, stmt), sink)
        elif kind == "nosql":
            self._check_nosql(first, stmt, line, sink)
        elif kind == "proto":
            self.hit("proto", line, _choose(*(self.chain_for(a, stmt) for a in args[1:] or args)), sink)
        elif kind == "dom":
            if sink in ("$", "jQuery") and not re.search(r"<|html", first, re.IGNORECASE) and not self.chain_for(first, stmt):
                return
            self.hit("dom", line, self.chain_for(first, stmt), sink)
        elif kind == "dom_insert":
            if len(args) > 1:
                self.hit("dom", line, self.chain_for(args[1], stmt), sink)
        elif kind == "xss":
            if not _html_like(first, self):
                return
            self.hit("xss", line, self.chain_for(first, stmt), sink)
        elif kind in ("deser", "ssti"):
            self.hit(kind, line, self.chain_for(first, stmt), sink)

    def _check_nosql(self, first, stmt, line, sink):
        first = first.strip()
        if first.startswith("{"):
            inner = first[1:first.rfind("}")] if "}" in first else first[1:]
            for prop in split_args(inner + ")"):
                key, _, value = prop.partition(":")
                key = key.strip().strip("'\"")
                value = value.strip() if value else key  # shorthand `{ email }`
                t = self.chain_for(value, stmt)
                if key == "$where" and t:
                    self.hit("nosql", line, (t[0], t[1] - {"nosql"}, t[2]), sink)
                elif t:
                    self.hit("nosql", line, t, sink)
            return
        if re.fullmatch(r"[\w$.?\[\]'\"]+", first):
            self.hit("nosql", line, self.chain_for(first, stmt), sink)


def _cls(kind):
    return {"sql_exec": "sql", "code_timer": "code", "ssrf_needle": "ssrf", "path_send": "path",
            "dom_insert": "dom"}.get(kind, kind)


def _extend(t, name, line):
    if not t:
        return None
    return (t[0] + ((name, line),), t[1], t[2])


def _names(lhs: str) -> list:
    lhs = re.sub(r":\s*[\w$<>\[\]|&, .]+$", "", lhs.strip()) if not lhs.strip().startswith(("{", "[")) else lhs.strip()
    if lhs.startswith(("{", "[")):
        close = "}" if lhs[0] == "{" else "]"
        inner = lhs[1:lhs.rfind(close)] if close in lhs else lhs[1:]
        return [n for n in (_strip_default(p) for p in split_args(inner + ")")) if re.fullmatch(r"[A-Za-z_$][\w$]*", n)]
    name = lhs.split(":")[0].strip()
    return [name] if re.fullmatch(r"[A-Za-z_$][\w$]*", name) else []


def _split_top(text: str) -> list:
    return split_args(text + ")") if text else []


def _split_assign(decl: str):
    depth, quote = 0, None
    for i, ch in enumerate(decl):
        if quote:
            if ch == quote and decl[i - 1] != "\\":
                quote = None
            continue
        if ch in "\"'`":
            quote = ch
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        elif ch == "=" and depth <= 0 and decl[i + 1: i + 2] not in ("=", ">") and decl[i - 1: i] not in ("!", "<", ">",
                                                                                                         "="):
            return decl[:i], "=", decl[i + 1:]
    return decl, "", ""


def _literal(arg: str) -> bool:
    arg = arg.strip()
    return bool(re.fullmatch(r"(['\"])(?:\\.|(?!\1).)*\1|`[^`$]*`|\d+(?:\.\d+)?|true|false|null|undefined", arg))


def _literal_value(arg: str):
    m = re.fullmatch(r"\s*(['\"`])((?:\\.|(?!\1).)*)\1\s*", arg)
    return m.group(2) if m else None


def _leading(arg: str):
    m = re.match(r"\s*(['\"`])((?:\\.|(?!\1)[^$])*)", arg)
    return m.group(2) if m else None


def _same_site(arg: str) -> bool:
    prefix = _leading(arg)
    return bool(prefix) and prefix.startswith("/") and len(prefix) > 1 and prefix[1] not in "/\\"


def _fixed_host(arg: str) -> bool:
    prefix = _leading(arg)
    return bool(prefix) and bool(re.match(r"(?i)^https?://[^/?#@${}]+[/?#]", prefix))


def _sqlish(arg: str) -> bool:
    return bool(re.search(r"(?i)\b(select|insert|update|delete)\b[\s\S]*\b(from|into|set|where)\b", arg))


def _html_like(arg: str, analysis) -> bool:
    """Express and Koa send a string as text/html. Objects, arrays and JSON go out as JSON."""
    arg = arg.strip()
    if not arg or arg.startswith(("{", "[", "JSON.stringify")) or re.match(r"^(?:new\s+)?(?:Buffer|Error)\b", arg):
        return False
    return True


def scan(files: list) -> list:
    out = []
    for f in files:
        low = f.path.lower()
        if not low.endswith(JS_EXT) or is_test_path(f.path) or ".min." in low:
            continue
        text = f.text
        if not any(h in text for h in SOURCE_HINT) or is_bundle(f.path, text):
            continue
        try:
            out += _File(f.path, text, f.lines).run()
        except Exception:  # noqa: BLE001 - one odd file must not end the scan of the whole repository
            continue
    return out
