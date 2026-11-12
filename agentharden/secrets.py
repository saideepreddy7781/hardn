"""Hard-coded credential detection. Values are always redacted before they leave this module."""
from __future__ import annotations

import math
import os
import re
import subprocess
from collections import Counter
from fnmatch import fnmatch

from . import gitsafe
from .code_rules import is_suppressed
from .models import Finding, cap_severity
from .walker import is_test_path

COMPROMISED = (
    "Treat the credential as compromised: it must be rotated/revoked by a human, and purged from git "
    "history (git filter-repo) if it was ever committed."
)
ROTATE = (
    "Move the value to an environment variable or secret manager, read it at runtime, and add a "
    "placeholder to .env.example. " + COMPROMISED
)

# (rule id, title, severity, regex, literal hints). A line is searched only when one of the hints occurs in it, so
# the ordinary line pays for a few substring tests instead of thirty regexes. Group 1, when present, is the value.
PROVIDERS = [
    ("SEC001", "AWS access key ID", "critical", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", ("AKIA", "ASIA")),
    ("SEC002", "GitHub token", "critical", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})",
     ("gh", "github_pat_")),
    ("SEC003", "Private key", "critical",
     r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----", ("PRIVATE KEY",)),
    ("SEC004", "Stripe live secret key", "critical", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}", ("_live_",)),
    ("SEC005", "Anthropic API key", "critical", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", ("sk-ant-",)),
    ("SEC006", "OpenAI API key", "critical", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}", ("sk-",)),
    ("SEC007", "Slack token", "high", r"\b(?:xox[abposre]|xapp)-[A-Za-z0-9-]{10,}", ("xox", "xapp-")),
    ("SEC007", "Slack incoming webhook URL", "high",
     r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9_/]{20,}", ("hooks.slack.com",)),
    ("SEC008", "Google API key", "high", r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])", ("AIza",)),
    ("SEC008", "Google OAuth token or client secret", "high",
     r"\bya29\.[0-9A-Za-z_\-]{30,}|\bGOCSPX-[0-9A-Za-z_\-]{24,}", ("ya29.", "GOCSPX-")),
    ("SEC009", "SendGrid API key", "high", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", ("SG.",)),
    ("SEC010", "Connection string with embedded password", "high",
     r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse|cockroachdb|"
     r"neo4j(?:\+s)?|ldaps?|smtps?|ftps?|sftp)://[^\s:/@'\"]*:([^\s@'\"]+)@[^\s'\"]+", ("://",)),
    ("SEC010", "URL with embedded password", "high",
     r"\b(?:https?|git\+https?|ssh)://[^\s:/@'\"`$]+:([^\s@/'\"`]+)@[\w.-]+", ("://",)),
    ("SEC010", "Connection string with embedded password", "high",
     r"\bjdbc:[a-z0-9]+:[^\s'\"]*?[;?&]password=([^\s;&'\"]+)", ("jdbc:",)),
    ("SEC011", "JSON Web Token", "medium", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     ("eyJ",)),
    ("SEC012", "GitLab token", "critical", r"\bglpat-[A-Za-z0-9_\-]{20,}", ("glpat-",)),
    ("SEC013", "npm access token", "critical", r"\bnpm_[A-Za-z0-9]{36}\b", ("npm_",)),
    ("SEC014", "PyPI upload token", "critical", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", ("pypi-",)),
    ("SEC015", "Hugging Face token", "high", r"\bhf_[A-Za-z]{34}\b", ("hf_",)),
    ("SEC016", "DigitalOcean token", "critical", r"\bdo[opr]_v1_[a-f0-9]{64}\b", ("_v1_",)),
    ("SEC017", "Shopify access token", "critical", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", ("shp",)),
    ("SEC018", "Twilio API key", "high", r"\bSK[0-9a-f]{32}\b", ("SK",)),
    ("SEC019", "Telegram bot token", "high", r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b", (":AA",)),
    ("SEC020", "Discord webhook URL", "high",
     r"https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{60,}", ("/api/webhooks/",)),
    ("SEC021", "Mailgun API key", "high", r"\bkey-[0-9a-f]{32}\b", ("key-",)),
    ("SEC022", "Azure storage account key", "critical", r"AccountKey=([A-Za-z0-9+/]{86}==)", ("AccountKey=",)),
    ("SEC023", "Linear API key", "high", r"\blin_api_[A-Za-z0-9]{40}\b", ("lin_api_",)),
    ("SEC024", "Square access token", "critical",
     r"\b(?:EAAA[A-Za-z0-9_\-]{60}|sq0csp-[0-9A-Za-z_\-]{43}|sq0atp-[0-9A-Za-z_\-]{22})\b", ("EAAA", "sq0")),
]
COMPILED = [(i, t, s, re.compile(p), h) for i, t, s, p, h in PROVIDERS]
PATTERNS = [(i, t, s, p) for i, t, s, p, _ in PROVIDERS]
PREFIX = re.compile(r"^(?:AKIA|ASIA|gh[pousr]_|github_pat_|[sr]k_live_|sk-ant-(?:api\d\d-)?|sk-(?:proj-|svcacct-|"
                    r"admin-)?|xox[abposre]-|xapp-|AIza|ya29\.|GOCSPX-|SG\.|glpat-|npm_|hf_|do[opr]_v1_|"
                    r"shp(?:at|ca|pa|ss)_|key-|lin_api_|sq0(?:csp|atp)-|EAAA)")
JWT_SAMPLES = ("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",)  # jwt.io's sample token, in every JWT tutorial

KEYWORDS = (r"secret|passwd|password|passphrase|pwd|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token|"
            r"private[_-]?key|client[_-]?secret|signing[_-]?key|credential")
GENERIC = re.compile(
    r"""(?i)\b([\w.-]*(?:""" + KEYWORDS + r""")[\w.-]*)["']?\s*(?::=|=>|[:=])\s*["']([^"'\n]{6,})["']"""
)
# Unquoted `key: value` / `key=value`, read only in config-type files (YAML, .properties, .ini, shell, .npmrc).
GENERIC_UNQUOTED = re.compile(
    r"""(?i)(?:^|[\s:/{,])([\w.-]*?(?:""" + KEYWORDS + r""")[\w.-]*)\s*(?::=|[:=])[ \t]*([^\s"'#;,]{6,})\s*$"""
)
GENERIC_XML = re.compile(r"(?i)<([\w.:-]*(?:" + KEYWORDS + r")[\w.:-]*)>([^<\s]{6,})</\1>")
CONFIG_SUFFIXES = (".yml", ".yaml", ".properties", ".ini", ".cfg", ".conf", ".toml", ".sh", ".bash", ".zsh",
                   ".npmrc", ".pypirc", ".netrc", ".tfvars", ".xml")
CONFIG_NAMES = ("credentials", ".npmrc", ".pypirc", ".netrc", ".git-credentials")
KEY_NOT_SECRET = re.compile(
    r"(?i)(_?(url|uri|path|file|field|name|label|header|type|endpoint|length|len|regex|pattern|placeholder|input|"
    r"message|msg|text|hint|error|prompt|id|count|expires?|expiry|ttl|timeout|policy|algorithm|algo|alg|hasher|"
    r"hashers|strength|backend|manager|provider|budget|limit|cookie|storage|kind|mode|format|scheme|strategy|"
    r"version|dir|prefix|suffix|column|param|attr|class|template|validator|validators|min|max|size|rounds|"
    r"enabled|required|lifetime|duration|location|host|port|username|email|key_name|keyname)s?$|"
    r"tokeni[sz]er|^(?:no|is|has|show|hide|use|enable|disable|reset|forgot|confirm|new|old|change|update|"
    r"remember|verify|current)_)"
)
STRONG_KEY = re.compile(r"(?i)(password|passwd|pwd|passphrase|secret|secret_?key|api_?key|apikey|private_?key|"
                        r"client_?secret|access_?key|auth_?token|token|credentials?)$")
PLACEHOLDER = re.compile(
    r"(?i)((?<![a-z])(example|sample|dummy|fake|placeholder|changeme|change_me|redacted|lorem|todo|test|demo|insert|"
    r"replace|secret|password|token|apikey|xxx+)(?![a-z])|your[_-]|<[^<>]*>|\$\{|\{\{|\}\}|%\(|process\.env|"
    r"os\.environ|getenv|xxxx|\*{3}|\.{3}|…|%s|\{\})"
)
WORDY = re.compile(r"(?i)(?<![a-z])(your|insert|replace|placeholder|example|sample|dummy|fake)")
ENV_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[A-Z]{3,}")
LOWER_IDENT = re.compile(r"[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)+")
TRIVIAL = re.compile(r"(?i)(true|false|yes|no|on|off|none|null|nil|undefined|\d+(\.\d+)?[smhdw]?|\d+[kmg]b?)")
REFERENCE = re.compile(r"^(\$\w|\$\{|\$\(|%\w+%|@\w|arn:|secret:|vault:|ssm:|sm://|op://|env:|ENV\[|!Ref|!Sub|"
                       r"\{\{|<%|#\{|\(\(|file:|keychain:)")
NON_ASCII = re.compile(r"[^\x00-\x7f]")
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$")
ENV_SECRET_KEY = re.compile(r"(?i)(secret|passw|pwd|token|api_?key|private|credential|dsn|database_url|access_key|"
                            r"_key$|^key$|auth)")
URL_USERINFO = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s/@:]*:([^\s/@]+)@")
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
PEM_BLOCK = re.compile(r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)(.*?)(-----END [A-Z0-9 ]*PRIVATE KEY"
                       r"(?: BLOCK)?-----|$)", re.DOTALL)
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# Any long base64-ish run with mixed case and digits is masked in snippets: key bodies, tokens, blobs.
LONG_BLOB = re.compile(r"(?<![\w/+-])(?=[A-Za-z0-9+/_-]{40,})(?=[A-Za-z0-9+/_-]*[a-z])(?=[A-Za-z0-9+/_-]*[A-Z])"
                       r"(?=[A-Za-z0-9+/_-]*\d)[A-Za-z0-9+/_-]{40,}={0,2}")
LOCALE_DIRS = {"locale", "locales", "i18n", "l10n", "lang", "langs", "languages", "translations", "translation",
               "intl", "nls"}
LOCALE_SUFFIXES = (".json", ".yml", ".yaml", ".po", ".pot", ".properties", ".strings", ".arb", ".xlf", ".xliff",
                   ".resx", ".ftl", ".lang", ".toml")
LANGS = {"en", "de", "fr", "es", "it", "pt", "nl", "sv", "no", "nb", "nn", "da", "fi", "pl", "cs", "sk", "hu", "ro",
         "bg", "el", "tr", "ru", "uk", "ja", "ko", "zh", "ar", "he", "iw", "hi", "bn", "id", "ms", "th", "vi", "fa",
         "ca", "et", "lv", "lt", "sl", "hr", "sr", "ta", "te", "mr", "ur", "sw", "eu", "gl", "is", "ga", "af"}
SKIP_FILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "go.sum", "Cargo.lock", "composer.lock",
              "uv.lock", "Pipfile.lock", "Gemfile.lock", "bun.lock")
GENERIC_HINTS = ("secret", "passw", "pwd", "key", "token", "credential", "passphrase")
LINE_LIMIT = 2000  # past this a line is a bundle or a data blob: only provider patterns run on it


def entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def redact(value: str) -> str:
    keep = value[:4] if len(value) > 12 else ""
    return f"{keep}…[{len(value)} chars redacted]"


def _is_reference(value: str) -> bool:
    return bool(REFERENCE.match(value)) or value.startswith(("process.env", "os.environ", "import.meta.env"))


def _looks_real(value: str, key: str = "") -> bool:
    """Is this a credential value, as opposed to a placeholder, a name, a reference or a sentence?"""
    value = value.strip()
    if len(value) < 6 or _is_reference(value) or PLACEHOLDER.search(value):
        return False
    if value.startswith(("http://", "https://", "/", "./", "../", "~/", "#")) or "://" in value:
        return False
    if ENV_NAME.fullmatch(value):  # an env var *name*, not a value
        return False
    if NON_ASCII.search(value) or re.search(r"\s", value):  # prose, or translated UI text
        return False
    if len(set(value)) <= 3 or TRIVIAL.fullmatch(value):
        return False
    if re.fullmatch(r"[\w.-]+\.(?:js|ts|py|json|html|css|png|svg|pem|key|crt|txt|yml|yaml|md)", value):
        return False
    if key and value.lower() in key.lower().replace("-", "_"):
        return False  # `csrfToken = "csrfToken" in props`: the value is the variable's own name
    if re.fullmatch(r"[a-z]+(?:[A-Z][a-z]+)+", value) and re.search(r"(?i)token|secret|key|passw|auth|session", value):
        return False  # camelCase name of a credential ("accessToken"), not the credential
    strong = bool(key) and bool(STRONG_KEY.search(key.rstrip("\"'")))
    if LOWER_IDENT.fullmatch(value):
        if not strong or not any(c.isdigit() for c in value) or re.search(r"(?i)token|secret|passw|key|auth|session", value):
            return False  # a setting, a model name, or the *name* of a token ("auth_access_token")
    has_digit = any(c.isdigit() for c in value)
    if strong and has_digit and any(c.isalpha() for c in value) and len(value) >= 8:
        return entropy(value) >= 2.5  # human-chosen passwords have low entropy and are still passwords
    return entropy(value) >= 3.0


def _placeholder_body(rid: str, value: str) -> bool:
    """A provider-shaped string that is obviously not a live key: docs, templates, tests."""
    if rid == "SEC001" and value.endswith("EXAMPLE"):
        return True  # AWS's documented example key
    if rid == "SEC003":
        return False
    if rid == "SEC010":
        return not _looks_real(value)
    if rid == "SEC011" and value.endswith(JWT_SAMPLES):
        return True
    body = PREFIX.sub("", value)
    compact = re.sub(r"[-_./:]", "", body)
    if len(set(compact)) <= 6 or "1234567890" in compact:
        return True
    if re.search(r"(?i)x{4,}|0{6,}|\*{3,}|\.{3}|[<>]|\$\{|\{\{", body):
        return True
    if rid != "SEC011" and (PLACEHOLDER.search(body) or WORDY.search(body)):
        return True
    if re.fullmatch(r"[a-z]+(?:[-_][a-z]+){2,}", body):  # kebab or snake words: a CSS class, a slug
        return True
    if rid in ("SEC006", "SEC007") and not any(c.isdigit() for c in body):
        return True  # real OpenAI and Slack secrets always carry digits
    return False


def _is_env_file(name: str) -> bool:
    return (name == ".env" or name.startswith(".env.") or name.endswith(".env")) and not re.search(
        r"(example|sample|template|dist|defaults)", name, re.IGNORECASE
    )


def _is_config_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name.endswith(CONFIG_SUFFIXES) or name in CONFIG_NAMES or name.startswith(("docker-compose", "compose."))


def _is_locale_file(path: str) -> bool:
    """Translation catalogues hold UI text such as "hide_password": "Hide password", which is not a credential."""
    low = path.lower()
    if not low.endswith(LOCALE_SUFFIXES):
        return False
    parts = low.split("/")
    if LOCALE_DIRS & set(parts[:-1]):
        return True
    stem = parts[-1].rsplit(".", 1)[0]
    m = re.fullmatch(r"(?:(?:messages|strings|translations?|locale|lang)[._-])?([a-z]{2})(?:[-_][a-z]{2,4})?", stem)
    return bool(m) and m.group(1) in LANGS


def _git(root: str, *args) -> int | None:
    try:
        return gitsafe.run(root, *args, timeout=10, text=False).returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def _gitignore_patterns(root: str) -> list:
    try:
        with open(os.path.join(root, ".gitignore"), encoding="utf-8", errors="replace") as fh:
            return [ln.strip().lstrip("/") for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


def _env_file_status(root: str, rel: str, patterns: list) -> str:
    """'tracked' (committed!), 'ignored', or 'exposed' (would be committed by `git add .`)."""
    if _git(root, "rev-parse", "--is-inside-work-tree") == 0:
        if _git(root, "ls-files", "--error-unmatch", rel) == 0:
            return "tracked"
        return "ignored" if _git(root, "check-ignore", "-q", rel) == 0 else "exposed"
    name = rel.rsplit("/", 1)[-1]
    return "ignored" if any(fnmatch(name, p) or fnmatch(rel, p) for p in patterns) else "exposed"


def _pem_has_body(lines: list, index: int, line: str, start: int) -> bool:
    """A private-key header followed by key material, as opposed to code that compares the header text."""
    if BASE64_RUN.search(line[start:].replace("\\n", "\n").replace("\\r", "")):
        return True
    for nxt in lines[index + 1: index + 6]:
        stripped = nxt.strip().strip("'\"`,+ ")
        if BASE64_RUN.match(stripped) or re.match(r"(?i)(proc-type|dek-info):", stripped):
            return True
    return False


def scan(files: list, root: str) -> list:
    findings = []
    gi = _gitignore_patterns(root)
    for f in files:
        name = f.path.rsplit("/", 1)[-1]
        if name in SKIP_FILES:
            continue
        if _is_env_file(name):
            findings.extend(_scan_env_file(f, root, gi))
        else:
            findings.extend(_scan_file(f))
    for finding in findings:
        if is_test_path(finding.file):  # fixtures are usually fake; still worth a look
            finding.severity = cap_severity(finding.severity, "medium")
            finding.extra["test_code"] = True
    return findings


def _scan_file(f) -> list:
    text = f.text
    providers = [p for p in COMPILED if any(h in text for h in p[4])]
    generic = any(h in text.lower() for h in GENERIC_HINTS) and not _is_locale_file(f.path)
    if not providers and not generic:
        return []
    config = _is_config_file(f.path)
    xml = f.path.lower().endswith((".xml", ".config", ".plist"))
    out, in_pem, lines = [], False, f.lines
    for lineno, line in enumerate(lines, 1):
        if in_pem:  # the key body was reported once, by its header
            in_pem = "-----END" not in line
            continue
        if is_suppressed(line):
            continue
        found = _scan_line(f.path, lineno, line, providers=providers, generic=generic and len(line) <= LINE_LIMIT,
                           config=config, xml=xml, lines=lines)
        if "-----END" not in line and any(x.rule_id == "SEC003" for x in found):
            in_pem = True
        out.extend(found)
    return out


def _overlaps(span, taken) -> bool:
    return any(a < span[1] and span[0] < b for a, b in taken)


def _scan_line(path: str, lineno: int, line: str, providers=None, generic: bool = True, config: bool | None = None,
               xml: bool = False, lines: list | None = None) -> list:
    out, taken = [], []
    if config is None:
        config = _is_config_file(path)
    for rid, title, sev, rx, hints in (COMPILED if providers is None else providers):
        if not any(h in line for h in hints):
            continue
        for m in rx.finditer(line):
            if _overlaps(m.span(), taken):
                continue
            value = m.group(1) if m.groups() and m.group(1) else m.group(0)
            if _placeholder_body(rid, value):
                continue
            if rid == "SEC003" and not _pem_has_body(lines or [line], lineno - 1 if lines else 0, line, m.end()):
                continue
            taken.append(m.span())
            level = sev
            if rid == "SEC010" and re.search(r"@(localhost|127\.0\.0\.1|db|postgres|mysql|redis|mongo)[:/]",
                                             m.group(0)):
                level = "low"  # local dev default: still worth moving to env
            out.append(_finding(rid, title, level, path, lineno, line, value))
    if not generic or not any(h in line.lower() for h in GENERIC_HINTS):
        return out
    candidates = [(m.span(), m.group(1), m.group(2)) for m in GENERIC.finditer(line)]
    if config:
        candidates += [(m.span(2), m.group(1), m.group(2)) for m in GENERIC_UNQUOTED.finditer(line)]
    if xml or config:
        candidates += [(m.span(), m.group(1), m.group(2)) for m in GENERIC_XML.finditer(line)]
    for span, key, value in candidates:
        if _overlaps(span, taken) or KEY_NOT_SECRET.search(key.strip(".-_")) or not _looks_real(value, key):
            continue
        taken.append(span)
        out.append(_finding("SEC100", "Hard-coded credential", "high", path, lineno, line, value))
    return out


def _env_value(raw: str) -> str:
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        end = raw.find(raw[0], 1)
        return raw[1:end] if end != -1 else raw[1:]
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def _env_secret(key: str, value: str) -> bool:
    if not value or _is_reference(value) or PLACEHOLDER.search(value) or TRIVIAL.fullmatch(value):
        return False
    if KEY_NOT_SECRET.search(key) and not re.search(r"(?i)(database_url|dsn)$", key):
        return False
    if "://" in value:  # a URL is only a secret when it carries a password
        m = URL_USERINFO.match(value)
        return bool(m) and _looks_real(m.group(1))
    return len(value) >= 4 and len(set(value)) > 2


def _scan_env_file(f, root: str, gi: list) -> list:
    status = _env_file_status(root, f.path, gi)
    if status == "ignored":
        return []  # local-only env file: exactly where secrets belong
    out = []
    sev = "critical" if status == "tracked" else "high"
    base_title = "Secret in committed env file" if status == "tracked" else "Secret in env file that is not git-ignored"
    in_pem = False
    for lineno, line in enumerate(f.lines, 1):
        if in_pem:
            in_pem = "-----END" not in line
            continue
        if is_suppressed(line) or line.lstrip().startswith("#"):
            continue
        m = ENV_LINE.match(line)
        if not m:
            continue
        key, value = m.group(1), _env_value(m.group(2))
        provider = next(iter(_scan_line(f.path, lineno, line, generic=False, lines=f.lines)), None)
        if provider is not None:  # a provider key is a secret whatever the variable is called
            title = f"{base_title}: {provider.title}"
            in_pem = provider.rule_id == "SEC003" and "-----END" not in line
        elif ENV_SECRET_KEY.search(key) and _env_secret(key, value):
            title = base_title
        else:
            continue
        out.append(_finding("SEC200", title, sev, f.path, lineno, line, value, whole_value=True))
    fix = (
        f"Add `{f.path.rsplit('/', 1)[-1]}` to .gitignore"
        + (f" and run `git rm --cached {f.path}`" if status == "tracked" else "")
        + ", and commit a `.env.example` listing the same variables with placeholder values. "
        + (COMPROMISED if status == "tracked" else "")
    ).strip()
    for finding in out:
        finding.fix = fix
        finding.extra["done"] = "the env file is git-ignored (and untracked), and `.env.example` documents every variable."
    return out


def _mask_pem(text: str) -> str:
    return PEM_BLOCK.sub(lambda m: m.group(1) + "…[key material redacted]" + m.group(3), text)


def _mask(m, group: int, key_group: int | None = None):
    value = m.group(group)
    if "…[" in value or not _looks_real(value, m.group(key_group) if key_group else ""):
        return m.group(0)
    return m.group(0).replace(value, redact(value))


def redact_text(text: str) -> str:
    """Safety net for snippets from any engine: mask anything that looks like a credential value."""
    if not text:
        return text
    text = _mask_pem(text)
    for rid, _, _, rx, hints in COMPILED:
        if rid == "SEC003" or not any(h in text for h in hints):
            continue
        text = rx.sub(lambda m: m.group(0).replace(v := (m.group(1) if m.groups() and m.group(1) else m.group(0)),
                                                   redact(v)), text)
    text = GENERIC.sub(lambda m: _mask(m, 2, 1), text)
    text = GENERIC_UNQUOTED.sub(lambda m: _mask(m, 2, 1), text)
    text = GENERIC_XML.sub(lambda m: _mask(m, 2, 1), text)
    return LONG_BLOB.sub(lambda m: redact(m.group(0)), text)


def _finding(rid, title, sev, path, lineno, line, value, whole_value: bool = False) -> Finding:
    snippet = line.strip()
    if PEM_BEGIN.search(snippet):
        snippet = _mask_pem(snippet)
    if whole_value:  # env files: everything after `=` is the value, inline comment and all
        snippet = re.sub(r"^((?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*).*$",
                         lambda m: m.group(1) + redact(value or "x"), snippet)
    elif value and value in snippet:
        snippet = snippet.replace(value, redact(value))
    snippet = redact_text(snippet)
    if len(snippet) > 200:
        snippet = snippet[:200] + "…"
    return Finding(
        rule_id=rid, title=title, severity=sev, category="secret", file=path, line=lineno,
        snippet=snippet, cwe="CWE-798", fix=ROTATE,
    )
