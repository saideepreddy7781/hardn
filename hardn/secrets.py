"""Hard-coded credential detection. Values are always redacted before they leave this module."""
from __future__ import annotations

import math
import os
import re
import subprocess
from collections import Counter
from fnmatch import fnmatch

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

PATTERNS = [
    ("SEC001", "AWS access key ID", "critical", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("SEC002", "GitHub token", "critical", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"),
    ("SEC003", "Private key", "critical", r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----"),
    ("SEC004", "Stripe live secret key", "critical", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}"),
    ("SEC005", "Anthropic API key", "critical", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("SEC006", "OpenAI API key", "critical", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"),
    ("SEC007", "Slack token", "high", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    ("SEC008", "Google API key", "high", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("SEC009", "SendGrid API key", "high", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("SEC010", "Connection string with embedded password", "high",
     r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql)://[^\s:/@'\"]+:([^\s@'\"]+)@[^\s'\"]+"),
    ("SEC011", "JSON Web Token", "medium", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]
COMPILED = [(i, t, s, re.compile(p)) for i, t, s, p in PATTERNS]

GENERIC = re.compile(
    r"""(?i)\b([\w.-]*(?:secret|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|"""
    r"""token|private[_-]?key|client[_-]?secret|signing[_-]?key)[\w.-]*)["']?\s*(?::=|=>|[:=])\s*["']([^"'\n]{8,})["']"""
)
KEY_NOT_SECRET = re.compile(
    r"(?i)(_?(url|uri|path|file|field|name|label|header|type|endpoint|length|len|regex|pattern|"
    r"placeholder|input|message|msg|text|hint|error|prompt|id|count|expires?|ttl|policy)$)"
)
PLACEHOLDER = re.compile(
    r"(?i)(example|changeme|change_me|your[_-]|<|>|\$\{|\{\{|process\.env|os\.environ|getenv|"
    r"placeholder|dummy|sample|redacted|xxxx|\*{4}|todo|fake|lorem|%s|\{\})"
)
# Unquoted `KEY=value` / `KEY value` assignments (Dockerfiles, shell, YAML) — used for redaction only.
UNQUOTED = re.compile(
    r"(?i)\b(\w*(?:secret|passw|pwd|token|api_?key|private_?key|credential)\w*)(=|:\s*|\s+)(?=[^\s\"'#(),;]*\d)([^\s\"'#(),;]{6,})"
)
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]?([^'\"#\n]*)")
ENV_SECRET_KEY = re.compile(r"(?i)(secret|passw|pwd|token|api_?key|private|credential|dsn|database_url|access_key)")
SKIP_FILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "go.sum", "Cargo.lock", "composer.lock")


def entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def redact(value: str) -> str:
    keep = value[:4] if len(value) > 12 else ""
    return f"{keep}…[{len(value)} chars redacted]"


def _looks_real(value: str) -> bool:
    if PLACEHOLDER.search(value) or value.startswith(("http://", "https://", "/", "./")):
        return False
    if re.fullmatch(r"[A-Z0-9_]+", value):  # an env var *name*, not a value
        return False
    if len(set(value)) <= 3 or value.count(" ") >= 2:  # repeated chars, or prose
        return False
    return entropy(value) >= 3.0


def _is_env_file(name: str) -> bool:
    return (name == ".env" or name.startswith(".env.") or name.endswith(".env")) and not re.search(
        r"(example|sample|template|dist|defaults)", name, re.I
    )


def _git(root: str, *args) -> int | None:
    try:
        return subprocess.run(["git", "-C", root, *args], capture_output=True, timeout=10).returncode
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


def scan(files: list, root: str) -> list:
    findings = []
    gi = _gitignore_patterns(root)
    for f in files:
        name = f.path.rsplit("/", 1)[-1]
        if name in SKIP_FILES:
            continue
        if _is_env_file(name):
            findings.extend(_scan_env_file(f, root, gi))
            continue
        for lineno, line in enumerate(f.lines, 1):
            if len(line) > 2000 or "hardn:ignore" in line or "gitleaks:allow" in line:
                continue
            findings.extend(_scan_line(f.path, lineno, line))
    for finding in findings:
        if is_test_path(finding.file):  # fixtures are usually fake; still worth a look
            finding.severity = cap_severity(finding.severity, "medium")
            finding.extra["test_code"] = True
    return findings


def _scan_line(path: str, lineno: int, line: str) -> list:
    out, taken = [], []
    for rid, title, sev, rx in COMPILED:
        for m in rx.finditer(line):
            if any(a < m.end() and m.start() < b for a, b in taken):
                continue
            value = m.group(1) if m.groups() and m.group(1) else m.group(0)
            if rid == "SEC010" and not _looks_real(value) or rid == "SEC001" and value.endswith("EXAMPLE"):
                continue  # placeholders, and AWS's documented example key
            taken.append(m.span())
            if rid == "SEC010" and re.search(r"@(localhost|127\.0\.0\.1|db|postgres|mysql|redis|mongo)[:/]", m.group(0)):
                sev = "low"  # local dev default — still worth moving to env
            out.append(_finding(rid, title, sev, path, lineno, line, value))
    for m in GENERIC.finditer(line):
        if any(a < m.end() and m.start() < b for a, b in taken):
            continue
        key, value = m.group(1), m.group(2)
        if KEY_NOT_SECRET.search(key) or not _looks_real(value):
            continue
        taken.append(m.span())
        out.append(_finding("SEC100", "Hard-coded credential", "high", path, lineno, line, value))
    return out


def _scan_env_file(f, root: str, gi: list) -> list:
    status = _env_file_status(root, f.path, gi)
    if status == "ignored":
        return []  # local-only env file: exactly where secrets belong
    out = []
    for lineno, line in enumerate(f.lines, 1):
        m = ENV_LINE.match(line)
        if not m or not ENV_SECRET_KEY.search(m.group(1)) or not m.group(2).strip():
            continue
        value = m.group(2).strip()
        if PLACEHOLDER.search(value):
            continue
        sev = "critical" if status == "tracked" else "high"
        title = "Secret in committed env file" if status == "tracked" else "Secret in env file that is not git-ignored"
        out.append(_finding("SEC200", title, sev, f.path, lineno, line, value))
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


def redact_text(text: str) -> str:
    """Safety net for snippets from any engine: mask anything that looks like a credential value."""
    for _, _, _, rx in COMPILED:
        text = rx.sub(lambda m: m.group(0).replace(v := (m.group(1) if m.groups() and m.group(1) else m.group(0)), redact(v)), text)
    text = GENERIC.sub(lambda m: m.group(0).replace(m.group(2), redact(m.group(2))) if _looks_real(m.group(2)) else m.group(0), text)
    text = UNQUOTED.sub(lambda m: m.group(1) + m.group(2) + (redact(m.group(3)) if not m.group(3).startswith(("$", "process.env", "os.environ")) and "…[" not in m.group(3) else m.group(3)), text)
    return text


def _finding(rid, title, sev, path, lineno, line, value) -> Finding:
    snippet = line.strip().replace(value, redact(value)) if value else line.strip()
    if len(snippet) > 200:
        snippet = snippet[:200] + "…"
    return Finding(
        rule_id=rid, title=title, severity=sev, category="secret", file=path, line=lineno,
        snippet=snippet, cwe="CWE-798", fix=ROTATE,
    )
