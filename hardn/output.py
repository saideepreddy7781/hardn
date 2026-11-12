"""Terminal summary, report.json, SARIF, and the only code that writes report files.

Text from the scanned repo (file names, snippets, engine messages) is untrusted, so everything printed to a
terminal goes through clean(), and every file is written through write_file(), which refuses symlinks.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import stat
import sys
import tempfile
from urllib.parse import quote

from . import __version__
from .models import SEV_RANK, SEVERITIES
from .scoring import LEVELS, grade, level, score

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
SEV_STYLE = {"critical": "1;97;41", "high": "1;31", "medium": "33", "low": "36", "info": "2"}
REPO_URL = "https://github.com/saideepreddy7781/hardn"

# C0 and C1 control characters, DEL, and the bidi overrides that can make a terminal show text out of order.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]")
_CONTROL_KEEP_LINES = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")


class OutputError(Exception):
    """A report could not be written safely."""


def clean(text, multiline: bool = False) -> str:
    """Make repo-derived text safe to print: control characters become '?', undecodable bytes become U+FFFD."""
    text = str(text)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates, e.g. from undecodable file names
        try:
            text = text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
        except UnicodeEncodeError:
            text = text.encode("utf-8", "replace").decode("utf-8")
    return (_CONTROL_KEEP_LINES if multiline else _CONTROL).sub("?", text)


def rel(path: str) -> str:
    """Path relative to cwd for display; absolute if outside cwd or on another drive (Windows)."""
    try:
        r = os.path.relpath(path)
    except ValueError:
        return path
    return path if r.startswith("..") else r


# ---------------------------------------------------------------- safe file writing

def _refuse_unsafe(path: str, want_dir: bool = False) -> None:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OutputError(f"cannot check {path}: {exc.strerror or exc}") from exc
    if stat.S_ISLNK(mode):
        raise OutputError(f"{path} is a symlink; hardn will not write through it. Remove it or use -o DIR")
    if want_dir and not stat.S_ISDIR(mode):
        raise OutputError(f"{path} exists and is not a directory. Remove it or use -o DIR")
    if not want_dir and not stat.S_ISREG(mode):
        raise OutputError(f"{path} exists and is not a regular file; hardn will not overwrite it")


def write_file(directory: str, name: str, text: str) -> str:
    """Write directory/name atomically with mode 0600. Never follows a symlink at the destination."""
    path = os.path.join(directory, name)
    _refuse_unsafe(directory, want_dir=True)
    _refuse_unsafe(path)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{name}.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        tmp = None
    except OSError as exc:
        raise OutputError(f"cannot write {path}: {exc.strerror or exc}. Use -o DIR to write reports elsewhere") \
            from exc
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return path


def ensure_out_dir(out_dir: str) -> None:
    """Create the output directory and (re)write its .gitignore. Raises OutputError."""
    _refuse_unsafe(out_dir, want_dir=True)
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        raise OutputError(f"cannot create {out_dir}: {exc.strerror or exc}. Use -o DIR to write reports elsewhere") \
            from exc
    _refuse_unsafe(out_dir, want_dir=True)
    # Always overwrite: a repo that ships `.hardn/.gitignore` containing `!*` would make reports committable.
    write_file(out_dir, ".gitignore", "# hardn output: keep reports out of version control\n*\n")


# ---------------------------------------------------------------- terminal summary

def c(text: str, style: str) -> str:
    return f"\033[{style}m{text}\033[0m" if _COLOR else text


def badge(sev: str) -> str:
    return c(f"{sev.upper():<8}", SEV_STYLE[sev])


def _trunc(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def gap_text(gap) -> str:
    if isinstance(gap, dict):
        gap = gap.get("message") or gap.get("reason") or json.dumps(gap, sort_keys=True)
    return clean(gap)


def hidden_text(result) -> str:
    if getattr(result, "untrusted", False):
        return "nothing (--untrusted ignores .hardnignore, baselines and inline suppressions)"
    h = result.hidden or {}
    return (f"{h.get('inline', 0)} suppressed inline · {h.get('hardnignore', 0)} files excluded by .hardnignore · "
            f"{h.get('baselined', 0)} baselined")


def skipped_text(result) -> str:
    sk = getattr(result, "skipped", None) or {}
    parts = []
    for key, label in (("oversize", "over 1 MB"), ("unreadable", "unreadable"), ("special", "not regular files"),
                       ("symlinks", "symlinks not followed"), ("generated_dirs", "generated folders")):
        n = (sk.get(key) or {}).get("count", 0)
        if n:
            parts.append(f"{n} {label}")
    return " · ".join(parts)


def _context_counts(findings: list) -> str:
    counts = {}
    for f in findings:
        counts[f.context] = counts.get(f.context, 0) + 1
    return " · ".join(f"{n} {ctx}" for ctx, n in sorted(counts.items(), key=lambda kv: -kv[1]))


def _row(x, width: int) -> str:
    return (f"  {badge(x.severity)}  {clean(x.rule_id):<{width}}  {clean(_trunc(x.title, 58)):<58}  "
            f"{c(clean(x.location()), '2')}")


def render(result, prompt_path: str, target: int, n_tasks: int, show: int = 15, verbose: bool = False,
           scope: str = "", level_findings: list | None = None) -> str:
    """The terminal summary. level_findings: what the level is computed on, when it differs from the list shown
    (with --diff the list is changed lines only, but the level describes the whole repository)."""
    shown = result.findings
    graded = shown if level_findings is None else level_findings
    gaps = list(result.gaps or [])
    cur, s = level(graded, gaps), score(graded)
    counted = [x for x in shown if x.counts]
    outside = [x for x in shown if not x.counts]
    out = ["", f"  {c('hardn', '1')} {c(__version__, '2')} · {clean(rel(result.root))}", ""]
    eng = []
    for name, st in result.engines.items():
        ok = (st.startswith("ok") or "packages checked" in st) and "incomplete" not in st
        mark = c("✓", "32") if ok else c("–", "2")
        detail = verbose or (not ok and name in ("built-in", "osv"))
        eng.append(f"{mark} {clean(name)}" + (c(f" ({clean(st)})", "2") if detail else ""))
    out.append(f"  {c('Engines', '2')}   " + "  ".join(eng))
    stack = result.stack.get("languages", [])[:4] + result.stack.get("frameworks", [])
    if stack:
        out.append(f"  {c('Stack', '2')}     " + clean(", ".join(stack)))
    out.append(f"  {c('Scanned', '2')}   {result.files_scanned} files in {result.duration:.2f}s")
    skipped = skipped_text(result)
    if skipped:
        out.append(f"  {c('Skipped', '2')}   {skipped} (paths in report.json)")
    if getattr(result, "untrusted", False):
        out.append(f"  {c('Mode', '2')}      untrusted: repo config ignored, every finding counts")
    if scope:
        out.append(f"  {c('Scope', '2')}     {clean(scope)}")
    out.append("")

    visible = [x for x in counted if x.severity != "info" or verbose]
    width = max((len(clean(x.rule_id)) for x in visible[:show]), default=6)
    out += [_row(x, width) for x in visible[:show]]
    if len(visible) > show:
        out.append(c(f"  … {len(visible) - show} more (full list: --verbose or report.json)", "2"))
    if not counted:
        if gaps:
            out.append("  No findings in the parts hardn could check. The blind spots below may hide some.")
        elif level_findings is not None:
            out.append("  No findings on the changed lines.")
        else:
            out.append(c("  No issues found.", "32"))
    if outside:
        out.append("")
        out.append(f"  {c('Outside app code', '2')}  {len(outside)} finding(s): {_context_counts(outside)}. "
                   "They do not change the level or --fail-on.")
        if verbose:
            ow = max(len(clean(x.rule_id)) for x in outside)
            out += [_row(x, ow) + c(f"  [{x.context}]", "2") for x in outside]
        else:
            out.append(c("  List them with --verbose or in report.json.", "2"))
    out.append("")

    if gaps:
        out.append(f"  {c('Blind spots', '1;33')}  hardn could not check the following, so this result is incomplete:")
        out += [f"    {c('!', '1;33')} {gap_text(g)}" for g in gaps]
        out.append("")

    bar = "".join(c("▰", "32") if i <= cur else c("▱", "2") for i in range(5))
    lvl_style = {0: "1;31", 1: "31", 2: "33", 3: "32", 4: "1;32"}[cur]
    note = []
    if gaps:
        note.append(c("incomplete", "1;33"))
    if level_findings is not None:
        note.append("whole repository")
    out.append(f"  {c('Level', '2')}     {bar}  {c(f'L{cur} {LEVELS[cur]}', lvl_style)}   "
               f"score {s}/100 ({grade(s)})" + (f"   {', '.join(note)}" if note else ""))
    counts = [f"{sum(1 for x in counted if x.severity == sv)} {sv}" for sv in reversed(SEVERITIES)
              if any(x.severity == sv for x in counted)]
    if counts:
        out.append(f"  {c('Findings', '2')}  " + " · ".join(counts))
    out.append(f"  {c('Hidden', '2')}    {hidden_text(result)}")
    out.append("")
    if n_tasks:
        quoted = clean(shlex.quote(prompt_path))
        out.append(f"  {c('→', '1;36')} Next: {c(f'L{target} {LEVELS[target]}', '1')}: {n_tasks} task"
                   f"{'s' if n_tasks != 1 else ''} written to {c(clean(prompt_path), '4')}")
        out.append(c(f'    claude "$(cat {quoted})"', "36") + c("     # or paste into Cursor / Copilot / any LLM", "2"))
    elif cur == 4 and not gaps:
        out.append(f"  {c('→', '1;36')} Top level reached. Keep it there: add `hardn scan . --fail-on low` to CI.")
    out.append("")
    return "\n".join(out)


def blind_spot_lines(result) -> list:
    """Short stderr notice for modes that print no summary (-q, --json, --print-prompt)."""
    gaps = list(result.gaps or [])
    if not gaps:
        return []
    return [f"hardn: incomplete scan, {len(gaps)} blind spot(s):"] + [f"  ! {gap_text(g)}" for g in gaps]


# ---------------------------------------------------------------- report.json

def report_dict(result, meta: dict | None = None, level_findings: list | None = None) -> dict:
    f = result.findings
    graded = f if level_findings is None else level_findings
    gaps = list(result.gaps or [])
    lvl, s = level(graded, gaps), score(graded)
    outside = [x for x in f if not x.counts]
    by_ctx = {}
    for x in outside:
        by_ctx[x.context] = by_ctx.get(x.context, 0) + 1
    return {
        "tool": "hardn", "version": __version__, "root": result.root, "stack": result.stack,
        "engines": result.engines, "level": lvl, "level_name": LEVELS[lvl], "score": s, "grade": grade(s),
        "level_scope": "repository" if level_findings is not None else "findings",
        "complete": not gaps, "gaps": gaps, "untrusted": bool(getattr(result, "untrusted", False)),
        "hidden": dict(result.hidden or {}), "skipped": getattr(result, "skipped", None) or {},
        "files_scanned": result.files_scanned, "duration_seconds": round(result.duration, 3),
        "outside_app": {"count": len(outside), "by_context": by_ctx},
        "scope": meta or {}, "findings": [dict(x.to_dict(), counts=x.counts) for x in f],
    }


def write_json(result, path: str, meta: dict | None = None, level_findings: list | None = None) -> str:
    text = json.dumps(report_dict(result, meta, level_findings), indent=2)
    return write_file(os.path.dirname(path) or ".", os.path.basename(path), text + "\n")


# ---------------------------------------------------------------- rule catalog

POSTURE_RULES = {
    "POS001": ("No dependency lockfile", "medium", "CWE-1104",
               "Commit a lockfile and install with `npm ci` in CI so builds are reproducible and auditable."),
    "POS002": ("Unbounded dependency versions", "medium", "CWE-1104",
               "Pin each listed package to a semver range or an exact version."),
    "POS003": ("No security headers middleware", "medium", "CWE-693",
               "Install the framework's headers middleware (helmet for Express) and register it before routes."),
    "POS004": ("No rate limiting", "medium", "CWE-307",
               "Add a strict limiter on authentication routes and a looser global limiter."),
    "POS005": ("No request schema validation library", "low", "CWE-20",
               "Validate every request body, query and params at the boundary with a schema library such as zod."),
    "POS006": ("No Content-Security-Policy for Next.js", "medium", "CWE-693",
               "Set Content-Security-Policy and the other security headers in next.config or middleware."),
    "POS010": ("Unpinned Python dependencies", "low", "CWE-1104",
               "Pin exact versions (pip-compile or uv pip compile) and install with hashes."),
    "POS011": ("No security headers for Flask", "medium", "CWE-693",
               "Add flask-talisman for HSTS, CSP and secure cookie defaults."),
    "POS012": ("Django production security settings missing", "medium", "CWE-693",
               "Set the listed settings from the environment, then run `python manage.py check --deploy`."),
    "POS020": ("Container runs as root", "medium", "CWE-250",
               "Create an unprivileged user in the Dockerfile and switch to it with USER before CMD."),
    "POS030": ("No .gitignore", "low", "CWE-538",
               "Add a .gitignore that excludes .env files, build output, dependency folders and local keys."),
    "POS031": ("No security policy (SECURITY.md)", "info", "",
               "Add SECURITY.md describing how to report vulnerabilities and which versions get fixes."),
    "POS032": ("No automated dependency updates", "low", "CWE-1104",
               "Set up automated dependency update pull requests for each package ecosystem."),
    "POS033": ("No security scanning in CI", "low", "",
               "Run `hardn scan . --fail-on high` on every pull request."),
}
EXTERNAL_PREFIXES = {"gitleaks:": "gitleaks", "bandit:": "bandit", "trivy:": "trivy"}


def rule_catalog() -> dict:
    """Every built-in rule id hardn can report: {id: {title, severity, cwe, fix, kind, applies}}."""
    from . import code_rules, secrets, taint_js, taint_py  # local import: those modules import walker and models

    cat = {}

    def add(rid, title, sev, cwe, fix, kind, applies=""):
        cat[rid] = {"title": title, "severity": sev, "cwe": cwe or "", "fix": fix or "", "kind": kind,
                    "applies": applies}

    fixes = {}
    for r in code_rules.RULES:
        fixes[r.id] = r.fix
        add(r.id, r.title, r.severity, r.cwe, r.fix,
            "config" if r.id.startswith(("DK", "CI", "K8S", "TF")) else "code", ", ".join(getattr(r, "targets", ())))
    rotate = getattr(secrets, "ROTATE", "")
    for row in getattr(secrets, "PATTERNS", []):
        add(row[0], row[1], row[2], "CWE-798", rotate, "secret", "any text file")
    add("SEC100", "Hard-coded credential", "high", "CWE-798", rotate, "secret", "any text file")
    add("SEC200", "Secret in an env file that is committed or not git-ignored", "high", "CWE-798",
        "Git-ignore the env file, remove it from the index, and commit a .env.example with placeholders. "
        + getattr(secrets, "COMPROMISED", ""), "secret", ".env files")
    for row in getattr(taint_py, "SINKS", []):
        fix_rule = row[5] if len(row) > 5 else None
        add(row[0], row[1], row[2], row[3], fixes.get(fix_rule) or getattr(taint_py, "SSTI_FIX", ""), "taint",
            "Python request handlers")
    for row in getattr(taint_js, "SINKS", []):
        fix_rule = row[5] if len(row) > 5 else None
        add(row[0], row[1], row[2], row[3], fixes.get(fix_rule) or getattr(taint_js, "PROTO_FIX", ""), "taint",
            "JavaScript and TypeScript")
    add("JST009", "XSS: request data written into HTML", "high", "CWE-79", fixes.get("JS004", ""), "taint",
        "JavaScript and TypeScript")
    for rid, (title, sev, cwe, fix) in POSTURE_RULES.items():
        add(rid, title, sev, cwe, fix, "posture", "project configuration")
    return cat


def explain_rule(rule_id: str, catalog: dict | None = None) -> dict | None:
    """Catalog entry for an id, including the pattern ids (DEP-*, gitleaks:*, ...) that have no fixed list."""
    catalog = catalog if catalog is not None else rule_catalog()
    hit = next((v | {"id": k} for k, v in catalog.items() if k.lower() == rule_id.lower()), None)
    if hit:
        return hit
    if rule_id.upper().startswith("DEP-") and len(rule_id) > 4:
        eco = rule_id[4:]
        return {"id": rule_id, "title": f"Dependency with known vulnerabilities ({eco})", "severity": "varies",
                "cwe": "CWE-1395", "kind": "dependency", "applies": f"{eco} lockfiles and pinned manifests",
                "fix": "Upgrade the package to the fixed version named in the finding. For a transitive dependency, "
                       "upgrade its parent or add an override, then run the tests."}
    for prefix, tool in EXTERNAL_PREFIXES.items():
        if rule_id.lower().startswith(prefix):
            return {"id": rule_id, "title": f"Reported by {tool} (rule {rule_id[len(prefix):]})", "severity": "varies",
                    "cwe": "", "kind": "external", "applies": f"files {tool} checks",
                    "fix": f"See the {tool} documentation for rule {rule_id[len(prefix):]}."}
    return None


# ---------------------------------------------------------------- SARIF

SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.5}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_ANCHORS = ("README.md", "README", "README.rst", "package.json", "pyproject.toml", "setup.py", "go.mod",
            "Cargo.toml", "pom.xml", ".gitignore")


def _uri(path: str, prefix: str) -> str:
    full = (prefix + path).replace(os.sep, "/")
    return quote(full, safe="/", errors="surrogateescape" if os.name != "nt" else "replace")


def _anchor(root: str, findings: list) -> str:
    """A file to attach project-wide findings to: GitHub drops results without a location."""
    for name in _ANCHORS:
        try:
            if stat.S_ISREG(os.lstat(os.path.join(root, name)).st_mode):
                return name
        except OSError:
            continue
    return next((f.file for f in findings if f.file), "README.md")


def _help_uri(cwe: str) -> str:
    m = re.fullmatch(r"CWE-(\d+)", cwe or "")
    return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html" if m else REPO_URL


def sarif_doc(result, prefix: str = "") -> dict:
    """SARIF 2.1.0. prefix: the scan root's path inside the repository (e.g. 'services/api/'), so URIs are
    relative to the repository root as GitHub code scanning expects."""
    from . import baseline  # local import: baseline writes through this module

    catalog = rule_catalog()
    anchor = _anchor(result.root, result.findings)
    rules, index, results = [], {}, []
    for x, fp in zip(result.findings, baseline.fingerprints(result.findings)):
        sev_score = SECURITY_SEVERITY[x.severity]
        if x.rule_id not in index:
            info = explain_rule(x.rule_id, catalog) or {}
            title = clean(info.get("title") or x.title)
            fix = clean(info.get("fix") or x.fix or x.title)
            cwe = info.get("cwe") or x.cwe
            sev = info.get("severity") if info.get("severity") in SEV_RANK else x.severity
            tags = ["security", x.category]
            if re.fullmatch(r"CWE-\d+", cwe or ""):
                tags.append(f"external/cwe/cwe-{cwe[4:]}")
            index[x.rule_id] = len(rules)
            rules.append({
                "id": x.rule_id, "name": re.sub(r"[^A-Za-z0-9]", "", x.rule_id) or "rule",
                "shortDescription": {"text": title}, "fullDescription": {"text": title},
                "help": {"text": fix, "markdown": fix}, "helpUri": _help_uri(cwe),
                "defaultConfiguration": {"level": SARIF_LEVEL[sev]},
                "properties": {"tags": tags, "security-severity": str(SECURITY_SEVERITY[sev]), "precision": "medium"},
            })
        rule = rules[index[x.rule_id]]
        if float(rule["properties"]["security-severity"]) < sev_score:
            rule["properties"]["security-severity"] = str(sev_score)
        region = {"startLine": max(int(x.line or 0), 1)}
        results.append({
            "ruleId": x.rule_id, "ruleIndex": index[x.rule_id],
            "level": SARIF_LEVEL[x.severity] if x.counts else "note",
            "message": {"text": clean(f"{x.title}. {x.fix}".strip())},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(x.file or anchor, prefix)},
                                                "region": region}}],
            "partialFingerprints": {"primaryLocationLineHash": fp},
            "properties": {"security-severity": str(sev_score), "context": x.context, "counted": x.counts,
                           "project-wide": not x.file},
        })
    gaps = list(result.gaps or [])
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "hardn", "version": __version__, "semanticVersion": __version__,
                                "informationUri": REPO_URL, "rules": rules}},
            "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": [
                {"level": "warning", "message": {"text": f"Blind spot: {gap_text(g)}"}} for g in gaps]}],
            "results": results,
            "properties": {"complete": not gaps},
        }],
    }


def write_sarif(result, path: str, prefix: str = "") -> str:
    text = json.dumps(sarif_doc(result, prefix), indent=2)
    return write_file(os.path.dirname(path) or ".", os.path.basename(path), text + "\n")
