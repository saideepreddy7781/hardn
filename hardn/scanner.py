from __future__ import annotations

import os
import re
import time

from . import code_rules, context, deps, engines, posture, secrets, taint_js, taint_py, walker
from . import stack as stack_mod
from .models import SEV_RANK, ScanResult

# Comments that switch a finding off. code_rules owns the list for code; secrets also honours gitleaks:allow.
_SUPPRESS = re.compile("|".join(p for p in (
    getattr(getattr(code_rules, "SUPPRESS", None), "pattern", ""), r"hardn:ignore", r"gitleaks:allow") if p))
# Config files a repo can ship to quieten an external engine. hardn cannot override them yet.
ENGINE_CONFIGS = {".gitleaks.toml": "gitleaks", ".gitleaksignore": "gitleaks", ".bandit": "bandit",
                  ".semgrepignore": "semgrep", ".trivyignore": "trivy", "trivy.yaml": "trivy"}


def _neutralize(f) -> walker.SourceFile:
    """The same file with every suppression comment blanked out, line lengths unchanged."""
    return walker.SourceFile(f.path, _SUPPRESS.sub(lambda m: "_" * len(m.group(0)), f.text))


def _builtin(files: list, root: str, all_paths: list, stack: dict, gaps: list, log) -> list:
    checks = (
        ("secrets", lambda: secrets.scan(files, root)),
        ("code rules", lambda: code_rules.scan(files)),
        ("Python taint", lambda: taint_py.scan(files)),
        ("JavaScript taint", lambda: taint_js.scan(files)),
        ("posture", lambda: posture.check(root, files, all_paths, stack)),
    )
    out = []
    for name, fn in checks:
        log(f"{name}…")
        try:
            out += fn()
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others' results
            gaps.append(f"the {name} check stopped with {type(exc).__name__}; its findings are missing")
    return out


def _inline_hidden(files: list, root: str) -> int:
    """How many findings inline comments suppressed: rescan the files that contain a marker, with and without."""
    marked = [f for f in files if _SUPPRESS.search(f.text)]
    if not marked:
        return 0

    def keys(batch):
        return {(f.rule_id, f.file, f.line) for f in secrets.scan(batch, root) + code_rules.scan(batch)}

    try:
        return len(keys([_neutralize(f) for f in marked]) - keys(marked))
    except Exception:  # noqa: BLE001 - counting is best effort; the scan itself already ran
        return 0


def run(root: str, external: bool = True, log=lambda *_: None, untrusted: bool = False) -> ScanResult:
    """Scan root. untrusted=True ignores .hardnignore and inline suppressions and counts every finding."""
    t0 = time.time()
    root = os.path.abspath(root)
    walk = walker.WalkReport()
    log("reading files…")
    files, all_paths = walker.walk(root, ignore=not untrusted, report=walk)
    gaps = []
    marked = 0
    if untrusted:
        marked = sum(1 for f in files if _SUPPRESS.search(f.text))
        files = [_neutralize(f) if _SUPPRESS.search(f.text) else f for f in files]
    stack = stack_mod.detect(root, files, all_paths)

    findings = _builtin(files, root, all_paths, stack, gaps, log)
    log("dependencies…")
    try:
        dep_findings, dep_note, *dep_gaps = deps.scan(root, all_paths)
        findings += dep_findings
        dep_gaps = list(dep_gaps[0]) if dep_gaps else []
        gaps += dep_gaps
        if dep_gaps:
            dep_note += " (incomplete: see blind spots)"
    except Exception as exc:  # noqa: BLE001
        dep_note = f"error: {type(exc).__name__}"
        gaps.append(f"the dependency check stopped with {type(exc).__name__}; vulnerable packages are not reported")
    statuses = {"built-in": f"ok ({len(code_rules.RULES)} rules + taint)", "osv": dep_note}
    if external:
        ext, ext_status = engines.run_all(root, stack, log)
        findings += ext
        statuses.update(ext_status)
        for name, st in ext_status.items():
            if str(st).startswith("error"):
                gaps.append(f"{name} was installed but failed ({st})")
        if untrusted:
            shipped = sorted({tool for name, tool in ENGINE_CONFIGS.items() if name in all_paths})
            if shipped:
                gaps.append(f"the repo ships config for {', '.join(shipped)}, which can switch off that engine's "
                            "checks; hardn cannot override it")
            if marked:
                gaps.append(f"external engines still honour inline suppression comments ({marked} files have them)")
    if walk.count("unreadable"):
        gaps.append(f"{walk.count('unreadable')} file(s) or folder(s) could not be read (see skipped.unreadable)")

    findings = dedupe(findings)
    by_path = {f.path: f for f in files}
    for f in findings:
        if f.category != "dependency":
            f.snippet = secrets.redact_text(f.snippet)
        if f.category == "secret" and f.line and f.file in by_path:
            lines = by_path[f.file].lines
            if f.line <= len(lines):
                f._secret_line = lines[f.line - 1]  # in memory only: baseline.py stores a salted HMAC of it
        if untrusted:
            f.context = context.APP
        elif f.context == "app":  # the dependency engine may already have set dev-dependency
            # Manifests (requirements.txt, package.json) take their context from their folder, never their suffix.
            path = f.file if f.category not in ("dependency", "posture") else os.path.dirname(f.file) + "/_"
            f.context = context.classify(path.lstrip("/"))
    findings.sort(key=lambda f: (not f.counts, -f.rank, f.category != "secret", f.file, f.line, f.rule_id))
    hidden = {"inline": 0, "hardnignore": 0} if untrusted else {
        "inline": _inline_hidden(files, root), "hardnignore": walk.ignored}
    result = ScanResult(root=root, stack=stack, findings=findings, engines=statuses, files_scanned=len(files),
                        duration=time.time() - t0, gaps=gaps, hidden=hidden)
    result.skipped = walk.to_dict()
    result.untrusted = untrusted
    return result


def _key(f) -> tuple:
    if f.category == "secret" and f.line:
        return ("secret", f.file, f.line)
    if f.category == "code" and f.line:
        # Same weakness on the same line from several engines (line rule, taint, semgrep, bandit) is one issue.
        return ("code", f.file, f.line, f.cwe or f.rule_id)
    return (f.rule_id, f.file, f.line, f.title)


def dedupe(findings: list) -> list:
    """Merge the same issue reported by several engines, keeping the richest evidence."""
    merged = {}
    for f in findings:
        key = _key(f)
        keep = merged.get(key)
        if keep is None:
            merged[key] = f
            continue
        new_has_flow, keep_has_flow = "flow" in f.extra, "flow" in keep.extra
        if (new_has_flow and not keep_has_flow) or ("hardn" in f.sources and "hardn" not in keep.sources):
            # Prefer built-in guidance (and redaction), and a taint trace over a bare pattern match.
            keep.rule_id, keep.title, keep.cwe, keep.snippet = f.rule_id, f.title, f.cwe or keep.cwe, f.snippet
            keep.fix = f.fix or keep.fix
            keep.extra.update(f.extra)
        if SEV_RANK[f.severity] > SEV_RANK[keep.severity]:
            keep.severity = f.severity
        keep.sources += [s for s in f.sources if s not in keep.sources]
    return list(merged.values())
