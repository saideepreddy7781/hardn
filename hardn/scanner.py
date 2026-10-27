from __future__ import annotations

import os
import time

from . import code_rules, deps, engines, posture, secrets, taint_js, taint_py, walker
from . import stack as stack_mod
from .models import SEV_RANK, ScanResult


def run(root: str, external: bool = True, log=lambda *_: None) -> ScanResult:
    t0 = time.time()
    root = os.path.abspath(root)
    files, all_paths = walker.walk(root)
    stack = stack_mod.detect(root, files, all_paths)

    findings = secrets.scan(files, root) + code_rules.scan(files)
    findings += taint_py.scan(files) + taint_js.scan(files)
    findings += posture.check(root, files, all_paths, stack)
    dep_findings, dep_note = deps.scan(root, all_paths)
    findings += dep_findings
    statuses = {"built-in": f"ok ({len(code_rules.RULES)} rules + taint)", "osv": dep_note}
    if external:
        ext, ext_status = engines.run_all(root, stack, log)
        findings += ext
        statuses.update(ext_status)

    findings = dedupe(findings)
    for f in findings:
        if f.category != "dependency":
            f.snippet = secrets.redact_text(f.snippet)
    findings.sort(key=lambda f: (-f.rank, f.category != "secret", f.file, f.line, f.rule_id))
    return ScanResult(root=root, stack=stack, findings=findings, engines=statuses,
                      files_scanned=len(files), duration=time.time() - t0)


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
