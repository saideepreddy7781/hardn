"""Turn scan results into a prompt an AI coding agent can execute safely.

Design goals:
- Scoped: one level-up at a time, so the agent produces a reviewable diff, not a rewrite.
- Grounded: exact file:line evidence, CWE, and a concrete fix strategy per task.
- Safe: secrets are redacted; irreversible steps (rotation, history rewrite) go to a human.
- Verifiable: every task has a "done when" check and the prompt ends with a re-scan.
"""
from __future__ import annotations

import os
from collections import OrderedDict

from . import __version__
from .models import SEVERITIES
from .scoring import LEVELS, grade, level, min_rank_for, score

FENCE = {
    ".py": "python", ".js": "js", ".jsx": "jsx", ".ts": "ts", ".tsx": "tsx", ".go": "go", ".java": "java",
    ".kt": "kotlin", ".rb": "ruby", ".php": "php", ".yml": "yaml", ".yaml": "yaml", ".tf": "hcl",
    ".json": "json", ".sh": "bash", ".html": "html",
}
DONE_WHEN = {
    "secret": "the literal is gone from the source, the code reads it from configuration (env var / secret manager), "
              "and `.env.example` documents the variable with a placeholder.",
    "code": "every listed location is fixed at the root cause (parameterized / validated / encoded / allowlisted — not "
            "just reformatted), and a test exercises a malicious input where a test suite exists.",
    "dependency": "the lockfile resolves the package to the fixed version or later and the test suite passes.",
    "config": "the configuration is corrected at every listed location.",
    "posture": "the control is in place, wired into the app's startup path, and covered by at least a smoke test.",
}


def group_tasks(findings: list) -> list:
    """One task per rule (dependency findings stay per package) so fixes land as coherent changes."""
    groups = OrderedDict()
    for f in findings:
        key = (f.rule_id, f.extra.get("package")) if f.category == "dependency" else (f.rule_id, f.title if f.category == "posture" else "")
        groups.setdefault(key, []).append(f)
    tasks = list(groups.values())
    tasks.sort(key=lambda g: (-max(f.rank for f in g), g[0].category != "secret", g[0].file))
    return tasks


def build(result, target: int | None = None, max_tasks: int = 30) -> tuple:
    """Return (markdown prompt, target level, task count)."""
    findings = result.findings
    current = level(findings)
    if target is None:
        target = max(min(current + 1, 4), 2)  # never stop short of 'no criticals or highs'
    threshold = min_rank_for(target)
    in_scope = [f for f in findings if f.rank >= threshold]
    later = [f for f in findings if f.rank < threshold and f.severity != "info"]
    tasks = group_tasks(in_scope)
    shown, deferred = tasks[:max_tasks], tasks[max_tasks:]
    s = score(findings)
    stack = result.stack
    sevs = [SEVERITIES[i] for i in range(4, threshold - 1, -1)]
    must_fix = ", ".join(sevs[:-1]) + " and " + sevs[-1] if len(sevs) > 1 else sevs[0]

    L = []
    w = L.append
    w("# Security remediation task\n")
    w("You are a senior application security engineer working in this repository. An offline static analysis "
      f"(hardn {__version__}) produced the findings below. Fix them in order, verifying each one, and do not "
      "stop at the first task.\n")
    w("## Context\n")
    if stack.get("languages"):
        w(f"- **Languages:** {', '.join(stack['languages'][:6])}")
    if stack.get("frameworks"):
        w(f"- **Frameworks:** {', '.join(stack['frameworks'])}")
    w(f"- **Current level:** L{current} {LEVELS[current]} — score {s}/100 ({grade(s)})")
    if current >= target:
        w(f"- **Goal:** already at L{target} {LEVELS[target]}; tasks below are optional polish.")
    else:
        w(f"- **Goal of this prompt:** reach **L{target} {LEVELS[target]}** by resolving every {must_fix} finding "
          f"({len(tasks)} task{'s' if len(tasks) != 1 else ''}).")
    w("- Paths are relative to the repository root.\n")

    w("## Ground rules\n")
    w("1. Fix root causes, not symptoms. Do not silence findings with `hardn:ignore` / `nosec` unless you have verified "
      "a false positive — then add the comment with a one-line justification and report it.")
    w("2. Keep each change minimal and scoped to its task. Preserve behavior and public interfaces; no drive-by refactors.")
    w("3. Prefer the framework's built-in security features. Add a dependency only when a task calls for one; pin it "
      "and update the lockfile.")
    w("4. Never print, log, or re-commit secret values. Snippets below are intentionally redacted.")
    w("5. Where the project has tests, add or update a test for each code-level fix (include a malicious input case).")
    w("6. Do not attempt irreversible or out-of-repo actions (credential rotation, git history rewrites, cloud console "
      "changes). List them under **Needs human action** in your final report.\n")

    w("## Tasks\n")
    if not shown:
        w("_No findings in scope for this level._\n")
    for n, group in enumerate(shown, 1):
        f0 = group[0]
        sev = max((f.severity for f in group), key=SEVERITIES.index)
        where = f0.location() if len(group) == 1 else f"{len(group)} locations"
        w(f"### T{n} · {sev.upper()} · {f0.title} — {where}\n")
        meta = [f"rule `{f0.rule_id}`", f0.category]
        if f0.cwe:
            meta.append(f0.cwe)
        srcs = sorted({s for f in group for s in f.sources})
        if srcs != ["hardn"]:
            meta.append("found by " + ", ".join(srcs))
        if any(f.extra.get("kev") for f in group):
            meta.append("**CISA KEV: actively exploited in the wild**")
        w("- " + " · ".join(meta))
        w("- **Evidence:**")
        for f in group[:12]:
            if f.snippet:
                lang = FENCE.get(os.path.splitext(f.file)[1].lower(), "")
                w(f"  - `{f.location()}`")
                w(f"    ```{lang}\n    {f.snippet}\n    ```")
            else:
                w(f"  - `{f.location()}`")
            if f.extra.get("flow"):
                w(f"    - data flow: {f.extra['flow']}")
        if len(group) > 12:
            w(f"  - …and {len(group) - 12} more locations of the same pattern (search the codebase for them).")
        if f0.fix:
            w(f"- **Fix:** {f0.fix}")
        w(f"- **Done when:** {f0.extra.get('done') or DONE_WHEN.get(f0.category, DONE_WHEN['code'])}\n")

    if deferred:
        w(f"_{len(deferred)} more tasks in scope were omitted to keep this prompt focused. Re-run `hardn scan` after "
          "this batch to get them._\n")

    human = [g for g in shown if g[0].category == "secret"]
    w("## Needs human action\n")
    if human:
        ids = ", ".join(f"T{shown.index(g) + 1}" for g in human)
        w(f"- Rotate/revoke every credential in {ids}. Removing a secret from code does not invalidate it.")
        w("- If those files were ever committed, purge them from history (`git filter-repo`) and force-push, "
          "coordinating with the team.")
    w("- Add anything else you could not safely complete here.\n")

    w("## Verify and report\n")
    w("1. Run the project's build, linter, and tests; fix anything you broke.")
    fail_on = SEVERITIES[threshold]
    w(f"2. Re-scan: `hardn scan . --fail-on {fail_on}` must exit 0 (in-scope findings resolved).")
    w("3. Finish with a table: `Task | Status (fixed / false positive / needs human) | Files changed | Notes`.\n")

    if later and current < 4:
        counts = {sv: sum(1 for f in later if f.severity == sv) for sv in ("medium", "low")}
        parts = [f"{c} {sv}" for sv, c in counts.items() if c]
        nxt = min(target + 1, 4)
        w("## Out of scope for now\n")
        w(f"{', '.join(parts)} finding(s) remain for later levels. Don't work on them in this pass; run "
          f"`hardn scan --target {LEVELS[nxt].lower()}` afterwards.\n")
    return "\n".join(L), target, len(tasks)
