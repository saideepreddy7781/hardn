from __future__ import annotations

import json
import os
import sys

from . import __version__
from .models import SEVERITIES
from .scoring import LEVELS, grade, level, score

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
SEV_STYLE = {"critical": "1;97;41", "high": "1;31", "medium": "33", "low": "36", "info": "2"}


def rel(path: str) -> str:
    """Path relative to cwd for display; absolute if outside cwd or on another drive (Windows)."""
    try:
        r = os.path.relpath(path)
    except ValueError:
        return path
    return path if r.startswith("..") else r


def ensure_out_dir(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    gi = os.path.join(out_dir, ".gitignore")
    if not os.path.exists(gi):
        with open(gi, "w") as fh:
            fh.write("# hardn output — keep reports out of version control\n*\n")


def c(text: str, style: str) -> str:
    return f"\033[{style}m{text}\033[0m" if _COLOR else text


def badge(sev: str) -> str:
    return c(f"{sev.upper():<8}", SEV_STYLE[sev])


def render(result, prompt_path: str, target: int, n_tasks: int, show: int = 15, verbose: bool = False,
           scope: str = "") -> str:
    f = result.findings
    cur, s = level(f), score(f)
    rel_root = rel(result.root)
    out = [""]
    out.append(f"  {c('hardn', '1')} {c(__version__, '2')} · {rel_root}")
    out.append("")
    eng = []
    for name, st in result.engines.items():
        ok = st.startswith("ok") or "packages checked" in st
        mark = c("✓", "32") if ok else c("–", "2")
        eng.append(f"{mark} {name}" + (c(f" ({st})", "2") if verbose or (not ok and name in ("built-in", "osv")) else ""))
    out.append(f"  {c('Engines', '2')}   " + "  ".join(eng))
    stack = result.stack.get("languages", [])[:4] + result.stack.get("frameworks", [])
    if stack:
        out.append(f"  {c('Stack', '2')}     " + ", ".join(stack))
    out.append(f"  {c('Scanned', '2')}   {result.files_scanned} files in {result.duration:.2f}s")
    if scope:
        out.append(f"  {c('Scope', '2')}     {scope}")
    out.append("")

    visible = [x for x in f if x.severity != "info" or verbose]
    width = max((len(x.rule_id) for x in visible[:show]), default=6)
    for x in visible[:show]:
        loc = c(x.location(), "2")
        out.append(f"  {badge(x.severity)}  {x.rule_id:<{width}}  {x.title[:58]:<58}  {loc}")
    if len(visible) > show:
        out.append(c(f"  … {len(visible) - show} more (full list: --verbose or report.json)", "2"))
    if not visible:
        out.append(c("  No issues found. 🎉", "32"))
    out.append("")

    bar = "".join(c("▰", "32") if i <= cur else c("▱", "2") for i in range(5))
    lvl_style = {0: "1;31", 1: "31", 2: "33", 3: "32", 4: "1;32"}[cur]
    out.append(f"  {c('Level', '2')}     {bar}  {c(f'L{cur} {LEVELS[cur]}', lvl_style)}   "
               f"score {s}/100 ({grade(s)})")
    counts = [f"{sum(1 for x in f if x.severity == sv)} {sv}" for sv in reversed(SEVERITIES) if any(x.severity == sv for x in f)]
    if counts:
        out.append(f"  {c('Findings', '2')}  " + " · ".join(counts))
    out.append("")
    if n_tasks:
        out.append(f"  {c('→', '1;36')} Next: {c(f'L{target} {LEVELS[target]}', '1')} — {n_tasks} task"
                   f"{'s' if n_tasks != 1 else ''} written to {c(prompt_path, '4')}")
        out.append(c(f'    claude "$(cat {prompt_path})"', "36") + c("     # or paste into Cursor / Copilot / any LLM", "2"))
    elif cur == 4:
        out.append(f"  {c('→', '1;36')} Top level reached. Keep it there: add `hardn scan . --fail-on low` to CI.")
    out.append("")
    return "\n".join(out)


def write_json(result, path: str, meta: dict | None = None) -> None:
    f = result.findings
    data = {
        "tool": "hardn", "version": __version__, "root": result.root, "stack": result.stack,
        "engines": result.engines, "level": level(f), "level_name": LEVELS[level(f)], "score": score(f),
        "grade": grade(score(f)), "scope": meta or {}, "findings": [x.to_dict() for x in f],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def write_sarif(result, path: str) -> None:
    sarif_level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, results = {}, []
    for x in result.findings:
        rules.setdefault(x.rule_id, {
            "id": x.rule_id, "shortDescription": {"text": x.title},
            "help": {"text": x.fix or x.title}, "properties": {"tags": [t for t in (x.cwe, x.category) if t]},
        })
        res = {"ruleId": x.rule_id, "level": sarif_level[x.severity], "message": {"text": f"{x.title}. {x.fix}".strip()}}
        if x.file:
            loc = {"artifactLocation": {"uri": x.file}}
            if x.line:
                loc["region"] = {"startLine": x.line}
            res["locations"] = [{"physicalLocation": loc}]
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "hardn", "version": __version__, "rules": list(rules.values())}},
                  "results": results}],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
