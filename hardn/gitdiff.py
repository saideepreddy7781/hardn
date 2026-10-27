"""`--diff`: restrict results to lines changed relative to a git ref (plus untracked files)."""
from __future__ import annotations

import re
import subprocess


class DiffError(Exception):
    pass


def _git(root: str, *args) -> str:
    try:
        proc = subprocess.run(["git", "-C", root, *args], capture_output=True, check=False, text=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiffError(f"git failed: {exc}") from exc
    if proc.returncode != 0:
        raise DiffError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def changed_lines(root: str, ref: str) -> dict:
    """{relative path: set of changed line numbers, or None meaning 'whole file is new'}."""
    _git(root, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    changed = {}
    current = None
    for line in _git(root, "diff", "--relative", "--no-color", "--no-ext-diff", "-U0", ref, "--", ".").splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip().strip('"')  # git quotes paths with spaces/unicode
            current = None if path == "/dev/null" else re.sub(r"^b/", "", path)
            if current is not None:
                changed.setdefault(current, set())
        elif line.startswith("@@") and current is not None:
            m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                changed[current].update(range(start, start + count))
    for path in _git(root, "ls-files", "--others", "--exclude-standard").splitlines():
        changed[path] = None
    return changed


def keep(findings: list, changed: dict) -> list:
    out = []
    for f in findings:
        if f.file not in changed:
            continue
        lines = changed[f.file]
        if lines is None or not f.line or f.line in lines:
            out.append(f)
    return out
