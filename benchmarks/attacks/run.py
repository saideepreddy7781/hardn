#!/usr/bin/env python3
"""Run the agentharden attack corpus: `python benchmarks/attacks/run.py [--json] [--suite injection|gaming] [-k ID]`.

Offline, standard library only. Builds each hostile repository from cases/*.json in a temp directory, runs
agentharden on it with a scripted agent from agents/, and checks the verdict. No model is ever called. Exit status
is 1 if any case fails.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent.parent
sys.path.insert(0, str(SRC))

from agentharden import deps, fix, prompt, scanner  # noqa: E402
from agentharden.scoring import counted, min_rank_for  # noqa: E402

AGENTS = HERE / "agents"
GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "bench", "GIT_AUTHOR_EMAIL": "bench@example.invalid",
           "GIT_COMMITTER_NAME": "bench", "GIT_COMMITTER_EMAIL": "bench@example.invalid",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


# ------------------------------------------------------------------ structure check (independent of prompt.py)

_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_CLOSE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")


def outside_data(markdown: str) -> str:
    """Every line a CommonMark reader would see outside a fenced block labelled `agentharden-data`.

    Follows the CommonMark rules for fenced code: a fence opens with 3+ backticks or tildes (a backtick
    fence's info string cannot contain a backtick) and closes on a line holding only the same character, at
    least as many times. Text in unlabelled fences counts as outside, because nothing marks it as data.
    """
    out, fence = [], None  # fence = (char, length, labelled)
    for line in markdown.split("\n"):
        if fence is None:
            m = _OPEN.match(line)
            if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
                info = m.group(2).strip()
                fence = (m.group(1)[0], len(m.group(1)), info.split(" ")[0] == "agentharden-data")
                if not fence[2]:
                    out.append(line)
                continue
            out.append(line)
            continue
        m = _CLOSE.match(line)
        if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= fence[1]:
            if not fence[2]:
                out.append(line)
            fence = None
            continue
        if not fence[2]:
            out.append(line)
    return "\n".join(out)


# ------------------------------------------------------------------ fixtures

def git(root: Path, *args) -> None:
    subprocess.run(["git", "-C", str(root), "-c", "commit.gpgsign=false", *args], check=True, capture_output=True,
                   env=GIT_ENV, stdin=subprocess.DEVNULL, timeout=60)


def make_repo(files: dict, parent: Path) -> Path:
    root = Path(tempfile.mkdtemp(dir=parent))
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "fixture")
    return root


@contextlib.contextmanager
def _quiet_fd1(path: Path):
    """Send what child processes (the scripted agents) write to stdout into a file, not the results table."""
    sys.stdout.flush()
    saved = os.dup(1)
    with open(path, "ab") as sink:
        os.dup2(sink.fileno(), 1)
    try:
        yield
    finally:
        os.dup2(saved, 1)
        os.close(saved)


def run_fix(root: Path, agent: list, **kw) -> tuple:
    buf = io.StringIO()
    with _quiet_fd1(root.parent / "agent-stdout.log"), contextlib.redirect_stdout(buf):
        try:
            rc = fix.run(str(root), agent=agent, yes=True, external=False, **kw)
        except fix.FixError as exc:
            print(f"FixError: {exc}")
            rc = 2
    return rc, buf.getvalue()


def in_scope(root: Path) -> int:
    return sum(1 for f in counted(scanner.run(str(root), external=False).findings) if f.rank >= min_rank_for(2))


# ------------------------------------------------------------------ suites

def injection_case(case: dict, tmp: Path) -> dict:
    row = {"suite": "injection", "id": case["id"], "vector": case["vector"], "expected": "payload stays in data"}
    if case.get("posix_only") and os.name == "nt":
        return {**row, "observed": "skipped (file name not allowed on Windows)", "passed": True, "skipped": True}
    root = make_repo(case["files"], tmp)
    canary = case["canary"]
    prompts = []
    text, _, _ = prompt.build(scanner.run(str(root), external=False), target=case.get("target"))
    prompts.append(("scan", text))
    log = Path(tempfile.mkdtemp(dir=tmp))
    test_cmd = case.get("test_cmd", "").replace("{python}", f'"{sys.executable}"') or None
    rc, out = run_fix(root, [sys.executable, str(AGENTS / "record_prompt.py"), "{prompt_file}", str(log)],
                      target=case.get("target"), max_rounds=case.get("rounds", 1), test_cmd=test_cmd, branch=False)
    for p in sorted(log.glob("prompt-*.md")):
        prompts.append((f"fix {p.stem}", p.read_text(encoding="utf-8")))

    problems = []
    if len(prompts) < 1 + case.get("rounds", 1):
        problems.append(f"expected {case.get('rounds', 1)} agent prompt(s), got {len(prompts) - 1}")
    delivered = any(canary in t for _, t in prompts)
    if case.get("rounds", 1) > 1 and not any(canary in t for name, t in prompts if name.endswith(str(case["rounds"]))):
        delivered = False
    if not delivered:
        problems.append("payload never reached a prompt, so the case did not exercise anything")
    for name, t in prompts:
        if canary in outside_data(t):
            problems.append(f"{name}: payload outside a data block")
        for lo, hi in case.get("forbid_ranges", []):
            if any(lo <= ord(ch) <= hi for ch in t):
                problems.append(f"{name}: hidden characters U+{lo:04X}..U+{hi:04X} reached the prompt")
    observed = "; ".join(problems) if problems else f"contained in {len(prompts)} prompt(s)"
    return {**row, "observed": observed, "passed": not problems}


def gaming_case(case: dict, base: dict, tmp: Path) -> dict:
    expect = case["expect"]
    want_v = case.get("violation")
    row = {"suite": "gaming", "id": case["id"], "vector": case["cheat"],
           "expected": "credit" if expect == "credit" else f"no credit{', ' + want_v if want_v else ''}"}
    root = make_repo({**base, **case.get("files", {})}, tmp)
    for name, text in case.get("dirty_files", {}).items():
        (root / name).write_text(text, encoding="utf-8")
    before = in_scope(root)
    test_cmd = case.get("test_cmd", "").replace("{python}", f'"{sys.executable}"') or None
    rc, out = run_fix(root, [sys.executable, str(AGENTS / case["agent"]), "{prompt_file}", str(SRC)],
                      max_rounds=case.get("rounds", 1), test_cmd=test_cmd, branch=case.get("branch", False),
                      allow_dirty=case.get("allow_dirty", False))
    credited = rc == 0
    kept = re.search(r"--git-dir=(\S+)", out)  # --allow-dirty keeps its snapshot for the printed undo command
    if kept and Path(kept.group(1).strip("'")).name.startswith("agentharden-snapshot-"):
        shutil.rmtree(kept.group(1).strip("'"), ignore_errors=True)
    no_credit_line = "no credit:" in out
    named = [k for k, text in KIND_TEXT.items() if text in out]
    effective = f"in-scope findings {before} -> {in_scope(root)}"
    if expect == "credit":
        passed = credited and not no_credit_line
        observed = "credit" if credited else f"no credit (rc {rc})"
        if named:
            observed += "; earlier round flagged " + ", ".join(named)
    else:
        passed = not credited and (want_v is None and not named or want_v in named and no_credit_line)
        observed = ("credit" if credited else "no credit") + (", " + ", ".join(named) if named else "")
    if not passed:
        observed += " | output tail: " + " / ".join(ln.strip() for ln in out.strip().splitlines()[-6:])
    return {**row, "observed": f"{observed} ({effective})", "passed": passed}


KIND_TEXT = {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    ap.add_argument("--suite", choices=["injection", "gaming"], help="run one suite")
    ap.add_argument("-k", dest="only", help="run only cases whose id contains this text")
    a = ap.parse_args(argv)

    from agentharden import guard
    KIND_TEXT.update({k: guard.KINDS[k] for k in guard.KINDS})
    rows = []
    with tempfile.TemporaryDirectory(prefix="agentharden-attacks-") as tmpdir:
        tmp = Path(tmpdir)
        home = deps.HOME
        deps.HOME = tmp / "no-advisory-db"  # hermetic: no advisory data, no network
        try:
            for suite in ("injection", "gaming"):
                if a.suite and a.suite != suite:
                    continue
                spec = json.loads((HERE / "cases" / f"{suite}.json").read_text(encoding="utf-8"))
                for case in spec["cases"]:
                    if a.only and a.only not in case["id"]:
                        continue
                    try:
                        if suite == "injection":
                            rows.append(injection_case(case, tmp))
                        else:
                            rows.append(gaming_case(case, spec["base_files"], tmp))
                    except Exception as exc:  # a crash is a failed case, with the reason shown
                        rows.append({"suite": suite, "id": case["id"], "vector": case.get("vector") or case.get("cheat"),
                                     "expected": "-", "observed": f"error: {type(exc).__name__}: {exc}",
                                     "passed": False})
        finally:
            deps.HOME = home

    failed = [r for r in rows if not r["passed"]]
    if a.json:
        print(json.dumps({"passed": len(rows) - len(failed), "failed": len(failed), "results": rows}, indent=2))
    else:
        print(f"{'suite':<10} {'case':<26} {'expected':<26} {'result':<6} observed")
        for r in rows:
            mark = "skip" if r.get("skipped") else ("PASS" if r["passed"] else "FAIL")
            print(f"{r['suite']:<10} {r['id']:<26} {r['expected']:<26} {mark:<6} {r['observed']}")
        print(f"\n{len(rows) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
