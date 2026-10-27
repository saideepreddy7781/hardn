"""`hardn fix`: scan → hand the prompt to a coding agent → re-scan, until the target level is reached.

Safety model: runs only inside a git repo, on a clean tree, on a new branch (by default), and asks
for confirmation before letting an agent edit files. Nothing is committed — you review `git diff`.
"""
from __future__ import annotations

import datetime
import os
import shlex
import shutil
import subprocess
import sys

from . import output, prompt, scanner
from .scoring import LEVELS, level, min_rank_for

AGENTS = {
    # prompt is sent on stdin unless the command contains {prompt_file}
    "claude": ["claude", "-p", "--permission-mode", "acceptEdits"],
    "aider": ["aider", "--yes-always", "--no-auto-commits", "--no-check-update", "--message-file", "{prompt_file}"],
    "codex": ["codex", "exec", "--full-auto", "-"],
}
FIX_PREAMBLE = (
    "> You are running non-interactively inside `hardn fix`. Edit the files directly; do not ask questions. "
    "Do not commit, push, or rewrite git history. You don't need to run `hardn` or the test suite yourself: "
    "hardn re-scans after you finish and runs the project's tests if configured. When finished, print the "
    "report table described at the end.\n\n"
)


class FixError(Exception):
    pass


def resolve_agent(spec) -> list:
    if isinstance(spec, (list, tuple)):
        return list(spec)
    if spec:
        if spec in AGENTS:
            return AGENTS[spec]
        return shlex.split(spec, posix=os.name != "nt")
    for name in ("claude", "aider", "codex"):
        if shutil.which(name):
            return AGENTS[name]
    raise FixError("no coding agent found. Install Claude Code (`claude`), aider, or Codex — or pass "
                   "--agent \"your-command {prompt_file}\".")


def _git(root, *args, check=True) -> str:
    proc = subprocess.run(["git", "-C", root, *args], capture_output=True, check=False, text=True, encoding="utf-8",
                          errors="replace")
    if check and proc.returncode != 0:
        raise FixError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def _in_scope(findings, target) -> int:
    return sum(1 for f in findings if f.rank >= min_rank_for(target))


def run(root: str, agent=None, target: int | None = None, max_rounds: int = 3, test_cmd: str | None = None,
        external: bool = True, yes: bool = False, branch: bool = True, allow_dirty: bool = False,
        max_tasks: int = 15, timeout: int = 1800) -> int:
    root = os.path.abspath(root)
    say = print
    if _git(root, "rev-parse", "--is-inside-work-tree", check=False).strip() != "true":
        raise FixError("`hardn fix` needs a git repository so every change is reviewable and revertible "
                       "(run `git init && git add -A && git commit -m init` first).")
    if not allow_dirty and _git(root, "status", "--porcelain").strip():
        raise FixError("working tree has uncommitted changes. Commit or stash them first so the agent's "
                       "changes are isolated (or pass --allow-dirty).")
    cmd = resolve_agent(agent)
    if not shutil.which(cmd[0]) and not os.path.isfile(cmd[0]):
        raise FixError(f"agent command not found: {cmd[0]}")

    result = scanner.run(root, external=external)
    start_findings = result.findings
    start_level = level(start_findings)
    _, target, n_tasks = prompt.build(result, target=target, max_tasks=max_tasks)
    start_count = _in_scope(start_findings, target)
    say(f"\n  {output.c('hardn fix', '1')} · L{start_level} {LEVELS[start_level]} → goal "
        f"{output.c(f'L{target} {LEVELS[target]}', '1')} · {start_count} in-scope finding(s) · agent: {cmd[0]}")
    if start_count == 0:
        say(output.c(f"  Already at L{target} {LEVELS[target]} — nothing to fix.\n", "32"))
        return 0

    if not yes:
        if not sys.stdin.isatty():
            raise FixError("refusing to let an agent edit files without confirmation; pass --yes in non-interactive use.")
        answer = input(f"  Let `{' '.join(cmd)}` edit files in {output.rel(root)}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            say("  Aborted.")
            return 1

    if branch:
        name = "hardn/fix-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        _git(root, "switch", "-c", name)
        say(f"  Working on new branch {output.c(name, '36')}")

    out_dir = os.path.join(root, ".hardn")
    output.ensure_out_dir(out_dir)
    prompt_file = os.path.join(out_dir, "FIX_PROMPT.md")
    prev_count, note, tests_ok = start_count, "", True
    for rnd in range(1, max_rounds + 1):
        text, _, n_tasks = prompt.build(result, target=target, max_tasks=max_tasks)
        if note:
            text += "\n## Previous round\n\n" + note + "\n"
        with open(prompt_file, "w", encoding="utf-8") as fh:
            fh.write(FIX_PREAMBLE + text)
        say(f"\n  {output.c(f'Round {rnd}/{max_rounds}', '1;36')} · {n_tasks} task(s) → {cmd[0]}\n")
        rc = _run_agent(cmd, FIX_PREAMBLE + text, prompt_file, root, timeout)
        if rc != 0:
            say(output.c(f"  Agent exited with code {rc}; stopping.", "31"))
            break

        tests_ok, note = True, ""
        if test_cmd:
            say(f"  Running tests: {test_cmd}")
            proc = subprocess.run(test_cmd, shell=True, cwd=root, capture_output=True, check=False, text=True,  # hardn:ignore — the user's own --test command; shell syntax (&&, |) is intended
                                  encoding="utf-8", errors="replace")
            tests_ok = proc.returncode == 0
            if not tests_ok:
                tail = (proc.stdout + proc.stderr)[-3000:]
                note = f"Your previous changes broke the test command `{test_cmd}`. Fix that first:\n\n```\n{tail}\n```"
                say(output.c("  Tests failed — feeding the failure into the next round.", "33"))

        result = scanner.run(root, external=external)
        count = _in_scope(result.findings, target)
        say(f"  In-scope findings: {prev_count} → {output.c(str(count), '1')}")
        if count == 0 and tests_ok:
            break
        if count >= prev_count and tests_ok:
            say(output.c("  No progress this round; stopping so you can take a look.", "33"))
            break
        prev_count = count

    end_level = level(result.findings)
    reached = _in_scope(result.findings, target) == 0 and tests_ok
    stat = "\n".join(_git(root, "status", "--short", check=False).strip().splitlines()[:40])
    say("")
    say(f"  {output.c('Result', '1')}   L{start_level} {LEVELS[start_level]} → "
        f"{output.c(f'L{end_level} {LEVELS[end_level]}', '1;32' if reached else '1;33')}   "
        f"({len(start_findings)} → {len(result.findings)} findings)")
    if stat:
        say("\n" + "\n".join("    " + ln for ln in stat.splitlines()))
    say("\n  Next: review with `git diff`, run your app/tests, then commit.")
    say("  Undo everything: `git checkout -- . && git clean -fd" + (" && git switch -`" if branch else "`"))
    say("  Open items and human-only steps (credential rotation) are in .hardn/FIX_PROMPT.md\n")
    return 0 if reached else 1


def _run_agent(cmd: list, text: str, prompt_file: str, root: str, timeout: int) -> int:
    uses_file = any("{prompt_file}" in part for part in cmd)
    argv = [part.replace("{prompt_file}", prompt_file) for part in cmd]
    try:
        proc = subprocess.run(argv, cwd=root, check=False, input=None if uses_file else text, text=True,
                              encoding="utf-8", timeout=timeout)
    except subprocess.TimeoutExpired:
        print(output.c(f"  Agent timed out after {timeout}s.", "31"))
        return 124
    except OSError as exc:
        raise FixError(f"could not start agent: {exc}") from exc
    return proc.returncode
