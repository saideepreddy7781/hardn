"""Run git against a repository we do not trust.

A cloned repo cannot ship its own .git/config, but a repo handed to you as a directory (a zip, a shared
folder, a container volume) can, and git runs programs named in that file: core.fsmonitor on `git status`,
filter.*.clean on `git diff`, hooks on `git switch`. A scanner must not execute the code it is scanning, so
every git call in agentharden goes through run(), which blanks those settings on the command line. Command-line
config outranks every config file, and git treats an empty value as "no program".
"""
from __future__ import annotations

import os
import re
import subprocess

_RUNS_A_PROGRAM = re.compile(
    r"^(core\.(fsmonitor|sshcommand|pager|editor|gitproxy|askpass|alternaterefscommand)"
    r"|filter\..+\.(clean|smudge|process)"
    r"|merge\..+\.driver|mergetool\..+\.cmd|difftool\..+\.cmd"
    r"|gpg\.program|gpg\..+\.program"
    r"|sequence\.editor|interactive\.difffilter|uploadpack\.packobjectshook"
    r"|pager\..+|alias\..+)$",
    re.IGNORECASE,
)
_ENV_DROP = ("GIT_EXTERNAL_DIFF", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PAGER", "GIT_EDITOR", "GIT_ASKPASS")


class UnsafeRepo(OSError):
    """The repo's git config cannot be neutralised, so git must not be run on it."""


def _env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in _ENV_DROP}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def overrides(root: str, timeout: int = 10) -> list:
    """The `-c key=` arguments that switch off every program named in this repo's effective git config."""
    args = ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}", "-c", "core.pager=cat"]
    proc = subprocess.run(["git", "-C", root, "config", "--name-only", "--null", "--list"], capture_output=True,
                          check=False, timeout=timeout, env=_env(), stdin=subprocess.DEVNULL)
    if proc.returncode != 0:
        return args  # not a repo, or git refused it: the real command will fail the same way
    seen = set()
    for raw in proc.stdout.split(b"\0"):
        key = raw.decode("utf-8", "replace").strip()
        if not key or key in seen or key.lower() in ("core.fsmonitor", "core.pager") or not _RUNS_A_PROGRAM.match(key):
            continue
        seen.add(key)
        if "=" in key:  # `-c` splits on the first "=", so this name would dodge the override
            raise UnsafeRepo(f"refusing to run git: unusual program setting in git config ({key!r})")
        args += ["-c", f"{key}="]
    return args


def run(root: str, *args, timeout: int = 60, text: bool = True) -> subprocess.CompletedProcess:
    """`git -C root <args>` with repo-defined programs disabled. Raises OSError/TimeoutExpired like subprocess."""
    if args and args[0] == "diff":  # git fails on a blank diff driver, so these are switched off by flag instead
        args = (args[0], "--no-ext-diff", "--no-textconv", *args[1:])
    cmd = ["git", *overrides(root), "-C", root, *args]
    if text:
        return subprocess.run(cmd, capture_output=True, check=False, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, env=_env(), stdin=subprocess.DEVNULL)
    return subprocess.run(cmd, capture_output=True, check=False, timeout=timeout, env=_env(), stdin=subprocess.DEVNULL)
