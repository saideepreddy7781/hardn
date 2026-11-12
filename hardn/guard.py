"""Anti-gaming check for `hardn fix`: did the agent fix the findings, or hide them?

An agent can make a re-scan come back clean without fixing anything: add `# nosec`, write `*` to
.hardnignore, delete the vulnerable file, empty the tests, or point the test command at `exit 0`. Every one
of those lowers the finding count. So before the first agent round hardn takes a snapshot of the working
tree, and after each round it reads the diff against that snapshot. A violation means the round earns no
level credit; `hardn fix` reports it, tells the next round to revert it, and exits non-zero if it remains.

The snapshot lives in a separate git directory outside the repository, with its own index, so it covers
uncommitted and untracked files (`--allow-dirty`), survives the agent committing or editing .gitignore, and
never touches the user's index, refs or objects. It borrows the repo's objects read-only via alternates.
Every git call goes through gitsafe.run.

A finding the agent believes is a false positive has one route: the agent leaves it and says so in its
report, and the user decides. There is no automatic credit for it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import tempfile
from dataclasses import dataclass, field

from . import gitsafe
from .context import classify

# Files whose only job is to make a scanner report less. Any change to one is a violation.
CONTROL_FILES = {
    ".hardnignore", ".hardn-baseline.json", ".gitleaks.toml", ".gitleaksignore", ".semgrepignore",
    ".semgrep.yml", ".semgrep.yaml", ".bandit", "bandit.yaml", "bandit.yml", ".trivyignore", ".trivyignore.yaml",
    "trivy.yaml", ".snyk", ".checkov.yml", ".checkov.yaml", ".tfsec.yml", ".kics.yml", "sonar-project.properties",
}
# Scanner suppression markers: adding one anywhere is a violation.
SCANNER_MARKERS = re.compile(
    r"hardn:ignore|\bnosec\b|\bnosemgrep\b|\bnosem\b|gitleaks:allow|trivy:ignore|tfsec:ignore|checkov:skip"
    r"|kics-scan\s+ignore|\bNOSONAR\b|lgtm\s*\[|codeql\s*\[|snyk:ignore|bandit:\s*skip|noqa:\s*S\d", re.IGNORECASE)
# General linter suppressions: a violation when added near a finding, or file-wide in a file that had one.
NEAR_MARKERS = re.compile(
    r"eslint-disable|\bnoqa\b|pylint:\s*disable|@ts-ignore|@ts-expect-error|@ts-nocheck|@SuppressWarnings"
    r"|rubocop:disable|phpcs:ignore|type:\s*ignore|\bnolint\b|#\[allow\(|biome-ignore|deno-lint-ignore", re.IGNORECASE)
FILE_WIDE = re.compile(r"eslint-disable(?!-)|@ts-nocheck|(flake8|ruff):\s*noqa|pylint:\s*(disable-all|skip-file)"
                       r"|rubocop:disable\s+all", re.IGNORECASE)
NEAR = 3
_WALK_SKIP = {".git", ".hardn", "node_modules", ".venv", "venv", "__pycache__"}
# Files that define how tests run. Any change is a violation.
TEST_CONFIG = re.compile(
    r"(^|/)(pytest\.ini|tox\.ini|noxfile\.py|\.rspec|phpunit\.xml(\.dist)?|karma\.conf\.[cm]?js"
    r"|(jest|vitest|playwright|cypress|ava)\.config\.[cm]?[jt]s|\.mocharc(\.[a-z]+)?|vitest\.workspace\.[jt]s)$")
SECTIONS = {  # file -> config sections that define the test run
    "pyproject.toml": ("tool.pytest.ini_options", "tool.pytest", "tool.tox", "tool.hatch.envs.test"),
    "setup.cfg": ("tool:pytest",),
}
MAKEFILES = ("Makefile", "makefile", "GNUmakefile")
ASSERTS = re.compile(r"\bassert|\bexpect\s*\(|\.should\b|\bt\.(Error|Fatal|Fail)|\brequire\.|\bverify\s*\(", re.IGNORECASE)
COMMENT = re.compile(r"^\s*(#|//|/\*|\*|--|<!--|;|%|')\s?")

KINDS = {  # kind -> what it means, in hardn's words (the path is shown separately, as data)
    "suppression": "a suppression comment was added",
    "control-file": "a scanner ignore, baseline or config file was changed",
    "deleted-source": "a source file that had findings was deleted, moved or replaced",
    "emptied-source": "a source file that had findings was emptied",
    "commented-out": "a line with a finding was commented out",
    "deleted-test": "a test file was deleted",
    "emptied-test": "a test file was emptied or lost all of its assertions",
    "test-command": "the definition of the test command was changed",
}


class GuardError(OSError):
    """The snapshot could not be taken or read."""


@dataclass
class Violation:
    kind: str
    path: str
    detail: str = ""

    def describe(self) -> str:
        return KINDS.get(self.kind, self.kind) + (f" ({self.detail})" if self.detail else "")


@dataclass
class Snapshot:
    root: str
    git_dir: str
    tree: str
    head: str
    control: dict
    finding_lines: dict  # path -> sorted line numbers of counted findings
    test_cmd: str | None = None
    test_files: set = field(default_factory=set)
    kept: bool = False


def _git(root, git_dir, *args, timeout=300, check=True):
    proc = gitsafe.run(root, f"--git-dir={git_dir}", f"--work-tree={root}", *args, timeout=timeout)
    if check and proc.returncode != 0:
        raise GuardError(f"snapshot: git {args[0]} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def _hash_controls(root: str) -> dict:
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _WALK_SKIP]
        for name in filenames:
            if name in CONTROL_FILES:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                try:
                    with open(full, "rb") as fh:
                        out[rel] = hashlib.sha256(fh.read(4_000_000)).hexdigest()
                except OSError:
                    out[rel] = "unreadable"
    return out


def _cmd_files(root: str, test_cmd: str | None) -> set:
    """Repo files the test command runs directly, e.g. `./run_tests.sh` or `python ci/test.py`."""
    if not test_cmd:
        return set()
    try:
        tokens = shlex.split(test_cmd)
    except ValueError:
        tokens = test_cmd.split()
    out = set()
    for tok in tokens:
        tok = tok.strip("'\"")
        if not tok or tok.startswith("-"):
            continue
        full = os.path.normpath(os.path.join(root, tok))
        if full.startswith(root + os.sep) and os.path.isfile(full):
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if classify(rel) != "test":  # a test file named on the command line may be edited; it is not the runner
                out.add(rel)
    return out


def take(root: str, findings: list, test_cmd: str | None = None) -> Snapshot:
    """Record the tree before the agent runs. `findings` are the counted findings at that point."""
    root = os.path.abspath(root)
    common = gitsafe.run(root, "rev-parse", "--git-common-dir").stdout.strip()
    if not common:
        raise GuardError("snapshot: not a git repository")
    objects = os.path.join(common if os.path.isabs(common) else os.path.join(root, common), "objects")
    git_dir = tempfile.mkdtemp(prefix="hardn-snapshot-")
    try:
        proc = gitsafe.run(root, "init", "-q", "--bare", git_dir)
        if proc.returncode != 0:
            raise GuardError(f"snapshot: git init failed: {proc.stderr.strip()[:200]}")
        with open(os.path.join(git_dir, "objects", "info", "alternates"), "w", encoding="utf-8") as fh:
            fh.write(os.path.abspath(objects) + "\n")
        _git(root, git_dir, "add", "-A", "--", ".")
        tree = _git(root, git_dir, "write-tree").strip()
    except BaseException:
        shutil.rmtree(git_dir, ignore_errors=True)
        raise
    head = gitsafe.run(root, "rev-parse", "-q", "--verify", "HEAD").stdout.strip()
    lines = {}
    for f in findings:
        if f.file and f.category != "dependency":
            lines.setdefault(f.file, set()).add(f.line or 0)
    snap = Snapshot(root=root, git_dir=git_dir, tree=tree, head=head, control=_hash_controls(root),
                    finding_lines={k: sorted(v) for k, v in lines.items()}, test_cmd=test_cmd)
    snap.test_files = _cmd_files(root, test_cmd)
    return snap


def close(snap: Snapshot | None, keep: bool = False) -> None:
    if snap is None:
        return
    snap.kept = keep
    if not keep:
        shutil.rmtree(snap.git_dir, ignore_errors=True)


def current_tree(snap: Snapshot) -> str:
    _git(snap.root, snap.git_dir, "add", "-A", "--", ".")
    return _git(snap.root, snap.git_dir, "write-tree").strip()


def _blob(snap: Snapshot, tree: str, path: str) -> str | None:
    proc = gitsafe.run(snap.root, f"--git-dir={snap.git_dir}", "cat-file", "blob", f"{tree}:{path}", timeout=60)
    return proc.stdout if proc.returncode == 0 else None


def _unquote(path: str) -> str:
    """Undo git's C-style quoting of unusual paths ("a\\tb", octal escapes for bytes)."""
    path = path.rstrip("\t")  # git ends the ---/+++ name with a tab when it contains a space
    if not (path.startswith('"') and path.endswith('"')):
        return path
    body, out, i = path[1:-1], bytearray(), 0
    simple = {"n": 10, "t": 9, '"': 34, "\\": 92, "a": 7, "b": 8, "f": 12, "r": 13, "v": 11}
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in "01234567" and i + 3 < len(body) + 1:
                out.append(int(body[i + 1:i + 4], 8) & 0xFF)
                i += 4
                continue
            out.append(simple.get(nxt, ord(nxt)))
            i += 2
            continue
        out += ch.encode("utf-8")
        i += 1
    return out.decode("utf-8", "replace")


def _parse_patch(text: str) -> dict:
    """path -> {"added": [(old_pos, line)], "removed": [(old_line, line)]} from a -U0 patch."""
    files, cur, old_pos = {}, None, 0
    minus = None
    for ln in text.split("\n"):
        if ln.startswith("diff --git "):
            cur, minus = None, None
        elif ln.startswith("--- "):
            minus = None if ln[4:] == "/dev/null" else _unquote(ln[4:])[2:]
        elif ln.startswith("+++ "):
            plus = None if ln[4:] == "/dev/null" else _unquote(ln[4:])[2:]
            cur = files.setdefault(plus or minus, {"added": [], "removed": []})
        elif ln.startswith("@@") and cur is not None:
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)", ln)
            old_pos = int(m.group(1)) if m else 0
        elif cur is not None and ln.startswith("+"):
            cur["added"].append((old_pos, ln[1:]))
        elif cur is not None and ln.startswith("-"):
            cur["removed"].append((old_pos, ln[1:]))
            old_pos += 1
    return files


def _section(text: str, names: tuple) -> str:
    """The body of INI/TOML sections with these names."""
    out, keep = [], False
    for ln in text.splitlines():
        m = re.match(r"\s*\[+\s*([^\]]+?)\s*\]+\s*$", ln)
        if m:
            keep = m.group(1).strip().strip('"') in names or any(m.group(1).startswith(n + ".") for n in names)
        if keep:
            out.append(ln.rstrip())
    return "\n".join(out)


def _make_targets(test_cmd: str | None) -> set:
    names = {"test", "tests", "check"}
    if test_cmd:
        m = re.search(r"\bmake\s+(?:-\S+\s+)*([\w.-]+)", test_cmd)
        if m:
            names.add(m.group(1))
    return names


def _make_recipe(text: str, targets: set) -> str:
    out, keep = [], False
    for ln in text.splitlines():
        m = re.match(r"^([\w.\- ]+?)\s*::?(?!=)", ln)
        if m and not ln.startswith("\t"):
            keep = bool(set(m.group(1).split()) & targets)
        elif ln and not ln.startswith(("\t", " ", "#")):
            keep = False
        if keep:
            out.append(ln.rstrip())
    return "\n".join(out)


def _npm_scripts(test_cmd: str | None) -> set:
    names = {"test", "pretest", "posttest"}
    if test_cmd:
        for m in re.finditer(r"\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+|run-script\s+)?([\w:.-]+)", test_cmd):
            if m.group(1) not in ("install", "ci", "exec", "x"):
                names |= {m.group(1), "pre" + m.group(1), "post" + m.group(1)}
    return names


def _package_test_def(text: str | None, scripts: set) -> str:
    if text is None:
        return ""
    try:
        doc = json.loads(text)
    except ValueError:
        return text  # unparsable: compare the whole file
    if not isinstance(doc, dict):
        return text
    s = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    picked = {k: s.get(k) for k in sorted(scripts) if k in s}
    for key in ("jest", "mocha", "ava", "vitest", "c8", "nyc"):
        if key in doc:
            picked["@" + key] = doc[key]
    return json.dumps(picked, sort_keys=True)


def _test_definition_changed(snap: Snapshot, base: str, new: str, path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if path in snap.test_files or TEST_CONFIG.search(path):
        return True
    if name == "package.json":
        scripts = _npm_scripts(snap.test_cmd)
        return _package_test_def(_blob(snap, base, path), scripts) != _package_test_def(_blob(snap, new, path), scripts)
    if name in MAKEFILES:
        targets = _make_targets(snap.test_cmd)
        return _make_recipe(_blob(snap, base, path) or "", targets) != _make_recipe(_blob(snap, new, path) or "", targets)
    if name in SECTIONS:
        names = SECTIONS[name]
        return _section(_blob(snap, base, path) or "", names) != _section(_blob(snap, new, path) or "", names)
    if path == "conftest.py":  # the root conftest can deselect or skip the whole suite
        return True
    return False


def _uncomment(line: str) -> str:
    return COMMENT.sub("", line, count=1).strip()


def check(snap: Snapshot) -> list:
    """Violations in the working tree compared with the snapshot. Empty list = nothing gamed."""
    out = []
    now = _hash_controls(snap.root)
    for path in sorted(set(now) | set(snap.control)):
        if now.get(path) != snap.control.get(path):
            out.append(Violation("control-file", path, "added" if path not in snap.control else
                                 "deleted" if path not in now else "edited"))
    new = current_tree(snap)
    if new == snap.tree:
        return out
    status = _git(snap.root, snap.git_dir, "diff-tree", "-r", "--no-renames", "-z", "--name-status", snap.tree, new)
    parts = status.split("\0")
    changes = {}
    for i in range(0, len(parts) - 1, 2):
        changes[parts[i + 1]] = parts[i]
    patch = _git(snap.root, snap.git_dir, "diff-tree", "-r", "--no-renames", "-p", "-U0", "--no-color",
                 "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", snap.tree, new)
    hunks = _parse_patch(patch)
    reported = {(v.kind, v.path) for v in out}

    def add(kind, path, detail=""):
        if (kind, path) not in reported:
            reported.add((kind, path))
            out.append(Violation(kind, path, detail))

    for path, st in sorted(changes.items()):
        is_test = classify(path) == "test"
        flagged = snap.finding_lines.get(path)
        if st == "D" or st == "T":
            if flagged:
                add("deleted-source", path)
            if is_test:
                add("deleted-test", path)
        elif st == "M":
            text = _blob(snap, new, path)
            empty = text is not None and not text.strip()
            if flagged and empty:
                add("emptied-source", path)
            if is_test:
                before = _blob(snap, snap.tree, path) or ""
                if empty or (ASSERTS.search(before) and not ASSERTS.search(text or "")):
                    add("emptied-test", path)
        if _test_definition_changed(snap, snap.tree, new, path):
            add("test-command", path)

        h = hunks.get(path)
        if not h:
            continue
        for marker in sorted({m.group(0).lower() for _, ln in h["added"] for m in SCANNER_MARKERS.finditer(ln)}):
            added = sum(len(re.findall(re.escape(marker), ln, re.IGNORECASE)) for _, ln in h["added"])
            removed = sum(len(re.findall(re.escape(marker), ln, re.IGNORECASE)) for _, ln in h["removed"])
            if added > removed:
                add("suppression", path, marker)
        if flagged:
            for pos, ln in h["added"]:
                m = NEAR_MARKERS.search(ln)
                if not m:
                    continue
                before = sum(1 for _, r in h["removed"] if m.group(0).lower() in r.lower())
                after = sum(1 for _, a in h["added"] if m.group(0).lower() in a.lower())
                if after <= before:
                    continue
                if FILE_WIDE.search(ln) or any(abs(pos - line) <= NEAR for line in flagged):
                    add("suppression", path, m.group(0).lower())
            added_plain = {_uncomment(a) for _, a in h["added"] if COMMENT.match(a)}
            for pos, ln in h["removed"]:
                if pos in flagged and ln.strip() and ln.strip() in added_plain:
                    add("commented-out", path, f"line {pos}")
    return out


def head_moved(snap: Snapshot) -> bool:
    """True if HEAD now points at a different commit than when the snapshot was taken (the agent committed)."""
    now = gitsafe.run(snap.root, "rev-parse", "-q", "--verify", "HEAD").stdout.strip()
    return bool(snap.head) and now != snap.head


def restore_command(snap: Snapshot) -> str:
    """Shell command that puts the working tree back to the snapshot (only valid while the snapshot is kept)."""
    g = f"git --git-dir={shlex.quote(snap.git_dir)} --work-tree={shlex.quote(snap.root)}"
    return f"{g} read-tree {snap.tree} && {g} checkout-index -a -f && {g} clean -fdq"
