"""`--diff`: restrict results to lines changed since a git ref (plus untracked files).

The diff is compared against the merge base of REF and HEAD, so changes made on the base branch after this
branch forked are not blamed on it. Parsing does not depend on the repo's own diff settings: prefixes are set
on the command line, quoted paths are decoded, and the list of changed files from `--numstat -z` is used as a
cross-check. If git reports changes that cannot be parsed, that is an error, never an empty (clean) result.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unicodedata

from . import gitsafe

_HUNK = re.compile(rb"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_ESCAPES = {b"a": 7, b"b": 8, b"t": 9, b"n": 10, b"v": 11, b"f": 12, b"r": 13, b'"': 34, b"\\": 92}


class DiffError(Exception):
    pass


class Changes(dict):
    """{relative path: set of changed line numbers, or None meaning 'the whole file is new'}."""

    def __init__(self, root: str = "", ref: str = "", base: str = ""):
        super().__init__()
        self.root, self.ref, self.base = root, ref, base
        self._old_pkgs = {}

    def old_packages(self, path: str):
        """(name, version) pairs in this lockfile at the base commit; None if the file did not exist there."""
        if path not in self._old_pkgs:
            self._old_pkgs[path] = _packages_at(self.root, self.base, path)
        return self._old_pkgs[path]


def _nfc(path: str) -> str:
    return unicodedata.normalize("NFC", path)


def _git(root: str, *args, ok=(0,)) -> bytes:
    try:
        proc = gitsafe.run(root, *args, timeout=120, text=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiffError(f"git failed: {exc}") from exc
    if proc.returncode not in ok:
        msg = proc.stderr.decode("utf-8", "replace").strip()
        raise DiffError(msg or f"git {args[0]} failed")
    return proc.stdout


def _unquote(raw: bytes) -> str:
    """Decode a path from a diff header: C-quoted ("b/caf\\303\\251.py") or plain, with git's trailing tab."""
    if raw.startswith(b'"') and raw.endswith(b'"') and len(raw) >= 2:
        body, out, i = raw[1:-1], bytearray(), 0
        while i < len(body):
            ch = body[i:i + 1]
            if ch != b"\\":
                out += ch
                i += 1
                continue
            nxt = body[i + 1:i + 2]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                i += 2
            elif re.fullmatch(rb"[0-7]{3}", body[i + 1:i + 4] or b""):
                out.append(int(body[i + 1:i + 4], 8))
                i += 4
            else:
                raise DiffError(f"cannot decode quoted path {raw!r} in git diff output")
        return os.fsdecode(bytes(out))
    if raw.endswith(b"\t"):
        raw = raw[:-1]
    return os.fsdecode(raw)


def _parse_patch(data: bytes) -> dict:
    changed, current = {}, None
    lines = data.split(b"\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.startswith(b"diff "):
            current = None
        elif line.startswith(b"+++ "):
            path = _unquote(line[4:])
            if path == "/dev/null":
                current = None
            elif path.startswith("b/"):
                current = _nfc(path[2:])
                changed.setdefault(current, set())
            else:
                raise DiffError(f"unexpected path {path!r} in git diff output")
        elif line.startswith(b"@@ "):
            m = _HUNK.match(line)
            if not m:
                raise DiffError(f"cannot parse hunk header {line[:80]!r}")
            old = int(m.group(1)) if m.group(1) is not None else 1
            start = int(m.group(2))
            new = int(m.group(3)) if m.group(3) is not None else 1
            if current is not None:
                changed[current].update(range(start, start + new))
            body = old + new  # skip the hunk body so a source line like "++ x" is never read as a header
            while body > 0 and i < len(lines):
                if not lines[i].startswith(b"\\"):  # "\ No newline at end of file" is not a counted line
                    body -= 1
                i += 1
    return changed


def _parse_numstat(data: bytes) -> dict:
    """{path: added line count, or None for binary}. Rename records are 'a\\td\\t\\0old\\0new\\0'."""
    out, parts, i = {}, data.split(b"\0"), 0
    while i < len(parts):
        rec = parts[i]
        i += 1
        if not rec:
            continue
        fields = rec.split(b"\t", 2)
        if len(fields) != 3:
            raise DiffError("cannot parse git diff --numstat output")
        added, _, path = fields
        if not path:  # rename or copy: the next two fields are the old and new path
            path = parts[i + 1] if i + 1 < len(parts) else b""
            i += 2
        out[_nfc(os.fsdecode(path))] = None if added == b"-" else int(added)
    return out


def _resolve(root: str, ref: str) -> str:
    if not ref or ref.startswith("-") or any(ch in ref for ch in "\0\n"):
        raise DiffError(f"invalid git ref {ref!r}")
    try:
        sha = _git(root, "rev-parse", "--verify", "--quiet", ref + "^{commit}").decode().strip()
    except DiffError as exc:
        raise DiffError(
            f"git ref {ref!r} was not found ({exc or 'unknown revision'}). In CI, check out full history "
            "(actions/checkout with fetch-depth: 0) or fetch the base branch first. A repository with no commits "
            "has nothing to compare against.") from exc
    try:
        merge_base = _git(root, "merge-base", sha, "HEAD").decode().strip()
    except DiffError:
        return sha  # no common history (or no HEAD): compare against the ref itself
    return merge_base or sha


def changed_lines(root: str, ref: str) -> Changes:
    """Lines changed since the merge base of REF and HEAD, including uncommitted and untracked files."""
    base = _resolve(root, ref)
    common = ("--no-color", "--relative", "--find-renames", "--submodule=short")
    patch = _git(root, "diff", *common, "-U0", "--inter-hunk-context=0", "--src-prefix=a/", "--dst-prefix=b/",
                 base, "--", ".")
    stats = _parse_numstat(_git(root, "diff", *common, "--numstat", "-z", base, "--", "."))
    changes = Changes(root, ref, base)
    changes.update(_parse_patch(patch))
    missing = [p for p, added in stats.items() if added and not changes.get(p)]
    if missing:
        raise DiffError(f"git reports changes in {len(missing)} file(s) that agentharden could not parse "
                        f"(first: {missing[0]!r}); refusing to report a clean result")
    for path, added in stats.items():
        if added is None:  # binary to git (or marked -diff in .gitattributes): treat the whole file as changed
            changes[path] = None
    for raw in _git(root, "ls-files", "-z", "--others", "--exclude-standard", "--", ".").split(b"\0"):
        if raw:
            changes[_nfc(os.fsdecode(raw))] = None
    return changes


def _packages_at(root: str, base: str, path: str):
    from . import deps

    try:
        proc = gitsafe.run(root, "show", f"{base}:./{path}", timeout=60, text=False)
    except (OSError, subprocess.TimeoutExpired):
        return set()  # unknown: report every package rather than hide one
    if proc.returncode != 0:
        return None  # the file is new since the base commit
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, *path.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(proc.stdout)
        try:
            return {(str(p[1]), str(p[2])) for p in deps.collect_packages(tmp, [path])}
        except Exception:  # noqa: BLE001 - a parser failure must report the packages, never hide them
            return set()


def touches(f, changed: dict) -> bool:
    """Does this finding sit on something the change touched?"""
    path = _nfc(f.file)
    if path not in changed:
        return False
    lines = changed[path]
    if lines is None:
        return True
    if f.category == "dependency" and isinstance(changed, Changes) and f.extra.get("package"):
        old = changed.old_packages(path)
        return old is None or (str(f.extra.get("package")), str(f.extra.get("version"))) not in old
    return not f.line or f.line in lines


def keep(findings: list, changed: dict) -> list:
    return [f for f in findings if touches(f, changed)]


def repo_prefix(root: str) -> str:
    """The scan root's path inside its git repository ('' at the top, or when it is not a repository)."""
    try:
        proc = gitsafe.run(root, "rev-parse", "--show-prefix", timeout=20, text=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return os.fsdecode(proc.stdout.strip(b"\n"))
