"""Find and read the files to scan.

The tree being scanned may be hostile, so the walker reads regular files only (a FIFO or a device would hang or
exhaust the scan), reads at most MAX_BYTES of each, and never follows a symlink. A link that points inside the
root is listed but not read, because its target is scanned under its own path. Anything left out is recorded in
a WalkReport so the scan can say what it did not look at.
"""
from __future__ import annotations

import os
import re
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from fnmatch import translate

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "venv", ".venv",
    "__pycache__", "dist", ".next", ".nuxt", ".svelte-kit", "vendor",
    ".hardn", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
    ".terraform", ".idea", ".vscode", "site-packages", ".gradle", "Pods",
}
# Often a virtualenv or build output, but also a common name for real source: NodeGoat keeps its config in
# config/env/ and Next.js keeps compiler code in src/build/. These are walked unless their contents look generated.
MAYBE_GENERATED = {"env", "build", "out", "target"}
GENERATED_MARKERS = {
    "pyvenv.cfg", "conda-meta",                              # Python virtualenvs
    "CACHEDIR.TAG", ".rustc_info.json",                      # Cargo target/, and any tool that tags its cache
    "CMakeCache.txt", "CMakeFiles", "build.ninja", ".ninja_log",
    "maven-status", "maven-archiver", "classes", "intermediates",  # Maven target/, Gradle build/
    "asset-manifest.json", ".last_build_id", "XCBuildData",  # Create React App, Flutter, Xcode
    "_next", "production",                                   # next export out/, IntelliJ out/
}
GENERATED_PREFIXES = ("bdist.", "temp.", "lib.")             # setuptools build/
SKIP_SUFFIXES = (
    ".min.js", ".min.css", ".map", ".lock", "-lock.json", "-lock.yaml", ".svg", ".png",
    ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".gz",
)
MAX_BYTES = 1_000_000
READ_THREADS = 8  # file reads are I/O bound; threads roughly halve the wall time on large trees
_LIST_CAP = 200   # paths kept per WalkReport list; the counts stay exact

_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


class NotReadable(OSError):
    """A path that is not a plain file, or is larger than the limit."""


@dataclass
class SourceFile:
    path: str  # relative, posix separators
    text: str

    @property
    def lines(self) -> list:
        if not hasattr(self, "_lines"):
            self._lines = self.text.splitlines()
        return self._lines


@dataclass
class WalkReport:
    """What the walk did not read, and why."""

    oversize: list = field(default_factory=list)        # regular files over MAX_BYTES
    unreadable: list = field(default_factory=list)      # permission denied, vanished, name too long
    special: list = field(default_factory=list)         # FIFOs, sockets, devices
    symlinks: list = field(default_factory=list)        # links leaving the root or pointing at a non-file
    generated_dirs: list = field(default_factory=list)  # env/build/out/target folders that look generated
    binary: int = 0
    ignored: int = 0                                    # files excluded by .hardnignore
    counts: dict = field(default_factory=dict)

    def add(self, kind: str, rel: str) -> None:
        self.counts[kind] = self.counts.get(kind, 0) + 1
        items = getattr(self, kind)
        if len(items) < _LIST_CAP:
            items.append(rel)

    def count(self, kind: str) -> int:
        return self.counts.get(kind, 0)

    def to_dict(self) -> dict:
        out = {"max_bytes": MAX_BYTES, "binary": self.binary, "hardnignore": self.ignored}
        for kind in ("oversize", "unreadable", "special", "symlinks", "generated_dirs"):
            out[kind] = {"count": self.count(kind), "paths": list(getattr(self, kind))}
        return out


def read_regular(path: str, limit: int = MAX_BYTES) -> bytes:
    """Read a regular file without following a final symlink. Raises NotReadable or OSError."""
    fd = os.open(path, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise NotReadable(f"{path}: not a regular file")
        if st.st_size > limit:
            raise NotReadable(f"{path}: larger than {limit} bytes")
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(fd, min(1 << 20, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    if size > limit:
        raise NotReadable(f"{path}: larger than {limit} bytes")
    return b"".join(chunks)


def load_ignore(root: str) -> list:
    path = os.path.join(root, ".hardnignore")
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return []
        raw = read_regular(path, 256_000)
    except OSError:
        return []
    lines = raw.decode("utf-8", errors="replace").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def _matcher(patterns: list):
    """Compile .hardnignore patterns once. Same meaning as is_ignored(), without a fnmatch call per pattern."""
    if not patterns:
        return lambda rel, name: False
    full, base = [], []
    for p in patterns:
        p = p.strip("/")
        full += [translate(p), translate(p + "/*")]
        base.append(translate(p))
    flags = re.IGNORECASE if os.name == "nt" else 0
    full_rx, base_rx = re.compile("|".join(full), flags), re.compile("|".join(base), flags)
    return lambda rel, name: bool(full_rx.match(rel) or base_rx.match(name))


def is_ignored(rel: str, patterns: list) -> bool:
    return _matcher(patterns)(rel, rel.rsplit("/", 1)[-1])


def _looks_generated(path: str) -> bool:
    try:
        with os.scandir(path) as it:
            names = [e.name for e in it]
    except OSError:
        return False
    if any(n in GENERATED_MARKERS or n.startswith(GENERATED_PREFIXES) for n in names):
        return True
    for activate in (("bin", "activate"), ("Scripts", "activate")):  # virtualenvs made without pyvenv.cfg
        if os.path.isfile(os.path.join(path, *activate)):
            return True
    return False


def _inside(path: str, real_root: str) -> bool:
    return path == real_root or path.startswith(real_root.rstrip(os.sep) + os.sep)


def _count_files(path: str) -> int:
    """Files under an excluded folder, so the report can say how much .hardnignore hid."""
    total, stack = 0, [path]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    if e.is_dir(follow_symlinks=False):
                        if e.name not in SKIP_DIRS:
                            stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        total += 1
        except OSError:
            continue
    return total


def _read(job):
    rel, full = job
    try:
        return rel, read_regular(full), None
    except NotReadable as exc:
        return rel, None, "oversize" if "larger than" in str(exc) else "special"
    except OSError:
        return rel, None, "unreadable"


def walk(root: str, ignore: bool = True, report: WalkReport | None = None):
    """Return (text files to scan, every relative path seen). Pass a WalkReport to learn what was skipped.

    ignore=False skips .hardnignore, for scans of a repository you do not trust.
    """
    report = report if report is not None else WalkReport()
    root = os.path.abspath(root)
    real_root = os.path.realpath(root)
    match = _matcher(load_ignore(root) if ignore else [])
    all_paths, jobs = [], []
    stack = [("", root)]
    while stack:
        rel_dir, dirpath = stack.pop()
        try:
            with os.scandir(dirpath) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            report.add("unreadable", rel_dir.rstrip("/") or ".")
            continue
        subdirs = []
        for e in entries:
            name, rel = e.name, rel_dir + e.name
            try:
                is_link = e.is_symlink()
                is_dir = not is_link and e.is_dir(follow_symlinks=False)
            except OSError:
                report.add("unreadable", rel)
                continue
            if is_dir:
                if name in SKIP_DIRS:
                    continue
                if match(rel, name):
                    report.ignored += _count_files(e.path)
                elif name in MAYBE_GENERATED and _looks_generated(e.path):
                    report.add("generated_dirs", rel)
                else:
                    subdirs.append((rel + "/", e.path))
                continue
            if match(rel, name):
                report.ignored += 1
                continue
            if is_link:
                _symlink(e.path, rel, real_root, report, all_paths)
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                report.add("unreadable", rel)
                continue
            if not stat.S_ISREG(st.st_mode):
                report.add("special", rel)
                continue
            all_paths.append(rel)
            if name.lower().endswith(SKIP_SUFFIXES):
                continue
            if st.st_size > MAX_BYTES:
                report.add("oversize", rel)
                continue
            jobs.append((rel, e.path))
        stack.extend(reversed(subdirs))  # depth-first, files before subfolders: the order os.walk gave

    if len(jobs) > 64:
        with ThreadPoolExecutor(READ_THREADS) as pool:
            results = list(pool.map(_read, jobs, chunksize=32))
    else:
        results = [_read(j) for j in jobs]
    files = []
    for rel, raw, problem in results:
        if problem:
            report.add(problem, rel)
        elif b"\x00" in raw[:8192]:
            report.binary += 1
        else:
            files.append(SourceFile(rel, raw.decode("utf-8", errors="replace")))
    return files, all_paths


def _symlink(full: str, rel: str, real_root: str, report: WalkReport, all_paths: list) -> None:
    """Links are never read. One to a regular file inside the root is listed so manifest checks still see it."""
    try:
        target = os.path.realpath(full)
        mode = os.stat(target).st_mode
    except (OSError, ValueError, RuntimeError):
        report.add("symlinks", rel)  # dangling, a loop, or unreadable
        return
    if _inside(target, real_root):
        if stat.S_ISREG(mode):
            all_paths.append(rel)
            return
        if stat.S_ISDIR(mode):
            return  # the folder is walked under its real path
    report.add("symlinks", rel)


def is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    if any(p in ("test", "tests", "__tests__", "spec", "specs", "fixtures", "__mocks__") for p in parts[:-1]):
        return True
    name = parts[-1]
    return (
        name.startswith("test_")
        or ".test." in name
        or ".spec." in name
        or name.endswith(("_test.go", "_test.py", "_spec.rb"))
    )
