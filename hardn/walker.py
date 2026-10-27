from __future__ import annotations

import os
from dataclasses import dataclass
from fnmatch import fnmatch

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "venv", ".venv", "env",
    "__pycache__", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit", "vendor",
    "target", ".hardn", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
    ".terraform", ".idea", ".vscode", "site-packages", ".gradle", "Pods",
}
SKIP_SUFFIXES = (
    ".min.js", ".min.css", ".map", ".lock", "-lock.json", "-lock.yaml", ".svg", ".png",
    ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".gz",
)
MAX_BYTES = 1_000_000


@dataclass
class SourceFile:
    path: str  # relative, posix separators
    text: str

    @property
    def lines(self) -> list:
        if not hasattr(self, "_lines"):
            self._lines = self.text.splitlines()
        return self._lines


def load_ignore(root: str) -> list:
    path = os.path.join(root, ".hardnignore")
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def is_ignored(rel: str, patterns: list) -> bool:
    base = rel.rsplit("/", 1)[-1]
    for p in patterns:
        p = p.strip("/")
        if fnmatch(rel, p) or fnmatch(rel, p + "/*") or fnmatch(base, p):
            return True
    return False


def walk(root: str):
    """Return (text files to scan, every relative path seen)."""
    patterns = load_ignore(root)
    files, all_paths = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = sorted(
            d for d in dirnames if d not in SKIP_DIRS and not is_ignored(rel_dir + d, patterns)
        )
        for name in sorted(filenames):
            rel = rel_dir + name
            if is_ignored(rel, patterns):
                continue
            all_paths.append(rel)
            if name.lower().endswith(SKIP_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
                with open(full, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if b"\x00" in raw[:8192]:
                continue  # binary
            files.append(SourceFile(rel, raw.decode("utf-8", errors="replace")))
    return files, all_paths


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
