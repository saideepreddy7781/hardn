"""Baselines: accept today's findings as known debt so CI only fails on *new* issues.

A baselined finding is identified by its rule and its normalized (redacted) code, not by line number, so it
survives edits that shift lines. Matching prefers the same file and the nearest line; a finding whose file was
moved or renamed matches an entry whose file no longer exists. For secrets the file also stores a salted HMAC of
the source line, so replacing a baselined key with a different key on the same line shows up as new. The raw
value is never written. The redacted code already pins everything on the line except the value, so a hash of
the line changes exactly when the value does.

Format 2 keeps format 1's keys (path-bound fingerprints), so an older hardn can still read the file.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import re
import stat

from . import __version__, output

FILENAME = ".hardn-baseline.json"
FORMAT = 2
MAX_BASELINE_BYTES = 50_000_000
_MAX_PAIRS = 40_000  # beyond this, pair findings and entries in order instead of by distance


class BaselineError(Exception):
    """The baseline file is missing, unsafe or unreadable."""


def _code(f) -> str:
    return re.sub(r"\s+", " ", f.snippet.strip())


def _basis(f) -> str:
    if f.category == "dependency":
        return f"{f.rule_id}|{f.extra.get('package')}|{f.extra.get('version')}"
    if f.line:
        return f"{f.rule_id}|{f.file}|{_code(f)}"
    return f"{f.rule_id}|{f.file}|{f.title}"


def identity(f) -> str:
    """Path-free id: the same code under a new path has the same id."""
    if f.category == "dependency":
        basis = f"{f.rule_id}|{f.extra.get('package')}|{f.extra.get('version')}"
    elif f.line:
        basis = f"{f.rule_id}|{_code(f)}"
    else:
        basis = f"{f.rule_id}|{f.title}|{f.file.rsplit('/', 1)[-1]}"
    return hashlib.sha256(basis.encode("utf-8", "surrogatepass")).hexdigest()[:20]


def fingerprints(findings: list) -> list:
    """Stable path-bound fingerprint per finding; identical code repeated in one file gets #2, #3, ..."""
    seen, out = {}, []
    for f in findings:
        h = hashlib.sha256(_basis(f).encode("utf-8", "surrogatepass")).hexdigest()[:20]
        seen[h] = seen.get(h, 0) + 1
        out.append(h if seen[h] == 1 else f"{h}#{seen[h]}")
    return out


def _value_hash(salt: bytes, f) -> str | None:
    """HMAC of the raw source line of a secret finding. scanner.run attaches the line in memory only."""
    line = getattr(f, "_secret_line", None)
    if not line or not salt:
        return None
    norm = re.sub(r"\s+", " ", line.strip()).encode("utf-8", "surrogatepass")
    return hmac.new(salt, norm, hashlib.sha256).hexdigest()[:32]


def path_for(root: str) -> str:
    return os.path.join(root, FILENAME)


def save(root: str, findings: list, path: str | None = None) -> str:
    path = os.path.abspath(path or path_for(root))
    salt = os.urandom(16)
    entries = {}
    for fp, f in zip(fingerprints(findings), findings):
        entry = {"rule": f.rule_id, "severity": f.severity, "location": f.location(), "title": f.title,
                 "id": identity(f), "file": f.file, "line": f.line}
        value = _value_hash(salt, f)
        if value:
            entry["value_hmac"] = value
        entries[fp] = entry
    doc = {
        "tool": "hardn", "version": __version__, "format": FORMAT,
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "salt": salt.hex(), "count": len(entries), "findings": dict(sorted(entries.items())),
    }
    try:
        return output.write_file(os.path.dirname(path), os.path.basename(path), json.dumps(doc, indent=2) + "\n")
    except output.OutputError as exc:
        raise BaselineError(str(exc)) from exc


class Known:
    """A loaded baseline. Behaves like the set of format-1 fingerprints it contains."""

    def __init__(self, entries: dict, salt: bytes = b""):
        self.entries, self.salt = entries, salt

    def __contains__(self, fp) -> bool:
        return fp in self.entries

    def __iter__(self):
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


def load(path: str) -> Known:
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc.strerror or exc}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise BaselineError(f"baseline {path} is a symlink or not a regular file; refusing to read it")
    from .walker import read_regular

    try:
        raw = read_regular(path, MAX_BASELINE_BYTES)
        doc = json.loads(raw.decode("utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}. Re-create it with `hardn baseline`") from exc
    found = doc.get("findings") if isinstance(doc, dict) else None
    if isinstance(found, list):
        found = {str(k): {} for k in found}
    if not isinstance(found, dict):
        raise BaselineError(f"baseline {path} has no findings table. Re-create it with `hardn baseline`")
    try:
        salt = bytes.fromhex(str(doc.get("salt", "")))
    except ValueError:
        salt = b""
    return Known({str(k): (v if isinstance(v, dict) else {}) for k, v in found.items()}, salt)


def split(findings: list, known, is_new=None, root: str | None = None) -> tuple:
    """Return (new findings, baselined findings).

    is_new(f): True for findings on lines the current change touched (--diff). Those never take a baselined
    entry from the same file, so a new line identical to a baselined one is reported.
    root: lets a finding take an entry from another file only when that file is gone (a move or rename).
    """
    if not isinstance(known, Known):
        known = Known({str(k): {} for k in known})
    n = len(findings)
    taken = [False] * n
    is_new = is_new or (lambda f: False)
    fresh = [bool(is_new(f)) for f in findings]

    pool = {}  # id -> [entry]
    legacy = set()
    for fp, e in known.entries.items():
        if e.get("id"):
            pool.setdefault(e["id"], []).append(dict(e, _used=False))
        else:
            legacy.add(fp)

    by_id = {}
    for i, f in enumerate(findings):
        by_id.setdefault(identity(f), []).append(i)

    def value_ok(f, e) -> bool:
        want = e.get("value_hmac")
        got = _value_hash(known.salt, f) if want else None
        return not want or not got or hmac.compare_digest(want, got)

    def gone(path: str) -> bool:
        if root is None or not path:
            return True
        return not os.path.lexists(os.path.join(root, path))

    for fid, idxs in by_id.items():
        ents = pool.get(fid)
        if not ents:
            continue
        for same_file in (True, False):
            pairs = []
            for i in idxs:
                if taken[i]:
                    continue
                f = findings[i]
                for j, e in enumerate(ents):
                    if e["_used"] or (e.get("file", "") == f.file) != same_file:
                        continue
                    if same_file and fresh[i]:
                        continue
                    if not same_file and not gone(e.get("file", "")):
                        continue
                    if not value_ok(f, e):
                        continue
                    pairs.append((abs((f.line or 0) - int(e.get("line") or 0)) if len(pairs) < _MAX_PAIRS else 0,
                                  i, j))
            for _, i, j in sorted(pairs):
                if not taken[i] and not ents[j]["_used"]:
                    taken[i], ents[j]["_used"] = True, True

    if legacy:  # format-1 entries: the old path-bound, order-numbered match
        for i, fp in enumerate(fingerprints(findings)):
            if not taken[i] and fp in legacy and not fresh[i]:
                taken[i] = True
    new = [f for f, t in zip(findings, taken) if not t]
    old = [f for f, t in zip(findings, taken) if t]
    return new, old
