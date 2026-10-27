"""Baselines: accept today's findings as known debt so CI only fails on *new* issues.

Fingerprints use rule + file + normalized (redacted) code, not line numbers, so they survive
unrelated edits that shift lines. Commit `.hardn-baseline.json` to share it with your team.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re

from . import __version__

FILENAME = ".hardn-baseline.json"


def _basis(f) -> str:
    if f.category == "dependency":
        return f"{f.rule_id}|{f.extra.get('package')}|{f.extra.get('version')}"
    if f.line:
        code = re.sub(r"\s+", " ", f.snippet.strip())
        return f"{f.rule_id}|{f.file}|{code}"
    return f"{f.rule_id}|{f.file}|{f.title}"


def fingerprints(findings: list) -> list:
    """Stable fingerprint per finding; identical code repeated in one file gets #2, #3, ..."""
    seen, out = {}, []
    for f in findings:
        h = hashlib.sha256(_basis(f).encode()).hexdigest()[:20]
        seen[h] = seen.get(h, 0) + 1
        out.append(h if seen[h] == 1 else f"{h}#{seen[h]}")
    return out


def path_for(root: str) -> str:
    return os.path.join(root, FILENAME)


def save(root: str, findings: list, path: str | None = None) -> str:
    path = path or path_for(root)
    entries = {
        fp: {"rule": f.rule_id, "severity": f.severity, "location": f.location(), "title": f.title}
        for fp, f in zip(fingerprints(findings), findings)
    }
    doc = {
        "tool": "hardn", "version": __version__, "format": 1,
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(entries), "findings": dict(sorted(entries.items())),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return path


def load(path: str) -> set:
    with open(path, encoding="utf-8") as fh:
        return set(json.load(fh).get("findings", {}))


def split(findings: list, known: set) -> tuple:
    """Return (new findings, baselined findings)."""
    new, old = [], []
    for fp, f in zip(fingerprints(findings), findings):
        (old if fp in known else new).append(f)
    return new, old
