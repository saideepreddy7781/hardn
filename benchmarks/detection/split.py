"""One-off: freeze the audit corpus into a tuning set and a holdout set.

Kept for the record. Re-running it needs the audit's case files, and it must not be re-run to get a
different holdout: the seed below is the one the published numbers were measured with.

    python benchmarks/detection/split.py /tmp/hardn-audit/detection
"""
from __future__ import annotations

import collections
import json
import random
import re
import shutil
import sys
from pathlib import Path

SEED = 20261110
HOLDOUT_FRACTION = 0.25
HERE = Path(__file__).resolve().parent


def main(audit: Path) -> None:
    sys.path.insert(0, str(audit))
    import casekit  # noqa: PLC0415
    import cases_js  # noqa: F401, PLC0415
    import cases_py  # noqa: F401, PLC0415
    import cases_rules  # noqa: F401, PLC0415
    import cases_sec  # noqa: F401, PLC0415

    corpus = audit / "corpus"
    cases = {c["id"]: c for c in casekit.CASES}
    on_disk = {p.name for engine in corpus.iterdir() if engine.is_dir() for p in engine.iterdir() if p.is_dir()}
    if on_disk != set(cases):
        raise SystemExit(f"corpus and case list disagree: {sorted(on_disk ^ set(cases))[:10]}")

    by_engine = collections.defaultdict(list)
    for cid, c in cases.items():
        by_engine[c["engine"]].append(cid)
    rng = random.Random(SEED)
    holdout = set()
    for engine in sorted(by_engine):
        ids = sorted(by_engine[engine])
        holdout |= set(rng.sample(ids, round(len(ids) * HOLDOUT_FRACTION)))

    audit_text = (audit.parent / "detection.md").read_text(encoding="utf-8")
    named = {cid for cid in holdout if re.search(rf"(?<![\w-]){re.escape(cid)}(?![\w-])", audit_text)}

    target = HERE / "corpus"
    shutil.rmtree(target, ignore_errors=True)
    manifest = {"seed": SEED, "holdout_fraction": HOLDOUT_FRACTION, "cases": {}}
    for cid, c in sorted(cases.items()):
        split = "holdout" if cid in holdout else "tuning"
        shutil.copytree(corpus / c["engine"] / cid, target / split / c["engine"] / cid)
        entry = {"split": split, "engine": c["engine"], "lang": c["lang"], "expect": c["expect"], "tags": c["tags"]}
        if split == "tuning":
            entry["note"] = c["note"]  # holdout notes describe the trap, so they stay out of the repo
        elif cid in named:
            entry["named_in_audit"] = True  # the audit report (read before the split) mentions this id
        manifest["cases"][cid] = entry
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(cases)} cases: {len(cases) - len(holdout)} tuning, {len(holdout)} holdout "
          f"({len(named)} holdout ids are named in the audit report), seed {SEED}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
