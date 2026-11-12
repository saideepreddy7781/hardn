"""Score agentharden's detection engines on the labelled corpus.

    python benchmarks/detection/run.py                 # tuning and holdout tables
    python benchmarks/detection/run.py --json          # the same numbers as JSON
    python benchmarks/detection/run.py --misses        # every wrong answer in the tuning split

`corpus/tuning` is what the engines were tuned against. `corpus/holdout` is a seeded random 25% (see split.py and
manifest.json) that was frozen before any engine changed. Holdout samples are scored but never listed, so reading
this script's output cannot leak them. Only the holdout figures are an honest estimate on unseen code. The holdout
table is printed a second time without the cases named in the audit report, which was read before the split.

Every file in the secrets cases is stored base64-encoded as NAME.b64, so the repository never holds strings in a
real key format (GitHub push protection and other scanners would flag them). The runner decodes the corpus into a
temporary directory and scores that copy. `--extract DIR` writes the decoded corpus to DIR for reading.

A vulnerable sample counts when a finding carries the expected CWE or rule. A safe sample counts as a false positive
when the engine under test reports anything on it (posture: the expected rule). Identical samples are scored once.
"""
from __future__ import annotations

import argparse
import base64
import collections
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))  # always score this checkout, whatever is installed
os.environ["GIT_CEILING_DIRECTORIES"] = str(HERE)  # corpus .env files must not see the surrounding repository

from agentharden import code_rules, posture, secrets, taint_js, taint_py, walker  # noqa: E402
from agentharden import stack as stack_mod  # noqa: E402

STORED = HERE / "corpus"
CORPUS = STORED  # replaced by the decoded copy in main()
ENCODED = ".b64"


def materialize(dest: Path) -> Path:
    """Copy the stored corpus to dest, decoding every NAME.b64 back to NAME."""
    for src in sorted(STORED.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(STORED)
        if src.name.endswith(ENCODED):
            out, data = dest / rel.with_name(src.name[:-len(ENCODED)]), base64.decodebytes(src.read_bytes())
        else:
            out, data = dest / rel, src.read_bytes()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    return dest
EXCLUDED_TAGS = {"extended", "out-of-claim", "lint", "debatable"}
# Rules that were split after the corpus was labelled. A finding from any successor satisfies the old label, on both
# splits alike: PHP001 became SQL / command / eval / include, RB002 lost eval to RB004, JS014 lost httpOnly to JS016.
SPLIT_RULES = {"PHP001": {"PHP001", "PHP004", "PHP005", "PHP006"}, "RB002": {"RB002", "RB004"},
               "JS014": {"JS014", "JS016"}}
REPORTS = [
    ("taint-py (engine alone)", "taint-py", "own"),
    ("taint-py (+ line rules)", "taint-py", "combo"),
    ("taint-js (engine alone)", "taint-js", "own"),
    ("taint-js (+ line rules)", "taint-js", "combo"),
    ("rules", "rules", "own"),
    ("secrets", "secrets", "own"),
    ("posture", "posture", "own"),
]


def engines_for(root: Path) -> dict:
    files, all_paths = walker.walk(str(root))
    stack = stack_mod.detect(str(root), files, all_paths)
    return {
        "taint-py": taint_py.scan(files),
        "taint-js": taint_js.scan(files),
        "rules": code_rules.scan(files),
        "secrets": secrets.scan(files, str(root)),
        "posture": posture.check(str(root), files, all_paths, stack),
    }


def fingerprint(root: Path, expect: str) -> str:
    parts = [expect]
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        parts += [str(path.relative_to(root)), path.read_text(encoding="utf-8", errors="replace")]
    return "\0".join(parts)


def score_side(root: Path, engine: str, expect: str) -> dict:
    res = engines_for(root)
    own = res[engine]
    if engine in ("taint-py", "taint-js"):
        combo = own + res["rules"]
    elif engine == "rules":
        combo = own + res["taint-py"] + res["taint-js"]
    else:
        combo = own
    accepted = SPLIT_RULES.get(expect, {expect})
    hits = lambda fs: [f for f in fs if f.rule_id in accepted or f.cwe == expect]  # noqa: E731
    brief = lambda fs: [f"{f.rule_id}@{f.file}:{f.line}" for f in fs]  # noqa: E731
    return {"own_hit": bool(hits(own)), "combo_hit": bool(hits(combo)), "own": brief(own), "combo": brief(combo),
            "fingerprint": fingerprint(root, expect)}


def evaluate(manifest: dict) -> list:
    rows = []
    for cid, case in sorted(manifest["cases"].items()):
        base = CORPUS / case["split"] / case["engine"] / cid
        row = dict(case, id=cid)
        for side in ("vuln", "safe"):
            row[side] = score_side(base / side, case["engine"], case["expect"]) if (base / side).is_dir() else None
        rows.append(row)
    return rows


def unique(rows: list, side: str) -> list:
    seen, out = set(), []
    for row in rows:
        sample = row[side]
        if sample is not None and sample["fingerprint"] not in seen:
            seen.add(sample["fingerprint"])
            out.append(row)
    return out


def false_positive(row: dict, mode: str) -> bool:
    sample = row["safe"]
    return sample["own_hit"] if row["engine"] == "posture" else bool(sample[mode])


def tally(rows: list, mode: str) -> dict:
    vuln, safe = unique(rows, "vuln"), unique(rows, "safe")
    tp = sum(1 for r in vuln if r["vuln"][f"{mode}_hit"])
    fp = sum(1 for r in safe if false_positive(r, mode))
    fn, tn = len(vuln) - tp, len(safe) - fp
    return {
        "vuln": len(vuln), "safe": len(safe), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": round(100 * tp / (tp + fn), 1) if tp + fn else None,
        "precision": round(100 * tp / (tp + fp), 1) if tp + fp else None,
        "fpr": round(100 * fp / (fp + tn), 1) if fp + tn else None,
    }


def report(rows: list) -> dict:
    head = [r for r in rows if not EXCLUDED_TAGS & set(r["tags"])]
    out = {}
    for title, engine, mode in REPORTS:
        subset = [r for r in head if r["engine"] == engine]
        table = {"overall": tally(subset, mode)}
        for lang in sorted({r["lang"] for r in subset}):
            table[lang] = tally([r for r in subset if r["lang"] == lang], mode)
        out[title] = table
    return out


def line(label: str, t: dict) -> str:
    pct = lambda v: "   n/a" if v is None else f"{v:5.1f}%"  # noqa: E731
    return (f"{label:<26} vuln={t['vuln']:<4} safe={t['safe']:<4} TP={t['tp']:<4} FN={t['fn']:<4} FP={t['fp']:<4} "
            f"TN={t['tn']:<4} recall={pct(t['recall'])} precision={pct(t['precision'])} FPR={pct(t['fpr'])}")


def print_tables(tables: dict) -> None:
    for split, table in tables.items():
        print(f"\n== {split} ==")
        for title, rows in table.items():
            print(line(title, rows["overall"]))
            for lang, t in rows.items():
                if lang != "overall":
                    print(line("  " + lang, t))


def print_misses(rows: list) -> None:
    for r in rows:
        if r["split"] != "tuning":
            continue
        mode = "combo" if r["engine"] in ("taint-py", "taint-js") else "own"
        v, s = r["vuln"], r["safe"]
        tag = ",".join(r["tags"])
        if v and not v[f"{mode}_hit"]:
            print(f"FN {r['engine']:<9} {r['lang']:<13} {r['id']:<30} {r['expect']:<9} [{tag}] {r.get('note', '')} | got: {v[mode]}")
        elif v and mode == "combo" and not v["own_hit"]:
            print(f"RULE-ONLY {r['engine']:<9} {r['lang']:<13} {r['id']:<30} {r['expect']:<9} [{tag}] {r.get('note', '')} | {v['combo']}")
        if s and false_positive(r, mode):
            print(f"FP {r['engine']:<9} {r['lang']:<13} {r['id']:<30} {r['expect']:<9} [{tag}] {r.get('note', '')} | {s[mode]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="print the tables as JSON")
    parser.add_argument("--misses", action="store_true", help="list every miss and false alarm in the tuning split")
    parser.add_argument("--extract", metavar="DIR", help="write the decoded corpus to DIR and exit")
    args = parser.parse_args()
    if args.extract:
        materialize(Path(args.extract))
        print(f"decoded corpus written to {args.extract}")
        return 0

    global CORPUS
    tmp = tempfile.mkdtemp(prefix="agentharden-corpus-")
    try:
        CORPUS = materialize(Path(tmp))
        os.environ["GIT_CEILING_DIRECTORIES"] = tmp
        return _run(args)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run(args) -> int:

    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    rows = evaluate(manifest)
    if args.misses:
        print_misses(rows)
        return 0
    holdout = [r for r in rows if r["split"] == "holdout"]
    tables = collections.OrderedDict(
        [("tuning", report([r for r in rows if r["split"] == "tuning"])),
         ("holdout", report(holdout)),
         ("holdout, excluding cases named in the audit report",
          report([r for r in holdout if not r.get("named_in_audit")]))]
    )
    if args.json:
        json.dump({"seed": manifest["seed"], "tables": tables}, sys.stdout, indent=1)
        print()
    else:
        print(f"Split seed {manifest['seed']}. Only the holdout tables estimate performance on unseen code.")
        print_tables(tables)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
