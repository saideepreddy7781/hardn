"""Security level ladder: each level is defined by the most severe open finding.

L0 Exposed   — critical issues open
L1 Basic     — no criticals
L2 Baseline  — no criticals or highs
L3 Hardened  — nothing above low
L4 Fortified — only informational items left
"""
from __future__ import annotations

LEVELS = ["Exposed", "Basic", "Baseline", "Hardened", "Fortified"]
TARGETS = {name.lower(): i for i, name in enumerate(LEVELS) if i > 0}
WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


INCOMPLETE_MAX_LEVEL = 2  # a scan with blind spots can never claim Hardened or Fortified


def counted(findings: list) -> list:
    """Findings that set the grade: application code, plus secrets wherever they are."""
    return [f for f in findings if f.counts]


def level(findings: list, gaps=()) -> int:
    lvl = 4 - max((f.rank for f in counted(findings)), default=0)
    return min(lvl, INCOMPLETE_MAX_LEVEL) if gaps else lvl


def min_rank_for(target: int) -> int:
    """Findings at or above this severity rank must be fixed to reach `target`."""
    return 5 - target


def score(findings: list) -> int:
    penalty, per_rule = 0.0, {}
    for f in counted(findings):
        n = per_rule[f.rule_id] = per_rule.get(f.rule_id, 0) + 1
        penalty += WEIGHTS[f.severity] * (1 if n <= 3 else 0.25)  # repeated instances of one rule count less
    return round(100 * 0.5 ** (penalty / 40))


def grade(s: int) -> str:
    return next(g for cutoff, g in ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")) if s >= cutoff)
