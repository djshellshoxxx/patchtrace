"""The pre-registered G-PIL gate (preregistration section 6), evaluated through the lineage cluster bootstrap."""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..bootstrap import MIN_GROUPS_HEADLINE, paired_delta
from ..common import Row
from ..run_locked_test import run_locked_test
from .contracts import CaseOutcome

MIN_RELATIVE_REDUCTION = 0.20


def relative_false_lead_reduction(outcomes: Sequence[CaseOutcome]) -> float | None:
    base = sum(o.b_false_leads for o in outcomes)
    return None if base == 0 else 1 - sum(o.p_false_leads for o in outcomes) / base


def _rows(outcomes: Sequence[CaseOutcome]) -> list[Row]:
    return [Row(id=o.case_id, group=o.lineage, x=(float(o.p_false_leads), float(o.b_false_leads), o.p_recall10,
                                                  o.b_recall10), y=0) for o in outcomes]


def _reduction_stat(rows, _a, _b):
    base = sum(r.x[1] for r in rows)
    return None if base == 0 else 1 - sum(r.x[0] for r in rows) / base


def _recall_stat(rows, _a, _b):
    return sum(r.x[2] - r.x[3] for r in rows) / len(rows) if rows else None


def evaluate_gate(outcomes: Sequence[CaseOutcome], *, b_count: int, seed) -> dict:
    rows = _rows(outcomes)
    lineages = len({o.lineage for o in outcomes})
    reduction = paired_delta(rows, {}, {}, _reduction_stat, b_count, seed)
    recall = paired_delta(rows, {}, {}, _recall_stat, b_count, seed)
    conditions = {'lineages_ok': lineages >= MIN_GROUPS_HEADLINE,
                  'false_leads_ok': reduction['lo'] is not None and reduction['lo'] >= MIN_RELATIVE_REDUCTION,
                  'recall10_ok': recall['lo'] is not None and recall['lo'] >= 0}
    if not conditions['lineages_ok']:
        status = 'insufficient-data'
    else:
        status = 'pass' if conditions['false_leads_ok'] and conditions['recall10_ok'] else 'fail'
    return {'status': status, 'conditions': conditions, 'lineages': lineages, 'cases': len(outcomes),
            'false_lead_reduction': reduction, 'recall10_difference': recall}


def locked_gate(corpus_dir: Path, prereg_sha: str, outcomes: Sequence[CaseOutcome], *, b_count: int, seed) -> dict:
    """The single look at locked-test: a second call for the same preregistration SHA raises `LockedTestError`."""
    return run_locked_test(corpus_dir, prereg_sha, lambda: evaluate_gate(outcomes, b_count=b_count, seed=seed))
