"""Descriptive curves of one engine over completed pairs (LBL-11; plan s7.1). Never shipped, never a calibration.

`native-precision`: 15 equal-width bins of the engine's native similarity in [0, 1] against the empirical share of its
paired rows that are correct pairs. A row counts when it touches at least one non-ambiguous labelled function (a
row over unlabelled or ambiguous code has no truth to be right or wrong about). Rows without a native score (unified,
attention) give no curve. Pooled over the given pairs: the curve says nothing about any one stratum.
"""
from __future__ import annotations

from collections.abc import Sequence

from ..common import r12
from ..tier_r import contracts as C
from .protocols import EnginePairs

N_BINS = 15


def _scoreable(labels: C.KnownAnswerLabels) -> tuple[set[tuple[int, int]], set[int], set[int]]:
    """(truth same pairs, old RVAs of scored records, new RVAs of scored records)."""
    scored = [f for f in labels.functions if f.identity != 'ambiguous' and f.label != 'ambiguous']
    truth = {(f.old_rva, f.new_rva) for f in scored if f.identity == 'same'}
    return (truth, {f.old_rva for f in scored if f.old_rva is not None},
            {f.new_rva for f in scored if f.new_rva is not None})


def native_precision_curve(engine: str, runs: Sequence[tuple[C.KnownAnswerLabels, EnginePairs]]
                           ) -> C.CurveBlock | None:
    total = [0] * N_BINS
    right = [0] * N_BINS
    seen = False
    for labels, pairs in runs:
        truth, old_scored, new_scored = _scoreable(labels)
        for p in pairs.pairs:
            if p.identity != 'paired' or p.native is None or not (p.old_rva in old_scored or p.new_rva in new_scored):
                continue
            seen = True
            i = min(int(min(max(p.native, 0.0), 1.0) * N_BINS), N_BINS - 1)
            total[i] += 1
            right[i] += (p.old_rva, p.new_rva) in truth
    if not seen:
        return None
    bins = tuple(C.CurveBin(lo=r12(i / N_BINS), hi=r12((i + 1) / N_BINS), n=total[i],
                            precision=r12(right[i] / total[i]) if total[i] else None) for i in range(N_BINS))
    return C.CurveBlock(kind='native-precision', engine=engine, bins=bins)
