"""Cluster (lineage) bootstrap, paired deltas and leave-one-lineage-out jackknife (spec §9.2).

Predictions are fixed (OOF or locked-test); only lineages are resampled, whole, with replacement.
"""
from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence

from .common import Row, det_uniform

Stat = Callable[[list[Row], Mapping[str, float]], float | None]
MIN_GROUPS_HEADLINE = 30
# PROPOSED (LBL-26 C-8; to be recorded in the lock commit): a headline interval is refused when more than this share of
# the lineage resamples has an undefined statistic (e.g. no accepted row at tau), because the percentile bounds of the
# defined resamples then describe a selected subset of the draws.
MAX_UNDEFINED_SHARE = 0.05


def group_rows(rows: Sequence[Row]) -> dict[str, list[Row]]:
    out: dict[str, list[Row]] = {}
    for row in sorted(rows, key=lambda r: r.id):
        out.setdefault(row.group, []).append(row)
    return out


def draws(groups: Sequence[str], b_count: int, seed) -> list[list[str]]:
    n = len(groups)
    return [[groups[int(det_uniform(seed, 'bs', b, j) * n)] for j in range(n)] for b in range(b_count)]


def _interval(vals: list[float], b_count: int, alpha: float, n_groups: int, max_undefined: float | None = None) -> dict:
    """Percentile interval of the defined resamples. `undefined` counts the others; `undefined_share` is their share and
    `refused` is True (bounds None) when `max_undefined` is given and the share exceeds it."""
    vals = sorted(vals)
    undefined = b_count - len(vals)
    share = undefined / b_count if b_count else 0.0
    refused = max_undefined is not None and share > max_undefined
    out = {'lo': None, 'hi': None, 'undefined': undefined, 'undefined_share': share, 'refused': refused,
           'anti_conservative': n_groups < MIN_GROUPS_HEADLINE}
    if vals and not refused:
        out['lo'] = vals[int(alpha / 2 * len(vals))]
        out['hi'] = vals[min(len(vals) - 1, int((1 - alpha / 2) * len(vals)))]
    return out


def cluster_bootstrap(rows: Sequence[Row], preds: Mapping[str, float], stat_fn: Stat, b_count: int, seed,
                      alpha: float = 0.05, max_undefined: float | None = None) -> dict:
    by_g = group_rows(rows)
    gs = sorted(by_g)
    vals = []
    for draw in draws(gs, b_count, seed):
        value = stat_fn([r for g in draw for r in by_g[g]], preds)
        if value is not None:
            vals.append(value)
    out = _interval(vals, b_count, alpha, len(gs), max_undefined)
    out['point'] = stat_fn(list(rows), preds)
    return out


def cluster_bootstrap_many(rows: Sequence[Row], preds: Mapping[str, float],
                           stat_fn: Callable[[list[Row], Mapping[str, float]], Sequence[float] | None],
                           names: Sequence[str], b_count: int, seed, alpha: float = 0.05,
                           max_undefined: float | None = None) -> dict[str, dict]:
    """Several statistics from ONE set of lineage resamples (e.g. calibration slope and intercept)."""
    by_g = group_rows(rows)
    gs = sorted(by_g)
    vals: list[list[float]] = [[] for _ in names]
    for draw in draws(gs, b_count, seed):
        value = stat_fn([r for g in draw for r in by_g[g]], preds)
        if value is not None:
            for k, v in enumerate(value):
                vals[k].append(v)
    point = stat_fn(list(rows), preds)
    out = {}
    for k, name in enumerate(names):
        out[name] = _interval(vals[k], b_count, alpha, len(gs), max_undefined)
        out[name]['point'] = None if point is None else point[k]
    return out


def paired_delta(rows: Sequence[Row], preds_a: Mapping[str, float], preds_b: Mapping[str, float],
                 stat_fn: Callable[[list[Row], Mapping[str, float], Mapping[str, float]], float | None],
                 b_count: int, seed, alpha: float = 0.05) -> dict:
    """CI of stat(A, B) (e.g. FDR_B - FDR_A at equal coverage) under the SAME lineage resamples."""
    by_g = group_rows(rows)
    gs = sorted(by_g)
    vals = []
    for draw in draws(gs, b_count, seed):
        value = stat_fn([r for g in draw for r in by_g[g]], preds_a, preds_b)
        if value is not None:
            vals.append(value)
    out = _interval(vals, b_count, alpha, len(gs))
    out['point'] = stat_fn(list(rows), preds_a, preds_b)
    return out


def jackknife(rows: Sequence[Row], preds: Mapping[str, float], stat_fn: Stat) -> dict:
    """Leave-one-lineage-out: worst value and maximum influence of a single lineage."""
    by_g = group_rows(rows)
    full = stat_fn(list(rows), preds)
    values = {}
    for g in sorted(by_g):
        values[g] = stat_fn([r for h in sorted(by_g) if h != g for r in by_g[h]], preds)
    defined = {g: v for g, v in values.items() if v is not None}
    if not defined or full is None:
        return {'worst_group': None, 'worst': None, 'max_influence': None}
    worst = min(defined, key=lambda g: (defined[g], g))
    return {'worst_group': worst, 'worst': defined[worst],
            'max_influence': max(abs(v - full) for v in defined.values())}


# ---- stat helpers -------------------------------------------------------------------------------------

def precision_stat(tau: float) -> Stat:
    def stat(rows, preds):
        sel = [r for r in rows if not r.abstain and preds[r.id] >= tau]
        sw = math.fsum(r.w for r in sel)
        return math.fsum(r.w * r.y for r in sel) / sw if sw else None
    return stat


def npv_stat(tau_low: float) -> Stat:
    def stat(rows, preds):
        sel = [r for r in rows if not r.abstain and preds[r.id] <= tau_low]
        sw = math.fsum(r.w for r in sel)
        return math.fsum(r.w * (1 - r.y) for r in sel) / sw if sw else None
    return stat


def coverage_stat(tau: float) -> Stat:
    def stat(rows, preds):
        total = math.fsum(r.w for r in rows)
        return math.fsum(r.w for r in rows if not r.abstain and preds[r.id] >= tau) / total if total else None
    return stat


def fdr_at_coverage(rows: Sequence[Row], preds: Mapping[str, float], coverage: float) -> float | None:
    """FDR of the top-`coverage` (by weight) accepted set; ties enter whole."""
    total = math.fsum(r.w for r in rows)
    ranked = sorted((r for r in rows if not r.abstain), key=lambda r: (-preds[r.id], r.id))
    cum_w = cum_pos = 0.0
    for k, r in enumerate(ranked):
        cum_w += r.w
        cum_pos += r.w * r.y
        if cum_w / total >= coverage - 1e-12 and (k + 1 == len(ranked) or preds[ranked[k + 1].id] != preds[r.id]):
            return 1 - cum_pos / cum_w
    return None if not cum_w else 1 - cum_pos / cum_w


def fdr_reduction_stat(tau_a: float) -> Callable:
    """FDR(B) - FDR(A) where A accepts p >= tau_a and B is matched to A's coverage in the same resample."""
    def stat(rows, preds_a, preds_b):
        cov = coverage_stat(tau_a)(rows, preds_a)
        prec = precision_stat(tau_a)(rows, preds_a)
        if not cov or prec is None:
            return None
        fdr_b = fdr_at_coverage(rows, preds_b, cov)
        return None if fdr_b is None else fdr_b - (1 - prec)
    return stat
