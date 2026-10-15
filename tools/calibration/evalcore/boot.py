"""Lineage (cluster) percentile bootstrap and paired deltas over per-pair observations (LBL-10).

The resampling unit is the lineage: whole lineages are drawn with replacement via `bootstrap.draws`, so a
paired delta evaluated with the same seed reuses IDENTICAL draws for both arms. Percentile intervals only
(no BCa). `anti_conservative` is True below `MIN_GROUPS_HEADLINE` (30) lineages.
"""
from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from ..bootstrap import MIN_GROUPS_HEADLINE, _interval, draws

B_COUNT = 2000
B_SMOKE = 500
Obs = Mapping[str, tuple[str, float]]  # pair id -> (lineage, value)
Reducer = Callable[[list[float]], float | None]


@dataclass(frozen=True)
class Interval:
    point: float | None
    lo: float | None
    hi: float | None
    undefined: int
    anti_conservative: bool


def mean_reducer(values: list[float]) -> float | None:
    return math.fsum(values) / len(values) if values else None


def _by_lineage(obs: Obs, ids: Sequence[str]) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {}
    for i in sorted(ids):
        g, v = obs[i]
        out.setdefault(g, []).append(v)
    return out


def _finish(vals: list[float], point: float | None, b_count: int, alpha: float, n_groups: int) -> Interval:
    iv = _interval(vals, b_count, alpha, n_groups)
    return Interval(point, iv['lo'], iv['hi'], iv['undefined'], iv['anti_conservative'])


def lineage_bootstrap(obs: Obs, b_count: int = B_COUNT, seed='evalcore', alpha: float = 0.05,
                      reducer: Reducer = mean_reducer) -> Interval:
    by_g = _by_lineage(obs, list(obs))
    gs = sorted(by_g)
    vals = []
    for draw in draws(gs, b_count, seed):
        v = reducer([x for g in draw for x in by_g[g]])
        if v is not None:
            vals.append(v)
    return _finish(vals, reducer([x for g in gs for x in by_g[g]]), b_count, alpha, len(gs))


def paired_delta_bootstrap(treatment: Obs, baseline: Obs, b_count: int = B_COUNT, seed='evalcore',
                           alpha: float = 0.05, reducer: Reducer = mean_reducer) -> Interval:
    """CI of reducer(treatment) - reducer(baseline) under the same lineage resamples. Both arms must cover
    the same pair ids with the same lineage for each id."""
    if set(treatment) != set(baseline):
        raise ValueError('paired arms must cover identical pair ids')
    ids = sorted(treatment)
    for i in ids:
        if treatment[i][0] != baseline[i][0]:
            raise ValueError(f'lineage mismatch for pair {i}')
    ta, tb = _by_lineage(treatment, ids), _by_lineage(baseline, ids)
    gs = sorted(ta)
    vals = []
    for draw in draws(gs, b_count, seed):
        a = reducer([x for g in draw for x in ta[g]])
        b = reducer([x for g in draw for x in tb[g]])
        if a is not None and b is not None:
            vals.append(a - b)
    pa, pb = reducer([x for g in gs for x in ta[g]]), reducer([x for g in gs for x in tb[g]])
    point = None if pa is None or pb is None else pa - pb
    return _finish(vals, point, b_count, alpha, len(gs))


def non_inferior(delta: Interval, margin: float) -> bool | None:
    """Paired lower bound strictly above `margin` (e.g. -0.02). None when undefined or anti-conservative
    (one lineage must never turn into a claim)."""
    if delta.lo is None or delta.anti_conservative:
        return None
    return delta.lo > margin


def headline_ok(n_lineages: int) -> bool:
    return n_lineages >= MIN_GROUPS_HEADLINE
