"""Abstention thresholds by fixed-sequence Learn-then-Test (spec §9.3 as amended; Angelopoulos et al.,
"Learn then Test", arXiv 2110.01052 - verify before ratification).

Each grid point tau is the null H_tau: "error rate among auto-accepted (p >= tau) > alpha". Hypotheses are
tested in a FIXED order from strict to loose with an exact binomial p-value at the design-effect effective n
(lineage clustering + weights), stopping at the first non-rejection; this controls the family-wise error
at delta without a union penalty. Two label-free rules shape the sequence BEFORE any label is used:
(1) it starts where the accepted set's Kish n reaches `ltt_start_n` (the size at which a true risk of alpha/2
is certified with 80 % power; smaller strict sets would almost surely stop the sequence on one error), and
(2) a grid point selecting the same set as the previous tested point is skipped, so a certified tau is never
extrapolated into a score range that contains no data.
Thresholds are chosen on dev OOF only and frozen into the artifact; locked-test evaluates the frozen tau.
"""
from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence

from .common import Row
from .stats import binom_cdf, effective_n, icc_anova, kish_n, ltt_start_n

TAU_GRID = tuple(round(1 - k / 1000, 3) for k in range(1, 501))       # 0.999 -> 0.500 (strict -> loose)
TAU_LOW_GRID = tuple(round(k / 1000, 3) for k in range(1, 501))       # 0.001 -> 0.500 (strict -> loose)
TARGET_PRECISION = 0.95
TARGET_NPV = 0.90
DELTA = 0.05
RHO_UNDEFINED = 1.0  # no information on error clustering -> most conservative design effect


def lineage_rho(rows: Sequence[Row]) -> float:
    """ICC of the error indicator (1 - y) by lineage over all natural rows (label-based, estimated once)."""
    return icc_anova([r.group for r in rows], [1.0 - r.y for r in rows], undefined=RHO_UNDEFINED)


def ltt_pvalue(selected: Sequence[Row], is_error: Callable[[Row], float], alpha: float, rho: float) -> dict:
    """Conservative exact binomial p-value of H: risk > alpha, at n = floor(n_eff), k = ceil(risk_hat*n_eff)."""
    if not selected:
        return {'p_value': 1.0, 'n_eff': 0.0, 'risk': None, 'k': 0, 'n': 0}
    w = [r.w for r in selected]
    risk = math.fsum(r.w * is_error(r) for r in selected) / math.fsum(w)
    n_eff = effective_n([r.group for r in selected], w, rho)
    n = math.floor(n_eff + 1e-9)
    k = math.ceil(risk * n_eff - 1e-9)
    return {'p_value': binom_cdf(k, n, alpha) if n else 1.0, 'n_eff': n_eff, 'risk': risk, 'k': k, 'n': n}


def _fixed_sequence(nat: Sequence[Row], grid: Sequence[float], select: Callable[[Row, float], bool],
                    is_error: Callable[[Row], float], alpha: float, delta: float, rho: float) -> tuple:
    min_n = ltt_start_n(round(alpha, 12), delta)
    trace, certified, previous = [], None, None
    for t in grid:
        sel = [r for r in nat if select(r, t)]
        if kish_n([r.w for r in sel]) < min_n:  # rule (1): label-free, before testing
            continue
        if previous is not None and len(sel) == previous:  # rule (2): identical set, no new hypothesis
            continue
        previous = len(sel)
        test = ltt_pvalue(sel, is_error, alpha, rho)
        trace.append({'tau': t, **test})
        if test['p_value'] > delta:
            break
        certified = (t, test)
    return certified, trace


def choose_tau(rows: Sequence[Row], oof: Mapping[str, float], *, target_precision: float = TARGET_PRECISION,
               delta: float = DELTA, grid: Sequence[float] = TAU_GRID, rho: float | None = None) -> dict | None:
    """Loosest certified tau, or None (artifact then ships tau=None: everything goes to review)."""
    nat = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: r.id)
    rho = lineage_rho(nat) if rho is None else rho
    certified, trace = _fixed_sequence(nat, grid, lambda r, t: not r.abstain and oof[r.id] >= t,
                                       lambda r: 1.0 - r.y, 1 - target_precision, delta, rho)
    if certified is None:
        return None
    tau, test = certified
    total = math.fsum(r.w for r in nat)
    acc = [r for r in nat if not r.abstain and oof[r.id] >= tau]
    return {'tau': tau, 'coverage': math.fsum(r.w for r in acc) / total, 'precision': 1 - test['risk'],
            'p_value': test['p_value'], 'n_eff': test['n_eff'], 'rho': rho, 'delta': delta,
            'alpha': 1 - target_precision, 'tested': len(trace)}


def choose_tau_low(rows: Sequence[Row], oof: Mapping[str, float], tau: float | None, *,
                   target_npv: float = TARGET_NPV, delta: float = DELTA, grid: Sequence[float] = TAU_LOW_GRID,
                   rho: float | None = None) -> dict | None:
    """Loosest certified 'likely wrong' threshold below tau (NPV >= target_npv), or None (omitted)."""
    nat = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: r.id)
    rho = lineage_rho(nat) if rho is None else rho
    usable = [t for t in grid if tau is None or t < tau]
    certified, _ = _fixed_sequence(nat, usable, lambda r, t: not r.abstain and oof[r.id] <= t,
                                   lambda r: float(r.y), 1 - target_npv, delta, rho)
    if certified is None:
        return None
    t, test = certified
    return {'tau_low': t, 'npv': 1 - test['risk'], 'p_value': test['p_value'], 'n_eff': test['n_eff'], 'rho': rho}


def evaluate_frozen_tau(rows: Sequence[Row], preds: Mapping[str, float], tau: float, *,
                        target_precision: float = TARGET_PRECISION, delta: float = DELTA,
                        rho: float | None = None) -> dict:
    """Locked-test: the single hypothesis at the frozen tau (a one-element fixed sequence)."""
    nat = sorted((r for r in rows if r.stratum == 'natural'), key=lambda r: r.id)
    rho = lineage_rho(nat) if rho is None else rho
    sel = [r for r in nat if not r.abstain and preds[r.id] >= tau]
    test = ltt_pvalue(sel, lambda r: 1.0 - r.y, 1 - target_precision, rho)
    return {'tau': tau, 'rho': rho, 'delta': delta, 'certified': test['p_value'] <= delta, **test}
