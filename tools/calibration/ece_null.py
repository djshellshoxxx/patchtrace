"""Null-calibration simulation for the ECE gate (spec §12 H1 as amended).

The plug-in ECE is biased upward even for a perfectly calibrated model (roughly
sum_b (n_b/n) sqrt(2/pi) sqrt(p_b(1-p_b)/n_b)), so the gate is not an absolute constant: the observed ECE
is compared with its distribution under perfect calibration at the SAME predictions, bins, weights and
lineage clustering. Per bin, outcomes are simulated as Binomial(n_eff_b, conf_b)/n_eff_b where
n_eff_b = Kish_b / (1 + (m_bar_b - 1) * rho) and rho is the ICC of residuals (y - p) by lineage.
For this gate an undefined rho falls back to 0 (smallest null ECE = strictest gate).
"""
from __future__ import annotations

import math
from collections.abc import Sequence

from .metrics import ECE_BINS, bin_index
from .stats import binom_draw, design_effect, icc_anova, kish_n

NULL_SIMS = 1000
RHO_UNDEFINED = 0.0


def residual_rho(p: Sequence[float], y: Sequence[int], groups: Sequence[str]) -> float:
    return icc_anova(list(groups), [yi - pi for pi, yi in zip(p, y, strict=True)], undefined=RHO_UNDEFINED)


def ece_null(p: Sequence[float], w: Sequence[float], groups: Sequence[str], *, rho: float,
             sims: int = NULL_SIMS, seed=31, bins: int = ECE_BINS) -> dict:
    total = math.fsum(w)
    cells: list[dict] = []
    for b in range(bins):
        idx = [i for i in range(len(p)) if bin_index(p[i], bins) == b]
        if not idx:
            continue
        wb = [w[i] for i in idx]
        sw = math.fsum(wb)
        n_eff = kish_n(wb) / design_effect([groups[i] for i in idx], rho)
        cells.append({'bin': b, 'share': sw / total, 'conf': math.fsum(w[i] * p[i] for i in idx) / sw,
                      'n': len(idx), 'n_eff': n_eff, 'n_sim': max(1, round(n_eff))})
    values = []
    for s in range(sims):
        acc = 0.0
        for c in cells:
            k = binom_draw(c['n_sim'], c['conf'], seed, 'ece-null', s, c['bin'])
            acc += c['share'] * abs(k / c['n_sim'] - c['conf'])
        values.append(acc)
    values.sort()
    mean = math.fsum(values) / len(values) if values else 0.0
    return {'null_mean': mean, 'null_q95': values[min(len(values) - 1, int(0.95 * len(values)))] if values else 0.0,
            'rho': rho, 'sims': sims, 'bins': [{k: c[k] for k in ('bin', 'n', 'n_eff')} for c in cells],
            'values': values}


def ece_null_summary(observed: float, ci_hi: float | None, null: dict) -> dict:
    """What the gate reads: excess over the null mean (point and CI upper) and the null p-value."""
    vals = null['values']
    p_value = (sum(v >= observed for v in vals) + 1) / (len(vals) + 1) if vals else None
    return {'observed': observed, 'null_mean': null['null_mean'], 'null_q95': null['null_q95'], 'rho': null['rho'],
            'excess': observed - null['null_mean'],
            'excess_hi': None if ci_hi is None else ci_hi - null['null_mean'], 'p_value': p_value,
            'bins': null['bins']}


def debiased_l2(p: Sequence[float], y: Sequence[int], w: Sequence[float], bins: int = ECE_BINS) -> float:
    """Reported only: squared-error calibration estimate with per-bin variance removed (Kumar et al. 2019
    style, effective n per bin), returned as sqrt(max(0, .))."""
    total = math.fsum(w)
    acc = []
    for b in range(bins):
        idx = [i for i in range(len(p)) if bin_index(p[i], bins) == b]
        if not idx:
            continue
        wb = [w[i] for i in idx]
        sw = math.fsum(wb)
        conf = math.fsum(w[i] * p[i] for i in idx) / sw
        hit = math.fsum(w[i] * y[i] for i in idx) / sw
        n_eff = kish_n(wb)
        var = hit * (1 - hit) / (n_eff - 1) if n_eff > 1 else 0.0
        acc.append(sw / total * ((hit - conf) ** 2 - var))
    return math.sqrt(max(0.0, math.fsum(acc)))
