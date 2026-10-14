"""Weighted evaluation metrics (spec §9.1). Natural stratum, out-of-fold or locked-test predictions only."""
from __future__ import annotations

import math
from collections.abc import Sequence

from .mathcore import fit_platt, logit

ECE_BINS = 15  # fixed, equal-width, pre-registered


def brier(p: Sequence[float], y: Sequence[int], w: Sequence[float]) -> float:
    return math.fsum(wi * (pi - yi) ** 2 for pi, yi, wi in zip(p, y, w, strict=True)) / math.fsum(w)


def prevalence(y: Sequence[int], w: Sequence[float]) -> float:
    return math.fsum(wi * yi for yi, wi in zip(y, w, strict=True)) / math.fsum(w)


def brier_skill(p, y, w) -> float | None:
    prev = prevalence(y, w)
    ref = prev * (1 - prev)
    return None if ref == 0 else 1 - brier(p, y, w) / ref


def bin_index(p: float, bins: int = ECE_BINS) -> int:
    return min(int(p * bins), bins - 1)


def reliability(p, y, w, bins: int = ECE_BINS) -> list[dict]:
    acc = [[0, 0.0, 0.0, 0.0] for _ in range(bins)]  # n, sum_w, sum_wp, sum_wy
    for pi, yi, wi in zip(p, y, w, strict=True):
        cell = acc[bin_index(pi, bins)]
        cell[0] += 1
        cell[1] += wi
        cell[2] += wi * pi
        cell[3] += wi * yi
    return [{'bin': b, 'lo': b / bins, 'hi': (b + 1) / bins, 'n': n, 'w': sw,
             'conf': swp / sw if sw else None, 'acc': swy / sw if sw else None}
            for b, (n, sw, swp, swy) in enumerate(acc)]


def ece(p, y, w, bins: int = ECE_BINS) -> float:
    total = math.fsum(w)
    return math.fsum(r['w'] / total * abs(r['acc'] - r['conf']) for r in reliability(p, y, w, bins) if r['w'])


def ece_equal_mass(p, y, w, bins: int = 10) -> float:
    """Secondary: weight-equal adaptive bins over sorted predictions."""
    order = sorted(range(len(p)), key=lambda i: (p[i], i))
    total = math.fsum(w)
    out, cur, cur_w = 0.0, [], 0.0
    for k, i in enumerate(order):
        cur.append(i)
        cur_w += w[i]
        if cur_w >= total / bins - 1e-12 or k == len(order) - 1:
            conf = math.fsum(w[j] * p[j] for j in cur) / cur_w
            accy = math.fsum(w[j] * y[j] for j in cur) / cur_w
            out += cur_w / total * abs(accy - conf)
            cur, cur_w = [], 0.0
    return out


def mce_topbins(p, y, w, min_n: int = 30, min_conf: float = 0.8) -> float | None:
    vals = [abs(r['acc'] - r['conf']) for r in reliability(p, y, w)
            if r['n'] >= min_n and r['conf'] is not None and r['conf'] >= min_conf]
    return max(vals) if vals else None


def calib_slope_intercept(p, y, w) -> tuple[float, float]:
    """Logistic recalibration y ~ sigmoid(b + a*logit(p)): (slope a, intercept b); ideal (1, 0)."""
    a, b = fit_platt([logit(pi, 1e-6) for pi in p], y, w, smooth=False)
    return a, b


def logloss(p, y, w, eps: float = 1e-12) -> float:
    return -math.fsum(wi * (yi * math.log(max(pi, eps)) + (1 - yi) * math.log(max(1 - pi, eps)))
                      for pi, yi, wi in zip(p, y, w, strict=True)) / math.fsum(w)


def auc(p, y, w) -> float | None:
    """Weighted Mann-Whitney AUC; ties count one half."""
    order = sorted(range(len(p)), key=lambda i: p[i])
    neg_below = 0.0
    total = 0.0
    i = 0
    while i < len(order):
        j = i
        while j < len(order) and p[order[j]] == p[order[i]]:
            j += 1
        tie = order[i:j]
        tie_neg = math.fsum(w[k] for k in tie if not y[k])
        tie_pos = math.fsum(w[k] for k in tie if y[k])
        total += tie_pos * (neg_below + 0.5 * tie_neg)
        neg_below += tie_neg
        i = j
    pos = math.fsum(w[k] for k in range(len(p)) if y[k])
    neg = math.fsum(w) - pos
    return None if pos == 0 or neg == 0 else total / (pos * neg)


def coverage_precision_curve(p, y, w, abstain: Sequence[bool] | None = None) -> list[dict]:
    """Selective-classification curve; coverage is relative to ALL candidates (abstentions count against it).
    A whole tie block is advanced before a point is emitted."""
    abstain = abstain or [False] * len(p)
    idx = sorted((i for i in range(len(p)) if not abstain[i]), key=lambda i: (-p[i], i))
    total = math.fsum(w)
    cum_w = cum_pos = 0.0
    out = []
    for k, i in enumerate(idx):
        cum_w += w[i]
        cum_pos += w[i] * y[i]
        if k + 1 == len(idx) or p[idx[k + 1]] != p[i]:
            out.append({'tau': p[i], 'coverage': cum_w / total, 'precision': cum_pos / cum_w,
                        'fdr': 1 - cum_pos / cum_w, 'n': k + 1})
    return out


def precision_at(p, y, w, tau: float, abstain=None) -> float | None:
    abstain = abstain or [False] * len(p)
    sel = [i for i in range(len(p)) if p[i] >= tau and not abstain[i]]
    sw = math.fsum(w[i] for i in sel)
    return math.fsum(w[i] * y[i] for i in sel) / sw if sw else None


def coverage_at(p, w, tau: float, abstain=None) -> float:
    abstain = abstain or [False] * len(p)
    return math.fsum(w[i] for i in range(len(p)) if p[i] >= tau and not abstain[i]) / math.fsum(w)


def npv_at(p, y, w, tau_low: float, abstain=None) -> float | None:
    abstain = abstain or [False] * len(p)
    sel = [i for i in range(len(p)) if p[i] <= tau_low and not abstain[i]]
    sw = math.fsum(w[i] for i in sel)
    return math.fsum(w[i] * (1 - y[i]) for i in sel) / sw if sw else None


def downsample_curve(points: list[dict], limit: int = 200) -> list[dict]:
    if len(points) <= limit:
        return points
    step = (len(points) - 1) / (limit - 1)
    return [points[round(k * step)] for k in range(limit)]
