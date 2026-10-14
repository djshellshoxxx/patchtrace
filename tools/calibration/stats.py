"""Small exact/approximate statistics used by Learn-then-Test and the ECE null simulation (stdlib only).

Design effect for clustered (lineage) data: n_eff = Kish_n / (1 + (m_bar - 1) * rho), with
Kish_n = (sum w)^2 / sum w^2, m_bar = sum_g n_g^2 / N (size-weighted mean cluster size) and rho the
one-way ANOVA intra-class correlation, clipped to [0, 1].
"""
from __future__ import annotations

import functools
import math
from collections.abc import Sequence

from .common import det_normal, det_uniform


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), summed in log space with fsum."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0:
        return 1.0
    if p >= 1:
        return 0.0
    lp, lq = math.log(p), math.log1p(-p)
    base = math.lgamma(n + 1)
    terms = [math.exp(base - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq)
             for i in range(k + 1)]
    return min(1.0, math.fsum(terms))


def binom_draw(n: int, p: float, seed, *key) -> int:
    """Deterministic Binomial(n, p) draw: exact inverse CDF when n*p*(1-p) < 50, else a rounded normal
    approximation (documented approximation; used only for null simulations)."""
    if n <= 0 or p <= 0:
        return 0
    if p >= 1:
        return n
    flip = p > 0.5
    q = 1 - p if flip else p
    if n * q * (1 - q) >= 50:
        x = round(n * q + math.sqrt(n * q * (1 - q)) * det_normal(seed, *key))
        x = min(n, max(0, x))
    else:
        u = det_uniform(seed, *key)
        pmf = math.exp(n * math.log1p(-q))
        cdf, x = pmf, 0
        ratio = q / (1 - q)
        while cdf < u and x < n:
            pmf *= (n - x) / (x + 1) * ratio
            x += 1
            cdf += pmf
    return n - x if flip else x


def icc_anova(groups: Sequence[str], values: Sequence[float], *, undefined: float) -> float:
    """One-way ANOVA intra-class correlation of `values` within `groups`, clipped to [0, 1].
    Returns `undefined` when it cannot be estimated (fewer than 2 groups or no variance at all)."""
    by_g: dict[str, list[float]] = {}
    for g, v in zip(groups, values, strict=True):
        by_g.setdefault(g, []).append(v)
    n_total, n_groups = len(values), len(by_g)
    if n_groups < 2 or n_total <= n_groups:
        return undefined
    grand = math.fsum(values) / n_total
    means = {g: math.fsum(v) / len(v) for g, v in by_g.items()}
    ssb = math.fsum(len(v) * (means[g] - grand) ** 2 for g, v in by_g.items())
    ssw = math.fsum((x - means[g]) ** 2 for g, v in by_g.items() for x in v)
    msb, msw = ssb / (n_groups - 1), ssw / (n_total - n_groups)
    n0 = (n_total - math.fsum(len(v) ** 2 for v in by_g.values()) / n_total) / (n_groups - 1)
    denom = msb + (n0 - 1) * msw
    if denom <= 0:
        return undefined
    return min(1.0, max(0.0, (msb - msw) / denom))


def kish_n(w: Sequence[float]) -> float:
    sq = math.fsum(v * v for v in w)
    return math.fsum(w) ** 2 / sq if sq else 0.0


def design_effect(groups: Sequence[str], rho: float) -> float:
    counts: dict[str, int] = {}
    for g in groups:
        counts[g] = counts.get(g, 0) + 1
    n = len(groups)
    if not n:
        return 1.0
    m_bar = math.fsum(c * c for c in counts.values()) / n
    return 1.0 + (m_bar - 1.0) * rho


def effective_n(groups: Sequence[str], w: Sequence[float], rho: float) -> float:
    return kish_n(w) / design_effect(groups, rho)


def zero_error_min_n(alpha: float, delta: float) -> int:
    """Smallest n whose all-correct outcome rejects 'risk > alpha' at level delta (59 for 0.05/0.05)."""
    return math.ceil(math.log(delta) / math.log(1 - alpha))


@functools.lru_cache(maxsize=64)
def ltt_start_n(alpha: float, delta: float, power: float = 0.8, r0: float | None = None) -> int:
    """Smallest n at which a true risk r0 (default alpha/2) is certified (H: risk > alpha rejected at delta)
    with probability >= power. Label-free design constant for where a fixed LTT sequence starts."""
    r0 = alpha / 2 if r0 is None else r0
    n = zero_error_min_n(alpha, delta)
    k = 0
    while n < 1_000_000:
        while binom_cdf(k + 1, n, alpha) <= delta:
            k += 1
        if binom_cdf(k, n, alpha) <= delta and binom_cdf(k, n, r0) >= power:
            return n
        n += 1
    raise ValueError('no feasible LTT start size')
