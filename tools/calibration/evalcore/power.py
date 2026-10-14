"""Lineage-level power helpers (normal approximation; LBL-10).

Effective n is lineages, not mutants. `sd` is the sample standard deviation of per-lineage paired
differences. Two-sided tests use alpha/2; the one-sided variant (non-inferiority) uses alpha.
"""
from __future__ import annotations

import math
import statistics
from collections.abc import Sequence

from ..bootstrap import MIN_GROUPS_HEADLINE

_N = statistics.NormalDist()


def anti_conservative(n_lineages: int) -> bool:
    return n_lineages < MIN_GROUPS_HEADLINE


def lineage_sd(per_lineage_deltas: Sequence[float]) -> float | None:
    return statistics.stdev(per_lineage_deltas) if len(per_lineage_deltas) >= 2 else None


def _z(alpha: float, power: float, one_sided: bool) -> float:
    return _N.inv_cdf(1 - (alpha if one_sided else alpha / 2)) + _N.inv_cdf(power)


def min_detectable_delta(n_lineages: int, sd: float, alpha: float = 0.05, power: float = 0.8,
                         one_sided: bool = False) -> float:
    if n_lineages < 1:
        raise ValueError('n_lineages must be >= 1')
    return _z(alpha, power, one_sided) * sd / math.sqrt(n_lineages)


def lineages_needed(delta: float, sd: float, alpha: float = 0.05, power: float = 0.8,
                    one_sided: bool = False) -> int:
    if delta <= 0:
        raise ValueError('delta must be > 0')
    return max(1, math.ceil((_z(alpha, power, one_sided) * sd / delta) ** 2))


def power_for_delta(delta: float, n_lineages: int, sd: float, alpha: float = 0.05,
                    one_sided: bool = False) -> float:
    if sd <= 0:
        return 1.0 if delta != 0 else 0.0
    crit = _N.inv_cdf(1 - (alpha if one_sided else alpha / 2))
    shift = abs(delta) * math.sqrt(n_lineages) / sd
    return _N.cdf(shift - crit)


def noninferiority_lineages(margin: float, true_delta: float, sd: float, alpha: float = 0.05,
                            power: float = 0.8) -> int:
    """Lineages so a true delta clears 'lower bound > margin' (margin < 0) with the given power:
    n = ((z_alpha + z_power) * sd / (true_delta - margin))**2, one-sided."""
    gap = true_delta - margin
    if gap <= 0:
        raise ValueError('true_delta must exceed margin')
    return lineages_needed(gap, sd, alpha, power, one_sided=True)
