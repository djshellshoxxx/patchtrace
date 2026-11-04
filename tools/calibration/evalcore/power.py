"""Lineage-level power helpers (normal approximation; LBL-10, hardened in audit 20261014-C).

Effective n is lineages, not mutants. `sd` is the sample standard deviation of per-lineage paired differences,
so every formula below is the ONE-SAMPLE (paired) z-test of a mean difference.

Formulas and sources (verified against the textbook derivation, not copied from code):
* Two-sided test at level alpha detecting a true mean difference delta with power 1 - beta needs
  n = ((z_{1-alpha/2} + z_{1-beta}) * sd / delta)**2 (the far-tail term is ignored in this closed form, which is
  accurate for any delta with power >= 0.5). Chow, Shao & Wang, "Sample Size Calculation in Clinical Research",
  2nd ed., CRC 2008, section 3.2.1 (test for equality, one-sample), eq. 3.2.2 form.
* Exact power of the two-sided z-test: Phi(shift - z_{1-alpha/2}) + Phi(-shift - z_{1-alpha/2}) with
  shift = |delta| sqrt(n) / sd; at delta = 0 this equals alpha (type-I error), not alpha/2.
* One-sided non-inferiority (H0: delta <= margin, margin < 0; H1: delta > margin) at level alpha with true
  difference d needs n = ((z_{1-alpha} + z_{1-beta}) * sd / (d - margin))**2. Chow et al. 2008, section 3.2.2
  (non-inferiority, one-sample); Julious, "Sample sizes for clinical trials with normal data", Stat Med 23(12),
  2004. The one-sided test uses alpha, not alpha/2.
* Decision level of non-inferiority: `boot.non_inferior` reads the lower bound of the TWO-sided 95% interval, which
  is a one-sided test at 0.025, so `noninferiority_lineages` sizes at `NI_ALPHA = 0.025` by default (ICH E9,
  "Statistical Principles for Clinical Trials", 1998, section 5.5: one-sided tests at half the two-sided level).
  Sizing at one-sided 0.05 against that rule undersizes (about 0.70 achieved power for a nominal 0.8).
* `power_for_delta` evaluated at an OBSERVED estimate (as `evalcore.report.paired_delta` does) is observed power: a
  one-to-one function of the observed p-value, descriptive only and never evidence of no difference (Hoenig &
  Heisey, "The abuse of power", The American Statistician 55(1):19-24, 2001). Report it with the sd and the minimum
  detectable delta, never alone.
* The normal approximation understates n when sd is estimated from few lineages. `lineages_needed_t` adds the
  Guenther (1981) correction n_t ~= n_z + z_{1-alpha/2}**2 / 2 (one-sided: z_{1-alpha}**2 / 2), Guenther,
  "Sample size formulas for normal theory t tests", The American Statistician 35(4):243-244. Use it for the
  go/no-go sizing; the bootstrap itself is declared anti-conservative below 30 lineages (`anti_conservative`).
Inputs are validated: 0 < alpha < 1, 0 < power < 1, sd >= 0, n_lineages >= 1.
"""
from __future__ import annotations

import math
import statistics
from collections.abc import Sequence

from ..bootstrap import MIN_GROUPS_HEADLINE

_N = statistics.NormalDist()
NI_ALPHA = 0.025  # one-sided level of 'two-sided 95% lower bound > margin' (boot.non_inferior; ICH E9 s5.5)


def anti_conservative(n_lineages: int) -> bool:
    return n_lineages < MIN_GROUPS_HEADLINE


def lineage_sd(per_lineage_deltas: Sequence[float]) -> float | None:
    return statistics.stdev(per_lineage_deltas) if len(per_lineage_deltas) >= 2 else None


def _check(alpha: float, power: float | None = None, sd: float | None = None) -> None:
    if not 0 < alpha < 1:
        raise ValueError('alpha must be in (0, 1)')
    if power is not None and not 0 < power < 1:
        raise ValueError('power must be in (0, 1)')
    if sd is not None and not (math.isfinite(sd) and sd >= 0):
        raise ValueError('sd must be finite and >= 0')


def _z(alpha: float, power: float, one_sided: bool) -> float:
    _check(alpha, power)
    return _N.inv_cdf(1 - (alpha if one_sided else alpha / 2)) + _N.inv_cdf(power)


def min_detectable_delta(n_lineages: int, sd: float, alpha: float = 0.05, power: float = 0.8,
                         one_sided: bool = False) -> float:
    if n_lineages < 1:
        raise ValueError('n_lineages must be >= 1')
    _check(alpha, power, sd)
    return _z(alpha, power, one_sided) * sd / math.sqrt(n_lineages)


def lineages_needed(delta: float, sd: float, alpha: float = 0.05, power: float = 0.8,
                    one_sided: bool = False) -> int:
    if delta <= 0:
        raise ValueError('delta must be > 0')
    _check(alpha, power, sd)
    return max(1, math.ceil((_z(alpha, power, one_sided) * sd / delta) ** 2))


def lineages_needed_t(delta: float, sd: float, alpha: float = 0.05, power: float = 0.8,
                      one_sided: bool = False) -> int:
    """`lineages_needed` plus the Guenther (1981) small-sample term z_crit**2 / 2 (t instead of z)."""
    crit = _N.inv_cdf(1 - (alpha if one_sided else alpha / 2))
    return lineages_needed(delta, sd, alpha, power, one_sided) + math.ceil(crit * crit / 2)


def power_for_delta(delta: float, n_lineages: int, sd: float, alpha: float = 0.05,
                    one_sided: bool = False) -> float:
    """Power of the z-test against a true difference `delta`. At an observed estimate this is observed power:
    descriptive only, never evidence of no difference (Hoenig & Heisey 2001)."""
    _check(alpha, None, sd)
    if n_lineages < 1:
        raise ValueError('n_lineages must be >= 1')
    crit = _N.inv_cdf(1 - (alpha if one_sided else alpha / 2))
    if sd <= 0:
        return 1.0 if delta != 0 else 0.0
    shift = delta * math.sqrt(n_lineages) / sd
    if one_sided:
        return _N.cdf(shift - crit)
    return _N.cdf(shift - crit) + _N.cdf(-shift - crit)


def noninferiority_lineages(margin: float, true_delta: float, sd: float, alpha: float = NI_ALPHA,
                            power: float = 0.8) -> int:
    """Lineages so a true delta clears 'lower bound > margin' (margin < 0) with the given power:
    n = ((z_{1-alpha} + z_power) * sd / (true_delta - margin))**2, one-sided at `alpha`. The default matches the
    decision rule (lower bound of the two-sided 95% interval, i.e. one-sided 0.025)."""
    gap = true_delta - margin
    if gap <= 0:
        raise ValueError('true_delta must exceed margin')
    return lineages_needed(gap, sd, alpha, power, one_sided=True)
