"""Lineage-cluster bootstrap of a statistic of summed counts (08-evaluation s1 [inf]: B = 2000, lineage-grouped).

Whole lineages are resampled with replacement through `tools.calibration.bootstrap.draws` (platform-independent, seeded by
text), so the interval is the same on every machine. A group holds a tuple of counts; the statistic reads the column sums.
With fewer than `MIN_GROUPS_HEADLINE` lineages the interval is flagged `anti_conservative` and the gates never pass on it.
"""
from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence

from tools.calibration.bootstrap import MIN_GROUPS_HEADLINE, draws

B_COUNT = 2000
ALPHA = 0.05
Stat = Callable[[tuple[float, ...]], float | None]


def _sums(rows: Sequence[Sequence[float]]) -> tuple[float, ...]:
    return tuple(math.fsum(col) for col in zip(*rows, strict=True)) if rows else ()


def _r(x: float | None) -> float | None:
    return None if x is None else round(x, 6)


def ci(groups: Mapping[str, Sequence[float]], stat: Stat, *, seed: str, b_count: int = B_COUNT) -> dict:
    """{'point', 'lo', 'hi', 'groups', 'anti_conservative', 'undefined'}; `lo`/`hi` are None when no draw was defined."""
    names = sorted(groups)
    point = stat(_sums([groups[g] for g in names])) if names else None
    values = []
    for draw in draws(names, b_count, seed) if names else []:
        value = stat(_sums([groups[g] for g in draw]))
        if value is not None:
            values.append(value)
    values.sort()
    lo = values[int(ALPHA / 2 * len(values))] if values else None
    hi = values[min(len(values) - 1, int((1 - ALPHA / 2) * len(values)))] if values else None
    return {'point': _r(point), 'lo': _r(lo), 'hi': _r(hi), 'groups': len(names), 'undefined': b_count - len(values),
            'anti_conservative': len(names) < MIN_GROUPS_HEADLINE}


def rate(num: int, den: int, places: int = 6) -> float | None:
    return round(num / den, places) if den else None
