"""Paired lineage-bootstrap diagnostics for synthetic evaluator experiments.

Uses the repository's deterministic cluster bootstrap, B=2000. Both systems' counts occupy the SAME group
and are resampled together. UNVERIFIED: runtime and statistical tests have not been run.
Intervals on scripted data are diagnostics, never corpus evidence or vulnerability confidence.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from math import ceil, log
from typing import Any

from tools.unified import cluster


def rate(sums: tuple[float, ...]) -> float | None:
    return sums[0] / sums[1] if len(sums) >= 2 and sums[1] else None


def paired_difference(groups: Mapping[str, Sequence[float]], *, seed: str) -> dict[str, Any]:
    """Each lineage supplies [new hits, new opportunities, baseline hits, baseline opportunities]."""
    for counts in groups.values():
        if len(counts) != 4 or any(x < 0 for x in counts):
            raise ValueError("four non-negative counts per lineage required")
        if counts[0] > counts[1] or counts[2] > counts[3]:
            raise ValueError("hits exceed opportunities")

    def difference(sums: tuple[float, ...]) -> float | None:
        if not sums or not sums[1] or not sums[3]:
            return None
        return sums[0] / sums[1] - sums[2] / sums[3]

    return cluster.ci(groups, difference, seed=seed)


def zero_event_cases(maximum_rate: float, alpha: float = 0.05) -> int:
    """Independent Bernoulli planning only: (1-p)^n <= alpha; not a clustered power calculation."""
    if not 0 < maximum_rate < 1 or not 0 < alpha < 1:
        raise ValueError("rates must be inside (0, 1)")
    return ceil(log(alpha) / log(1 - maximum_rate))
