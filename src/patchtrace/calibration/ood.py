"""Apply a stored out-of-distribution spec (spec §9.6). Heuristic flags; validated offline, not assumed."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from .artifact import OodSpec


def mahalanobis2(x: Sequence[float], mu: Sequence[float], chol: Sequence[Sequence[float]]) -> float:
    """(x-mu)^T S^-1 (x-mu) with S = L L^T, L lower triangular (forward substitution)."""
    z: list[float] = []
    for i, row in enumerate(chol):
        acc = (x[i] - mu[i]) - sum(row[j] * z[j] for j in range(i))
        z.append(acc / row[i])
    return sum(v * v for v in z)


def ood_flags(values: Mapping[str, float], categories: Mapping[str, str], engine_versions: Sequence[str],
              spec: OodSpec) -> tuple[str, ...]:
    """`values` must already be median-imputed. Hard flags abstain; soft flags are shown only."""
    flags = []
    if spec.names and mahalanobis2([values[n] for n in spec.names], spec.mu, spec.chol) > spec.d2_cut:
        flags.append('hard:mahalanobis')
    elif spec.names and mahalanobis2([values[n] for n in spec.names], spec.mu, spec.chol) > spec.d2_soft:
        flags.append('soft:mahalanobis')
    for name, (lo, hi) in sorted(spec.ranges.items()):
        pad = 0.05 * (hi - lo)
        if not lo - pad <= values[name] <= hi + pad:
            flags.append('hard:range')
            break
    if any(cat in spec.cat_levels and level not in spec.cat_levels[cat] for cat, level in categories.items()):
        flags.append('hard:unseen-level')
    if any(version not in spec.engine_versions for version in engine_versions):
        flags.append('soft:engine-version')
    return tuple(flags)
