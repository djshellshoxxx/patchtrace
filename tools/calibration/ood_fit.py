"""Fit the OOD spec stored in the artifact (spec §9.6) and validate it (flagged error rate must exceed
unflagged; otherwise hard flags reduce to range/unseen-level only)."""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from patchtrace.calibration.artifact import OodSpec
from patchtrace.calibration.ood import mahalanobis2, ood_flags

from .common import canonical_json, r12, weighted_quantile
from .mathcore import cholesky

SHRINK = 0.1
SOFT_Q, HARD_Q = 0.99, 0.995


def ood_fit(rows: Sequence[Mapping[str, float]], w: Sequence[float], continuous: Sequence[str],
            categories: Sequence[Mapping[str, str]], engine_versions: Sequence[str]) -> dict:
    """`rows` are median-imputed feature dicts from TRAINING folds only."""
    names = list(continuous)
    total = math.fsum(w)
    mu = [math.fsum(wi * r[n] for r, wi in zip(rows, w, strict=True)) / total for n in names]
    d = len(names)
    cov = [[math.fsum(wi * (r[names[i]] - mu[i]) * (r[names[j]] - mu[j]) for r, wi in zip(rows, w, strict=True))
            / total for j in range(d)] for i in range(d)]
    for i in range(d):
        cov[i][i] = max(cov[i][i], 1e-9)
    shrunk = [[cov[i][j] * (1 - SHRINK) if i != j else cov[i][i] for j in range(d)] for i in range(d)]
    low = cholesky(shrunk) if d else []
    d2 = [mahalanobis2([r[n] for n in names], mu, low) for r in rows] if d else [0.0] * len(rows)
    ranges = {}
    for n in names:
        vals = [r[n] for r in rows]
        ranges[n] = [r12(weighted_quantile(vals, w, 0.001)), r12(weighted_quantile(vals, w, 0.999))]
    levels: dict[str, set[str]] = {}
    for cats in categories:
        for k, v in cats.items():
            levels.setdefault(k, set()).add(v)
    return {'names': names, 'mu': [r12(v) for v in mu],
            'chol': [[r12(low[i][j]) for j in range(i + 1)] for i in range(d)],
            'd2_soft': r12(weighted_quantile(d2, w, SOFT_Q)), 'd2_cut': r12(weighted_quantile(d2, w, HARD_Q)),
            'ranges': ranges, 'cat_levels': {k: sorted(v) for k, v in sorted(levels.items())},
            'engine_versions': sorted(set(engine_versions))}


def apply_spec(spec: Mapping, values: Mapping[str, float], categories: Mapping[str, str] | None = None,
               engine_versions: Sequence[str] = ()) -> tuple[str, ...]:
    """Flags exactly as the shipped runtime computes them (same OodSpec model and ood_flags code)."""
    return ood_flags(values, categories or {}, engine_versions, OodSpec.model_validate_json(canonical_json(dict(spec))))


def reduce_spec(spec: Mapping) -> dict:
    """Preregistered fallback when validation fails: drop the Mahalanobis test, keep range/unseen-level."""
    return dict(spec, names=[], mu=[], chol=[], d2_soft=0.0, d2_cut=0.0)


def risk_ratio(flagged: Sequence[bool], error: Sequence[int], w: Sequence[float]) -> float | None:
    """Weighted error rate of flagged / unflagged rows."""
    def rate(sel):
        sw = math.fsum(wi for f, wi in zip(flagged, w, strict=True) if f == sel)
        return math.fsum(wi * e for f, e, wi in zip(flagged, error, w, strict=True) if f == sel) / sw if sw else None
    a, b = rate(True), rate(False)
    return None if a is None or not b else a / b
