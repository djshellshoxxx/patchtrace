"""Inference: impute, standardise, logit, calibrate (spec §7.2, §10.3). Pure dot product + interpolation."""
from __future__ import annotations

import bisect
import math
from dataclasses import dataclass

from .artifact import CalibrationArtifact, Isotonic
from .features import FeatureRow
from .ood import ood_flags


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def apply_isotonic(knots, s: float) -> float:
    xs = [k[0] for k in knots]
    if s <= xs[0]:
        return knots[0][1]
    if s >= xs[-1]:
        return knots[-1][1]
    i = bisect.bisect_right(xs, s)
    (x0, y0), (x1, y1) = knots[i - 1], knots[i]
    return y0 if x1 == x0 else y0 + (y1 - y0) * (s - x0) / (x1 - x0)


def apply_calibrator(calibrator, score: float) -> float:
    if isinstance(calibrator, Isotonic):
        return apply_isotonic(calibrator.knots, score)
    return sigmoid(calibrator.a * score + calibrator.b)


@dataclass(frozen=True)
class Prediction:
    match_id: str
    profile: str
    p: float
    score: float
    flags: tuple[str, ...]
    vector: tuple[tuple[str, float], ...]


def impute(row: FeatureRow, artifact: CalibrationArtifact) -> dict[str, float]:
    values = row.as_dict()
    return {f.name: f.median if values.get(f.name) is None else float(values[f.name]) for f in artifact.features}


def predict(row: FeatureRow, artifact: CalibrationArtifact) -> Prediction | None:
    """None when the row has no vector or its profile differs from the artifact (no imputation of families)."""
    if row.status != 'ok' or row.profile != artifact.profile:
        return None
    values = impute(row, artifact)
    score = artifact.intercept + math.fsum(f.coef * (values[f.name] - f.mean) / f.sd for f in artifact.features)
    p = round(min(1.0, max(0.0, apply_calibrator(artifact.calibrator, score))), 6)
    flags = ood_flags(values, dict(row.categories), row.engine_versions, artifact.ood)
    return Prediction(row.match_id, row.profile, p, score, flags,
                      tuple((f.name, values[f.name]) for f in artifact.features))


def provenance(prediction: Prediction, artifact: CalibrationArtifact, row: FeatureRow) -> dict:
    """Export block for a shown/exported prediction (spec §10.3)."""
    return {'model_id': artifact.model_id, 'model_digest_sha256': artifact.digest_sha256,
            'status': artifact.status, 'profile': prediction.profile, 'feature_schema': artifact.feature_schema,
            'features': [list(item) for item in prediction.vector], 'engine_versions': list(row.engine_versions),
            'flags': list(prediction.flags), 'tau': artifact.policy.tau, 'tau_low': artifact.policy.tau_low,
            'calibration_domain': artifact.calibration_domain.model_dump(mode='json'),
            'note': 'Estimate of function-match correctness only (target A); not calibrated outside the stated '
                    'domain; never a vulnerability probability.'}
