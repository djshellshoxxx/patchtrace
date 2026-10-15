"""Decision policy and display level (spec §9.5, §12). Pure.

`display_level()` is the seam C6 reads: it returns 'ordinal' (L0) unless a loaded, valid artifact carries
passing go/no-go gates. With no artifact it always returns 'ordinal'.
"""
from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .artifact import CalibrationArtifact, LoadResult, load_bundled, windows_scope_ok
from .features import FeatureRow
from .predict import Prediction, predict

# Mirrors tools.calibration.gates.G0_MIN['n_lineages'] (pinned equal by a test): an artifact whose calibration
# domain rests on fewer independent code sets than this never raises the display level, whatever gates it carries.
MIN_LINEAGES_FOR_CLAIM = 40
DisplayLevel = Literal['ordinal', 'bands', 'numeric']
Decision = Literal['auto-accept', 'review', 'likely-wrong', 'manual', 'abstain']


@dataclass(frozen=True)
class PolicyResult:
    match_id: str
    decision: Decision
    reason: str
    shown_p: float | None = None  # only for display level 'numeric', rounded DOWN to 5 %
    prediction: Prediction | None = None


def artifact_display_level(artifact: CalibrationArtifact | None) -> DisplayLevel:
    if artifact is None or not windows_scope_ok(artifact):
        return 'ordinal'  # synthetic (Tier R only) evidence can never raise the display level
    if artifact.calibration_domain.n_lineages < MIN_LINEAGES_FOR_CLAIM:
        return 'ordinal'  # too few independent code sets for any calibrated claim
    gates = artifact.evidence.gates
    if (artifact.status == 'numeric-ok' and artifact.policy.display == 'number'
            and all(gates.get(g) == 'pass' for g in ('G0', 'G2', 'G3'))):
        return 'numeric'
    if (artifact.status in ('bands-ok', 'numeric-ok') and artifact.policy.display in ('band', 'number')
            and all(gates.get(g) == 'pass' for g in ('G0', 'G2'))):
        return 'bands'
    return 'ordinal'


def display_level(profile: str | None = None, models: Mapping[str, LoadResult] | None = None) -> DisplayLevel:
    """Highest display level permitted. Without a profile: the lowest level over loaded profiles."""
    try:
        loaded = load_bundled() if models is None else models
        if profile is not None:
            result = loaded.get(profile)
            return artifact_display_level(result.artifact if result else None)
        if not loaded:
            return 'ordinal'
        order = ('ordinal', 'bands', 'numeric')
        return min((artifact_display_level(r.artifact) for r in loaded.values()), key=order.index)
    except Exception:  # noqa: BLE001 - the safe answer is always L0
        return 'ordinal'


def decide(row: FeatureRow, models: Mapping[str, LoadResult]) -> PolicyResult:
    """Fixed rule order; a model can never override `contested`."""
    if row.status in ('not-comparable', 'one-sided'):
        return PolicyResult(row.match_id, 'abstain', 'not-comparable')
    if row.status == 'contested':
        return PolicyResult(row.match_id, 'manual', 'contested')
    result = models.get(row.profile or '')
    artifact = result.artifact if result else None
    if artifact is None:
        return PolicyResult(row.match_id, 'abstain', 'no-model')
    prediction = predict(row, artifact)
    if prediction is None:
        return PolicyResult(row.match_id, 'abstain', 'missing-family')
    if any(flag.startswith('hard:') for flag in prediction.flags):
        return PolicyResult(row.match_id, 'abstain', 'ood', prediction=prediction)
    level = artifact_display_level(artifact)
    shown = math.floor(prediction.p * 20 + 1e-9) / 20 if level == 'numeric' else None
    tau, tau_low = artifact.policy.tau, artifact.policy.tau_low
    validated = artifact.status in ('bands-ok', 'numeric-ok')
    if validated and tau is not None and prediction.p >= tau:
        return PolicyResult(row.match_id, 'auto-accept', 'p >= tau', shown, prediction)
    if validated and tau_low is not None and prediction.p <= tau_low:
        return PolicyResult(row.match_id, 'likely-wrong', 'p <= tau_low', shown, prediction)
    return PolicyResult(row.match_id, 'review', 'between thresholds or unvalidated model', shown, prediction)
