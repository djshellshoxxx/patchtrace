"""The report's `calibration` block (SPEC-50 section 6, "Uncalibrated number shown as vulnerability confidence").

The exporter asks `calibration.policy.display_level()` itself and caps any caller request at that answer. Anything short
of a loaded artifact that supplies model id, digest and gates degrades to `ordinal`, which carries no numbers at all.
"""
from __future__ import annotations

from collections.abc import Mapping

from ..calibration.artifact import LoadResult, load_bundled
from ..calibration.policy import display_level
from .contracts import Calibration

_ORDER = ('ordinal', 'bands', 'numeric')


def _details(profile: str | None, models: Mapping[str, LoadResult] | None) -> dict | None:
    try:
        artifact = (load_bundled() if models is None else models).get(profile or '')
        artifact = artifact.artifact if artifact else None
        if artifact is None:
            return None
        return {'profile': profile, 'model_id': artifact.model_id, 'artifact_digest': artifact.digest_sha256,
                'gates': {str(g): str(s) for g, s in artifact.evidence.gates.items()}}
    except Exception:  # noqa: BLE001 - the safe answer is always ordinal
        return None


def build_calibration_block(requested: str = 'ordinal', *, profile: str | None = None,
                            models: Mapping[str, LoadResult] | None = None) -> Calibration:
    if requested not in _ORDER:
        raise ValueError(f'display level must be one of {_ORDER}')
    permitted = display_level(profile, models)
    level = _ORDER[min(_ORDER.index(requested), _ORDER.index(permitted))]
    if level != 'ordinal':
        details = _details(profile, models)
        if details is not None and details['gates']:
            try:
                return Calibration(display_level=level, **details)
            except ValueError:
                pass
    return Calibration(display_level='ordinal')
