"""PIL identities (s7): every input digest, nothing else. Pure.

Each key is `enrichment.identity.domain_id(<domain>, 1, payload)` over canonical JSON; the domains are listed in
`DOMAINS`. Timestamps, review events, absolute paths and display preferences are never hashed. A candidate is
identified exactly like a SPEC-31 row (`unified.keys.row_id`: older/newer SHA-256 plus sorted RVAs); the formula is
re-derived here so the package imports no other feature, and a test pins the two to each other.

Records certify themselves: `verify_assessment`, `verify_manifest` and `verify_pointer` recompute every id and digest
and raise `PT-PILOT-INTEGRITY` on any mismatch (a tampered or foreign sidecar is never trusted).
"""
from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Sequence

from ..enrichment.identity import canonical_json, domain_id
from .contracts import (
    Observation,
    PilotAssessment,
    PilotConfig,
    PilotInputs,
    PilotManifest,
    PilotPart,
    PilotResultPointer,
)
from .limits import DEFAULT_LIMITS, PilotError, PilotLimits

DOMAINS = ('pilot-result', 'pilot-config', 'pilot-limits', 'pilot-obs', 'pilot-origins', 'unified-row')
KIND = 'patch-intent'  # reserved enrichment kind (storage.KINDS); not a derived kind, so retention never deletes it
POINTER_PREFIX = 'pilot-result:'
REVIEW_PREFIX = 'pilot-review:'
RELATIVE_ROOT = 'intelligence/pilot'
MANIFEST_NAME = 'manifest.json'
ASSESSMENT_NAME = 'assessment.json.gz'
_RVA_MAX = 2**32 - 1
_SHA256 = re.compile(r'[0-9a-f]{64}')
_NO_OBS_ID = '0' * 64


def limits_digest(limits: PilotLimits = DEFAULT_LIMITS) -> str:
    return domain_id('pilot-limits', 1, limits.as_dict())


def default_config(limits: PilotLimits = DEFAULT_LIMITS, **overrides) -> PilotConfig:
    """The plan defaults (locality 2 tokens, window 2 CVEs, lexical moderate allowed) under `limits`."""
    return PilotConfig(limits_digest=limits_digest(limits), **overrides)


def config_digest(config: PilotConfig) -> str:
    return domain_id('pilot-config', 1, config.model_dump(mode='json'))


def result_id(inputs: PilotInputs) -> str:
    return domain_id('pilot-result', 1, inputs.model_dump(mode='json'))


def changed_inputs(stored: PilotInputs, current: PilotInputs) -> tuple[str, ...]:
    """Names of the result_id inputs that differ (state L6 says which input changed)."""
    a, b = stored.model_dump(mode='json'), current.model_dump(mode='json')
    return tuple(name for name in PilotInputs.model_fields if a[name] != b[name])


def _rvas(values: Sequence[int], side: str) -> list[int]:
    out = []
    for value in values:
        if type(value) is not int or not 0 <= value <= _RVA_MAX:
            raise ValueError(f'{side} rva must be an int in 0..2**32-1')
        out.append(value)
    if len(set(out)) != len(out):
        raise ValueError(f'{side} rvas must be unique')
    return sorted(out)


def candidate_key(older_sha256: str, newer_sha256: str, older_rvas: Sequence[int], newer_rvas: Sequence[int]) -> str:
    """Stable across runs for the same pairing, different after an orientation swap; rva order does not matter."""
    older, newer = _rvas(older_rvas, 'older'), _rvas(newer_rvas, 'newer')
    if not older and not newer:
        raise ValueError('a candidate key needs at least one rva')
    return domain_id('unified-row', 1, {'older_sha256': older_sha256, 'newer_sha256': newer_sha256,
                                        'older_rvas': older, 'newer_rvas': newer})


def observation_id(observation: Observation) -> str:
    """Content id of an observation: every field except `obs_id` itself (equal content, equal id)."""
    payload = observation.model_dump(mode='json')
    del payload['obs_id']
    return domain_id('pilot-obs', 1, payload)


def make_observation(**fields) -> Observation:
    """Build an observation whose `obs_id` is derived from its content (all fields but `obs_id`)."""
    probe = Observation(obs_id=_NO_OBS_ID, **fields)
    return probe.model_copy(update={'obs_id': observation_id(probe)})


def canonical_bytes(record) -> bytes:
    """Canonical JSON (NFC strings, sorted keys, compact separators, UTF-8) of any contract record."""
    return canonical_json(record.model_dump(mode='json'))


def content_sha256(record) -> str:
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def _checked(value: str, what: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f'{what} must be a lower-case SHA-256 hex digest')
    return value


def pointer_entry_id(result: str) -> str:
    """Entry id of the pointer row (kind `patch-intent`)."""
    return POINTER_PREFIX + _checked(result, 'result_id')


def review_entry_id(uuid_text: str) -> str:
    """Entry id of a review event row; the id is the canonical lower-case UUID text."""
    if str(uuid.UUID(uuid_text)) != uuid_text:
        raise ValueError('review ids use the canonical lower-case UUID text')
    return REVIEW_PREFIX + uuid_text


def relative_dir(result: str) -> str:
    """Sidecar directory relative to the project root (kept short for Windows paths)."""
    return f'{RELATIVE_ROOT}/{_checked(result, "result_id")[:16]}'


def guard_parts(project_id: str, inputs: PilotInputs) -> tuple[str, str, str, str]:
    """The enrichment `Guard` fields: (project_id, ghidriff_run_id, raw_sha256, result_id)."""
    return project_id, inputs.ghidriff_run_id, inputs.raw_sha256, result_id(inputs)


# --- building and verifying the stored chain: assessment -> manifest -> pointer ---------------------------------------

def make_manifest(assessment: PilotAssessment, config: PilotConfig, *, created_utc: str) -> PilotManifest:
    data = canonical_bytes(assessment)
    part = PilotPart(name='assessment.json.gz', sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    return PilotManifest(result_id=assessment.result_id, inputs=assessment.inputs, config=config,
                         status=assessment.status, limitations=assessment.limitations,
                         counts=assessment.lead_counts(), queue_count=assessment.queue_count, parts=(part,),
                         created_utc=created_utc)


def make_pointer(manifest: PilotManifest) -> PilotResultPointer:
    return PilotResultPointer(result_id=manifest.result_id, relative_dir=relative_dir(manifest.result_id),
                              manifest_sha256=content_sha256(manifest), status=manifest.status,
                              counts=manifest.counts, config_digest=manifest.inputs.config_digest)


def _integrity(message: str, reason: str) -> PilotError:
    return PilotError('PT-PILOT-INTEGRITY', message, reason=reason)


def verify_assessment(assessment: PilotAssessment) -> None:
    if result_id(assessment.inputs) != assessment.result_id:
        raise _integrity('The assessment result id does not match its inputs', 'result-id')
    for observation in assessment.observations:
        if observation_id(observation) != observation.obs_id:
            raise _integrity('An observation id does not match its content', 'observation-id')


def verify_manifest(manifest: PilotManifest, assessment: PilotAssessment | None = None) -> None:
    """Check the manifest against itself and, when given, against the assessment it describes."""
    if result_id(manifest.inputs) != manifest.result_id:
        raise _integrity('The manifest result id does not match its inputs', 'result-id')
    if config_digest(manifest.config) != manifest.inputs.config_digest:
        raise _integrity('The manifest configuration does not match its inputs', 'config-digest')
    if assessment is None:
        return
    if assessment.result_id != manifest.result_id or assessment.inputs != manifest.inputs:
        raise _integrity('The assessment does not belong to this manifest', 'result-id')
    data = canonical_bytes(assessment)
    part = next(p for p in manifest.parts if p.name == 'assessment.json.gz')
    if part.sha256 != hashlib.sha256(data).hexdigest() or part.bytes != len(data):
        raise _integrity('The assessment part does not match its digest', 'part-digest')
    if (assessment.lead_counts(), assessment.queue_count) != (manifest.counts, manifest.queue_count):
        raise _integrity('The manifest counts do not match the assessment', 'counts')
    if (assessment.status, assessment.limitations) != (manifest.status, manifest.limitations):
        raise _integrity('The manifest status does not match the assessment', 'status')


def verify_pointer(pointer: PilotResultPointer, manifest: PilotManifest) -> None:
    if pointer.manifest_sha256 != content_sha256(manifest):
        raise _integrity('The pointer manifest digest does not match the manifest', 'manifest-digest')
    if pointer != make_pointer(manifest):
        raise _integrity('The pointer does not match its manifest', 'pointer')
