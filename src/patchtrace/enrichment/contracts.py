"""Strict, frozen enrichment/1 records (SPEC-07). Pure: no Qt, Ghidra, network or I/O.

Every record forbids extra fields and coerces nothing (strict mode), so booleans are
never accepted as integers and floats never stand in for scores. Records are frozen
so a validated view cannot be mutated after a stage has hashed it.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CONTRACT = 'enrichment/1'
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Status = Literal['complete', 'partial', 'unavailable', 'cancelled', 'failed']
Side = Literal['older', 'newer']
Confidence = Literal['strong', 'moderate', 'weak', 'unavailable']
DetectorId = Literal['BND', 'INT', 'OVF', 'VAL', 'ERR', 'SIZE', 'WIL', 'SCRUB']
DETECTOR_IDS: tuple[str, ...] = ('BND', 'INT', 'OVF', 'VAL', 'ERR', 'SIZE', 'WIL', 'SCRUB')
DEFAULT_WEIGHTS: dict[str, int] = {'BND': 30, 'INT': 22, 'OVF': 28, 'VAL': 20, 'ERR': 12,
                                   'SIZE': 24, 'WIL': 12, 'SCRUB': 34}
ErrorCode = Literal['PT-ENRICH-INPUT', 'PT-ENRICH-OWNERSHIP', 'PT-ENRICH-CONFIG', 'PT-ENRICH-LIMIT',
                    'PT-ENRICH-CANCEL', 'PT-ENRICH-STALE', 'PT-ENRICH-CACHE', 'PT-ENRICH-NETWORK',
                    'PT-ENRICH-PROVIDER']
UINT32_MAX = 4_294_967_295


class EnrichmentError(Exception):
    """Typed failure. `message` is redacted and user-safe; causes chain via __cause__."""

    def __init__(self, code: ErrorCode, message: str, *, recoverable: bool = False):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message
        self.recoverable = recoverable


class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    contract: Literal['enrichment/1'] = CONTRACT


class SourceLocation(Contract):
    """Exact source excerpt. Lines are 1-based inclusive; address 0 is valid, None unknown."""
    side: Side
    artifact_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    function_id: str = Field(min_length=1, max_length=128)
    representation: Literal['decompiled', 'assembly', 'metadata'] = 'decompiled'
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt_sha256: Sha256
    address: int | None = Field(default=None, ge=0, le=2**64 - 1)

    @model_validator(mode='after')
    def _ordered(self):
        if self.end_line < self.start_line:
            raise ValueError('end_line precedes start_line')
        return self


class StageResult(Contract):
    stage: str = Field(min_length=1, max_length=64)
    stage_version: int = Field(ge=1)
    stage_id: Sha256
    status: Status
    error_code: ErrorCode | None = None
    message: str = Field(default='', max_length=2000)
    limitations: tuple[str, ...] = ()


class ChangeSignal(Contract):
    signal_id: Sha256
    pairing_id: Sha256
    match_id: str = Field(min_length=1, max_length=128)
    detector: DetectorId
    detector_version: int = Field(ge=1)
    confidence: Confidence
    group_key: Sha256
    locations: tuple[SourceLocation, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1, max_length=2000)
    limitations: tuple[str, ...] = ()
    typed_evidence: bool = False


class DetectorOutcome(Contract):
    """Per pairing and detector: `unavailable` means evidence missing, never 'no defect'."""
    pairing_id: Sha256
    detector: DetectorId
    status: Status
    reason: str = Field(default='', max_length=500)


class SignalSet(Contract):
    pairing_id: Sha256
    match_id: str
    category: str
    signals: tuple[ChangeSignal, ...] = ()
    outcomes: tuple[DetectorOutcome, ...] = ()
    status: Status


class RankingConfig(Contract):
    formula: Literal['attention/1'] = 'attention/1'
    weights: dict[DetectorId, int] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    enabled: tuple[DetectorId, ...] = DETECTOR_IDS

    @model_validator(mode='after')
    def _weights(self):
        if set(self.weights) != set(DETECTOR_IDS):
            raise ValueError('weights must name exactly the eight detector IDs')
        for value in self.weights.values():
            if type(value) is not int or not 0 <= value <= 100:
                raise ValueError('weights must be whole integers 0..100')
        if len(set(self.enabled)) != len(self.enabled):
            raise ValueError('duplicate enabled detector')
        return self


class GroupSubtotal(Contract):
    group_key: Sha256
    a: int = Field(ge=0, le=100)
    b: int = Field(ge=0, le=100)
    points: int = Field(ge=0, le=40)
    signal_ids: tuple[Sha256, ...]
    strong: bool


class RankingEntry(Contract):
    pairing_id: Sha256
    match_id: str
    rank: int = Field(ge=1)
    score: int = Field(ge=0, le=100)
    raw: int = Field(ge=0, le=80)
    groups: tuple[GroupSubtotal, ...] = ()
    strong_groups: int = Field(ge=0)
    evidence: Status
    match_certainty: str = 'unknown'
    counterevidence: tuple[str, ...] = ()


class RankingResult(Contract):
    formula: Literal['attention/1'] = 'attention/1'
    config_digest: Sha256
    input_digest: Sha256
    entries: tuple[RankingEntry, ...] = ()
    status: Status


FeatureControl = Literal['cfg-dominance', 'lexical-enclosure', 'adjacent', 'unknown']
TransitionKind = Literal['introduced', 'removed', 'condition-changed', 'guarded-behavior-changed',
                         'unchanged-around-change', 'unknown']


class FeatureSite(Contract):
    identifier: str = Field(min_length=1, max_length=64)
    feature_id: int | None = Field(default=None, ge=0, le=UINT32_MAX)
    side: Side
    location: SourceLocation
    control: FeatureControl
    wrapper: str = Field(default='', max_length=200)


class FeatureTransition(Contract):
    transition_id: Sha256
    pairing_id: Sha256
    match_id: str
    feature_id: int | None = Field(default=None, ge=0, le=UINT32_MAX)
    kind: TransitionKind
    older_sites: tuple[FeatureSite, ...] = ()
    newer_sites: tuple[FeatureSite, ...] = ()
    confidence: Confidence
    qualifies: bool
    symbol_status: Literal['verified', 'unverified', 'mismatched', 'absent'] = 'absent'
    notes: tuple[str, ...] = ()


class AttributedText(Contract):
    source: str = Field(min_length=1, max_length=32)
    lang: str = Field(default='en', max_length=16)
    text: str = Field(max_length=20000)


class AttributedValue(Contract):
    source: str = Field(min_length=1, max_length=32)
    value: str = Field(min_length=1, max_length=2000)


class CvssRecord(Contract):
    source: str
    version: str = Field(max_length=8)
    vector: str = Field(max_length=200)
    base_score_tenths: int | None = Field(default=None, ge=0, le=100)
    severity: str = Field(default='', max_length=16)


class CveSnapshot(Contract):
    snapshot_id: Sha256
    cve_id: str = Field(pattern=r'^CVE-\d{4}-\d{4,19}$', max_length=24)
    normalization_version: int = Field(ge=1)
    response_digests: dict[str, Sha256]
    retrieved_at: str
    descriptions: tuple[AttributedText, ...] = ()
    cwes: tuple[AttributedValue, ...] = ()
    cvss: tuple[CvssRecord, ...] = ()
    products: tuple[AttributedValue, ...] = ()
    advisories: tuple[AttributedValue, ...] = ()
    feature_ids: tuple[int, ...] = ()
    published: tuple[AttributedValue, ...] = ()
    conflicts: tuple[str, ...] = ()


class ContextContribution(Contract):
    kind: Literal['identifier', 'cwe', 'feature', 'product']
    points: int = Field(ge=0, le=30)
    context_field: str = Field(min_length=1, max_length=200)
    binary_ref: str = Field(min_length=1, max_length=200)
    detail: str = Field(default='', max_length=500)


class ContextualEntry(Contract):
    pairing_id: Sha256
    match_id: str
    base_score: int = Field(ge=0, le=100)
    base_rank: int = Field(ge=1)
    adjustment: int = Field(ge=0, le=30)
    context_score: int = Field(ge=0, le=100)
    context_rank: int = Field(ge=1)
    contributions: tuple[ContextContribution, ...] = ()
    blocked: tuple[str, ...] = ()


class ContextualRanking(Contract):
    ranking_input: Sha256
    snapshot_ids: tuple[Sha256, ...]
    dictionary_version: int = Field(ge=1)
    entries: tuple[ContextualEntry, ...] = ()
    status: Status
    stale_snapshots: tuple[str, ...] = ()


class CacheManifest(Contract):
    key: Sha256
    stage: str = Field(pattern=r'^[a-z][a-z0-9-]{0,31}$')
    size: int = Field(ge=0)
    sha256: Sha256
    inputs: dict[str, str]
    created: str


class PipelineStatus(Contract):
    project_id: str
    revision: int = Field(ge=0)
    run_id: str
    raw_sha256: Sha256
    stages: tuple[StageResult, ...] = ()
    status: Status
