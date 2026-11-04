"""`report/2` contract models (SPEC-50 7.1, 7.2). Strict, frozen, `extra='forbid'`; pure data, no Qt.

Text fields reject anything that `text.neutralize` would change: builders normalize once, the contract proves it. No
model has a cross-engine aggregate or a probability field (`verdict`, `tier` and states only), and every optional section
is `None` when its producer is absent.
"""
from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from . import text

CALIBRATION_NOTE = 'Scores are ordinal triage indices, not probabilities of a vulnerability.'
NORMALIZATION_NOTE = 'report/2 text normalization applied'
ATTENTION_LABEL = 'attention index (ordinal)'


def _normalized(value: str) -> str:
    if text.neutralize(value, verbatim=True) != value:
        raise ValueError('text must be normalized (bidi, control or surrogate characters present)')
    return value


Text = Annotated[str, AfterValidator(_normalized)]
Sha256 = Annotated[str, StringConstraints(pattern='^[0-9a-f]{64}$')]
Ident = Annotated[str, StringConstraints(min_length=1, max_length=128), AfterValidator(_normalized)]


class _Model(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid')


class Tool(_Model):
    name: Literal['PatchTrace'] = 'PatchTrace'
    version: Ident
    release_tag: Ident | None = None
    signed: Literal['yes', 'no', 'unknown'] = 'unknown'


class Orientation(_Model):
    older_sha256: Sha256 | None
    newer_sha256: Sha256 | None


class Provenance(_Model):
    derived_from: Literal['persisted-project-snapshot'] = 'persisted-project-snapshot'
    revision: int = Field(ge=0)
    network_used: Literal[False] = False


class Calibration(_Model):
    display_level: Literal['ordinal', 'bands', 'numeric']
    profile: Ident | None = None
    model_id: Ident | None = None
    artifact_digest: Sha256 | None = None
    gates: dict[str, str] | None = None
    note: Literal['Scores are ordinal triage indices, not probabilities of a vulnerability.'] = CALIBRATION_NOTE

    @model_validator(mode='after')
    def _ordinal_carries_nothing(self):
        details = (self.profile, self.model_id, self.artifact_digest, self.gates)
        if self.display_level == 'ordinal' and any(d is not None for d in details):
            raise ValueError('ordinal display level carries no profile, model, digest or gates')
        if self.display_level != 'ordinal' and (
                self.model_id is None or self.artifact_digest is None or not self.gates):
            raise ValueError('bands and numeric levels require model_id, artifact_digest and gates')
        return self


class Redaction(_Model):
    profile: Literal['local', 'share', 'custom']
    paths: bool
    code: bool
    notes: bool
    urls: Literal['text', 'defanged', 'removed']
    rules_applied: dict[str, int] = {}


class Truncated(_Model):
    section: Ident
    omitted_count: int = Field(ge=1)


# --- engine evidence ------------------------------------------------------------------------------------------

class Engine(_Model):
    name: Ident
    version: Ident


class Channel(_Model):
    engine: Ident
    state: Literal['present', 'absent', 'not_run', 'not_comparable']
    note: Text = ''


class AlternativeRank(_Model):
    engine: Ident
    rank: int = Field(ge=1)


class EvidenceRow(_Model):
    match_id: Ident
    verdict: Literal['corroborated', 'contested', 'single-engine', 'insufficient']
    tier: Literal['high', 'moderate', 'low', 'unassessed']
    channels: list[Channel]
    supporting_engines: list[Ident]
    contradicting_engines: list[Ident]
    missing_engines: list[Ident]  # unknown, never a negative vote
    alternative_ranks: list[AlternativeRank] = []
    limitations: list[Text] = []
    ordinal_index: int | None = Field(default=None, ge=0, le=83)
    explanation: Text = ''


class EngineEvidence(_Model):
    engines: list[Engine]
    rows: list[EvidenceRow]
    limitations: list[Text] = []  # shared-origin engines and the ordinal-index caveat, noted once
    stale: bool = False


# --- other sections -------------------------------------------------------------------------------------------

class SeriesBuild(_Model):
    ordinal: int = Field(ge=0)
    label: Text
    sha256: Sha256


class SeriesPair(_Model):
    older_ordinal: int = Field(ge=0)
    newer_ordinal: int = Field(ge=0)
    state: Literal['analyzed', 'not_run', 'not_comparable']


class SeriesChain(_Model):
    label: Text
    ordinals: list[int]


class SeriesGap(_Model):
    after_ordinal: int = Field(ge=0)
    reason: Text  # a gap is unknown, not a negative result


class Series(_Model):
    builds: list[SeriesBuild]
    pairs: list[SeriesPair] = []
    chains: list[SeriesChain] = []
    gaps: list[SeriesGap] = []
    stale: bool = False


class UnifiedResult(_Model):
    result_id: Sha256
    manifest_sha256: Sha256
    engines: list[Ident]
    status: Literal['complete', 'partial']
    stale: bool


FactName = Literal['file_version', 'product_version', 'original_filename', 'company_name', 'pdb_guid_age',
                   'signer_subject', 'timestamp_claim', 'manifest_exec_level']


class BuildFact(_Model):
    side: Literal['older', 'newer']
    fact: FactName
    value: Text
    source: Ident
    claim_level: Literal['observed-in-file'] = 'observed-in-file'
    truncated: bool = False


class StagedPdb(_Model):
    pdb_name: Ident
    guid_age: Annotated[str, StringConstraints(pattern='^[0-9A-F]{33,40}$')]
    sha256: Sha256


class Symbols(_Model):
    mode: Literal['off', 'local', 'online']
    servers: list[Ident] = []
    staged: list[StagedPdb] = []
    launcher_version: Ident | None = None
    consent: dict[str, Text] | None = None

    @model_validator(mode='after')
    def _servers_only_online(self):
        if self.servers and self.mode != 'online':
            raise ValueError('symbol servers are listed only for online mode')
        return self


_ADVISORY_ID = {'cve': re.compile(r'CVE-\d{4}-\d{4,19}', re.ASCII), 'kb': re.compile(r'KB\d{6,8}', re.ASCII),
                'cwe': re.compile(r'CWE-\d{1,5}', re.ASCII)}


class Advisory(_Model):
    kind: Literal['cve', 'kb', 'cwe', 'phrase']
    id: Ident
    vendor: Text = ''
    url_text: Text = ''
    fetched_at: Text = ''
    snapshot_digest: Sha256 | None = None
    claim_level: Literal['vendor-claim'] = 'vendor-claim'
    kev_listed: bool | None = None  # external context only; None is unknown, never "not exploited"
    text: Text
    truncated: bool = False

    @model_validator(mode='after')
    def _strict_ids(self):
        pattern = _ADVISORY_ID.get(self.kind)
        if pattern is not None and not pattern.fullmatch(self.id):
            raise ValueError(f'{self.kind} id must match {pattern.pattern}')
        return self


class Lead(_Model):
    lead_id: Ident
    kind: Ident
    channels: list[Ident] = Field(min_length=1)  # independent channels, never merged into one number
    statement: Text
    evidence_ids: list[Ident] = []


SECTION_KEYS = ('engine_evidence', 'series', 'unified_result', 'build_facts', 'symbols', 'advisories', 'leads')


class Report2(_Model):
    """The v1 keys keep their v1 shapes (loosely typed here: `reports._snapshot` owns them); new keys are additive."""
    schema_version: Literal[1] = 1
    report_version: Literal[2] = 2
    project_id: Ident
    name: Text
    revision: int
    created: Text
    sample: Any
    limitations: list[Text]
    selection: dict[str, Any]
    artifacts: list[dict[str, Any]]
    analysis_runs: list[dict[str, Any]]
    matches: list[dict[str, Any]]
    interpretations: list[dict[str, Any]]
    change_ranking: dict[str, Any] | None
    annotations: list[dict[str, Any]]
    content_digest: Sha256 | None = None
    generated_at: Text
    sections_present: list[Ident]
    stale_sections: list[Ident]
    tool: Tool
    orientation: Orientation
    calibration: Calibration
    redaction: Redaction
    provenance: Provenance
    unknowns: list[Text]
    normalization: Literal['report/2 text normalization applied'] = NORMALIZATION_NOTE
    truncated: list[Truncated] = []
    engine_evidence: EngineEvidence | None = None
    series: Series | None = None
    unified_result: UnifiedResult | None = None
    build_facts: list[BuildFact] | None = None
    symbols: Symbols | None = None
    advisories: list[Advisory] | None = None
    leads: list[Lead] | None = None

    @model_validator(mode='after')
    def _sections_present_matches(self):
        present = sorted([k for k in SECTION_KEYS if getattr(self, k) is not None]
                         + (['change_ranking'] if self.change_ranking is not None else []))
        if sorted(self.sections_present) != present:
            raise ValueError('sections_present must list exactly the sections with data')
        return self

    def to_dict(self) -> dict:
        """JSON-ready; absent optional sections are omitted (not null), v1 keys keep their nulls."""
        data = self.model_dump(mode='json')
        for key in SECTION_KEYS:
            if data[key] is None:
                del data[key]
        return data
