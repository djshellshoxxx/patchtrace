"""Strict `strings-*` contracts (spec WB3 s7). Pure: no Qt, no I/O.

Small records forbid extra fields, coerce nothing and are frozen. Evidence from strings stays an `anchor`: nothing
here carries a score, and review tiers are ordinal labels that are never combined with other attention signals.
Per-row data of a whole side lives in `table.StringTable`, not in these models.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..enrichment.identity import domain_id
from .limits import (
    DISPLAY_CHARS,
    MAX_ANCHORS,
    MAX_CHANGE_CUES,
    MAX_CHANGE_LINKS,
    MAX_CHANGE_OFFSETS,
    MAX_DELTA_ROWS,
)

BASIS_CONTRACT = 'strings-basis/1'
TABLE_CONTRACT = 'strings-table/1'
DELTA_CONTRACT = 'strings-delta/1'
ANCHOR_HIT_CONTRACT = 'strings-anchor-hit/1'
STATIC_SEMANTICS_ID = 'ascii+utf16le-ascii/v1'

Side = Literal['older', 'newer']
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Address = Annotated[int, Field(ge=0, le=2**64 - 1)]
Short = Annotated[str, Field(max_length=256)]
StringType = Literal['static', 'stack', 'tight', 'decoded', 'language']
Encoding = Literal['ASCII', 'UTF-16LE', 'UTF-8']
StageName = Literal['static', 'stack', 'tight', 'decoded', 'language']
StageStateName = Literal['complete', 'heuristic', 'not-run', 'failed', 'truncated']
Source = Literal['builtin-scan', 'floss']
LinkTier = Literal['L1', 'L2', 'L3', 'L4', 'L5', 'L6']
PairStatus = Literal['added', 'removed', 'modified', 'unchanged', 'ambiguous', 'unknown']
ChangeStatus = Literal['only-older', 'only-newer', 'both', 'representation-changed', 'edited', 'not-compared',
                       'indeterminate']
MatchKind = Literal['exact', 'casefold', 'substring', 'import-equal']

CUES: tuple[str, ...] = ('message', 'format', 'path', 'registry', 'url', 'guid', 'api-name', 'dynamic-api',
                         'dll-name', 'pdb-path', 'version', 'identifier', 'advisory-text', 'advisory-api',
                         'lookalike', 'secret-like', 'resource', 'noise-like')
Cue = Literal['message', 'format', 'path', 'registry', 'url', 'guid', 'api-name', 'dynamic-api', 'dll-name',
              'pdb-path', 'version', 'identifier', 'advisory-text', 'advisory-api', 'lookalike', 'secret-like',
              'resource', 'noise-like']
ErrorCode = Literal['PT-STR-INPUT', 'PT-STR-BASIS', 'PT-STR-STALE', 'PT-STR-LIMIT', 'PT-STR-SOURCE', 'PT-STR-LINK',
                    'PT-STR-CONSENT', 'PT-STR-EXPORT', 'PT-STR-CANCEL']


class StringsError(Exception):
    """Typed, user-safe failure; `message` never contains raw tool output or local paths."""

    def __init__(self, code: ErrorCode, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class StageState(_Strict):
    state: StageStateName
    detail: str = Field(default='', max_length=200)


class LanguageInfo(_Strict):
    detected: str | None = Field(default=None, max_length=32)
    selected: str | None = Field(default=None, max_length=32)


class BasisPart(_Strict):
    source: Source
    semantics_id: str = Field(min_length=1, max_length=64)
    source_version: str = Field(default='', max_length=64)
    executable_sha256: Sha256 | None = None
    run_id: str | None = Field(default=None, min_length=1, max_length=128)
    raw_sha256: Sha256 | None = None
    types: tuple[StringType, ...] = Field(min_length=1, max_length=5)
    config_digest: Sha256
    consent_sha256: Sha256 | None = None

    @model_validator(mode='after')
    def _floss_is_traceable(self):
        if self.source == 'floss' and (self.run_id is None or self.raw_sha256 is None):
            raise ValueError('a floss part names its run and raw output')
        if self.source == 'builtin-scan' and (self.run_id or self.raw_sha256 or self.consent_sha256):
            raise ValueError('the built-in scan has no tool run')
        if len(set(self.types)) != len(self.types):
            raise ValueError('duplicate types')
        return self


class StringBasis(_Strict):
    """What a table was extracted with; two tables compare only through their bases (spec WB3 s7.1)."""
    contract: Literal['strings-basis/1'] = BASIS_CONTRACT
    artifact_sha256: Sha256
    side: Side
    min_length: int = Field(ge=1, le=4096)
    language: LanguageInfo = LanguageInfo()
    rows_seen: int = Field(ge=0)
    rows_kept: int = Field(ge=0)
    stages: dict[StageName, StageState]
    parts: tuple[BasisPart, ...] = Field(min_length=1, max_length=2)

    @model_validator(mode='after')
    def _consistent(self):
        if self.rows_kept > self.rows_seen:
            raise ValueError('rows_kept exceeds rows_seen')
        if len({part.source for part in self.parts}) != len(self.parts):
            raise ValueError('at most one part per source')
        return self

    def digest(self) -> str:
        return domain_id('strings-basis', 1, self.model_dump(mode='json'))


class FunctionRef(_Strict):
    side: Side
    rva: Address | None = None
    project_function_id: str | None = Field(default=None, max_length=128)
    match_id: str | None = Field(default=None, max_length=128)
    name: str | None = Field(default=None, max_length=256)
    ambiguous: bool = False


class StringLink(_Strict):
    tier: LinkTier
    join: Literal['exact', 'contains'] | None = None
    function: FunctionRef
    pair_status: PairStatus
    line: int | None = Field(default=None, ge=1)
    lineage_group: str = Field(min_length=1, max_length=128)
    evidence_ref: str = Field(min_length=1, max_length=256)


class SideObservation(_Strict):
    types: tuple[StringType, ...] = ()
    encodings: tuple[Encoding, ...] = ()
    offsets: tuple[Address, ...] = Field(default=(), max_length=MAX_CHANGE_OFFSETS)
    rvas: tuple[Address, ...] = Field(default=(), max_length=MAX_CHANGE_OFFSETS)
    region: str | None = Field(default=None, max_length=64)


class EditRef(_Strict):
    of: Sha256
    kind: Literal['insert', 'delete', 'replace', 'prefix', 'suffix']


class StringChange(_Strict):
    id: Sha256
    value_sha256: Sha256
    display: str = Field(max_length=DISPLAY_CHARS)
    length: int = Field(ge=0)
    status: ChangeStatus
    older: SideObservation | None = None
    newer: SideObservation | None = None
    links: tuple[StringLink, ...] = Field(default=(), max_length=MAX_CHANGE_LINKS)
    cues: tuple[Cue, ...] = Field(default=(), max_length=MAX_CHANGE_CUES)
    review_tier: int = Field(ge=1, le=7)
    reasons: tuple[Short, ...] = ()
    notes: tuple[Short, ...] = ()
    edit: EditRef | None = None
    lookalike_of: Sha256 | None = None

    @model_validator(mode='after')
    def _sides_match_status(self):
        needs = {'only-older': (True, False), 'only-newer': (False, True)}.get(self.status)
        if needs and (self.older is not None, self.newer is not None) != needs:
            raise ValueError(f'{self.status} must observe exactly the matching side')
        if self.status in ('both', 'representation-changed') and (self.older is None or self.newer is None):
            raise ValueError(f'{self.status} must observe both sides')
        return self


class Harmonized(_Strict):
    min_length: int = Field(ge=1, le=4096)
    types: tuple[StringType, ...]


class PairingInfo(_Strict):
    available: bool
    notes: tuple[Short, ...] = ()


class StringAnchorHit(_Strict):
    contract: Literal['strings-anchor-hit/1'] = ANCHOR_HIT_CONTRACT
    anchor_id: str = Field(min_length=1, max_length=128)
    kind: str = Field(min_length=1, max_length=64)
    match: MatchKind
    string_id: Sha256
    presence_older: bool
    presence_newer: bool
    links: tuple[StringLink, ...] = Field(default=(), max_length=MAX_CHANGE_LINKS)
    strength: Literal['anchor'] = 'anchor'
    lineage_group: str = Field(min_length=1, max_length=128)


class AnchorJoin(_Strict):
    digest: Sha256 | None = None
    hits: tuple[StringAnchorHit, ...] = Field(default=(), max_length=MAX_ANCHORS * 8)


class StringsDelta(_Strict):
    contract: Literal['strings-delta/1'] = DELTA_CONTRACT
    older_basis_digest: Sha256
    newer_basis_digest: Sha256
    comparable: bool
    harmonized: Harmonized | None = None
    basis_notes: tuple[Short, ...] = ()
    counts: dict[str, int] = {}
    changes: tuple[StringChange, ...] = Field(default=(), max_length=MAX_DELTA_ROWS)
    truncated: bool = False
    pairing: PairingInfo = PairingInfo(available=False)
    anchors: AnchorJoin = AnchorJoin()
    value_gate: Literal['unvalidated'] = 'unvalidated'

    @model_validator(mode='after')
    def _not_comparable_means_no_changes(self):
        if not self.comparable and self.changes:
            raise ValueError('a non-comparable delta carries no changes')
        return self


class SearchRow(_Strict):
    """Row for WB1's index; WB1 owns the translation into its own storage."""
    doc_key: Short
    text: Short
    title: Short
    field: Literal['strings'] = 'strings'
    side: Side
    status: ChangeStatus
    function_ids: tuple[Short, ...] = ()
    offsets: tuple[Address, ...] = Field(default=(), max_length=MAX_CHANGE_OFFSETS)
    coverage: Short = ''
    flags: tuple[Short, ...] = ()
