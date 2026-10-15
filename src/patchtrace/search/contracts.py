"""Search contracts (WB1 section 7), frozen by slice S1: later additions are additive only.

Every model is strict, frozen and `extra='forbid'`; stored JSON is revalidated with `model_validate_json`
(strict Python mode rejects JSON arrays as tuples). Display strings are sanitised on construction
(`sanitize_text`), so a hostile symbol never makes a lead unbuildable and never carries control characters.
No numeric relevance score exists anywhere in these models: ordering is categorical (section 7 ordering key).
"""
from __future__ import annotations

import json
from typing import Annotated, Literal, get_args

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from patchtrace.enrichment.identity import domain_id
from patchtrace.search.limits import DEFAULT_LIMITS
from patchtrace.search.normalize import sanitize_text

SearchKind = Literal['function', 'code', 'asm', 'string', 'import', 'export', 'capability', 'rule', 'build',
                     'advisory', 'cve', 'cwe', 'kb', 'note', 'finding']
Origin = Literal['ghidra', 'pe-parse', 'floss', 'capa', 'diec', 'yara-x', 'advisory', 'analyst', 'model']
Side = Literal['older', 'newer']
Scope = Literal['indexed', 'changed']
Mode = Literal['auto', 'words', 'exact', 'prefix', 'substring', 'similar']
SortKey = Literal['relevance', 'change', 'name', 'address']
InField = Literal['name', 'code', 'signature', 'text']
IsValue = Literal['modified', 'added', 'removed', 'unchanged']
IdentityKind = Literal['cve', 'kb', 'cwe', 'address', 'sha256', 'guid', 'module']
ReasonCode = Literal['exact-id', 'name-words', 'name-prefix', 'name-substring', 'text-words', 'code-words', 'typo',
                     'delta', 'corroborated']
LocatorScheme = Literal['function', 'string', 'import', 'export', 'pe-field', 'capability', 'rule', 'advisory',
                        'cve', 'note', 'finding']
PresenceState = Literal['present', 'absent', 'unknown']
CoverageStatus = Literal['indexed', 'building', 'missing', 'unavailable', 'failed', 'truncated', 'not-applicable']
ResultStatus = Literal['ok', 'partial', 'no-results', 'too-broad', 'indexing', 'unsupported', 'stale', 'cancelled',
                       'error']
MatchCategory = Literal['modified', 'added', 'removed', 'unmatched', 'ambiguous', 'split', 'merged', 'unchanged']
Review = Literal['unreviewed', 'accepted', 'rejected', 'needs-review']

_L = DEFAULT_LIMITS
_Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
_Digest16 = Annotated[str, Field(pattern=r'^[0-9a-f]{16}$')]
_Utc = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(\+00:00|Z)$')]
_Id = Annotated[str, Field(pattern=r'^[A-Za-z0-9._:-]{1,64}$')]
_Count = Annotated[int, Field(ge=0)]


def _sanitized(limit: int):
    def clean(value):
        return sanitize_text(value, limit) if isinstance(value, str) else value
    return Annotated[str, BeforeValidator(clean), Field(max_length=limit)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Term(_Strict):
    nfc: str = Field(min_length=1, max_length=_L.query_chars)
    fold: str = Field(min_length=1, max_length=18 * _L.query_chars)  # NFKC expands one character to at most 18
    prefix: bool = False  # explicit `word*`
    alt: tuple[str, ...] = Field(default=(), max_length=2)  # `0x..` and decimal spellings of an integer >= 16


class IdentityTerm(_Strict):
    kind: IdentityKind
    value: str = Field(min_length=1, max_length=128)


class QueryPlan(_Strict):
    """Built only by `query.parse_query`; `canonical()` is the sorted-key NFC JSON that `digest()` hashes."""
    contract: Literal['search-query/1'] = 'search-query/1'
    text: str = Field(max_length=_L.query_chars)
    terms: tuple[Term, ...] = Field(default=(), max_length=_L.query_terms)
    phrases: tuple[str, ...] = Field(default=(), max_length=_L.query_terms)
    excludes: tuple[str, ...] = Field(default=(), max_length=_L.query_excludes)
    last_prefix: bool = False
    kinds: tuple[SearchKind, ...] = ()
    sides: tuple[Side, ...] = ()
    scope: Scope = 'indexed'
    is_: tuple[IsValue, ...] = ()
    in_: tuple[InField, ...] = ()
    mode: Mode = 'auto'
    identity: tuple[IdentityTerm, ...] = Field(default=(), max_length=_L.query_terms)

    def canonical(self) -> str:
        return json.dumps(self.model_dump(mode='json'), sort_keys=True, separators=(',', ':'), ensure_ascii=False)

    def digest(self) -> str:
        """Identity of what is asked: the typed fields without the display `text`, so `a kind:x` equals `kind:x a`."""
        return domain_id('search-query', 1, self.model_dump(mode='json', exclude={'text'}))


class SearchRequest(_Strict):
    plan: QueryPlan
    sort: SortKey = 'relevance'
    limit: int = Field(default=50, ge=1, le=_L.page_max)
    cursor: str | None = Field(default=None, max_length=512)  # opaque keyset bound to an index_key
    group: bool = True
    expand: bool = True
    generation: _Count = 0


class Reason(_Strict):
    code: ReasonCode
    field: _sanitized(16)
    detail: _sanitized(80) = ''


class Locator(_Strict):
    scheme: LocatorScheme
    run_id: _Id | None = None
    side: Side | None = None
    function_id: _Id | None = None
    rva: _Count | None = None
    file_offset: _Count | None = None
    line_start: _Count | None = None
    line_end: _Count | None = None
    excerpt_sha256: _Sha256 | None = None
    source_ref: _sanitized(128) | None = None

    @model_validator(mode='after')
    def _lines(self):
        if (self.line_start is None) != (self.line_end is None):
            raise ValueError('line_start and line_end go together')
        if self.line_start is not None and self.line_end < self.line_start:
            raise ValueError('line_end precedes line_start')
        return self


class Evidence(_Strict):
    """One matched document with its provenance. `seen_by` lists the independent origins that carry it."""
    kind: SearchKind
    side: Side | None = None
    origin: Origin
    title: _sanitized(200)
    snippet: _sanitized(300) = ''
    spans: tuple[tuple[_Count, _Count], ...] = ()  # integer offsets into `snippet`, never markup
    reasons: tuple[Reason, ...] = Field(default=(), max_length=8)
    locator: Locator
    seen_by: tuple[Origin, ...] = Field(min_length=1, max_length=len(get_args(Origin)))
    group: _sanitized(32)
    digest16: _Digest16

    @model_validator(mode='after')
    def _spans(self):
        for start, end in self.spans:
            if not 0 <= start < end <= len(self.snippet):
                raise ValueError('span outside the snippet')
        if self.origin not in self.seen_by:
            raise ValueError('origin must be among seen_by')
        return self


class Presence(_Strict):
    older: PresenceState = 'unknown'
    newer: PresenceState = 'unknown'
    basis: _sanitized(120) = ''


class FunctionRef(_Strict):
    function_id: _Id
    name: _sanitized(200)
    side: Side
    rva: _Count | None = None


class Attention(_Strict):
    """Ordinal position only (uncalibrated): shown as 'rank 3 of 41'."""
    rank: int = Field(ge=1)
    of: int = Field(ge=1)
    formula: Literal['attention/1'] = 'attention/1'

    @model_validator(mode='after')
    def _bounds(self):
        if self.rank > self.of:
            raise ValueError('rank exceeds the ranked population')
        return self


class UnifiedSummary(_Strict):
    decision: _sanitized(32)
    materiality: _sanitized(32)
    classes: tuple[_sanitized(48), ...] = Field(default=(), max_length=8)


class PairExpansion(_Strict):
    """Resolved live per page from the open project; never stored in an index."""
    category: MatchCategory
    counterparts: tuple[FunctionRef, ...] = Field(default=(), max_length=16)
    match_types: tuple[_sanitized(48), ...] = Field(default=(), max_length=8)
    quality: _sanitized(32) = 'unknown'
    manual: bool = False
    review: Review = 'unreviewed'
    attention: Attention | None = None
    signals: tuple[_sanitized(64), ...] = Field(default=(), max_length=8)
    unified: UnifiedSummary | None = None
    tool_delta: tuple[_sanitized(48), ...] = Field(default=(), max_length=8)
    series: _sanitized(64) | None = None
    limitations: tuple[_sanitized(200), ...] = Field(default=(), max_length=8)


class SearchHit(_Strict):
    """A lead, not a verdict. Ordering fields are categorical or ordinal; nothing here is a score."""
    hit_id: _Id
    tier: int = Field(ge=0, le=4)
    change_class: int = Field(ge=0, le=3)
    components: int = Field(ge=1, le=len(get_args(Origin)))  # distinct independent origins
    evidence: tuple[Evidence, ...] = Field(max_length=6)
    evidence_total: _Count
    presence: Presence | None = None
    expansion: PairExpansion | None = None
    rank_reasons: tuple[_sanitized(120), ...] = Field(default=(), max_length=8)

    @model_validator(mode='after')
    def _total(self):
        if self.evidence_total < len(self.evidence):
            raise ValueError('evidence_total is smaller than the evidence listed')
        return self


class CoverageEntry(_Strict):
    group: _sanitized(32)
    kinds: tuple[SearchKind, ...]
    side: Side | None = None
    status: CoverageStatus
    docs: _Count = 0
    reason: _sanitized(200) = ''
    digest16: _Digest16 | None = None
    built_utc: _Utc | None = None


class NameSuggestion(_Strict):
    """A typo suggestion over names only; an integer edit distance, never a match."""
    name: _sanitized(200)
    edits: int = Field(ge=0, le=3)
    locator: Locator


class CounterpartHint(_Strict):
    older: FunctionRef
    newer: FunctionRef
    edits: int = Field(ge=0, le=3)
    shared_words: tuple[_sanitized(48), ...] = Field(default=(), max_length=8)


class SearchResult(_Strict):
    contract: Literal['search/1'] = 'search/1'
    status: ResultStatus
    coverage: tuple[CoverageEntry, ...] = ()
    hits: tuple[SearchHit, ...] = Field(default=(), max_length=_L.page_max)
    total: _Count | None = None
    total_capped: bool = False
    cursor: str | None = Field(default=None, max_length=512)
    interpreted_as: _sanitized(300) = ''
    suggestions: tuple[NameSuggestion, ...] = Field(default=(), max_length=_L.suggestions)
    counterpart_hints: tuple[CounterpartHint, ...] = Field(default=(), max_length=_L.page_max)
    warnings: tuple[_sanitized(200), ...] = Field(default=(), max_length=16)
    index_key: _Digest16 | None = None
    timings_ms: dict[Annotated[str, Field(pattern=r'^[a-z_]{1,24}$')], _Count] = Field(default_factory=dict, max_length=16)


class SavedSearch(_Strict):
    """Append-only analyst row (enrichment kind `search-saved`): `create` carries a plan, `delete` tombstones `of`."""
    contract: Literal['search-saved/1'] = 'search-saved/1'
    saved_id: _Id
    op: Literal['create', 'delete']
    name: _sanitized(64) = ''
    plan: QueryPlan | None = None
    of: _Id | None = None
    created: _Utc

    @model_validator(mode='after')
    def _shape(self):
        if self.op == 'create' and (not self.name or self.plan is None or self.of is not None):
            raise ValueError('a create row needs a name and a plan, and no target')
        if self.op == 'delete' and (self.of is None or self.plan is not None or self.name):
            raise ValueError('a delete row names its target and nothing else')
        return self
