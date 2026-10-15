"""Strict, frozen `fabric/1` records (FAB-integration-plan.md s4, s7). Persisted contracts are additive only from here.

Pure: pydantic + stdlib; no Qt, I/O, sqlite, network or other feature. Records forbid extra fields, coerce nothing
(strict mode) and are frozen; every set-like collection is a tuple in canonical order and there is no float, so a dump
is deterministic. Stored JSON is revalidated in JSON mode (``model_validate_json``). The models check shape only; the
semantic rules (key grammar per kind, roles, sides, subjects) and the self-certifying ids live in `ids`, which raises
typed `PT-FAB-*` errors.

Vocabulary that keeps claims honest: an anchor is `observed` (read from the artifacts or a tool run on them),
`stated` (said by an advisory, catalog or analyst) or `hint` (something to look for). The role is part of the identity,
so a statement can never be read as found evidence; and no verdict `absent` exists, so missing evidence stays unknown.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

from .limits import DEFAULT_LIMITS, FabricError

_L = DEFAULT_LIMITS

# --- vocabulary (frozen; s4, s7) ------------------------------------------------------------------------------------

Kind = Literal['function', 'string', 'import', 'capability', 'rule', 'build_fact', 'advisory_phrase', 'cve', 'kb',
               'cwe']
Side = Literal['older', 'newer', 'both', 'none']
Role = Literal['observed', 'stated', 'hint']
# The order is the display order: the label of the first producer present describes a merged anchor.
Producer = Literal['core', 'ue', 'cap', 'die', 'wb3', 'wbq', 'wb2', 'wb1', 'yrx', 'kb', 'kev', 'pil', 'analyst']

KINDS: tuple[str, ...] = get_args(Kind)
SIDES: tuple[str, ...] = get_args(Side)
ROLES: tuple[str, ...] = get_args(Role)
PRODUCERS: tuple[str, ...] = get_args(Producer)
ROLES_BY_KIND = MappingProxyType({
    'function': ('observed',), 'string': ('observed', 'hint'), 'import': ('observed', 'hint'),
    'capability': ('observed',), 'rule': ('observed', 'stated'), 'build_fact': ('observed', 'stated'),
    'advisory_phrase': ('stated', 'hint'), 'cve': ('stated',), 'kb': ('stated',), 'cwe': ('stated', 'hint')})
# `resolve` answers "is there something to look at": code-side kinds count observed anchors only.
CODE_EVIDENCE_KINDS = frozenset({'function', 'string', 'import', 'capability'})
RESOLVE_STATUSES = ('found', 'ambiguous', 'unknown', 'unsupported')  # never 'absent': missing is unknown
PROJECT_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
SHA256_RE = re.compile(r'[0-9a-f]{64}')

# --- plain text -----------------------------------------------------------------------------------------------------
# Everything `secondary.evidence_view.sanitize_text` removes (C0 except tab and newline, DEL and C1, LRM and RLM, line
# and paragraph separators, bidirectional embeddings and isolates); a line also rejects tab and newline. The
# bidirectional set is built from code points: a typed escape may reach the file as the raw invisible character.
_BIDI = ''.join(chr(code) for code in (0x200E, 0x200F, *range(0x2028, 0x202F), *range(0x2066, 0x206A)))
_UNSAFE_LINE = re.compile('[\x00-\x1f\x7f-\x9f' + _BIDI + ']')
_UNSAFE_ANY = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f' + _BIDI + '\ud800-\udfff]')


def plain_line(value: str) -> str:
    """Validator: single-line plain text (what producers store after sanitising untrusted text)."""
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('text must be UTF-8 encodable') from None
    if _UNSAFE_LINE.search(value):
        raise ValueError('text must be one line of plain text (no control, bidirectional or separator characters)')
    return value


def clean_line(value: object, limit: int = _L.f05_label_chars) -> str:
    """Untrusted text -> a value `plain_line` accepts: unsafe characters and lone surrogates removed, tabs and
    newlines become spaces, capped at `limit` characters with an ellipsis (same cap rule as `sanitize_text`)."""
    text = '' if value is None else str(value).replace('\n', ' ').replace('\t', ' ')
    text = _UNSAFE_ANY.sub('', text)
    return text if len(text) <= limit else text[:max(0, limit - 3)] + '...'


def _line(max_length: int, min_length: int = 0):
    return Annotated[str, AfterValidator(plain_line), Field(min_length=min_length, max_length=max_length)]


Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Rva = Annotated[int, Field(ge=0, le=2**32 - 1)]
Slug = Annotated[str, Field(pattern=r'^[a-z0-9-]{1,48}$')]
FacetName = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_]{0,31}$')]
Batch = Annotated[str, Field(pattern=rf'^[a-z0-9][a-z0-9._-]{{0,{_L.f11_batch_chars - 1}}}$')]
OriginTag = Annotated[str, Field(pattern=r'^D_[a-z0-9_]{1,32}$')]
Pointer = Annotated[str, AfterValidator(plain_line),
                    Field(max_length=_L.f14_pointer_chars, pattern=r'^(/([^/~]|~[01])*)*$')]
Key = _line(_L.f06_key_chars, 1)
Label = _line(_L.f05_label_chars, 1)
FacetText = _line(_L.f07_facet_chars, 1)
ToolText = _line(_L.f15_tool_chars, 1)
RefId = _line(_L.f13_ref_id_chars, 1)


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


def _sorted_unique(values, what: str, key=None):
    items = list(values)
    keyed = [key(v) for v in items] if key else items
    if keyed != sorted(set(keyed)):
        raise ValueError(f'{what} must be sorted and unique')
    return values


# --- records --------------------------------------------------------------------------------------------------------

class Ref(_Strict):
    """What a witness was read from: a source kind and id, an optional RFC 6901 pointer and content digest."""
    kind: Slug
    id: RefId
    pointer: Pointer | None = None
    sha256: Sha256 | None = None


class Witness(_Strict):
    """One producer's statement of an anchor, with its provenance. `witness_id` is the content id (`ids.witness_id`),
    so an identical republish collapses; `origins` must equal the registry's tags of `source` (`PT-FAB-ORIGIN`)."""
    witness_id: Sha256
    producer: Producer
    batch: Batch
    source: Slug
    origins: tuple[OriginTag, ...] = Field(min_length=1, max_length=_L.f10_origins_per_witness)
    label: Label
    facets: tuple[tuple[FacetName, FacetText], ...] = Field(default=(), max_length=_L.f04_facets_per_witness)
    tool: ToolText | None = None
    tool_version: ToolText | None = None
    input_sha256: Sha256 | None = None
    ref: Ref | None = None

    @field_validator('origins')
    @classmethod
    def _origins(cls, value):
        return _sorted_unique(value, 'origins')

    @field_validator('facets')
    @classmethod
    def _facets(cls, value):
        return _sorted_unique(value, 'facets', key=lambda facet: facet[0])


class PairRef(_Strict):
    """The preimage of a `pair:` key: both artifact hashes in explicit older/newer order and the RVA lists. One side may
    be empty (an added or removed function)."""
    older_sha256: Sha256
    newer_sha256: Sha256
    older_rvas: tuple[Rva, ...] = Field(max_length=_L.f08_pair_rvas_per_side)
    newer_rvas: tuple[Rva, ...] = Field(max_length=_L.f08_pair_rvas_per_side)

    @field_validator('older_rvas', 'newer_rvas')
    @classmethod
    def _rvas(cls, value, info):
        return _sorted_unique(value, info.field_name)

    @model_validator(mode='after')
    def _has_a_function(self):
        if not self.older_rvas and not self.newer_rvas:
            raise ValueError('a pair needs at least one function')
        return self


_PRODUCER_ORDER = {name: index for index, name in enumerate(PRODUCERS)}


class Anchor(_Strict):
    """A typed, keyed, oriented statement with 1..16 witnesses. Identity is (kind, key, side, role, subject)."""
    anchor_id: Sha256
    kind: Kind
    key: Key
    side: Side
    role: Role
    subject: Key | None = None
    pair: PairRef | None = None
    witnesses: tuple[Witness, ...] = Field(min_length=1, max_length=_L.f03_witnesses_per_anchor)

    @field_validator('witnesses')
    @classmethod
    def _witnesses(cls, value):
        return _sorted_unique(value, 'witnesses', key=lambda witness: witness.witness_id)

    @property
    def display(self) -> Witness:
        """The witness that describes the anchor: first by producer order, then batch, then id (never hash order alone)."""
        return min(self.witnesses, key=lambda w: (_PRODUCER_ORDER[w.producer], w.batch, w.witness_id))

    @property
    def label(self) -> str:
        return self.display.label


# --- in-process values (never persisted) ----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AnchorQuery:
    """Filters combine with AND. `side` is an exact match; a `pair:` subject also matches its member `image:` subjects."""
    kind: str | None = None
    key: str | None = None
    side: str | None = None
    role: str | None = None
    subject: str | None = None
    producer: str | None = None
    offset: int = 0
    limit: int = 100

    def __post_init__(self) -> None:
        if self.kind is not None and self.kind not in KINDS:
            raise FabricError('PT-FAB-KIND', 'The query names an unknown anchor kind', reason='kind')
        for name, allowed in (('side', SIDES), ('role', ROLES), ('producer', PRODUCERS)):
            value = getattr(self, name)
            if value is not None and value not in allowed:
                raise FabricError('PT-FAB-INPUT', 'The query names an unknown value', reason=name)
        for name in ('key', 'subject'):
            value = getattr(self, name)
            if value is not None and (type(value) is not str or not 1 <= len(value) <= _L.f06_key_chars):
                raise FabricError('PT-FAB-INPUT', 'The query key is malformed', reason=name)
        if type(self.offset) is not int or self.offset < 0:
            raise FabricError('PT-FAB-INPUT', 'The query offset must be a non-negative int', reason='offset')
        if type(self.limit) is not int or not 1 <= self.limit <= _L.f09_page_rows:
            raise FabricError('PT-FAB-INPUT', 'The query limit is out of range', reason='limit')


@dataclass(frozen=True, slots=True)
class AnchorPage:
    """A page in canonical order (kind, key, side, role, subject, id); a store may return fewer rows than asked."""
    items: tuple[Anchor, ...]
    total: int


@dataclass(frozen=True, slots=True)
class Resolution:
    """`found` (exactly one anchor), `ambiguous` (candidates, never the first), `unknown` (nothing published, which is not
    absence) or `unsupported` (no fabric behind the reader)."""
    status: str
    anchor_id: str | None = None
    label: str | None = None
    candidates: tuple[str, ...] = ()
    count: int = 0

    def __post_init__(self) -> None:
        if self.status not in RESOLVE_STATUSES:
            raise ValueError(f'unknown resolution status {self.status!r}')


@dataclass(frozen=True, slots=True)
class PublishReport:
    """What a call changed among the anchors it touched: new, existing with a different witness set, existing with the
    same witness set, and anchors that lost their last witness."""
    added: int = 0
    merged: int = 0
    unchanged: int = 0
    removed: int = 0
