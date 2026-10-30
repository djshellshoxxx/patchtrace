"""SPEC-31 persisted records (02-data-model s1-s5). Pure: pydantic + stdlib; no Qt, I/O, network or processes.

Every record is strict (`extra='forbid', strict=True, frozen=True`); stored JSON is revalidated in JSON mode
(strict Python mode rejects JSON arrays as tuples). Caps come from `limits.DEFAULT_LIMITS` (L-xx) or are the
contract constants below (baked at import: a custom `UnifiedLimits` never changes a contract cap). Free text is
bounded and UTF-8 encodable, and two kinds exist (02 s9.1): DISPLAY text derived from untrusted binaries and tools
(`_text`) is sanitised on construction (control, bidirectional and invisible characters become U+FFFD), so a hostile
symbol never makes a record unbuildable; IDENTIFIER and protocol text (`_ident`) is rejected instead of rewritten.
"""
from __future__ import annotations

import dataclasses
import json
import re
import unicodedata
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Literal, get_args

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .limits import (  # noqa: F401 - re-exported
    DEFAULT_LIMITS,
    ERROR_CODES,
    MIN_HEAP_MIB,
    BudgetExhausted,
    UnifiedError,
    UnifiedLimits,
)

_L = DEFAULT_LIMITS
MAX_NATIVE = 4
MAX_HINTS = 32
MAX_NOTES = 64
MAX_SOURCES = 64
MAX_STAGES = 16
PROVENANCE_MAX_KEYS = 16
PROVENANCE_MAX_CHARS = 256
MAX_DELTAS_OMITTED = 8 * _L.l06_fn_instructions  # a pair has at most L-06 instructions and a few deltas per one
_PROVENANCE_KEY = re.compile(r'[a-z0-9_]{1,64}')
# C1 controls, DEL, soft hyphen, bidirectional marks/embeddings/isolates, zero-width and word-joiner characters,
# line and paragraph separators, BOM and the interlinear/tag format characters: invisible or reordering in a UI.
# Built from code points so that this file holds no invisible character itself.
_INVISIBLE_RANGES = ((0x7F, 0x9F), (0xAD, 0xAD), (0x61C, 0x61C), (0x180E, 0x180E), (0x200B, 0x200F),
                     (0x2028, 0x202E), (0x2060, 0x206F), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0xE0000, 0xE007F))
REPLACEMENT = chr(0xFFFD)


def _char_class(ranges) -> re.Pattern:
    return re.compile('[' + ''.join(f'{chr(low)}-{chr(high)}' for low, high in ranges) + ']')


_UNSAFE_TEXT = _char_class(((0x00, 0x1F), *_INVISIBLE_RANGES))
_SURROGATES = _char_class(((0xD800, 0xDFFF),))
_STDERR_UNSAFE = _char_class(((0x00, 0x08), (0x0B, 0x1F), *_INVISIBLE_RANGES))  # tab and newline stay
_UTC = r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(\+00:00|Z)$'
_UTC_FULL = re.compile(_UTC[1:-1])
# Windows device names (also with an extension) and a trailing dot alias other files or fail to open (F-06).
_DEVICE_NAME = re.compile(r'(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?')
_LIMIT_NAMES = frozenset(f.name for f in dataclasses.fields(UnifiedLimits))
_CONTRACT_NAME = re.compile(r'([a-z][a-z0-9-]*)/([0-9]{1,6})')
_TERMINAL_CODES = ('PT-UNIFIED-CANCEL', 'PT-UNIFIED-TIMEOUT', 'PT-UNIFIED-UNSUPPORTED')  # own run statuses


def _encodable(value: str) -> str:
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('text must be UTF-8 encodable') from None
    return value


def _display(value):
    """Before-validator of display text: unsafe characters become U+FFFD (length-preserving); ASCII is untouched."""
    if isinstance(value, str) and not (value.isascii() and value.isprintable()):
        return _UNSAFE_TEXT.sub(REPLACEMENT, value)
    return value


def replace_surrogates(text: str, replacement: str = REPLACEMENT) -> str:
    """Lone surrogates (JSON `\\ud800` escapes decode to them) cannot be encoded as UTF-8: they become `replacement`."""
    return _SURROGATES.sub(replacement, text)


def strip_unsafe(text: str, *, keep_layout: bool = False, replacement: str = REPLACEMENT) -> str:
    """Untrusted text made safe to show or store: lone surrogates, controls (TAB and LF stay with `keep_layout`) and
    every invisible or bidirectional character are replaced. The one definition the readers and panes share."""
    return replace_surrogates((_STDERR_UNSAFE if keep_layout else _UNSAFE_TEXT).sub(replacement, text), replacement)


def _identifier(value: str, *, nfc: bool = True) -> str:
    """After-validator of identifier and protocol text: surrogates, control/invisible characters and (identity
    strings) non-NFC spellings are errors, never rewritten."""
    if not (value.isascii() and value.isprintable()):
        _encodable(value)
        if _UNSAFE_TEXT.search(value):
            raise ValueError('text must not contain control, bidirectional or invisible characters')
        if nfc and not unicodedata.is_normalized('NFC', value):
            raise ValueError('text must be NFC normalised')
    return value


def _text(max_length: int, min_length: int = 0):
    """Display text (sanitised, see the module docstring)."""
    return Annotated[str, BeforeValidator(_display), AfterValidator(_encodable),
                     Field(min_length=min_length, max_length=max_length)]


def _ident(max_length: int, min_length: int = 0):
    """Identifier or protocol text (rejected, never rewritten)."""
    return Annotated[str, AfterValidator(_identifier), Field(min_length=min_length, max_length=max_length)]


def canonical_utc(value):
    """One spelling per instant (F-11): ASCII digits, a real calendar date, `Z` or `+00:00` in, `+00:00` out."""
    if not isinstance(value, str):
        return value
    if not _UTC_FULL.fullmatch(value):
        raise ValueError('timestamp must be YYYY-MM-DDTHH:MM:SS[.ffffff] followed by Z or +00:00')
    try:
        return datetime.fromisoformat(value).astimezone(UTC).isoformat()
    except ValueError:
        raise ValueError('timestamp is not a calendar date and time') from None


def safe_run_id(value: str) -> str:
    """A run id becomes a directory name: Windows device names and a trailing dot would alias other files."""
    if value.endswith('.') or _DEVICE_NAME.fullmatch(value):
        raise ValueError('run id must not be a Windows device name or end with a dot')
    return value


class _FrozenDict(dict):
    """A dict that stays what validation made it: `frozen=True` models would otherwise keep a mutable field."""
    __slots__ = ()

    def _blocked(self, *_args, **_kwargs):
        raise TypeError('this mapping is immutable')
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _blocked

    def __hash__(self) -> int:
        return hash(tuple(sorted(self.items())))

    def __reduce__(self):  # copy.deepcopy / model_copy(deep=True) rebuild through the constructor, not setitem
        return (type(self), (dict(self),))


def _freeze(value: Mapping) -> _FrozenDict:
    return _FrozenDict(value)


Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Rva = Annotated[int, Field(ge=0, le=2**32 - 1)]
Count = Annotated[int, Field(ge=0)]
SourceId = Annotated[str, Field(pattern=r'^[a-z][a-z0-9-]{1,31}$')]
StepId = _text(64, 1)
Slug = Annotated[str, Field(pattern=r'^[a-z0-9-]{1,48}$')]
RunId = Annotated[str, Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'), AfterValidator(safe_run_id)]
Utc = Annotated[str, Field(pattern=_UTC), BeforeValidator(canonical_utc)]  # Field first: the schema keeps the pattern
Version = _ident(64)
Note = _text(200, 1)
Tier = Literal['M', 'A', 'B', 'C', 'W']
Card = Literal['1:1', '1:N', 'N:1', 'N:M', 'non-exclusive']
Decision = Literal['matched', 'tentative', 'candidate', 'contested', 'ambiguous', 'older-only', 'newer-only', 'unknown']
Materiality = Literal['unchanged', 'cosmetic', 'material', 'review', 'unknown', 'not-applicable']
ChannelId = Literal['C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8']
ChannelState = Literal['equal', 'differs', 'unavailable', 'not-applicable']
ChangeClass = Literal['constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref',
                      'struct-offset', 'cfg', 'block-added', 'block-removed', 'string', 'size-only', 'refcount-only',
                      'address-only', 'register-only', 'layout-only', 'name-only', 'frame', 'eh', 'unknown']
RowFlag = Literal['tiny', 'thunk', 'import', 'hub', 'icf', 'oversize', 'truncated', 'ir-missing', 'pdata-confirmed',
                  'library', 'mask-missing', 'mask-unlocated']
ProofId = Literal['UNCH/1', 'COS-ADDR/1', 'COS-LAYOUT/1', 'COS-PSEUDO/1']
EvidenceClass = Literal['E-NAME', 'E-BODY', 'E-CFG', 'E-CALL', 'E-DATA', 'E-DECOMP', 'E-LAYOUT', 'E-RESID',
                        'E-MANUAL', 'E-UNKNOWN']
ProducerMode = Literal['gzf', 'analyze', 'binexport', 'rizin']

DECISIONS: tuple[str, ...] = get_args(Decision)
MATERIALITIES: tuple[str, ...] = get_args(Materiality)
CHANNELS: tuple[str, ...] = get_args(ChannelId)
# Semantic delta classes (05 s2.5) that may never coexist with an unchanged/cosmetic verdict; `material` needs
# one of them or an added/removed block (which COS-LAYOUT may legitimately carry for a fall-through JMP).
SEMANTIC_CLASSES = ('constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref',
                    'struct-offset', 'string')
MATERIAL_CLASSES = (*SEMANTIC_CLASSES, 'block-added', 'block-removed')
BYTES_GROUP = ('C0', 'C1', 'C2', 'C5')  # same data group as the first channel C2: never an anchored second channel
STRUCTURAL_PROOFS = ('UNCH/1', 'COS-ADDR/1', 'COS-LAYOUT/1')


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


def _unique(values, what: str):
    if len(set(values)) != len(values):
        raise ValueError(f'{what} must be unique')
    return values


# --- rows and facts (02 s4) ---------------------------------------------------------------------------------------

class Atom(_Strict):
    """One piece of pairing evidence from one source."""
    source: SourceId
    step: StepId
    tier: Tier
    cardinality: Card
    cls: EvidenceClass
    older_rva: Rva | None
    newer_rva: Rva | None
    native: tuple[tuple[_text(32, 1), _text(120)], ...] = Field(default=(), max_length=MAX_NATIVE)
    ref: _text(128, 1) | None = None

    @model_validator(mode='after')
    def _consistent(self):
        if self.older_rva is None and self.newer_rva is None:
            raise ValueError('an atom needs at least one endpoint')
        if self.cardinality == 'non-exclusive' and self.tier != 'W':
            raise ValueError('only tier W atoms may be non-exclusive')
        return self


class SideRef(_Strict):
    rva: Rva
    name: _text(256) | None = None
    kind: Literal['function', 'thunk', 'import', 'external', 'unknown']


class Support(_Strict):
    component: str = Field(pattern=r'^K[0-9]{1,2}$')
    tier: Tier
    atom_index: Count


class Contest(_Strict):
    strength: Literal['strong', 'weak']
    against: tuple[Count, ...] = Field(min_length=1)

    @field_validator('against')
    @classmethod
    def _sorted(cls, value):
        if list(value) != sorted(set(value)):
            raise ValueError('contest atom indexes must be unique and ascending')
        return value


class UnifiedMatch(_Strict):
    """One pairing row (02 s4). Invariants beyond the field types: sides are unique and sorted by rva; one-sided
    decisions have one side and materiality not-applicable/unknown; pairing decisions need both sides; `contested`
    needs a contest, a contest appears only on contested or manual matched rows and is strong iff an against-atom
    has tier M, A or B; `support` points at an atom of the same tier. Text fields are sanitised (02 s9.1)."""
    contract: Literal['unified-match/1'] = 'unified-match/1'
    row_id: Sha256
    older: tuple[SideRef, ...]
    newer: tuple[SideRef, ...]
    decision: Decision
    support: tuple[Support, ...] = ()
    contest: Contest | None = None
    atoms: tuple[Atom, ...] = Field(max_length=_L.l39_atoms_per_row)
    ghidriff_match_id: _ident(128, 1) | None = None
    materiality: Materiality = 'unknown'
    change_classes: tuple[ChangeClass, ...] = ()
    flags: tuple[RowFlag, ...] = ()
    hints: tuple[Note, ...] = Field(default=(), max_length=MAX_HINTS)

    @model_validator(mode='after')
    def _consistent(self):
        for side in (self.older, self.newer):
            rvas = [s.rva for s in side]
            if rvas != sorted(set(rvas)):
                raise ValueError('side references must be unique and sorted by rva')
        if not self.older and not self.newer:
            raise ValueError('a row needs at least one function')
        if self.decision == 'older-only' and (not self.older or self.newer):
            raise ValueError('older-only rows have only older functions')
        if self.decision == 'newer-only' and (not self.newer or self.older):
            raise ValueError('newer-only rows have only newer functions')
        if self.decision in ('matched', 'tentative', 'candidate', 'contested', 'ambiguous') and not (
                self.older and self.newer):
            raise ValueError(f'{self.decision} rows need functions on both sides')
        if self.decision in ('older-only', 'newer-only') and self.materiality not in ('not-applicable', 'unknown'):
            raise ValueError('one-sided rows have materiality not-applicable or unknown')
        if self.decision == 'contested' and self.contest is None:
            raise ValueError('a contested row needs its contest')
        if self.contest is not None:
            if self.decision != 'contested' and not (self.decision == 'matched'
                                                     and any(a.tier == 'M' for a in self.atoms)):
                raise ValueError('a contest is shown only on contested rows or manual matched rows')
            if self.contest.against[-1] >= len(self.atoms):
                raise ValueError('contest atom index out of range')
            strong = any(self.atoms[i].tier in ('M', 'A', 'B') for i in self.contest.against)
            if (self.contest.strength == 'strong') != strong:
                raise ValueError('contest strength must be strong iff an against-atom has tier M, A or B')
        _unique([s.component for s in self.support], 'support components')
        for s in self.support:
            if s.atom_index >= len(self.atoms) or self.atoms[s.atom_index].tier != s.tier:
                raise ValueError('support must point at an atom of the same tier')
        _unique(self.change_classes, 'change classes')
        _unique(self.flags, 'row flags')
        return self


class Delta(_Strict):
    cls: ChangeClass
    channel: ChannelId
    older_rva: Rva | None
    newer_rva: Rva | None
    old: _text(120) | None = None
    new: _text(120) | None = None

    @model_validator(mode='after')
    def _anchored(self):
        if self.older_rva is None and self.newer_rva is None:
            raise ValueError('a delta needs at least one endpoint')
        return self


# Structural classes that no proof may carry; only COS-LAYOUT/1 (a fall-through JMP) may carry block deltas.
UNPROVABLE_CLASSES = ('cfg', 'unknown')
BLOCK_CLASSES = ('block-added', 'block-removed')


class ChangeFacts(_Strict):
    """Change facts of one row (02 s4, 05 s2.5). Invariants: all nine channels in order; a proof iff the verdict is
    unchanged/cosmetic (UNCH/1 only for unchanged), a second channel iff material; a proof needs every address
    target mapped, the proof's channel equal (UNCH/1 C0, COS-ADDR/1 C1, COS-PSEUDO/1 C6), EH-EQ for structural
    proofs and no semantic delta, no `cfg`/`unknown` delta, and block deltas only under COS-LAYOUT/1; a material
    verdict needs a semantic or block delta and a differing second channel outside the bytes group."""
    contract: Literal['change-facts/1'] = 'change-facts/1'
    row_id: Sha256
    verdict: Materiality
    proof: ProofId | None = None
    second_channel: ChannelId | None = None
    channels: tuple[tuple[ChannelId, ChannelState], ...]
    targets: tuple[Count, Count, Count] = (0, 0, 0)
    eh: Literal['equal', 'differs', 'absent', 'unavailable'] = 'unavailable'
    deltas: tuple[Delta, ...] = Field(default=(), max_length=_L.l28_deltas_per_pair)
    deltas_omitted: int = Field(default=0, ge=0, le=MAX_DELTAS_OMITTED)
    limits_hit: tuple[Slug, ...] = Field(default=(), max_length=MAX_NOTES)

    @model_validator(mode='after')
    def _consistent(self):
        if tuple(c for c, _ in self.channels) != CHANNELS:
            raise ValueError('channels must list C0..C8 once, in order')
        state = dict(self.channels)
        classes = {d.cls for d in self.deltas}
        if (self.proof is not None) != (self.verdict in ('unchanged', 'cosmetic')):
            raise ValueError('a proof is required iff the verdict is unchanged or cosmetic')
        if (self.second_channel is not None) != (self.verdict == 'material'):
            raise ValueError('a second channel is required iff the verdict is material')
        if self.verdict == 'unchanged' and self.proof != 'UNCH/1':
            raise ValueError('unchanged needs proof UNCH/1')
        if self.verdict == 'cosmetic' and self.proof == 'UNCH/1':
            raise ValueError('cosmetic needs a COS-* proof')
        if self.proof is not None:
            if self.targets[1] or self.targets[2]:
                raise ValueError('unchanged/cosmetic need every address target mapped (05 s2.7)')
            if classes & set(SEMANTIC_CLASSES):
                raise ValueError('unchanged/cosmetic rows carry no semantic delta')
            if classes & {*UNPROVABLE_CLASSES, *(() if self.proof == 'COS-LAYOUT/1' else BLOCK_CLASSES)}:
                raise ValueError('unchanged/cosmetic rows carry no structural delta (only COS-LAYOUT/1 block deltas)')
            needed = {'UNCH/1': 'C0', 'COS-ADDR/1': 'C1', 'COS-PSEUDO/1': 'C6'}.get(self.proof)
            if needed and state[needed] != 'equal':
                raise ValueError(f'{self.proof} needs {needed} equal')
            if self.proof in STRUCTURAL_PROOFS and self.eh not in ('equal', 'absent'):
                raise ValueError('structural proofs need EH-EQ (eh equal or absent)')
            if self.proof == 'COS-PSEUDO/1' and self.eh == 'differs':
                raise ValueError('COS-PSEUDO/1 never holds when unwind data differs')
        if self.verdict == 'material':
            if self.second_channel in BYTES_GROUP or state[self.second_channel] != 'differs':
                raise ValueError('material needs an anchored second channel from another data group that differs')
            if not classes & set(MATERIAL_CLASSES):
                raise ValueError('material needs a semantic delta')
        return self


# --- result manifest, pointer and run rows (02 s4) ----------------------------------------------------------------

class IrRef(_Strict):
    ir_key: Sha256
    content_digest: Sha256
    producer_mode: ProducerMode
    functions: Count


class SourceRef(_Strict):
    source: SourceId
    entry_id: _ident(128, 1)
    file_sha256: Sha256 | None
    version: Version


class Part(_Strict):
    """`sha256`, `bytes` and `records` describe the DECOMPRESSED JSON Lines content (02 s9)."""
    name: Literal['rows.jsonl.gz', 'facts.jsonl.gz', 'decomp.jsonl.gz']
    sha256: Sha256
    bytes: Count
    records: Count


class DecisionCounts(_Strict):
    matched: Count
    tentative: Count
    candidate: Count
    contested: Count
    ambiguous: Count
    older_only: Count
    newer_only: Count
    unknown: Count


class MaterialityCounts(_Strict):
    unchanged: Count
    cosmetic: Count
    material: Count
    review: Count
    unknown: Count
    not_applicable: Count


class Counts(_Strict):
    """One int per Decision and per Materiality value (`-` spelled `_`); both sums equal the row count."""
    decisions: DecisionCounts
    materiality: MaterialityCounts

    @model_validator(mode='after')
    def _balanced(self):
        if sum(self.decisions.model_dump().values()) != sum(self.materiality.model_dump().values()):
            raise ValueError('decision and materiality counts must sum to the same row count')
        return self

    def total(self) -> int:
        return sum(self.decisions.model_dump().values())

    @classmethod
    def of_tallies(cls, decisions: Mapping[str, int], materiality: Mapping[str, int]) -> Counts:
        """From one tally per Decision and per Materiality value (hyphenated names, as in `DECISIONS`)."""
        return cls(decisions=DecisionCounts(**{k.replace('-', '_'): v for k, v in decisions.items()}),
                   materiality=MaterialityCounts(**{k.replace('-', '_'): v for k, v in materiality.items()}))

    @classmethod
    def of(cls, rows) -> Counts:
        d = dict.fromkeys(DECISIONS, 0)
        m = dict.fromkeys(MATERIALITIES, 0)
        for row in rows:
            d[row.decision] += 1
            m[row.materiality] += 1
        return cls.of_tallies(d, m)


class UnifiedResultManifest(_Strict):
    contract: Literal['unified-result/1'] = 'unified-result/1'
    result_id: Sha256
    older_sha256: Sha256
    newer_sha256: Sha256
    orientation: Literal['older->newer']
    ghidriff_run_id: RunId
    ghidriff_raw_sha256: Sha256
    ir_older: IrRef | None
    ir_newer: IrRef | None
    sources: tuple[SourceRef, ...] = Field(max_length=MAX_SOURCES)
    manual_digest: Sha256
    config_digest: Sha256
    engine_version: Literal['ude/1']
    status: Literal['complete', 'partial']
    limitations: tuple[Note, ...] = Field(max_length=MAX_NOTES)
    counts: Counts
    parts: tuple[Part, ...]
    created_utc: Utc

    @model_validator(mode='after')
    def _consistent(self):
        if (self.ir_older is None) != (self.ir_newer is None):
            raise ValueError('ProgramIR is used for both sides or for neither (F1)')
        keys = [(s.source, s.entry_id, s.file_sha256 or '', s.version) for s in self.sources]
        if keys != sorted(set(keys)):
            raise ValueError('sources must be unique and sorted')
        names = [p.name for p in self.parts]
        if names != sorted(set(names)) or not {'rows.jsonl.gz', 'facts.jsonl.gz'} <= set(names):
            raise ValueError('parts must be unique, sorted and include rows and facts')
        parts = {p.name: p for p in self.parts}
        if parts['rows.jsonl.gz'].records != self.counts.total():
            raise ValueError('rows part record count must equal the counts total')
        if parts['facts.jsonl.gz'].records > parts['rows.jsonl.gz'].records:
            raise ValueError('more fact records than rows')
        if sum(p.bytes for p in self.parts) > _L.l30_dir_bytes or any(p.bytes > _L.l30_part_bytes
                                                                       for p in self.parts):
            raise ValueError('result parts exceed L-30')
        if self.status == 'partial' and not self.limitations:
            raise ValueError('a partial result names its limitations')
        return self


_RELATIVE_DIR = r'^runs/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/unified/results/[0-9a-f]{16}$'


class UnifiedResultPointer(_Strict):
    """Body of the `unified-result` enrichment row (entry id = result_id), contract `/1`. Kept as the READ model of
    rows written before S0a-FIX; writers use `UnifiedResultPointerV2`, readers use `parse_pointer`."""
    contract: Literal['unified-result-ptr/1'] = 'unified-result-ptr/1'
    result_id: Sha256
    relative_dir: str = Field(pattern=_RELATIVE_DIR)
    manifest_sha256: Sha256
    status: Literal['complete', 'partial']
    counts: Counts
    config_digest: Sha256

    @model_validator(mode='after')
    def _dir_matches(self):
        run, leaf = self.relative_dir.split('/')[1], self.relative_dir.rsplit('/', 1)[1]
        safe_run_id(run)
        if leaf != self.result_id[:16]:
            raise ValueError('relative_dir must end with result_id[:16]')
        return self


class UnifiedResultPointerV2(UnifiedResultPointer):
    """`unified-result-ptr/2`: `/1` plus the pair identity that retention groups on, so one pair or orientation
    never evicts another's results (F-01). `/1` is frozen (`extra='forbid'`), hence a new contract number."""
    contract: Literal['unified-result-ptr/2'] = 'unified-result-ptr/2'  # type: ignore[assignment]
    older_sha256: Sha256
    newer_sha256: Sha256


def newer_contract(found, current: str) -> bool:
    """True when `found` is a higher `/N` of the family of `current` (`unified-result/2` against
    `unified-result/1`); malformed spellings (`/0`, `/abc`, `/`) are not 'newer', they are invalid."""
    new = _CONTRACT_NAME.fullmatch(found) if isinstance(found, str) else None
    old = _CONTRACT_NAME.fullmatch(current)
    return bool(new and old and new.group(1) == old.group(1) and int(new.group(2)) > int(old.group(2)))


def parse_pointer(body) -> UnifiedResultPointer:
    """Version-gated reader of a `unified-result` row body: `/2` (with the pair) and `/1` (without). A higher
    `/N` raises `UnifiedError('PT-UNIFIED-STALE', reason='newer-contract')`; anything else invalid raises a
    pydantic `ValidationError`. The result is a `UnifiedResultPointer`; `/2` rows are `UnifiedResultPointerV2`."""
    contract = body.get('contract') if isinstance(body, dict) else None
    if newer_contract(contract, 'unified-result-ptr/2'):
        raise UnifiedError('PT-UNIFIED-STALE', 'The unified pointer was written by a newer PatchTrace',
                           reason='newer-contract')
    model = UnifiedResultPointerV2 if contract == 'unified-result-ptr/2' else UnifiedResultPointer
    return model.model_validate_json(json.dumps(body))


class StageRecord(_Strict):
    stage: Slug
    status: Literal['ok', 'partial', 'failed', 'cancelled', 'timeout', 'skipped', 'unsupported']
    duration_ms: Count
    reason: Slug | None = None


class UnifiedRun(_Strict):
    """Body of the `unified-run` enrichment row (entry id = run_id = keys.unified_run_id(result_key, started_utc)).
    Invariants: ok/cached name a result and no error code; partial names a result, is neither cancelled nor
    unsupported and has a cause (an error code or a stage that is not ok); cancelled/timeout/unsupported carry their
    own code and no result; failed carries any other code and no result. `provenance` values and `stderr_tail` are
    sanitised (02 s9.1); `stderr_tail` also folds CRLF/CR to LF and stays within 32 KiB of UTF-8."""
    contract: Literal['unified-run/1'] = 'unified-run/1'
    run_id: Sha256
    result_id: Sha256 | None
    status: Literal['ok', 'partial', 'failed', 'cancelled', 'timeout', 'unsupported', 'cached']
    error_code: Literal[ERROR_CODES] | None = None  # type: ignore[valid-type]
    stages: tuple[StageRecord, ...] = Field(default=(), max_length=MAX_STAGES)
    provenance: dict[str, str] = Field(default_factory=_FrozenDict)
    stderr_tail: str = ''
    peak_rss_bytes: Count | None = None
    started_utc: Utc
    duration_ms: Count

    @field_validator('provenance')
    @classmethod
    def _bounded(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > PROVENANCE_MAX_KEYS:
            raise ValueError(f'provenance has more than {PROVENANCE_MAX_KEYS} keys')
        clean = {}
        for key, text in value.items():
            text = _display(text)
            if not _PROVENANCE_KEY.fullmatch(key) or len(text) > PROVENANCE_MAX_CHARS:
                raise ValueError('provenance keys are [a-z0-9_]{1,64} and values at most 256 characters')
            clean[key] = _encodable(text)
        return _freeze(clean)

    @field_validator('stderr_tail', mode='before')
    @classmethod
    def _fold_line_ends(cls, value):
        """A Windows child writes CRLF: fold it, then neutralise what could mislead a reader (F-09)."""
        if isinstance(value, str):
            return _STDERR_UNSAFE.sub(REPLACEMENT, value.replace('\r\n', '\n').replace('\r', '\n'))
        return value

    @field_validator('stderr_tail')
    @classmethod
    def _bounded_tail(cls, value: str) -> str:
        _encodable(value)
        if len(value.encode('utf-8')) > _L.l31_stderr_tail_bytes:
            raise ValueError('stderr_tail exceeds L-31 (32 KiB)')
        return value

    @model_validator(mode='after')
    def _consistent(self):
        code = self.error_code
        if self.status in ('ok', 'cached') and (self.result_id is None or code is not None):
            raise ValueError(f'status {self.status} needs a result and no error code')
        if self.status == 'partial':
            if self.result_id is None:
                raise ValueError('a partial run names its result')
            if code in ('PT-UNIFIED-CANCEL', 'PT-UNIFIED-UNSUPPORTED'):
                raise ValueError('a partial run is neither cancelled nor unsupported')
            if code is None and all(stage.status == 'ok' for stage in self.stages):
                raise ValueError('a partial run names its cause (an error code or a stage that is not ok)')
        if self.status in ('failed', 'cancelled', 'timeout', 'unsupported'):
            expected = {'cancelled': 'PT-UNIFIED-CANCEL', 'timeout': 'PT-UNIFIED-TIMEOUT',
                        'unsupported': 'PT-UNIFIED-UNSUPPORTED'}.get(self.status)
            if self.result_id is not None or code is None or (expected and code != expected) or (
                    not expected and code in _TERMINAL_CODES):
                raise ValueError(f'status {self.status} has no result and a matching error code')
        return self


# --- ProgramIR manifest and extractor protocol (02 s2-s3, 03 s2) --------------------------------------------------

_PRODUCER_MODES = {'ghidra': ('gzf', 'analyze'), 'binexport': ('binexport',), 'rizin': ('rizin',)}


def _check_producer(kind: str, mode: str, script_sha256, analysis_options_digest) -> None:
    """A producer's mode fits its kind, and a Ghidra IR is identified by its script and options: without them two
    runs with different (unhashed) options would share one `ir_key` and serve each other's IR (F-15)."""
    if mode not in _PRODUCER_MODES[kind]:
        raise ValueError(f'producer {kind} cannot have mode {mode}')
    if kind == 'ghidra' and (script_sha256 is None or analysis_options_digest is None):
        raise ValueError('a ghidra producer records its script and analysis options digests')


class IrProducer(_Strict):
    kind: Literal['ghidra', 'binexport', 'rizin']
    mode: ProducerMode
    ghidra: Version
    pyghidra: Version
    java: Version
    python: Version
    script_sha256: Sha256 | None
    analysis_options_digest: Sha256 | None
    gzf_sha256: Sha256 | None = None
    symbols: Literal['primary', 'none']

    @model_validator(mode='after')
    def _mode_fits_kind(self):
        _check_producer(self.kind, self.mode, self.script_sha256, self.analysis_options_digest)
        return self


class IrCounts(_Strict):
    functions: Count
    blocks: Count
    instructions: Count
    call_edges: Count
    strings: Count
    consts: Count
    refs: Count
    thunks: Count
    imports: Count
    pdata_confirmed: Count
    mask_unlocated: Count


class ProgramIrManifest(_Strict):
    contract: Literal['program-ir/1'] = 'program-ir/1'
    ir_key: Sha256
    content_digest: Sha256
    artifact_sha256: Sha256
    program_sha256: Sha256
    image_base: int = Field(ge=0, le=2**64 - 1)
    size_of_image: int = Field(ge=1, le=2**32 - 1)
    producer: IrProducer
    ingest_version: Literal['ir-ingest/1']
    norm_version: Literal['norm/1']
    counts: IrCounts
    limits_hit: tuple[Slug, ...] = Field(default=(), max_length=MAX_NOTES)
    warnings: tuple[Note, ...] = Field(default=(), max_length=MAX_NOTES)
    file_sha256: Sha256
    created_utc: Utc

    @model_validator(mode='after')
    def _consistent(self):
        if self.artifact_sha256 != self.program_sha256:
            raise ValueError('program_sha256 must equal artifact_sha256')
        c = self.counts
        if max(c.thunks, c.imports, c.pdata_confirmed, c.mask_unlocated) > c.functions:
            raise ValueError('per-function counts cannot exceed the function count')
        return self


def _no_dot_absolute(value: str) -> str:
    """Platform-independent: absolute in POSIX or Windows form (a leading `//` or `\\\\` UNC path is not supported),
    below the root, no control character, no dot-prefixed component (Ghidra path rule, 01 s7.6), no component that a
    Windows file system would alias (trailing dot or space, device names), < 240 chars."""
    _identifier(value, nfc=False)  # a Windows path need not be NFC; control characters and NUL are never valid
    posix = value.startswith('/') and not value.startswith('//')
    windows = re.match(r'^[A-Za-z]:[\\/]', value) is not None
    if not (posix or windows):
        raise ValueError('path must be absolute')
    if len(value) >= 240:
        raise ValueError('path must be shorter than 240 characters')
    parts = [p for p in re.split(r'[\\/]', value[2:] if windows else value) if p]
    if not parts:
        raise ValueError('path must name a location below the root')
    if any(p.startswith('.') for p in parts):
        raise ValueError('path must not contain dot-prefixed components')
    if any(p[-1] in '. ' or _DEVICE_NAME.fullmatch(p) for p in parts):
        raise ValueError('path components must not end with a dot or space or be Windows device names')
    return value


AbsPath = Annotated[str, AfterValidator(_no_dot_absolute)]


def _known_limit(name: str) -> str:
    if name not in _LIMIT_NAMES:
        raise ValueError('limits are named after UnifiedLimits fields')
    return name


LimitName = Annotated[str, Field(pattern=r'^l[0-9]{2}_[a-z0-9_]{1,48}$'), AfterValidator(_known_limit)]
LimitValue = Annotated[int, Field(ge=1, le=2**63 - 1)]  # a JVM/Jython long must hold it


class ExtractRequest(_Strict):
    """Request to the extractor child (03 s2); PatchTrace-authored, so text is rejected, never rewritten.
    Invariants: gzf mode needs gzf_path+gzf_sha256 together, analyze takes none, decompile needs a GZF and at least
    one sorted unique RVA, analysis_options apply to analyze only, limits are `UnifiedLimits` fields."""
    contract: Literal['ir-extract-request/1'] = 'ir-extract-request/1'
    side: Literal['older', 'newer']
    artifact_path: AbsPath
    artifact_sha256: Sha256
    mode: Literal['gzf', 'analyze', 'decompile']
    gzf_path: AbsPath | None
    gzf_sha256: Sha256 | None
    out_dir: AbsPath
    work_dir: AbsPath
    max_heap_mb: int = Field(ge=MIN_HEAP_MIB, le=_L.l03_heap_max_mib)
    analysis_options: Annotated[dict[_ident(128, 1), _ident(256)], AfterValidator(_freeze)]
    limits: Annotated[dict[LimitName, LimitValue], AfterValidator(_freeze)]
    decompile_rvas: tuple[Rva, ...] = Field(default=(), max_length=_L.l41_decompile_pairs)

    @model_validator(mode='after')
    def _consistent(self):
        if self.mode in ('gzf', 'decompile') and (self.gzf_path is None or self.gzf_sha256 is None):
            raise ValueError(f'{self.mode} mode needs gzf_path and gzf_sha256')
        if self.mode == 'decompile' and not self.decompile_rvas:
            raise ValueError('decompile mode needs at least one RVA')
        if self.mode == 'analyze' and (self.gzf_path is not None or self.gzf_sha256 is not None):
            raise ValueError('analyze mode takes no input GZF')
        if (self.gzf_path is None) != (self.gzf_sha256 is None):
            raise ValueError('gzf_path and gzf_sha256 come together')
        if self.analysis_options and self.mode != 'analyze':
            raise ValueError('analysis_options apply to analyze mode only')
        if self.decompile_rvas and self.mode != 'decompile':
            raise ValueError('decompile_rvas apply to decompile mode only')
        if list(self.decompile_rvas) != sorted(set(self.decompile_rvas)):
            raise ValueError('decompile_rvas must be unique and sorted')
        return self


class IrExtractProducer(_Strict):
    mode: Literal['gzf', 'analyze']
    ghidra: Version
    pyghidra: Version
    java: Version
    python: Version
    script_sha256: Sha256
    analysis_options_digest: Sha256
    analyzed: bool
    symbols: Literal['primary', 'none']


class IrExtractHeader(_Strict):
    """First line of `ir.jsonl` (UNTRUSTED); every line carries `type` = header | fn | footer."""
    type: Literal['header']
    contract: Literal['ir-extract/1']
    artifact_sha256: Sha256
    program_sha256: Sha256
    image_base: int = Field(ge=0, le=2**64 - 1)
    size_of_image: int = Field(ge=1, le=2**32 - 1)
    language: _ident(64, 1)
    compiler: _ident(64)
    producer: IrExtractProducer


class IrExtractFooter(_Strict):
    type: Literal['footer']
    functions: Count
    instructions: Count
    status: Literal['complete', 'partial']
    warnings: tuple[Note, ...] = Field(default=(), max_length=MAX_NOTES)


# --- identity payloads (02 s5; hashed by keys.py, never persisted on their own) ------------------------------------

class IrKeyInputs(_Strict):
    artifact_sha256: Sha256
    producer_kind: Literal['ghidra', 'binexport', 'rizin']
    mode: ProducerMode
    symbols: Literal['primary', 'none']
    ghidra: Version
    pyghidra: Version
    python: Version
    script_sha256: Sha256 | None
    analysis_options_digest: Sha256 | None
    ingest_version: Literal['ir-ingest/1'] = 'ir-ingest/1'
    norm_version: Literal['norm/1'] = 'norm/1'
    ingest_limits_digest: Sha256

    @model_validator(mode='after')
    def _consistent(self):
        _check_producer(self.producer_kind, self.mode, self.script_sha256, self.analysis_options_digest)
        return self


class ResultKeyInputs(_Strict):
    older_sha256: Sha256
    newer_sha256: Sha256
    orientation: Literal['older->newer'] = 'older->newer'
    ghidriff_raw_sha256: Sha256
    ir_older_digest: Sha256 | None
    ir_newer_digest: Sha256 | None
    sources: tuple[SourceRef, ...] = Field(default=(), max_length=MAX_SOURCES)
    manual_digest: Sha256
    config_digest: Sha256


SCHEMA_MODELS = ((UnifiedMatch, 'unified-match/1'), (ChangeFacts, 'change-facts/1'),
                 (UnifiedResultManifest, 'unified-result/1'), (UnifiedResultPointer, 'unified-result-ptr/1'),
                 (UnifiedResultPointerV2, 'unified-result-ptr/2'),
                 (UnifiedRun, 'unified-run/1'), (ProgramIrManifest, 'program-ir/1'),
                 (ExtractRequest, 'ir-extract-request/1'), (IrExtractHeader, 'ir-extract/1'),
                 (IrExtractFooter, 'ir-extract/1'))
