"""Strict, frozen ``yara-rules/1`` records (YRX-integration-plan section 7). Persisted contracts are additive only from
here on: a new optional field is appended with a default; nothing is removed, renamed or retyped.

Pure: pydantic + stdlib; no Qt, I/O, network, sqlite or engine import. Every record forbids extra fields, coerces nothing
(strict mode) and is frozen; every set-like collection is a tuple in canonical order and the contract has no float, so a
dump is deterministic. Stored JSON is revalidated in JSON mode (``model_validate_json``).

Vocabulary that keeps claims honest: a rule is a *pattern* found in an older or newer build. Nothing here can express a
vulnerability verdict, a score or a probability; a hit count is a raw number, a miss is ``no-hit`` (never a negative
vote), and a file that was not scanned has no hit count at all (``None``), so it can never read as clean.

Rule text is untrusted data. ``rule_text`` is LF-only printable ASCII (the grammar escapes everything else), its hash is
verified wherever both appear, and every free-text field rejects control, format (bidi, zero-width) and separator
characters by explicit code point sets (never the Unicode database, so a Python upgrade cannot change what a stored row
means).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from .errors import ErrorCode
from .limits import DEFAULT_LIMITS

_L = DEFAULT_LIMITS
CONTRACT = 'yara-rules/1'
WORKER_CONTRACT = 'rules-worker/1'
GRAMMAR = 'yrx-gen/1'
ENGINE = 'yara-x'
# The versions this release was built and measured with (YRX plan s2). `EngineStamp.version_source == 'pin'` means the
# stamp states this constant because the installation carries no readable distribution metadata (frozen builds).
ENGINE_PIN = '1.21.0'
DECODER_PIN = '1.21.0'

# --- plain text and identifier shapes -----------------------------------------------------------------------------
# C0 controls, DEL and C1, soft hyphen, Arabic letter mark, Mongolian vowel separator, zero-width and bidi marks, line and
# paragraph separators, bidi embeddings, word joiner and invisible operators, bidi isolates, deprecated format controls,
# BOM, interlinear annotations, tag characters and lone surrogates.
_UNSAFE_LINE = re.compile('[\x00-\x1f\x7f-\x9f­؜᠎​-‏ -‮⁠-⁯﻿'
                          '￹-￻\U000e0000-\U000e007f\ud800-\udfff]')
_UNSAFE_TEXT = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f­؜᠎​-‏ -‮⁠-⁯﻿'
                          '￹-￻\U000e0000-\U000e007f\ud800-\udfff]')
_RULE_TEXT = re.compile(r'[\x20-\x7e\n]+')


def _encodable(value: str) -> str:
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('text must be UTF-8 encodable') from None
    return value


def plain_line(value: str) -> str:
    """Validator: single-line plain text (no control, format, separator or bidirectional characters)."""
    _encodable(value)
    if _UNSAFE_LINE.search(value):
        raise ValueError('text must be a single line of plain text (no control, bidirectional or separator characters)')
    return value


def plain_text(value: str) -> str:
    """Validator: plain text that may span lines (tab and newline allowed; analyst notes)."""
    _encodable(value)
    if _UNSAFE_TEXT.search(value):
        raise ValueError('text must be plain text (tab and newline only; no other control or bidirectional characters)')
    return value


def clean_line(value: object, limit: int) -> str:
    """Untrusted text (engine messages) -> a value `plain_line` accepts: unsafe characters become spaces, whitespace
    collapses and the result is capped at `limit` characters."""
    text = _UNSAFE_LINE.sub(' ', '' if value is None else str(value))
    return ' '.join(text.split())[:limit].rstrip()


def strict_json(text: str) -> object:
    """Parse a stored or exchanged document: duplicate keys, NaN and Infinity, any float (the contracts have none),
    integers beyond the interpreter's digit limit, lone surrogates and nesting beyond the parser's recursion limit are
    refused (`ValueError`). Moderate nesting is the model parser's to refuse (`model_validate_json`)."""
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate JSON key')
            value[key] = item
        return value

    def refuse(_):
        raise ValueError('JSON floats and constants are not part of this contract')
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=refuse, parse_float=refuse)
        json.dumps(value, ensure_ascii=False).encode('utf-8')  # a lone surrogate escape parses but cannot be stored
        return value
    except UnicodeEncodeError:
        raise ValueError('JSON contains an unpaired surrogate escape') from None
    except RecursionError:
        raise ValueError('JSON nesting limit exceeded') from None


def ascii_lf_text(value: str) -> str:
    """Validator: rule text is printable ASCII with LF line ends only (deterministic on every platform)."""
    if not _RULE_TEXT.fullmatch(value):
        raise ValueError('rule text must be printable ASCII with LF line ends only')
    return value


def _utc(value: str) -> str:
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise ValueError('timestamp must be a real UTC date and time') from None
    return value


def _line(max_length: int, min_length: int = 1):
    return Annotated[str, AfterValidator(plain_line), Field(min_length=min_length, max_length=max_length)]


PlainLine64 = _line(64)
PlainLine120 = _line(_L.label_chars)
PlainLine200 = _line(200)
PlainLine256 = _line(256)
PlainLine300 = _line(300)
PlainLine400 = _line(400)
Note = Annotated[str, AfterValidator(plain_text), Field(max_length=2000)]
RuleText = Annotated[str, AfterValidator(ascii_lf_text), Field(min_length=1, max_length=_L.rule_text_bytes)]
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Rva = Annotated[int, Field(ge=0, le=2**32 - 1)]
FileOffset = Annotated[int, Field(ge=0, lt=2**40)]
Count = Annotated[int, Field(ge=0)]
Slug = Annotated[str, Field(pattern=r'^[a-z0-9-]{1,48}$')]
# Same shapes as intelligence/1 and kb-syntax/1; duplicated so no other feature is imported (parity is tested).
CveId = Annotated[str, Field(max_length=24, pattern=r'^CVE-[0-9]{4}-[0-9]{4,19}$')]
CweId = Annotated[str, Field(pattern=r'^CWE-[1-9][0-9]{0,5}$')]
KbId = Annotated[str, Field(pattern=r'^KB[0-9]{4,10}$')]
FileVersion = Annotated[str, Field(pattern=r'^[0-9]{1,5}(\.[0-9]{1,5}){3}$')]
ProjectId = Annotated[str, Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
Key = Annotated[str, Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]  # a caller's key for a rule or a target
Utc = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(\+00:00|Z)$'),
                AfterValidator(_utc)]
VersionText = Annotated[str, Field(pattern=r'^[0-9A-Za-z][0-9A-Za-z.+_-]{0,39}$')]
ModuleName = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_]{0,31}$')]
YaraIdentifier = Annotated[str, Field(pattern=r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
WarningCode = Annotated[str, Field(pattern=r'^(?:E[0-9]{3}|[a-z][a-z0-9_]{1,63})$')]
RuleName = Annotated[str, Field(pattern=r'^PT_[0-9a-f]{12}_(?:older|newer)$')]
_HEX_TOKEN = r'(?:[0-9A-F]{2}|\?\?)'
HexPattern = Annotated[str, Field(pattern=rf'^{_HEX_TOKEN}(?: {_HEX_TOKEN}){{{_L.window_min_bytes - 1},'
                                          rf'{_L.hex_pattern_bytes - 1}}}$')]
# A YARA text string as emitted: printable ASCII except quote and backslash, or one of the escapes \\ \" \n \r \t \xNN.
EscapedText = Annotated[str, Field(pattern=r'^(?:[ !#-\[\]-~]|\\(?:["\\nrt]|x[0-9A-Fa-f]{2}))+$',
                                   max_length=4 * _L.text_pattern_bytes)]
_ESCAPED_UNIT = re.compile(r'[ !#-\[\]-~]|\\(?:["\\nrt]|x[0-9A-Fa-f]{2})')

Side = Literal['older', 'newer']
Direction = Side
Category = Literal['modified', 'added', 'removed']
Extent = Literal['pdata', 'unified-ir', 'unknown']
Materiality = Literal['unchanged', 'cosmetic', 'material', 'review', 'unknown']
Separation = Literal['older-only', 'newer-only', 'both-sides', 'unknown']
MaskKind = Literal['rip-disp', 'branch-ext', 'reloc', 'addr-ref']
MaskSourceName = Literal['iced-x86', 'unified-ir']
DecoderName = Literal['iced-x86', 'unified-ir', 'none']
Encoding = Literal['ascii', 'wide', 'ascii-wide']
LinkedBy = Literal['xref', 'file-level']
Origin = Literal['pe-imports', 'capa-api']
Classification = Literal['newly-introduced', 'removed-with-code']
GateId = Literal['elig', 'len', 'wild', 'uniq', 'sep', 'compile', 'secret', 'dist']
GateState = Literal['pass', 'fail', 'unknown', 'waived']
Action = Literal['accept', 'reject', 'defer', 'archive']
Role = Literal['older-anchor', 'newer-anchor', 'series', 'extra', 'clean', 'control']
Expect = Literal['hit', 'no-hit', 'unknown']
ToolchainFlag = Literal['none', 'toolchain-changed', 'packed', 'protected', 'unknown']
CellState = Literal['hit', 'no-hit', 'not-scanned', 'timeout', 'error']
Verdict = Literal['as-expected', 'unexpected-hit', 'unexpected-miss', 'unscored']
RunStatus = Literal['complete', 'partial', 'cancelled', 'failed']
WorkerOp = Literal['probe', 'lint', 'scan']
# CSAF applicability words as intelligence/1 states them (parity is tested); a rule never decides one.
Resolution = Literal['affected', 'not_affected', 'fixed', 'under_investigation', 'contradictory', 'ambiguous',
                     'unknown']
GATE_IDS: tuple[str, ...] = get_args(GateId)
NOT_SCANNED_REASONS = ('too-large', 'unreadable', 'not-pe', 'file-changed', 'cancelled')
_OTHER: dict[str, str] = {'older': 'newer', 'newer': 'older'}


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Contract(Record):
    contract: Literal['yara-rules/1'] = CONTRACT


class WorkerRecord(Record):
    contract: Literal['rules-worker/1'] = WORKER_CONTRACT


# --- helpers shared with the slices that produce these records ----------------------------------------------------

def rule_text_sha256(text: str) -> str:
    """The one definition of ``rule_sha256``: SHA-256 of the UTF-8 (= ASCII) rule text as stored, LF line ends."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def rule_name_for(lineage_id: str, direction: str) -> str:
    """``PT_<first 12 hex of the lineage id>_<older|newer>`` (plan s7 grammar)."""
    return f'PT_{lineage_id[:12]}_{direction}'


def pattern_metrics(pattern: str) -> tuple[int, int, int]:
    """(length, literal bytes, longest literal run) of a hex pattern in token form; wildcards are ``??``."""
    tokens = pattern.split(' ')
    longest = run = 0
    for token in tokens:
        run = 0 if token == '??' else run + 1
        longest = max(longest, run)
    return len(tokens), sum(1 for t in tokens if t != '??'), longest


def unescaped_length(text: str) -> int:
    """Number of bytes an ``EscapedText`` stands for (each escape is one byte)."""
    return len(_ESCAPED_UNIT.findall(text))


def _sorted_unique(values, what: str, key=None) -> None:
    items = list(values)
    keyed = [key(v) for v in items] if key else items
    if keyed != sorted(set(keyed)):
        raise ValueError(f'{what} must be sorted and unique')


def _unique(values, what: str) -> None:
    items = list(values)
    if len(set(items)) != len(items):
        raise ValueError(f'{what} must be unique')


def _text_contains_rule(text: str, name: str) -> bool:
    return re.search(rf'(?m)^rule {re.escape(name)}\b', text) is not None


# --- engine identity ----------------------------------------------------------------------------------------------

class EngineStamp(Record):
    """What produced a result. A change of ``version``, ``grammar`` or ``worker`` marks stored grids stale; the rule text
    is kept. ``decoder`` is ``none`` for a stamp that has no byte-feature step (scan-only work, decoder not installed)."""
    engine: Literal['yara-x'] = ENGINE
    version: VersionText
    version_source: Literal['metadata', 'pin']
    decoder: DecoderName = 'none'
    decoder_version: VersionText | None = None
    grammar: Literal['yrx-gen/1'] = GRAMMAR
    worker: Literal['rules-worker/1'] = WORKER_CONTRACT

    @model_validator(mode='after')
    def _decoder(self):
        if (self.decoder == 'none') != (self.decoder_version is None):
            raise ValueError('a decoder has a version; no decoder has none')
        return self


# --- the accepted pair a rule comes from ----------------------------------------------------------------------------

class FunctionRef(Record):
    """One side's function. ``size`` is known only with a verified extent (``.pdata`` or the unified IR); a leaf function
    without exception data has ``extent == 'unknown'`` and no size, so no bytes feature can be built from it."""
    name: PlainLine256 | None = None  # off by default in exports: names may come from symbol files
    rva: Rva
    size: Annotated[int, Field(ge=1, lt=2**32)] | None = None
    extent: Extent

    @model_validator(mode='after')
    def _extent(self):
        if (self.extent == 'unknown') != (self.size is None):
            raise ValueError('a size needs a verified extent and an unknown extent has no size')
        return self


class PairSource(Record):
    """The analyst-accepted changed-function pair. Eligibility (``materiality == 'material'`` or analyst confirmation) is a
    gate of the candidate, not a property of this fact record."""
    project_id: ProjectId
    revision: Count
    run_id: ProjectId
    older_sha256: Sha256
    newer_sha256: Sha256
    match_id: ProjectId
    category: Category
    review: Literal['accepted']
    materiality: Materiality
    analyst_confirmed_material: bool
    finding_id: ProjectId | None = None
    cwe: CweId | None = None
    older: FunctionRef | None = None
    newer: FunctionRef | None = None

    @model_validator(mode='after')
    def _consistent(self):
        if self.older_sha256 == self.newer_sha256:
            raise ValueError('the older and newer builds must differ')
        has_older, has_newer = self.older is not None, self.newer is not None
        if (has_older, has_newer) != {'modified': (True, True), 'added': (False, True),
                                      'removed': (True, False)}[self.category]:
            raise ValueError(f'a {self.category} pair has exactly the functions of its category')
        return self


# --- features -----------------------------------------------------------------------------------------------------

class CallPin(Record):
    """Ties a masked ``call [rip+disp32]`` inside a bytes window to the import slot it goes through. Offsets are inside the
    window; ``end_offset`` is where the instruction ends (the base of the RIP-relative displacement)."""
    disp_offset: Annotated[int, Field(ge=0, lt=_L.hex_pattern_bytes)]
    end_offset: Annotated[int, Field(ge=4, le=_L.hex_pattern_bytes)]
    dll: PlainLine256
    name: PlainLine256

    @model_validator(mode='after')
    def _span(self):
        if self.disp_offset + 4 > self.end_offset:
            raise ValueError('a 4-byte displacement must end at or before the instruction end')
        return self


class BytesFeature(Record):
    kind: Literal['bytes'] = 'bytes'
    included: bool
    side: Side
    window_rva: Rva
    length: Annotated[int, Field(ge=_L.window_min_bytes, le=_L.hex_pattern_bytes)]
    pattern: HexPattern
    literal: Count
    longest_run: Count
    mask: tuple[MaskKind, ...] = ()
    mask_source: MaskSourceName
    pins: tuple[CallPin, ...] = Field(default=(), max_length=_L.pins_per_feature)
    source_hits: Count | None = None
    other_hits: Count | None = None
    separation: Separation

    @model_validator(mode='after')
    def _consistent(self):
        length, literal, longest = pattern_metrics(self.pattern)
        if (self.length, self.literal, self.longest_run) != (length, literal, longest):
            raise ValueError('length, literal and longest_run must be the pattern\'s own numbers')
        _sorted_unique(self.mask, 'mask')
        if '??' in self.pattern and not self.mask:
            raise ValueError('wildcards need the mask kinds that produced them')
        tokens = self.pattern.split(' ')
        _sorted_unique(self.pins, 'pins', key=lambda p: p.disp_offset)
        previous_end = 0
        for pin in self.pins:
            if pin.end_offset > self.length or pin.disp_offset < previous_end:
                raise ValueError('pins must lie inside the window and must not overlap')
            if any(t != '??' for t in tokens[pin.disp_offset:pin.disp_offset + 4]):
                raise ValueError('a pinned displacement must be wildcarded in the pattern')
            previous_end = pin.disp_offset + 4
        expected = ('unknown' if self.other_hits is None else
                    f'{self.side}-only' if self.other_hits == 0 else 'both-sides')
        if self.separation != expected:
            raise ValueError(f'separation must be {expected} for other_hits={self.other_hits}')
        return self


class StringFeature(Record):
    """A static string the changed code references. ``text`` is the escaped form exactly as the rule emits it (exact bytes
    were re-read from the verified artifact; the display form is never used); ``length`` is the byte count it stands for."""
    kind: Literal['string'] = 'string'
    included: bool
    side: Side
    value_sha256: Sha256
    length: Annotated[int, Field(ge=1, le=_L.text_pattern_bytes)]
    text: EscapedText
    encoding: Encoding
    offset: FileOffset
    evidence_run_id: PlainLine200
    linked_by: LinkedBy
    separation: Separation

    @model_validator(mode='after')
    def _consistent(self):
        if unescaped_length(self.text) != self.length:
            raise ValueError('length must be the number of bytes the escaped text stands for')
        if self.separation == f'{_OTHER[self.side]}-only':
            raise ValueError('a string present in this build cannot exist only in the other build')
        return self


class ImportFeature(Record):
    kind: Literal['import'] = 'import'
    included: bool
    dll: PlainLine256
    name: PlainLine256 | None = None
    ordinal: Annotated[int, Field(ge=1, le=65535)] | None = None
    delay: bool = False
    origin: Origin
    separation: Separation

    @model_validator(mode='after')
    def _one_identity(self):
        if (self.name is None) == (self.ordinal is None):
            raise ValueError('an import has exactly one of name and ordinal')
        return self


class ApiRef(Record):
    dll: PlainLine256
    name: PlainLine256


class CapabilityFeature(Record):
    """A capa capability that appeared or disappeared with the changed code. It contributes metadata and API gates; it is
    never a rule condition by itself."""
    kind: Literal['capability'] = 'capability'
    included: bool
    rule_id: PlainLine256
    namespace: PlainLine256 | None = None
    attack: tuple[PlainLine64, ...] = Field(default=(), max_length=16)
    classification: Classification
    api_gates: tuple[ApiRef, ...] = Field(default=(), max_length=8)
    separation: Separation

    @model_validator(mode='after')
    def _consistent(self):
        _sorted_unique(self.attack, 'attack')
        _sorted_unique(self.api_gates, 'api_gates', key=lambda g: (g.dll, g.name))
        want = 'newer-only' if self.classification == 'newly-introduced' else 'older-only'
        if self.separation != want:
            raise ValueError(f'{self.classification} means {want}')
        return self


Feature = Annotated[BytesFeature | StringFeature | ImportFeature | CapabilityFeature, Field(discriminator='kind')]


class Gate(Record):
    """One check with its measured number (a count, a size or short text), never combined into a score."""
    gate_id: GateId
    state: GateState
    measured: Count | PlainLine64 | None = None
    detail: Annotated[str, AfterValidator(plain_line), Field(max_length=300)] = ''


# --- candidates, decisions, versions ------------------------------------------------------------------------------

def _check_rule_text(text: str, digest: str) -> None:
    if rule_text_sha256(text) != digest:
        raise ValueError('rule_sha256 is not the hash of rule_text')


class RuleCandidate(Contract):
    """One proposed rule for one direction of one accepted pair. Included features all describe that direction's build
    only (delta, not inventory); features of the other build, or present in both, are shown but never included."""
    candidate_id: Sha256
    lineage_id: Sha256
    direction: Direction
    source: PairSource
    features: tuple[Feature, ...] = Field(min_length=1, max_length=_L.features_per_candidate)
    rule_name: RuleName
    rule_text: RuleText
    rule_sha256: Sha256
    gates: tuple[Gate, ...] = Field(max_length=len(GATE_IDS))
    compile_warnings: tuple[WarningCode, ...] = Field(default=(), max_length=_L.diagnostics_per_rule)
    engine: EngineStamp
    unvetted: bool

    @model_validator(mode='after')
    def _consistent(self):
        src = self.source
        if (src.older if self.direction == 'older' else src.newer) is None:
            raise ValueError(f'a {self.direction}-build rule needs a {self.direction} function in the pair')
        if src.materiality != 'material' and not src.analyst_confirmed_material:
            raise ValueError('only a pair reviewed as material, or confirmed by the analyst, has candidates')
        if self.unvetted != (src.materiality != 'material'):
            raise ValueError('unvetted is exactly "material by analyst confirmation only"')
        if self.rule_name != rule_name_for(self.lineage_id, self.direction):
            raise ValueError('rule_name must be PT_<lineage id first 12 hex>_<direction>')
        _check_rule_text(self.rule_text, self.rule_sha256)
        if not _text_contains_rule(self.rule_text, self.rule_name):
            raise ValueError('rule_text must define rule_name')
        order = [g.gate_id for g in self.gates]
        if order != [g for g in GATE_IDS if g in order]:
            raise ValueError('gates must be unique and in canonical order')
        _sorted_unique(self.compile_warnings, 'compile_warnings')
        included = [f for f in self.features if f.included]
        if not included:
            raise ValueError('a candidate includes at least one feature')
        for feature in included:
            if feature.separation != f'{self.direction}-only':
                raise ValueError(f'an included feature must exist only in the {self.direction} build')
            if getattr(feature, 'side', self.direction) != self.direction:
                raise ValueError('an included feature must come from the rule\'s own build')
        hex_n = sum(isinstance(f, BytesFeature) for f in included)
        text_n = sum(isinstance(f, StringFeature) for f in included)
        if hex_n > _L.hex_patterns_per_rule or text_n > _L.text_patterns_per_rule \
                or hex_n + text_n > _L.patterns_per_rule:
            raise ValueError('included features exceed the pattern ceilings of one rule')
        return self


class RuleDecision(Contract):
    """The analyst's action on a candidate. Accepting needs a label and saves a version; it publishes nothing."""
    decision_id: Sha256
    candidate_id: Sha256
    action: Action
    analyst_label: PlainLine120 | None = None
    note: Note = ''
    cve: tuple[CveId, ...] = Field(default=(), max_length=16)
    kb: tuple[KbId, ...] = Field(default=(), max_length=16)
    cwe: tuple[CweId, ...] = Field(default=(), max_length=16)
    decided_at: Utc

    @model_validator(mode='after')
    def _consistent(self):
        if self.action == 'accept' and self.analyst_label is None:
            raise ValueError('accepting a rule needs a label')
        if self.action != 'accept' and (self.analyst_label is not None or self.cve or self.kb or self.cwe):
            raise ValueError('a label and advisory ids belong to an accept decision')
        for name in ('cve', 'kb', 'cwe'):
            _sorted_unique(getattr(self, name), name)
        return self


class RuleVersion(Contract):
    """An accepted, immutable rule text. A revision is a new version that supersedes the previous one."""
    version_id: Sha256
    lineage_id: Sha256
    version: Annotated[int, Field(ge=1, le=_L.versions_per_lineage)]
    supersedes: Sha256 | None = None
    candidate_id: Sha256
    decision_id: Sha256
    rule_text: RuleText
    rule_sha256: Sha256
    source: PairSource
    engine: EngineStamp
    created_at: Utc

    @model_validator(mode='after')
    def _consistent(self):
        if (self.version == 1) != (self.supersedes is None):
            raise ValueError('version 1 supersedes nothing and every later version supersedes its predecessor')
        if self.supersedes == self.version_id:
            raise ValueError('a version cannot supersede itself')
        _check_rule_text(self.rule_text, self.rule_sha256)
        if re.search(rf'(?m)^rule PT_{self.lineage_id[:12]}_(?:older|newer)\b', self.rule_text) is None:
            raise ValueError('rule_text must define the rule of this lineage')
        return self


# --- tests of a rule against builds ---------------------------------------------------------------------------------

class TargetRef(Record):
    """One scanned build. Records keep hashes and a display label, never a path. ``expect`` is the analyst's expectation
    (``unknown`` until set); ``advisory_says`` is shown beside the rule's own result and never merged with it."""
    target_id: Key
    label: PlainLine256
    role: Role
    sha256: Sha256
    size: Annotated[int, Field(ge=0, lt=2**40)]
    ordinal: Annotated[int, Field(ge=1, le=_L.series_targets)] | None = None
    expect: Expect = 'unknown'
    advisory_says: Resolution = 'unknown'
    file_version: FileVersion | None = None
    kb: KbId | None = None
    toolchain_flag: ToolchainFlag = 'unknown'

    @model_validator(mode='after')
    def _ordinal(self):
        if self.role in ('extra', 'clean', 'control') and self.ordinal is not None:
            raise ValueError(f'a {self.role} file has no series ordinal')
        if self.role == 'series' and self.ordinal is None:
            raise ValueError('a series build has an ordinal')
        return self


class CellResult(Record):
    """One rule against one target. ``hits`` counts the matches of the first rule pattern that matched (capped by the
    engine at ``max_matches_per_pattern``), or is 1 for a rule that matched without a pattern; ``offsets`` are the first
    file offsets (ascending) and ``rvas`` their module-relative addresses (``None`` outside every section). A file that
    was not scanned, timed out or errored has ``hits is None``: unknown is never zero."""
    state: CellState
    hits: Count | None = None
    offsets: tuple[FileOffset, ...] = Field(default=(), max_length=_L.offsets_per_cell)
    rvas: tuple[Rva | None, ...] = Field(default=(), max_length=_L.offsets_per_cell)
    reason: Slug | None = None
    elapsed_ms: Annotated[int, Field(ge=0, lt=2**40)] = 0
    verdict: Verdict = 'unscored'

    @model_validator(mode='after')
    def _consistent(self):
        scanned = self.state in ('hit', 'no-hit')
        if self.state == 'hit' and (self.hits is None or self.hits < 1):
            raise ValueError('a hit has at least one match')
        if self.state == 'no-hit' and self.hits != 0:
            raise ValueError('no-hit means zero matches')
        if not scanned and self.hits is not None:
            raise ValueError('a file that was not scanned has no hit count')
        if self.offsets and self.state != 'hit':
            raise ValueError('only a hit has offsets')
        if any(a >= b for a, b in zip(self.offsets, self.offsets[1:], strict=False)):
            raise ValueError('offsets must be strictly ascending')
        if len(self.rvas) != len(self.offsets) or len(self.offsets) > min(self.hits or 0, _L.offsets_per_cell):
            raise ValueError('rvas parallel offsets and offsets cannot exceed the hit count')
        if self.state == 'not-scanned' and self.reason not in NOT_SCANNED_REASONS:
            raise ValueError('not-scanned needs one reason of the closed list')
        if self.state == 'error' and self.reason is None:
            raise ValueError('an error cell needs a reason slug')
        if self.state in ('hit', 'no-hit', 'timeout') and self.reason is not None:
            raise ValueError('only not-scanned and error cells carry a reason')
        if not scanned and self.verdict != 'unscored':
            raise ValueError('a cell without a scan result is never scored')
        return self


class RunRule(Record):
    version_id: Sha256
    rule_sha256: Sha256


class MatrixRun(Contract):
    """A grid of rule versions (columns) against builds (rows). ``cells`` is row-major: ``cells[i * len(rules) + j]`` is
    target ``i`` against rule ``j``. ``failed`` runs keep no cells."""
    run_id: ProjectId
    cache_key: Sha256
    engine: EngineStamp
    status: RunStatus
    rules: tuple[RunRule, ...] = Field(min_length=1, max_length=_L.rules_per_run)
    targets: tuple[TargetRef, ...] = Field(min_length=1, max_length=_L.targets_per_run)
    cells: tuple[CellResult, ...] = Field(default=(), max_length=_L.cells)
    limits: dict[Annotated[str, Field(pattern=r'^[a-z][a-z0-9_]{0,47}$')], Annotated[int, Field(ge=0, lt=2**63)]] = \
        Field(max_length=64)
    anomalies: tuple[PlainLine256, ...] = Field(default=(), max_length=64)
    finished_at: Utc

    @model_validator(mode='after')
    def _consistent(self):
        _unique([r.version_id for r in self.rules], 'rules')  # column and row order is the display order
        _unique([t.target_id for t in self.targets], 'targets')
        want = 0 if self.status == 'failed' else len(self.targets) * len(self.rules)
        if len(self.cells) != want:
            raise ValueError('cells must be targets x rules (none for a failed run)')
        return self


class ExportRecord(Contract):
    """That an analyst saved a rule as a local ``.yar`` file: a basename and the file's hash, never a path."""
    export_id: Sha256
    version_id: Sha256
    basename: Annotated[str, AfterValidator(plain_line), Field(min_length=1, max_length=128,
                                                                  pattern=r'^[^/\\]+$')]
    sha256: Sha256
    exported_at: Utc
    warnings: tuple[Slug, ...] = Field(default=(), max_length=16)

    @model_validator(mode='after')
    def _canonical(self):
        _sorted_unique(self.warnings, 'warnings')
        return self


# --- the worker boundary (hidden child process; request and result are JSON files) ---------------------------------------

class WorkerRule(Record):
    """``name`` is the caller's key for this rule (a version id), not the YARA identifier."""
    name: Key
    text: RuleText


class WorkerTarget(Record):
    """``sha256`` is None for a file whose identity the caller does not know (an extra build); ``size`` is what the caller
    saw. A file that differs from either is reported as changed, never scanned as if it were the recorded build."""
    target_id: Key
    path: Annotated[str, Field(min_length=1, max_length=4096, pattern=r'^[^\x00]+$')]
    sha256: Sha256 | None = None
    size: Annotated[int, Field(ge=0, lt=2**40)]


class WorkerLimits(Record):
    """The caps the child enforces itself (the parent also enforces the process memory cap and the wall clock)."""
    memory_bytes: Annotated[int, Field(ge=16 * 1024 ** 2, le=_L.worker_memory_max_bytes)] = _L.worker_memory_bytes
    file_bytes: Annotated[int, Field(ge=1, le=_L.file_bytes)] = _L.file_bytes
    target_timeout_s: Annotated[int, Field(ge=1, le=_L.target_timeout_max_s)] = _L.target_timeout_s
    max_matches_per_pattern: Annotated[int, Field(ge=1, le=_L.max_matches_per_pattern)] = _L.max_matches_per_pattern
    offsets_per_cell: Annotated[int, Field(ge=1, le=_L.offsets_per_cell)] = _L.offsets_per_cell
    patterns_per_rule: Annotated[int, Field(ge=1, le=_L.patterns_per_rule)] = _L.patterns_per_rule
    diagnostics_per_rule: Annotated[int, Field(ge=1, le=_L.diagnostics_per_rule)] = _L.diagnostics_per_rule


class WorkerRequest(WorkerRecord):
    op: WorkerOp
    rules: tuple[WorkerRule, ...] = Field(default=(), max_length=_L.rules_per_run)
    targets: tuple[WorkerTarget, ...] = Field(default=(), max_length=_L.targets_per_run)
    limits: WorkerLimits = WorkerLimits()
    result: Annotated[str, Field(min_length=1, max_length=4096, pattern=r'^[^\x00]+$')]

    @model_validator(mode='after')
    def _shape(self):
        _unique([r.name for r in self.rules], 'rule names')
        _unique([t.target_id for t in self.targets], 'target ids')
        needs = {'probe': (False, False), 'lint': (True, False), 'scan': (True, True)}[self.op]
        if (bool(self.rules), bool(self.targets)) != needs:
            raise ValueError(f'a {self.op} request carries {"rules" if needs[0] else "no rules"} and '
                             f'{"targets" if needs[1] else "no targets"}')
        if len(self.rules) * len(self.targets) > _L.cells:
            raise ValueError('rules x targets exceeds the cell cap')
        return self


class Diagnostic(Record):
    """A compiler error or warning, reduced to what is safe to keep: engine rule text and source excerpts are dropped."""
    code: Annotated[str, Field(pattern=r'^(?:E[0-9]{3}|[A-Za-z][A-Za-z0-9_]{1,63})$')]
    title: PlainLine200
    line: Annotated[int, Field(ge=1, lt=2**31)] | None = None
    column: Annotated[int, Field(ge=1, lt=2**31)] | None = None


class LintResult(Record):
    """Compiling one rule text with the PatchTrace linters (required provenance metadata, rule-name regex, tag whitelist,
    no includes, slow patterns are errors). ``ok`` also requires exactly one rule, ``import "pe"`` as the only import and
    at most ``patterns_per_rule`` patterns. ``formatter_stable`` (the text equals YARA-X's own formatting) is reported
    separately: it pins the grammar, but a formatter change in a newer YARA-X must not invalidate stored rules."""
    name: Key
    ok: bool
    errors: tuple[Diagnostic, ...] = Field(default=(), max_length=_L.diagnostics_per_rule)
    warnings: tuple[Diagnostic, ...] = Field(default=(), max_length=_L.diagnostics_per_rule)
    identifiers: tuple[YaraIdentifier, ...] = Field(default=(), max_length=16)
    imports: tuple[ModuleName, ...] = Field(default=(), max_length=16)
    patterns: Count = 0
    formatter_stable: bool = False

    @model_validator(mode='after')
    def _consistent(self):
        if self.ok == bool(self.errors):
            raise ValueError('ok means no errors and not ok means at least one')
        if self.formatter_stable and not self.ok:
            raise ValueError('only a rule that compiled can be formatter-stable')
        return self


class WorkerError(Record):
    code: ErrorCode
    message: PlainLine400
    reason: Slug | None = None


class WorkerResult(WorkerRecord):
    """One strict JSON document per run. ``cells`` is row-major over the request's targets and rules; every verdict is
    ``unscored`` because the child knows no expectations (the matrix layer scores against the analyst's)."""
    op: WorkerOp
    kind: Literal['ok', 'error']
    engine: EngineStamp | None = None
    modules: tuple[ModuleName, ...] = Field(default=(), max_length=64)
    lint: tuple[LintResult, ...] = Field(default=(), max_length=_L.rules_per_run)
    cells: tuple[CellResult, ...] = Field(default=(), max_length=_L.cells)
    error: WorkerError | None = None

    @model_validator(mode='after')
    def _shape(self):
        if self.kind == 'error':
            if self.error is None or self.engine is not None or self.modules or self.lint or self.cells:
                raise ValueError('an error result carries the error alone')
            return self
        if self.error is not None or self.engine is None:
            raise ValueError('an ok result carries the engine stamp and no error')
        wants = {'probe': (True, False, False), 'lint': (False, True, False), 'scan': (False, True, True)}[self.op]
        if (bool(self.modules), bool(self.lint), bool(self.cells)) != wants:
            raise ValueError(f'a {self.op} result carries exactly its own sections')
        if any(c.verdict != 'unscored' for c in self.cells):
            raise ValueError('the worker scores nothing')
        return self
