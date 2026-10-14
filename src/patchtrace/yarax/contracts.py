"""Strict `yara-rules/1` contracts (plan s7). Pure: no Qt, no I/O, no `yara_x`.

Models are frozen, forbid extra fields and coerce nothing. A match is a pattern observation: nothing here carries a
score, a vulnerability claim or a combined confidence; gates and metrics stay separate raw values.
"""
from __future__ import annotations

import hashlib
from typing import Annotated, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .limits import LIMITS

CONTRACT = 'yara-rules/1'
GRAMMAR = 'yrx-gen/1'
WORKER_CONTRACT = 'rules-worker/1'
EXPORT_MARKER = 'patchtrace-rule-export/1'

Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Rva = Annotated[int, Field(ge=0, le=2**32 - 1)]
Short = Annotated[str, Field(max_length=LIMITS.meta_string_chars)]
Name = Annotated[str, Field(max_length=256)]
Utc = Annotated[str, Field(pattern=r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')]
Cve = Annotated[str, Field(pattern=r'^CVE-\d{4}-\d{4,7}$')]
Kb = Annotated[str, Field(pattern=r'^KB\d{6,8}$')]
Cwe = Annotated[str, Field(pattern=r'^CWE-\d{1,5}$')]
HexPattern = Annotated[str, Field(pattern=r'^([0-9A-F]{2}|\?\?)( ([0-9A-F]{2}|\?\?))*$')]
RuleName = Annotated[str, Field(pattern=r'^PT_[0-9a-f]{12}_(older|newer)$')]

Side = Literal['older', 'newer']
Extent = Literal['pdata', 'unified-ir', 'unknown']
Category = Literal['modified', 'added', 'removed']
Separation = Literal['older-only', 'newer-only', 'both', 'neither', 'unknown']
MaskKind = Literal['rip-disp', 'branch-ext', 'reloc', 'addr-ref']
GateId = Literal['elig', 'len', 'wild', 'uniq', 'sep', 'compile', 'secret', 'dist']
GateState = Literal['pass', 'fail', 'unknown', 'waived']
DecisionAction = Literal['accept', 'reject', 'defer', 'archive']
TargetRole = Literal['older-anchor', 'newer-anchor', 'series', 'extra', 'clean', 'control']
Expect = Literal['hit', 'no-hit', 'unknown']
CellState = Literal['hit', 'no-hit', 'not-scanned', 'timeout', 'error']
Verdict = Literal['as-expected', 'unexpected-hit', 'unexpected-miss', 'unscored']
RunStatus = Literal['complete', 'partial', 'cancelled', 'failed']
WorkerOp = Literal['probe', 'lint', 'scan']


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


def _no_controls(value: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError('control characters are not allowed')
    return value


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


class EngineStamp(_Strict):
    engine: Literal['yara-x'] = 'yara-x'
    version: str = Field(min_length=1, max_length=32)
    version_source: Literal['metadata', 'pin']
    decoder: str = Field(min_length=1, max_length=32)
    decoder_version: str = Field(min_length=1, max_length=32)
    grammar: Literal['yrx-gen/1'] = GRAMMAR
    worker: Literal['rules-worker/1'] = WORKER_CONTRACT


class FunctionRef(_Strict):
    name: Name = ''
    rva: Rva
    size: Annotated[int, Field(ge=0, le=LIMITS.function_bytes)]
    extent: Extent


class PairSource(_Strict):
    project_id: str = Field(min_length=1, max_length=128)
    revision: int = Field(ge=0)
    run_id: str = Field(min_length=1, max_length=128)
    older_sha256: Sha256
    newer_sha256: Sha256
    match_id: str = Field(min_length=1, max_length=128)
    category: Category
    review: Literal['accepted'] = 'accepted'
    materiality: Short
    analyst_confirmed_material: bool = False
    finding_id: str | None = Field(default=None, max_length=128)
    cwe: tuple[Cwe, ...] = ()
    older: FunctionRef | None = None
    newer: FunctionRef | None = None

    @model_validator(mode='after')
    def _sides_match_category(self) -> PairSource:
        # an added function has no older body, a removed one no newer body
        if (self.older is None) != (self.category == 'added') or (self.newer is None) != (self.category == 'removed'):
            raise ValueError('function sides do not match the category')
        return self


class CallPin(_Strict):
    disp_offset: int = Field(ge=0, lt=LIMITS.hex_pattern_bytes)
    end_offset: int = Field(ge=0, le=LIMITS.hex_pattern_bytes)
    dll: Name
    name: Name

    @model_validator(mode='after')
    def _ordered(self) -> CallPin:
        if self.end_offset <= self.disp_offset:
            raise ValueError('pin end must follow the displacement offset')
        return self


class BytesFeature(_Strict):
    kind: Literal['bytes'] = 'bytes'
    included: bool = True
    side: Side
    window_rva: Rva
    length: int = Field(ge=LIMITS.hex_pattern_min_bytes, le=LIMITS.hex_pattern_bytes)
    pattern: HexPattern
    literal: int = Field(ge=0, le=LIMITS.hex_pattern_bytes)
    longest_run: int = Field(ge=0, le=LIMITS.hex_pattern_bytes)
    mask: tuple[MaskKind, ...] = ()
    mask_source: Literal['iced-x86', 'unified-ir']
    pins: tuple[CallPin, ...] = Field(default=(), max_length=LIMITS.call_pins)
    source_hits: int = Field(ge=0)
    other_hits: int = Field(ge=0)
    separation: Separation

    @model_validator(mode='after')
    def _pattern_agrees(self) -> BytesFeature:
        tokens = self.pattern.split(' ')
        literal = sum(token != '??' for token in tokens)
        if len(tokens) != self.length or literal != self.literal or self.longest_run > literal:
            raise ValueError('pattern disagrees with length, literal or longest_run')
        return self


class StringFeature(_Strict):
    kind: Literal['string'] = 'string'
    included: bool = False
    side: Side
    value_sha256: Sha256
    length: int = Field(ge=1, le=LIMITS.text_pattern_bytes)
    text: Annotated[str, Field(max_length=LIMITS.text_pattern_bytes * 4)]  # escaped form, so it may exceed length
    encoding: Literal['ascii', 'wide', 'ascii-wide']
    offset: int = Field(ge=0)
    evidence_run_id: str = Field(min_length=1, max_length=128)
    linked_by: Literal['xref', 'file-level']
    separation: Separation


class ImportFeature(_Strict):
    kind: Literal['import'] = 'import'
    included: bool = False
    dll: Name
    name: Name | None = None
    ordinal: int | None = Field(default=None, ge=0, le=0xFFFF)
    delay: bool = False
    origin: Literal['pe-imports', 'capa-api']
    separation: Separation

    @model_validator(mode='after')
    def _name_or_ordinal(self) -> ImportFeature:
        if (self.name is None) == (self.ordinal is None):
            raise ValueError('exactly one of name and ordinal is required')
        return self


class CapabilityFeature(_Strict):
    kind: Literal['capability'] = 'capability'
    included: bool = False
    rule_id: Name
    namespace: Name
    attack: tuple[Name, ...] = ()
    classification: Short = ''
    api_gates: tuple[Name, ...] = ()
    separation: Separation


Feature = Annotated[BytesFeature | StringFeature | ImportFeature | CapabilityFeature, Field(discriminator='kind')]


class Gate(_Strict):
    gate_id: GateId
    state: GateState
    measured: int | str | None = None
    detail: Short = ''


class LintFinding(_Strict):
    rule_name: Name
    code: str = Field(min_length=1, max_length=64)
    severity: Literal['warning', 'error']
    message: Annotated[str, Field(max_length=LIMITS.meta_string_chars)]


class RuleCandidate(_Strict):
    candidate_id: Sha256
    lineage_id: Sha256
    direction: Side
    source: PairSource
    features: tuple[Feature, ...] = Field(max_length=LIMITS.patterns_per_rule * 2)
    rule_name: RuleName
    rule_text: str = Field(min_length=1, max_length=LIMITS.rule_text_bytes)
    rule_sha256: Sha256
    gates: tuple[Gate, ...] = Field(max_length=len(get_args(GateId)))
    compile_warnings: tuple[LintFinding, ...] = Field(default=(), max_length=64)
    engine: EngineStamp
    unvetted: bool = False

    @model_validator(mode='after')
    def _consistent(self) -> RuleCandidate:
        if self.rule_name != f'PT_{self.lineage_id[:12]}_{self.direction}':
            raise ValueError('rule_name does not follow lineage and direction')
        if self.rule_sha256 != text_sha256(self.rule_text):
            raise ValueError('rule_sha256 does not match rule_text')
        if len({gate.gate_id for gate in self.gates}) != len(self.gates):
            raise ValueError('duplicate gate')
        return self


class RuleDecision(_Strict):
    decision_id: Sha256
    candidate_id: Sha256
    action: DecisionAction
    analyst_label: Annotated[str, Field(max_length=LIMITS.label_chars)] = ''
    note: Annotated[str, Field(max_length=2000)] = ''
    cve: tuple[Cve, ...] = ()
    kb: tuple[Kb, ...] = ()
    cwe: tuple[Cwe, ...] = ()
    decided_at: Utc

    @model_validator(mode='after')
    def _label(self) -> RuleDecision:
        _no_controls(self.analyst_label)
        if self.action == 'accept' and not self.analyst_label.strip():
            raise ValueError('accepting a rule needs an analyst label')
        return self


class RuleVersion(_Strict):
    version_id: Sha256
    lineage_id: Sha256
    version: int = Field(ge=1, le=LIMITS.versions_per_lineage)
    supersedes: Sha256 | None = None
    candidate_id: Sha256
    decision_id: Sha256
    rule_text: str = Field(min_length=1, max_length=LIMITS.rule_text_bytes)
    rule_sha256: Sha256
    source: PairSource
    engine: EngineStamp
    created_at: Utc

    @model_validator(mode='after')
    def _consistent(self) -> RuleVersion:
        if (self.version == 1) != (self.supersedes is None):
            raise ValueError('only the first version has no predecessor')
        if self.rule_sha256 != text_sha256(self.rule_text):
            raise ValueError('rule_sha256 does not match rule_text')
        return self


class TargetRef(_Strict):
    target_id: str = Field(min_length=1, max_length=128)
    label: Annotated[str, Field(max_length=LIMITS.label_chars)] = ''
    role: TargetRole
    sha256: Sha256
    size: int = Field(ge=0, le=LIMITS.target_file_bytes)
    ordinal: int | None = Field(default=None, ge=0)
    expect: Expect = 'unknown'
    advisory_says: Short = ''  # the advisory's words, shown verbatim as data
    file_version: Annotated[str, Field(max_length=64)] = ''
    kb: tuple[Kb, ...] = ()
    toolchain_flag: bool = False


class CellResult(_Strict):
    rule_name: Name
    target_id: str = Field(min_length=1, max_length=128)
    state: CellState
    hits: int = Field(default=0, ge=0)
    offsets: tuple[int, ...] = Field(default=(), max_length=LIMITS.cell_offsets)
    rvas: tuple[Rva, ...] = Field(default=(), max_length=LIMITS.cell_offsets)
    reason: Short = ''
    elapsed_ms: int = Field(default=0, ge=0)
    verdict: Verdict = 'unscored'

    @model_validator(mode='after')
    def _consistent(self) -> CellResult:
        if (self.state == 'hit') != (self.hits > 0):
            raise ValueError('hits must be positive exactly when the state is hit')
        # an unscanned cell is unknown, never a negative: it carries no evidence and no verdict
        if self.state not in ('hit', 'no-hit') and (self.offsets or self.rvas or self.verdict != 'unscored'):
            raise ValueError('an unscanned cell carries no offsets, rvas or verdict')
        return self


class MatrixRun(_Strict):
    run_id: str = Field(min_length=1, max_length=128)
    cache_key: Sha256
    engine: EngineStamp
    status: RunStatus
    targets: tuple[TargetRef, ...]
    cells: tuple[CellResult, ...] = Field(max_length=LIMITS.cells)
    limits: dict[str, int]
    anomalies: tuple[Short, ...] = ()


class ExportRecord(_Strict):
    export_id: Sha256
    version_id: Sha256
    basename: Annotated[str, Field(pattern=r'^[A-Za-z0-9_.-]{1,128}$')]
    sha256: Sha256
    exported_at: Utc
    warnings: tuple[Short, ...] = ()


class RuleText(_Strict):
    name: RuleName
    text: str = Field(min_length=1, max_length=LIMITS.rule_text_bytes)


class WorkerTarget(_Strict):
    target_id: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=1024)
    sha256: Sha256 | None
    size: int = Field(ge=0, le=LIMITS.target_file_bytes)


class WorkerRequest(_Strict):
    op: WorkerOp
    rules: tuple[RuleText, ...] = Field(default=(), max_length=LIMITS.rules_per_run)
    targets: tuple[WorkerTarget, ...] = ()
    limits: dict[str, int]
    result: str = Field(min_length=1, max_length=1024)

    @model_validator(mode='after')
    def _op_inputs(self) -> WorkerRequest:
        if self.op != 'probe' and not self.rules:
            raise ValueError('lint and scan need rules')
        if self.op == 'scan' and not self.targets:
            raise ValueError('scan needs targets')
        return self


class WorkerResult(_Strict):
    kind: Literal['ok', 'error']
    engine: EngineStamp | None = None
    error_code: Literal['PT-RULE-ENGINE', 'PT-RULE-TIMEOUT', 'PT-RULE-CANCEL', 'PT-RULE-COMPILE',
                        'PT-RULE-UNAVAILABLE'] | None = None
    message: Annotated[str, Field(max_length=LIMITS.stderr_tail_bytes)] = ''
    lint: tuple[LintFinding, ...] = ()
    cells: tuple[CellResult, ...] = Field(default=(), max_length=LIMITS.cells)

    @model_validator(mode='after')
    def _kind(self) -> WorkerResult:
        if self.kind == 'ok' and (self.engine is None or self.error_code is not None):
            raise ValueError('ok needs an engine stamp and no error code')
        if self.kind == 'error' and self.error_code is None:
            raise ValueError('error needs an error code')
        return self
