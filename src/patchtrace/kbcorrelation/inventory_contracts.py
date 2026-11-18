"""Strict, immutable PW-01 CSV metadata records. No I/O or binary-identity claims.

The original CSV bytes remain the source of truth. Logical CSV records and
physical line spans are deliberately not represented as JSON Pointers.
"""
from __future__ import annotations

import json
import re
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from ..acquisition.contracts import AcquisitionError, validate_file_name
from ..hostile_text import replace_hostile
from .contracts import Arch, KbId, Record, Sha256, domain_id

PARSER_VERSION = 1
MAX_BYTES = 16 * 1024 * 1024
MAX_FIELD_CHARS = 65_536
MAX_RECORD_CHARS = 262_144
MAX_COLUMNS = 32
MAX_RECORDS = 100_000
MAX_ENTRIES = 50_000
MAX_PAGE_ENTRIES = 5_000
MAX_DIAGNOSTICS = 1_000
MAX_SECTIONS = 1_000
UINT64_MAX = 2**64 - 1
RawText = Annotated[str, Field(max_length=MAX_FIELD_CHARS)]
ContextText = Annotated[str, Field(min_length=1, max_length=1_000)]
Code = Literal['UNKNOWN_ARCHITECTURE', 'ARCHITECTURE_CONFLICT', 'UNKNOWN_VERSION', 'INVALID_SIZE',
               'INVALID_FILENAME', 'COLUMN_COUNT', 'PRODUCT_CONFLICT', 'RELEASE_CONFLICT', 'BUILD_CONFLICT',
               'INVALID_METADATA', 'CONFLICTING_METADATA', 'UNKNOWN_SECTION', 'RESULT_LIMIT', 'RECORD_LIMIT']
VersionComponent = Annotated[int, Field(ge=0, le=UINT64_MAX)]
_BASENAME = re.compile(r'[A-Za-z0-9._-]{1,128}')
_DEVICE = re.compile(r'(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', re.IGNORECASE)
_PE_V1 = frozenset({'exe', 'dll', 'sys', 'efi', 'drv', 'ocx', 'cpl', 'scr'})
_PE_V2 = _PE_V1 | {'tsp'}


def _normalize_filename(value: str, extensions: frozenset[str]) -> tuple[str, bool] | None:
    if (not _BASENAME.fullmatch(value) or value.endswith('.') or value.startswith(('.', '-'))
            or _DEVICE.fullmatch(value)):
        return None
    name = value.lower()
    is_pe = '.' in name and name.rsplit('.', 1)[1] in extensions
    if is_pe:
        try:
            validate_file_name(name)
        except AcquisitionError:
            return None
    return name, is_pe


def normalize_inventory_filename(value: str) -> tuple[str, bool] | None:
    """Frozen v1 classification; shared acquisition additions cannot reinterpret saved evidence."""
    return _normalize_filename(value, _PE_V1)


def normalize_inventory_page_filename(value: str) -> tuple[str, bool] | None:
    """The explicitly versioned page parser also supports the TSP PE suffix."""
    return _normalize_filename(value, _PE_V2)


class InventoryLimits(Record):
    """Callers may lower a budget, never raise a hard ceiling."""
    max_bytes: int = Field(default=MAX_BYTES, ge=1, le=MAX_BYTES)
    max_text_chars: int = Field(default=MAX_BYTES, ge=1, le=MAX_BYTES)
    max_field_chars: int = Field(default=MAX_FIELD_CHARS, ge=1, le=MAX_FIELD_CHARS)
    max_record_chars: int = Field(default=MAX_RECORD_CHARS, ge=1, le=MAX_RECORD_CHARS)
    max_columns: int = Field(default=MAX_COLUMNS, ge=1, le=MAX_COLUMNS)
    max_records: int = Field(default=MAX_RECORDS, ge=1, le=MAX_RECORDS)
    max_entries: int = Field(default=MAX_ENTRIES, ge=1, le=MAX_ENTRIES)
    max_diagnostics: int = Field(default=MAX_DIAGNOSTICS, ge=1, le=MAX_DIAGNOSTICS)
    max_sections: int = Field(default=MAX_SECTIONS, ge=1, le=MAX_SECTIONS)
    max_seconds: float = Field(default=10.0, gt=0, le=10, allow_inf_nan=False)


DEFAULT_LIMITS = InventoryLimits()


class InventoryPageLimits(InventoryLimits):
    """Source pages retain a smaller population without changing serialized budget fields."""
    max_entries: int = Field(default=MAX_PAGE_ENTRIES, ge=1, le=MAX_PAGE_ENTRIES)


DEFAULT_PAGE_LIMITS = InventoryPageLimits()


class InventoryContext(Record):
    kb: KbId
    product_scope_id: Sha256 | None = None
    product: ContextText | None = None
    release: ContextText | None = None
    build: ContextText | None = None
    architecture: Arch = 'unknown'
    delimiter: Literal['comma', 'semicolon', 'tab'] = 'comma'
    locale: Literal['invariant', 'en-US', 'de-DE'] = 'en-US'

    @field_validator('product', 'release', 'build')
    @classmethod
    def _safe_context(cls, value):
        if value is not None and (not value.strip() or replace_hostile(value) != value):
            raise ValueError('asserted context must be nonempty plain text without controls')
        return value


class CsvRecordRef(Record):
    raw_sha256: Sha256
    logical_record: int = Field(ge=1, le=MAX_RECORDS)
    line_start: int = Field(ge=1, le=MAX_BYTES + 1)
    line_end: int = Field(ge=1, le=MAX_BYTES + 1)
    section_index: int = Field(ge=0, lt=MAX_SECTIONS)

    @model_validator(mode='after')
    def _span(self):
        if self.line_end < self.line_start:
            raise ValueError('a CSV physical line span cannot run backwards')
        return self


class CsvDiagnostic(Record):
    code: Code
    message: Annotated[str, Field(min_length=1, max_length=500)]
    level: Literal['warning', 'error']
    reference: CsvRecordRef | None = None


class InventorySection(Record):
    index: int = Field(ge=0, lt=MAX_SECTIONS)
    banner: Annotated[str, Field(max_length=MAX_RECORD_CHARS)]
    architecture: Arch
    reference: CsvRecordRef

    @model_validator(mode='after')
    def _section(self):
        if self.index != self.reference.section_index:
            raise ValueError('section index and reference disagree')
        return self


class InventoryEntry(Record):
    entry_id: Sha256
    reference: CsvRecordRef
    original_fields: tuple[RawText, ...] = Field(min_length=1, max_length=MAX_COLUMNS)
    original_filename: RawText
    basename: Annotated[str, Field(min_length=1, max_length=128)] | None
    original_version: RawText
    version_components: tuple[VersionComponent, VersionComponent, VersionComponent, VersionComponent] | None
    original_size: RawText | None
    size_bytes: int | None = Field(ge=0, le=UINT64_MAX)
    date_text: RawText | None
    time_text: RawText | None
    architecture: Arch
    architecture_basis: Literal['column', 'section', 'context', 'unknown', 'conflicted']
    product: ContextText | None
    release: ContextText | None
    build: ContextText | None
    state: Literal['metadata-only', 'unknown', 'conflicted', 'descriptive-only']
    duplicate_of: Sha256 | None = None
    conflict_group: Sha256 | None = None
    diagnostics: tuple[Code, ...] = Field(default=(), max_length=32)

    @staticmethod
    def _filename(value):
        return normalize_inventory_filename(value)

    @model_validator(mode='after')
    def _consistent(self):
        filename = self._filename(self.basename) if self.basename is not None else None
        if self.basename is not None and (filename is None or filename[0] != self.basename):
            raise ValueError('normalized basenames must be safe lowercase filenames')
        if any(value is not None and (not value.strip() or replace_hostile(value) != value)
               for value in (self.product, self.release, self.build)):
            raise ValueError('normalized product metadata must be nonempty plain text')
        if len(self.diagnostics) != len(set(self.diagnostics)):
            raise ValueError('entry diagnostics must be unique')
        if self.architecture_basis == 'conflicted' and (self.architecture != 'unknown'
                                                       or self.state != 'conflicted'):
            raise ValueError('a conflicting architecture is unknown and the entry remains conflicted')
        if self.architecture_basis == 'unknown' and self.architecture != 'unknown':
            raise ValueError('unknown architecture basis cannot assert an architecture')
        if self.architecture_basis in ('column', 'section', 'context') and self.architecture == 'unknown':
            raise ValueError('a known architecture basis must identify an architecture')
        if self.state == 'metadata-only' and (filename is None or not filename[1]
                                              or self.architecture == 'unknown' or self.version_components is None):
            raise ValueError('metadata-only PE entries need a safe PE basename, known architecture and version')
        if self.state == 'descriptive-only' and (filename is None or filename[1]):
            raise ValueError('descriptive-only entries need a safe non-PE basename')
        if self.conflict_group is not None and self.state != 'conflicted':
            raise ValueError('a conflicting metadata group cannot be hidden')
        return self


class InventoryPageEntry(InventoryEntry):
    @staticmethod
    def _filename(value):
        return normalize_inventory_page_filename(value)


class InventoryRetention(Record):
    architecture: Literal['all', 'amd64', 'arm64', 'x86', 'unknown'] = 'all'
    page: int = Field(default=1, ge=1, le=MAX_RECORDS)


class InventoryConflictWitness(Record):
    conflict_group: Sha256
    field: Literal['version_components', 'size_bytes', 'date_text', 'time_text']
    first: CsvRecordRef
    second: CsvRecordRef

    @model_validator(mode='after')
    def _ordered(self):
        if self.first.raw_sha256 != self.second.raw_sha256 or self.first.logical_record >= self.second.logical_record:
            raise ValueError('a contradiction needs two ordered records from the same raw source')
        return self


def inventory_identity(raw_sha256: str, context: InventoryContext,
                       limits: InventoryLimits = DEFAULT_LIMITS) -> str:
    limits_json = json.dumps(limits.model_dump(mode='json'), sort_keys=True, separators=(',', ':'), allow_nan=False)
    return domain_id('kbc.csv-inventory', 1, {'parser_version': PARSER_VERSION, 'raw_sha256': raw_sha256,
                                            'context': context.model_dump(mode='json'), 'limits_json': limits_json})


def inventory_page_identity(raw_sha256: str, context: InventoryContext, retention: InventoryRetention,
                            limits: InventoryLimits = DEFAULT_PAGE_LIMITS) -> str:
    limits_json = json.dumps(limits.model_dump(mode='json'), sort_keys=True, separators=(',', ':'), allow_nan=False)
    return domain_id('kbc.csv-inventory', 2, {'parser_version': 2, 'raw_sha256': raw_sha256,
                                            'context': context.model_dump(mode='json'), 'limits_json': limits_json,
                                            'retention': retention.model_dump(mode='json')})


def entry_identity(inventory_id: str, logical_record: int) -> str:
    return domain_id('kbc.csv-entry', 1, {'inventory_id': inventory_id, 'logical_record': logical_record})


class CsvInventory(Record):
    contract: Literal['kb-file-inventory/1'] = 'kb-file-inventory/1'
    parser_version: Literal[1] = PARSER_VERSION
    inventory_id: Sha256
    raw_sha256: Sha256
    raw_size: int = Field(ge=0, le=MAX_BYTES)
    encoding: Literal['utf-8', 'utf-8-sig', 'utf-16-le', 'utf-16-be']
    context: InventoryContext
    limits: InventoryLimits = DEFAULT_LIMITS
    entries: tuple[InventoryEntry, ...] = Field(max_length=MAX_ENTRIES)
    sections: tuple[InventorySection, ...] = Field(min_length=1, max_length=MAX_SECTIONS)
    diagnostics: tuple[CsvDiagnostic, ...] = Field(max_length=MAX_DIAGNOSTICS)
    records_scanned: int = Field(ge=1, le=MAX_RECORDS)
    accepted_count: int = Field(ge=0, le=MAX_ENTRIES)
    rejected_count: int = Field(ge=0, le=MAX_RECORDS)
    duplicate_count: int = Field(ge=0, le=MAX_ENTRIES)
    conflict_count: int = Field(ge=0, le=MAX_ENTRIES)
    diagnostics_omitted: int = Field(ge=0)
    truncated: bool
    status: Literal['complete', 'partial']

    @field_validator('parser_version', mode='before')
    @classmethod
    def _strict_version(cls, value):
        if type(value) is not int:
            raise ValueError('parser version must be an integer, not a coerced literal')
        return value

    def _expected_identity(self):
        return inventory_identity(self.raw_sha256, self.context, self.limits)

    @model_validator(mode='after')
    def _consistent(self):
        if self.inventory_id != self._expected_identity():
            raise ValueError('inventory identity does not match raw bytes, context, limits and parser')
        if (self.raw_size > self.limits.max_bytes or self.records_scanned > self.limits.max_records
                or len(self.entries) > self.limits.max_entries or len(self.sections) > self.limits.max_sections
                or len(self.diagnostics) > self.limits.max_diagnostics):
            raise ValueError('captured records exceed their declared parsing budgets')
        if self.accepted_count != len(self.entries):
            raise ValueError('accepted count does not match retained entries')
        if self.duplicate_count != sum(entry.duplicate_of is not None for entry in self.entries):
            raise ValueError('duplicate count does not match retained claims')
        if self.conflict_count != sum(entry.state == 'conflicted' for entry in self.entries):
            raise ValueError('conflict count does not match retained claims')
        if (self.truncated or self.rejected_count or self.diagnostics or self.diagnostics_omitted
                or self.conflict_count) and self.status != 'partial':
            raise ValueError('partial evidence cannot claim complete status')
        if tuple(section.index for section in self.sections) != tuple(range(len(self.sections))):
            raise ValueError('section indexes must be contiguous')
        seen: set[str] = set()
        last_record = 0
        for entry in self.entries:
            ref = entry.reference
            if ref.raw_sha256 != self.raw_sha256 or ref.logical_record > self.records_scanned:
                raise ValueError('entry reference does not belong to the captured CSV')
            if ref.section_index >= len(self.sections) or ref.logical_record <= last_record:
                raise ValueError('entry references must name valid sections in logical record order')
            if entry.entry_id != entry_identity(self.inventory_id, ref.logical_record):
                raise ValueError('entry identity does not match inventory and logical record')
            if entry.duplicate_of is not None and entry.duplicate_of not in seen:
                raise ValueError('duplicate must name an earlier retained entry')
            seen.add(entry.entry_id)
            last_record = ref.logical_record
        for item in (*self.sections, *self.diagnostics):
            ref = item.reference
            if ref is not None and (ref.raw_sha256 != self.raw_sha256 or ref.logical_record > self.records_scanned
                                    or ref.section_index >= len(self.sections)):
                raise ValueError('section or diagnostic reference does not belong to the captured CSV')
        if sum(len(value) for entry in self.entries for value in entry.original_fields) > MAX_BYTES:
            raise ValueError('retained original fields exceed the source text budget')
        return self


class CsvInventoryPage(CsvInventory):
    contract: Literal['kb-file-inventory/2'] = 'kb-file-inventory/2'
    parser_version: Literal[2] = 2
    limits: InventoryPageLimits = DEFAULT_PAGE_LIMITS
    entries: tuple[InventoryPageEntry, ...] = Field(max_length=MAX_PAGE_ENTRIES)
    accepted_count: int = Field(ge=0, le=MAX_PAGE_ENTRIES)
    duplicate_count: int = Field(ge=0, le=MAX_PAGE_ENTRIES)
    conflict_count: int = Field(ge=0, le=MAX_PAGE_ENTRIES)
    retention: InventoryRetention
    scan_complete: bool
    matching_count: int = Field(ge=0, le=MAX_RECORDS)
    excluded_count: int = Field(ge=0, le=MAX_RECORDS)
    omitted_count: int = Field(ge=0, le=MAX_RECORDS)
    conflict_witnesses: tuple[InventoryConflictWitness, ...] = Field(max_length=MAX_PAGE_ENTRIES)

    def _expected_identity(self):
        return inventory_page_identity(self.raw_sha256, self.context, self.retention, self.limits)

    @model_validator(mode='after')
    def _page_consistent(self):
        start = (self.retention.page - 1) * self.limits.max_entries
        if self.accepted_count != min(self.limits.max_entries, max(0, self.matching_count - start)):
            raise ValueError('retained count does not match the requested source page')
        if (self.matching_count + self.excluded_count + self.rejected_count > self.records_scanned
                or self.omitted_count != self.matching_count - self.accepted_count):
            raise ValueError('page counters disagree with scanned and retained records')
        if self.scan_complete == self.truncated or self.scan_complete and not self.entries:
            raise ValueError('a complete scan cannot be truncated or retain an empty page')
        if (self.omitted_count or self.excluded_count or not self.scan_complete) and self.status != 'partial':
            raise ValueError('omitted or unscanned claims cannot imply a complete inventory')
        if self.retention.architecture != 'all' and any(
                entry.architecture not in (self.retention.architecture, 'unknown') for entry in self.entries):
            raise ValueError('retained entries do not match the captured architecture filter')
        groups = {entry.conflict_group for entry in self.entries if 'CONFLICTING_METADATA' in entry.diagnostics}
        keys = tuple(witness.conflict_group for witness in self.conflict_witnesses)
        if None in groups or keys != tuple(sorted(groups)) or len(keys) != len(set(keys)):
            raise ValueError('each retained metadata-conflict group needs exactly one canonical witness')
        for witness in self.conflict_witnesses:
            for ref in (witness.first, witness.second):
                if (ref.raw_sha256 != self.raw_sha256 or ref.logical_record > self.records_scanned
                        or ref.section_index >= len(self.sections)):
                    raise ValueError('conflict witness does not belong to the scanned raw source')
        return self
