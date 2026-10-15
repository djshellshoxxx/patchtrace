"""Strict Tier-W contracts (SPEC-33 s3, s5.3, s6-s10). Strict JSON (duplicate keys, NaN rejected) then pydantic
strict with extra=forbid and explicit size/count limits. Every persisted document carries `tier`."""
from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ..common import strict_json
from .paths import TierWError

Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
U32 = Annotated[int, Field(ge=0, le=2**32 - 1)]
Date = Annotated[str, Field(pattern=r'^\d{4}-\d{2}-\d{2}$')]
Ident = Annotated[str, Field(pattern=r'^[A-Za-z0-9._-]{1,64}$')]
LineKey = Annotated[str, Field(pattern=r'^[A-Za-z0-9._-]{1,32}$')]
Guid = Annotated[str, Field(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
FileName = Annotated[str, Field(min_length=1, max_length=255, pattern=r'^[^/\\:\x00]+$')]
Family = Literal['kernel', 'driver', 'usermode-dll']
Machine = Literal['x64', 'x86', 'arm64', 'other']

MAX_NAME = 4096
MAX_RANGES_PER_SYMBOL = 4096
MAX_RANGES_TOTAL = 4_000_000
MAX_SYMBOLS = 1_000_000
MAX_WARNINGS = 2000
SYMBOL_MAP_LIMIT = 256 * 1024 * 1024
CATALOGUE_LIMIT = 256 * 1024 * 1024
DOC_LIMIT = 64 * 1024 * 1024
_PRINTABLE_NO_NUL = re.compile(r'^[^\x00]+$')


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


# ---- catalogue (s3.2) ---------------------------------------------------------------------------------------

class KbLine(_Strict):
    kb: str = Field(min_length=1, max_length=64)
    date: Date | None = None
    release: str | None = Field(default=None, max_length=64)
    kind: Literal['monthly', 'preview', 'oob', 'base']


class CatalogueBuild(_Strict):
    sha256: Sha256
    size: int = Field(ge=1, le=2**32 - 1)
    machine: int = Field(ge=0, le=0xFFFF)
    timestamp: U32
    virtual_size: int | None = Field(default=None, ge=1, le=2**32 - 1)
    last_section_va: U32 | None = None
    last_section_raw: U32 | None = None
    resolved_virtual_size: int | None = Field(default=None, ge=1, le=2**32 - 1)
    version: str | None = Field(default=None, max_length=128)
    download: Literal['direct', 'candidates', 'unavailable']
    record_sha256: Sha256
    lines: dict[LineKey, tuple[KbLine, ...]]

    @field_validator('lines')
    @classmethod
    def _bounded(cls, value):
        if len(value) > 64 or any(len(kbs) > 256 for kbs in value.values()):
            raise ValueError('too many lines or KBs')
        return value

    @property
    def size_of_image(self) -> int | None:
        return self.virtual_size or self.resolved_virtual_size


class Catalogue(_Strict):
    contract: Literal['tier-w-catalogue/1']
    tier: Literal['W']
    file_name: str = Field(pattern=r'^[a-z0-9._-]{1,128}$')
    family: Family
    source: str = Field(pattern=r'^winbindex@\d{4}-\d{2}-\d{2}$')
    retrieved_at: str = Field(max_length=40)
    metadata_sha256: Sha256 | None
    builds: tuple[CatalogueBuild, ...] = Field(max_length=100_000)
    skipped: int = Field(ge=0)
    non_x64: int = Field(ge=0)
    dropped_kbs: int = Field(ge=0)
    warnings: tuple[str, ...] = Field(default=(), max_length=200)

    @model_validator(mode='after')
    def _unique(self):
        shas = [b.sha256 for b in self.builds]
        if shas != sorted(set(shas)):
            raise ValueError('builds must be sorted by sha256 and unique')
        return self


# ---- pairs sidecar (s3.7) ------------------------------------------------------------------------------------

class PairBinary(_Strict):
    id: Ident
    file_name: str = Field(pattern=r'^[a-z0-9._-]{1,128}$')
    sha256: Sha256
    record_sha256: Sha256
    family: Family
    version: str | None = Field(default=None, max_length=128)


class PairEntry(_Strict):
    id: Ident
    older: Ident
    newer: Ident
    kind: Literal['adjacent-patch', 'cross-version']
    file_name: str = Field(pattern=r'^[a-z0-9._-]{1,128}$')
    lines: tuple[LineKey, ...] = Field(min_length=1)
    older_kbs: tuple[KbLine, ...]
    newer_kbs: tuple[KbLine, ...]
    older_date: Date | None
    newer_date: Date | None
    tags: tuple[str, ...]


class Coverage(_Strict):
    classes: tuple[Family, ...]
    files_with_pairs: tuple[str, ...]
    complete: bool
    allow_incomplete: bool
    missing: tuple[str, ...] = ()


class PairsDoc(_Strict):
    contract: Literal['tier-w-pairs/1']
    tier: Literal['W']
    corpus_id: str = Field(pattern=r'^tier-w-[A-Za-z0-9._-]{1,57}$')
    created: str = Field(max_length=40)
    params: dict[str, str | int | float | bool | None | tuple[str, ...]]
    binaries: tuple[PairBinary, ...]
    pairs: tuple[PairEntry, ...]
    exclusions: dict[str, int]
    coverage: Coverage


# ---- exact-preview fetch plan (s4) --------------------------------------------------------------------------

class FetchInput(_Strict):
    source: str = Field(min_length=1, max_length=160)
    sha256: Sha256


class FetchExclusion(_Strict):
    file_name: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9._-]+$')
    sha256: Sha256 | None = None
    reason: Literal['unavailable', 'unresolved-size', 'no-codeview', 'not-x64', 'deferred']


class FetchItem(_Strict):
    kind: Literal['binary', 'pdb']
    file_name: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9._-]+$')
    source_url: str = Field(min_length=1, max_length=2048)
    sha256: Sha256 | None = None
    record_sha256: Sha256 | None = None
    size: int | None = Field(default=None, ge=1, le=2**32 - 1)
    cap_bytes: int = Field(ge=1, le=2 * 1024 * 1024 * 1024)
    binary_sha256: Sha256 | None = None
    guid: Guid | None = None
    age: U32 | None = None
    timestamp: U32 | None = None
    size_of_image: U32 | None = None
    pair_ids: tuple[Ident, ...] = Field(default=(), max_length=100_000)

    @model_validator(mode='after')
    def _valid_fetch_item(self):
        from urllib.parse import urlsplit
        from patchtrace.acquisition.contracts import SYMBOL_SERVER, symbol_server_url

        parts = urlsplit(self.source_url)
        if (parts.scheme != 'https' or parts.hostname != 'msdl.microsoft.com'
                or parts.port not in (None, 443) or parts.username or parts.password
                or parts.query or parts.fragment):
            raise ValueError('fetch plan URL must be an exact HTTPS Microsoft symbol-server URL')
        if self.pair_ids != tuple(sorted(set(self.pair_ids))):
            raise ValueError('pair ids must be sorted and unique')
        if self.kind == 'binary':
            if (self.sha256 is None or self.record_sha256 is None or self.size is None
                    or self.binary_sha256 is not None or self.guid is not None or self.age is not None
                    or self.timestamp is None or self.size_of_image is None):
                raise ValueError('binary entry has incomplete or mixed identity fields')
            if self.cap_bytes != self.size:
                raise ValueError('binary cap must equal its expected size')
            expected = symbol_server_url(self.file_name.lower(), self.timestamp, self.size_of_image)
            if self.file_name != self.file_name.lower() or self.source_url != expected:
                raise ValueError('binary URL does not match its pinned identity')
        else:
            if (self.sha256 is not None or self.record_sha256 is not None or self.size is not None
                    or self.binary_sha256 is None or self.guid is None or self.age is None
                    or self.timestamp is not None or self.size_of_image is not None
                    or not self.file_name.lower().endswith('.pdb')):
                raise ValueError('PDB entry has incomplete or mixed identity fields')
            guid_hex = self.guid.replace('-', '').upper()
            name = self.file_name.lower()
            expected = f'{SYMBOL_SERVER}/{name}/{guid_hex}{self.age:X}/{name}'
            if self.file_name != name or self.source_url != expected:
                raise ValueError('PDB URL does not match its CodeView identity')
        return self


class FetchPlan(_Strict):
    contract: Literal['tier-w-fetch-plan/1']
    tier: Literal['W']
    operation: Literal['binary', 'pdb']
    corpus_id: str = Field(pattern=r'^tier-w-[A-Za-z0-9._-]{1,57}$')
    selected_pairs: tuple[Ident, ...] = Field(default=(), max_length=100_000)
    max_files: int = Field(ge=1, le=100_000)
    source_digests: tuple[FetchInput, ...] = Field(max_length=100_001)
    input_plan_sha256: Sha256 | None = None
    entries: tuple[FetchItem, ...] = Field(max_length=100_000)
    exclusions: tuple[FetchExclusion, ...] = Field(default=(), max_length=100_000)

    @model_validator(mode='after')
    def _consistent(self):
        if self.selected_pairs != tuple(sorted(set(self.selected_pairs))):
            raise ValueError('selected pair ids must be sorted and unique')
        source_names = [item.source for item in self.source_digests]
        if source_names != sorted(set(source_names)):
            raise ValueError('source digests must be sorted by unique source name')
        if len(self.entries) > self.max_files:
            raise ValueError('plan exceeds max_files')
        if any(item.kind != self.operation for item in self.entries):
            raise ValueError('entry kind does not match operation')
        keys = [(item.sha256 or item.binary_sha256, item.file_name) for item in self.entries]
        if keys != sorted(set(keys)):
            raise ValueError('entries must be sorted and unique')
        if self.operation == 'binary' and (self.input_plan_sha256 is not None or not self.selected_pairs):
            raise ValueError('binary plan requires selected pairs and has no source plan')
        if self.operation == 'pdb' and self.input_plan_sha256 is None:
            raise ValueError('PDB plan must bind to the binary plan')
        return self


# ---- Ghidra raw output (s5.2) and symbol-map/1 (s5.3) ---------------------------------------------------------

def _check_ranges(ranges: Sequence[Sequence[int]]) -> int:
    total, last = 0, -1
    if len(ranges) > MAX_RANGES_PER_SYMBOL:
        raise ValueError('too many ranges')
    for start, end in ranges:
        if not 0 <= start < end <= 2**32 or start < last:
            raise ValueError('ranges must be sorted, non-overlapping and inside 32-bit RVA space')
        last = end
        total += end - start
    return total


class GName(_Strict):
    name: str = Field(min_length=1, max_length=MAX_NAME, pattern=_PRINTABLE_NO_NUL.pattern)
    source: str = Field(pattern=r'^[A-Z_]{1,32}$')
    primary: bool


class GFunction(_Strict):
    rva: U32
    ranges: tuple[tuple[int, int], ...]
    thunk: bool
    names: tuple[GName, ...] = Field(max_length=16)

    @model_validator(mode='after')
    def _ranges(self):
        _check_ranges(self.ranges)
        return self


class GPdb(_Strict):
    loaded: bool
    file: str | None = Field(default=None, max_length=1024)
    guid: str | None = Field(default=None, max_length=64)
    age: int | None = Field(default=None, ge=0, le=2**32 - 1)


class GhidraRaw(_Strict):
    contract: Literal['ghidra-symbols/1']
    ghidra_version: str = Field(max_length=100)
    python: str = Field(max_length=300)
    file_name: str = Field(max_length=1024)
    image_base: int = Field(ge=0, le=2**64 - 1)
    executable_sha256: str | None = Field(default=None, max_length=64)
    pdb: GPdb
    functions: tuple[GFunction, ...] = Field(max_length=MAX_SYMBOLS)
    unnamed: int = Field(ge=0)
    truncated: int = Field(ge=0)
    warnings: tuple[str, ...] = Field(default=(), max_length=MAX_WARNINGS)

    @model_validator(mode='after')
    def _totals(self):
        if sum(len(f.ranges) for f in self.functions) > MAX_RANGES_TOTAL:
            raise ValueError('too many ranges in total')
        rvas = [f.rva for f in self.functions]
        if len(set(rvas)) != len(rvas):
            raise ValueError('duplicate function entry')
        return self


class Image(_Strict):
    file_name: FileName
    sha256: Sha256
    image_base: int = Field(ge=0, le=2**64 - 1)
    size_of_image: U32 | None
    machine: Machine


class PdbRef(_Strict):
    name: str | None = Field(default=None, max_length=255)
    guid: Guid | None = None
    age: U32 | None = None
    sha256: Sha256 | None = None
    stripped: bool | None = None


class Producer(_Strict):
    tool: Literal['ghidra', 'llvm-pdbutil', 'msf']
    version: str = Field(min_length=1, max_length=200)
    detail: str = Field(default='', max_length=500)


class Symbol(_Strict):
    name: str = Field(min_length=1, max_length=MAX_NAME, pattern=_PRINTABLE_NO_NUL.pattern)
    rva: U32
    size: int | None = Field(ge=0, le=2**32 - 1)
    size_source: Literal['ghidra-body', 'pdb-proc', 'pdata'] | None
    kind: Literal['public', 'private', 'unknown']
    aliases: int = Field(ge=0, le=1_000_000)
    thunk: bool
    ranges: tuple[tuple[int, int], ...]

    @model_validator(mode='after')
    def _consistent(self):
        total = _check_ranges(self.ranges)
        if (self.size is None) != (self.size_source is None):
            raise ValueError('size and size_source must both be present or absent')
        if self.ranges and total != self.size:
            raise ValueError('size must equal the summed range lengths')
        if self.ranges and self.ranges[0][0] != self.rva and not any(s <= self.rva < e for s, e in self.ranges):
            raise ValueError('entry RVA must lie inside the body ranges')
        return self


class Stats(_Strict):
    functions: int = Field(ge=0)
    unnamed: int = Field(ge=0)
    dropped: int = Field(ge=0)


class SymbolMap(_Strict):
    contract: Literal['symbol-map/1']
    tier: Literal['W', 'R', 'test']
    image: Image
    pdb: PdbRef
    producer: Producer
    symbols: tuple[Symbol, ...] = Field(max_length=MAX_SYMBOLS)
    stats: Stats
    warnings: tuple[str, ...] = Field(default=(), max_length=MAX_WARNINGS)

    @model_validator(mode='after')
    def _ordered(self):
        rvas = [s.rva for s in self.symbols]
        if rvas != sorted(set(rvas)):
            raise ValueError('symbols must be sorted by RVA with one name per RVA')
        if sum(len(s.ranges) for s in self.symbols) > MAX_RANGES_TOTAL:
            raise ValueError('too many ranges in total')
        return self


# ---- labels, audit, runs (s6-s9) -------------------------------------------------------------------------------

class DetailSide(_Strict):
    rva: U32 | None
    name: str | None = Field(default=None, max_length=MAX_NAME)
    size: int | None = Field(default=None, ge=0)
    tags: tuple[str, ...] = ()
    exported: bool = False


class LabelDetail(_Strict):
    contract: Literal['tier-w-label-detail/1']
    tier: Literal['W', 'test']
    pair: Ident
    match_id: str = Field(min_length=1, max_length=200)
    kind: Literal['truth', 'candidate']
    A: Literal['same', 'different'] | None
    rule: str = Field(min_length=1, max_length=64)
    older: DetailSide
    newer: DetailSide
    size_change: float | None = None
    engine: str | None = Field(default=None, max_length=64)


class AuditItem(_Strict):
    pair: Ident
    match_id: str = Field(min_length=1, max_length=200)
    A: Literal['same', 'different']
    stratum: Literal['census', 'random']
    p_incl: float = Field(gt=0, le=1)


class AuditKey(_Strict):
    contract: Literal['tier-w-audit-key/1']
    tier: Literal['W', 'test']
    corpus_id: str = Field(max_length=64)
    population: Literal['candidates', 'truth']
    seed: str = Field(max_length=64)
    rate: float = Field(gt=0, le=1)
    size_change: float = Field(gt=0)
    created: str = Field(max_length=40)
    population_counts: dict[Literal['census', 'random'], int]
    items: tuple[AuditItem, ...]


class MatchLine(_Strict):
    contract: Literal['tier-w-matches/1']
    tier: Literal['W', 'test']
    pair: Ident
    engine: str = Field(min_length=1, max_length=64)
    engine_version: str = Field(default='unknown', max_length=200)
    condition: Literal['symbols-hidden', 'symbols-visible', 'n/a']
    match_id: str = Field(min_length=1, max_length=200)
    older_rva: U32 | None
    newer_rva: U32 | None


def _load(model: type[BaseModel], data: bytes, limit: int, what: str):
    if len(data) > limit:
        raise TierWError('PT-TIERW-LIMIT', f'{what} exceeds {limit} bytes')
    try:
        strict_json(data)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise TierWError('PT-TIERW-INPUT', f'{what} is not strict JSON: {str(exc)[:200]}') from None
    try:
        return model.model_validate_json(data)
    except ValidationError as exc:
        first = str(exc).splitlines()
        raise TierWError('PT-TIERW-INPUT', f'{what} invalid: {" ".join(first[:3])[:400]}') from None


def load_fetch_plan(data: bytes) -> FetchPlan:
    return _load(FetchPlan, data, DOC_LIMIT, 'Tier-W fetch plan')


def load_catalogue(data: bytes) -> Catalogue:
    return _load(Catalogue, data, CATALOGUE_LIMIT, 'catalogue')


def load_pairs(data: bytes) -> PairsDoc:
    return _load(PairsDoc, data, DOC_LIMIT, 'pairs sidecar')


def load_ghidra_raw(data: bytes) -> GhidraRaw:
    return _load(GhidraRaw, data, SYMBOL_MAP_LIMIT, 'Ghidra export')


def load_symbol_map(data: bytes) -> SymbolMap:
    return _load(SymbolMap, data, SYMBOL_MAP_LIMIT, 'symbol map')


def load_audit_key(data: bytes) -> AuditKey:
    return _load(AuditKey, data, DOC_LIMIT, 'audit key')


def load_jsonl(model: type[BaseModel], data: bytes, what: str, *, max_lines: int = 5_000_000,
               line_limit: int = 1024 * 1024) -> list[Any]:
    out = []
    for number, line in enumerate(data.splitlines(), 1):
        if not line.strip():
            continue
        if number > max_lines:
            raise TierWError('PT-TIERW-LIMIT', f'{what} has more than {max_lines} lines')
        out.append(_load(model, line, line_limit, f'{what} line {number}'))
    return out
