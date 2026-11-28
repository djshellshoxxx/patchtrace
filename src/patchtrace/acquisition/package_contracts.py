"""Strict local-package/1 metadata. Pure records never confer native or trust evidence."""
from __future__ import annotations

import json
import math
import unicodedata
from collections import defaultdict
from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from ..enrichment.identity import domain_id
from .contracts import AcquisitionError, Record, validate_file_name
from .package_paths import NameRegistry, decode_member_name

CONTRACT = 'local-package/1'
PARSER_VERSION = 1
MAX_SOURCE = 2**31 - 1
MAX_EXPANDED = 8 * 2**30
MAX_ENTRY = 2**30
MAX_JSON = 64 * 2**20
MAX_ENTRIES = 50_000
MAX_CONTAINERS = 256
MAX_DEPTH = 4
UINT64_MAX = 2**64 - 1
Sha256 = Annotated[str, Field(min_length=64, max_length=64, pattern=r'^[0-9a-f]{64}$')]
FileId = Annotated[str, Field(min_length=32, max_length=32, pattern=r'^[0-9a-f]{32}$')]
PlainText = Annotated[str, Field(min_length=1, max_length=1024)]
Mode = Literal['headers', 'recursive']
ContentState = Literal['header-only', 'decoded', 'reverified']
PartKind = Literal['cab', 'msu', 'cat', 'mum', 'manifest', 'delta', 'psfx', 'fullfile', 'unknown']


def _plain(value: str) -> str:
    if not value.strip() or any(unicodedata.category(c).startswith('C') or c in '\u2028\u2029' for c in value):
        raise ValueError('package metadata must be nonempty plain text')
    return value


class PackageLimits(Record):
    max_source_bytes: int = Field(default=MAX_SOURCE, ge=1, le=MAX_SOURCE)
    max_expanded_bytes: int = Field(default=MAX_EXPANDED, ge=1, le=MAX_EXPANDED)
    max_entry_bytes: int = Field(default=MAX_ENTRY, ge=1, le=MAX_ENTRY)
    max_entries: int = Field(default=MAX_ENTRIES, ge=1, le=MAX_ENTRIES)
    max_containers: int = Field(default=MAX_CONTAINERS, ge=1, le=MAX_CONTAINERS)
    max_depth: int = Field(default=MAX_DEPTH, ge=0, le=MAX_DEPTH)
    max_name_bytes: int = Field(default=1024, ge=1, le=1024)
    max_xml_bytes: int = Field(default=2 * 2**20, ge=1, le=2 * 2**20)
    max_metadata_bytes: int = Field(default=32 * 2**20, ge=1, le=32 * 2**20)
    max_json_bytes: int = Field(default=MAX_JSON, ge=1, le=MAX_JSON)
    max_diagnostics: int = Field(default=1000, ge=1, le=1000)
    max_live_allocation_bytes: int = Field(default=512 * 2**20, ge=1, le=512 * 2**20)
    max_process_bytes: int = Field(default=2**30, ge=1, le=2**30)
    max_callbacks: int = Field(default=2_000_000, ge=1, le=2_000_000)
    max_seconds: int = Field(default=1800, ge=1, le=1800)


class PackageFileIdentity(Record):
    volume_serial: int = Field(ge=0, le=UINT64_MAX)
    file_id: FileId
    size: int = Field(ge=1, le=MAX_SOURCE)
    last_write_ticks: int = Field(ge=0, le=UINT64_MAX)

    @field_validator('file_id')
    @classmethod
    def _nonzero(cls, value):
        if value == '0' * 32:
            raise ValueError('a package source needs a known nonzero native file identity')
        return value


class PackageSource(Record):
    sha256: Sha256
    size: int = Field(ge=1, le=MAX_SOURCE)
    file_identity: PackageFileIdentity
    display_name: PlainText
    source_claims: tuple[PlainText, ...] = Field(default=(), max_length=32)
    signature_state: Literal['signature-unknown'] = 'signature-unknown'

    @model_validator(mode='after')
    def _source(self):
        try:
            name = decode_member_name(self.display_name.encode('utf-8'), utf8=True)
        except (AcquisitionError, UnicodeError) as exc:
            raise ValueError('source display name must be a safe redacted basename') from exc
        if name.path != name.basename or self.size != self.file_identity.size:
            raise ValueError('source basename or captured size is inconsistent')
        for claim in self.source_claims:
            _plain(claim)
        return self

    @property
    def source_id(self) -> str:
        return domain_id('acquisition.package-source', 1, {'sha256': self.sha256, 'size': self.size})


class PackageDecoder(Record):
    name: Literal['windows-cabinet-fdi'] = 'windows-cabinet-fdi'
    abi: Literal['win64-fdi-v1'] = 'win64-fdi-v1'
    dll_sha256: Sha256
    digest_scope: Literal['on-disk-system-component'] = 'on-disk-system-component'
    dll_version: PlainText
    os_version: PlainText
    probe_state: Literal['not-run', 'passed']
    qualification: Literal['pending'] = 'pending'

    _text = field_validator('dll_version', 'os_version')(_plain)


class PackageCapability(Record):
    platform: Literal['windows', 'linux', 'other']
    architecture: Literal['amd64', 'other']
    status: Literal['unsupported-platform', 'unsupported-architecture', 'unavailable-decoder', 'available']
    decoder: PackageDecoder | None = None

    @model_validator(mode='after')
    def _capability(self):
        if self.status == 'available':
            if (self.platform != 'windows' or self.architecture != 'amd64' or self.decoder is None
                    or self.decoder.probe_state != 'passed'):
                raise ValueError('available FDI requires a matching Windows AMD64 decoder probe')
        elif self.decoder is not None:
            raise ValueError('an unavailable capability cannot carry a successful decoder')
        return self


def member_identity(container_sha256: str, ancestors: tuple[str, ...], ordinal: int,
                    raw_name_hex: str, name_utf8: bool) -> str:
    return domain_id('acquisition.package-member', 1,
                     {'container_sha256': container_sha256, 'ancestors': ancestors, 'ordinal': ordinal,
                      'raw_name_hex': raw_name_hex, 'name_utf8': name_utf8})


class PackagePart(Record):
    member_id: Sha256
    container_sha256: Sha256
    ancestors: tuple[Sha256, ...] = Field(default=(), max_length=MAX_DEPTH)
    ordinal: int = Field(ge=1, le=MAX_ENTRIES)
    raw_name_hex: str = Field(min_length=2, max_length=2048, pattern=r'^[0-9a-f]+$')
    name_utf8: bool
    logical_path: str = Field(min_length=1, max_length=1024)
    declared_size: int = Field(ge=0, le=MAX_ENTRY)
    compressed_size: int | None = Field(default=None, ge=0, le=MAX_SOURCE)
    kind: PartKind = 'unknown'
    kind_basis: Literal['unknown', 'filename-hint', 'content'] = 'unknown'
    content_state: ContentState = 'header-only'
    observed_size: int | None = Field(default=None, ge=0, le=MAX_ENTRY)
    observed_sha256: Sha256 | None = None
    rehash_sha256: Sha256 | None = None
    machine: int | None = Field(default=None, ge=0, le=65535)
    signature_state: Literal['signature-unknown'] = 'signature-unknown'

    @model_validator(mode='after')
    def _member(self):
        try:
            raw = bytes.fromhex(self.raw_name_hex)
            name = decode_member_name(raw, utf8=self.name_utf8)
        except (ValueError, AcquisitionError) as exc:
            raise ValueError('invalid raw member-name identity') from exc
        if raw.hex() != self.raw_name_hex or name.path != self.logical_path:
            raise ValueError('member logical name disagrees with exact raw bytes')
        if len(set(self.ancestors)) != len(self.ancestors):
            raise ValueError('member ancestry cannot repeat an identity')
        if self.member_id != member_identity(self.container_sha256, self.ancestors, self.ordinal,
                                             self.raw_name_hex, self.name_utf8):
            raise ValueError('member identity disagrees with its source occurrence')
        if (self.kind == 'unknown') != (self.kind_basis == 'unknown'):
            raise ValueError('known material needs an explicit classification basis')
        if self.content_state == 'header-only':
            if self.kind_basis == 'content' or any(value is not None for value in (
                    self.observed_size, self.observed_sha256, self.rehash_sha256, self.machine)):
                raise ValueError('header metadata cannot assert observed payload bytes or PE identity')
        else:
            if self.observed_size != self.declared_size or self.observed_sha256 is None:
                raise ValueError('decoded member needs an exact observed size and complete hash')
            if self.content_state == 'reverified':
                if self.rehash_sha256 != self.observed_sha256:
                    raise ValueError('reverification must match the complete decoded bytes')
            elif self.rehash_sha256 is not None:
                raise ValueError('a decoded-only member has no independent rehash')
        if self.machine is not None and (self.kind != 'fullfile' or self.kind_basis != 'content'):
            raise ValueError('PE machine identity requires a content-identified full file')
        return self

    @property
    def eligible_full_pe(self) -> bool:
        return (self.kind == 'fullfile' and self.kind_basis == 'content' and self.machine == 34404
                and self.content_state == 'reverified')


class PackageContainer(Record):
    container_sha256: Sha256
    ancestors: tuple[Sha256, ...] = Field(default=(), max_length=MAX_DEPTH)
    size: int = Field(ge=1, le=MAX_SOURCE)
    entry_count: int = Field(ge=0, le=MAX_ENTRIES)
    complete: bool


class PackageDiagnostic(Record):
    code: str = Field(min_length=1, max_length=64, pattern=r'^[A-Z][A-Z0-9_]*$')
    message: str = Field(min_length=1, max_length=512)
    member_id: Sha256 | None = None

    _text = field_validator('message')(_plain)


def _json_values(value):
    if isinstance(value, BaseModel):
        return value.model_dump(mode='json')
    if isinstance(value, Mapping):
        return {key: _json_values(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_values(item) for item in value]
    return value


def inventory_identity(values: Mapping) -> str:
    payload = {key: value for key, value in values.items() if key != 'inventory_id'}
    payload.setdefault('contract', CONTRACT)
    payload.setdefault('parser_version', PARSER_VERSION)
    payload.setdefault('diagnostics', ())
    payload = _json_values(payload)
    limit = payload.get('limits', {}).get('max_json_bytes', MAX_JSON)
    if type(limit) is not int or not 1 <= limit <= MAX_JSON:
        raise ValueError('invalid captured inventory JSON limit')
    # Include the exact-length identity field in the serialized budget without
    # constructing one oversized JSON string before checking its byte count.
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    size = 0
    for chunk in encoder.iterencode(payload | {'inventory_id': '0' * 64}):
        size += len(chunk.encode('utf-8'))
        if size > limit:
            raise ValueError('inventory exceeds its captured serialization budget')
    return domain_id('acquisition.package-inventory', 1, payload)


class PackageInventory(Record):
    contract: Literal['local-package/1'] = CONTRACT
    parser_version: Literal[1] = PARSER_VERSION
    inventory_id: Sha256
    source: PackageSource
    decoder: PackageDecoder
    mode: Mode
    limits: PackageLimits
    parts: tuple[PackagePart, ...] = Field(max_length=MAX_ENTRIES)
    containers: tuple[PackageContainer, ...] = Field(min_length=1, max_length=MAX_CONTAINERS)
    complete: bool
    diagnostics: tuple[PackageDiagnostic, ...] = Field(default=(), max_length=1000)

    @field_validator('parser_version', mode='before')
    @classmethod
    def _version(cls, value):
        if type(value) is not int or value != PARSER_VERSION:
            raise ValueError('unsupported strict package parser version')
        return value

    @model_validator(mode='after')
    def _inventory(self):
        if self.decoder.probe_state != 'passed':
            raise ValueError('an inventory requires a completed decoder probe')
        if (len(self.parts) > self.limits.max_entries or len(self.containers) > self.limits.max_containers
                or len(self.diagnostics) > self.limits.max_diagnostics):
            raise ValueError('inventory exceeds its captured population budget')
        root_key = (self.source.sha256, ())
        scopes = {(scope.container_sha256, scope.ancestors): scope for scope in self.containers}
        if len(scopes) != len(self.containers) or root_key not in scopes:
            raise ValueError('inventory needs a unique exact root scope')
        if sum(not scope.ancestors for scope in self.containers) != 1:
            raise ValueError('inventory cannot contain a foreign root scope')
        if scopes[root_key].size != self.source.size:
            raise ValueError('root scope size disagrees with captured source')
        if self.mode == 'headers' and (len(scopes) != 1 or any(
                part.content_state != 'header-only' for part in self.parts)):
            raise ValueError('header enumeration cannot assert nested or observed payload data')
        members = {part.member_id: part for part in self.parts}
        if len(members) != len(self.parts):
            raise ValueError('inventory repeats a member identity')
        grouped = defaultdict(list)
        registries = {}
        for part in self.parts:
            key = (part.container_sha256, part.ancestors)
            if key not in scopes or part.declared_size > self.limits.max_entry_bytes:
                raise ValueError('member is foreign or exceeds its captured size budget')
            if part.compressed_size is not None and part.compressed_size > scopes[key].size:
                raise ValueError('known compressed bytes cannot exceed their container')
            grouped[key].append(part)
            registry = registries.setdefault(key, NameRegistry(max_entries=self.limits.max_entries,
                                                               max_bytes=self.limits.max_name_bytes))
            try:
                registry.add(bytes.fromhex(part.raw_name_hex), utf8=part.name_utf8)
            except AcquisitionError as exc:
                raise ValueError('inventory contains an unsafe or colliding member name') from exc
        for key, scope in scopes.items():
            if len(scope.ancestors) > self.limits.max_depth or scope.size > self.limits.max_source_bytes:
                raise ValueError('container exceeds the captured depth or input budget')
            entries = grouped[key]
            if (scope.entry_count != len(entries)
                    or sorted(part.ordinal for part in entries) != list(range(1, len(entries) + 1))):
                raise ValueError('container population or member ordinals disagree')
            parent_sha = self.source.sha256
            for depth, member_id in enumerate(scope.ancestors):
                parent = members.get(member_id)
                if (parent is None or parent.ancestors != scope.ancestors[:depth]
                        or parent.container_sha256 != parent_sha or parent.kind not in {'cab', 'msu'}
                        or parent.kind_basis != 'content' or parent.content_state != 'reverified'):
                    raise ValueError('nested scope is disconnected from verified parent content')
                parent_sha = parent.observed_sha256
            if scope.ancestors:
                parent = members[scope.ancestors[-1]]
                if scope.container_sha256 != parent.observed_sha256 or scope.size != parent.observed_size:
                    raise ValueError('nested container does not match the exact parent bytes')
        if sum(part.observed_size or 0 for part in self.parts) > self.limits.max_expanded_bytes:
            raise ValueError('retained observed output exceeds the operation budget')
        nested_complete = self.mode == 'headers' or all(
            (part.observed_sha256, (*part.ancestors, part.member_id)) in scopes
            for part in self.parts if part.kind in {'cab', 'msu'})
        if self.complete and (not all(scope.complete for scope in self.containers) or not nested_complete):
            raise ValueError('complete inventory omits requested container enumeration')
        if any(item.member_id is not None and item.member_id not in members for item in self.diagnostics):
            raise ValueError('diagnostic belongs to a foreign member')
        if self.inventory_id != inventory_identity(self.model_dump(mode='json')):
            raise ValueError('inventory identity does not bind its exact receipt')
        return self


class PackageSelection(Record):
    inventory_id: Sha256
    source_sha256: Sha256
    member_id: Sha256
    ancestors: tuple[Sha256, ...] = Field(default=(), max_length=MAX_DEPTH)
    side: Literal['older', 'newer']
    expected_basename: str = Field(min_length=1, max_length=128)
    expected_sha256: Sha256 | None = None

    @field_validator('expected_basename')
    @classmethod
    def _basename(cls, value):
        try:
            return validate_file_name(value)
        except AcquisitionError as exc:
            raise ValueError('selection requires the canonical safe PE basename') from exc


def select_member(inventory: PackageInventory, selection: PackageSelection) -> PackagePart:
    """No filesystem operations or trust upgrades; native admission must still rehash."""
    if (not inventory.complete or selection.inventory_id != inventory.inventory_id
            or selection.source_sha256 != inventory.source.sha256):
        raise AcquisitionError('PT-ACQ-VERIFY', 'selection does not own a complete source inventory')
    matches = [part for part in inventory.parts if part.member_id == selection.member_id]
    if len(matches) != 1 or matches[0].ancestors != selection.ancestors:
        raise AcquisitionError('PT-ACQ-VERIFY', 'selection does not own this member occurrence')
    member = matches[0]
    if not member.eligible_full_pe:
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'selected member is not a reverified AMD64 full PE')
    basename = member.logical_path.rsplit('/', 1)[-1]
    if not basename.isascii():
        raise AcquisitionError('PT-ACQ-INPUT', 'selected PE basename must contain only ASCII characters')
    name = validate_file_name(basename.lower())
    if (name != selection.expected_basename or selection.expected_sha256 is not None
            and member.observed_sha256 != selection.expected_sha256):
        raise AcquisitionError('PT-ACQ-VERIFY', 'selected full-file identity disagrees with expected bytes or name')
    return member


class PackageUsage(Record):
    reserved_output_bytes: int = Field(ge=0, le=MAX_EXPANDED)
    confirmed_output_bytes: int = Field(ge=0, le=MAX_EXPANDED)
    entries: int = Field(ge=0, le=MAX_ENTRIES)
    containers: int = Field(ge=0, le=MAX_CONTAINERS)
    callbacks: int = Field(ge=0, le=2_000_000)
    live_allocated_bytes: int = Field(ge=0, le=512 * 2**20)
    peak_allocated_bytes: int = Field(ge=0, le=512 * 2**20)
    hashed_input_bytes: int = Field(ge=0, le=UINT64_MAX)
    metadata_bytes: int = Field(ge=0, le=32 * 2**20)
    elapsed_ns: int = Field(ge=0, le=UINT64_MAX)
    failed: bool
    failure_code: Literal['PT-ACQ-INPUT', 'PT-ACQ-LIMIT', 'PT-ACQ-CANCEL', 'PT-ACQ-VERIFY'] | None

    @model_validator(mode='after')
    def _usage(self):
        if (self.confirmed_output_bytes > self.reserved_output_bytes
                or self.live_allocated_bytes > self.peak_allocated_bytes
                or self.failed != (self.failure_code is not None)):
            raise ValueError('package usage counters or failure state disagree')
        return self


def parse_record[T: Record](model: type[T], raw: bytes, *, max_bytes: int = MAX_JSON) -> T:
    """Bound and strictly parse external JSON before Pydantic's frozen record validation."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_JSON or type(raw) is not bytes:
        raise AcquisitionError('PT-ACQ-INPUT', 'invalid package JSON boundary')
    if len(raw) > max_bytes:
        raise AcquisitionError('PT-ACQ-LIMIT', 'package JSON exceeds its byte limit')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result

    def constant(_):
        raise ValueError('nonfinite JSON number')

    def finite(token):
        value = float(token)
        if not math.isfinite(value):
            raise ValueError('nonfinite JSON number')
        return value

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)
        if not isinstance(value, dict):
            raise ValueError('expected a JSON object')
        result = model.model_validate_json(raw)
    except (ValueError, UnicodeError, RecursionError, ValidationError, AcquisitionError) as exc:
        raise AcquisitionError('PT-ACQ-INPUT', 'invalid strict package record') from exc
    if isinstance(result, PackageInventory) and len(raw) > result.limits.max_json_bytes:
        raise AcquisitionError('PT-ACQ-LIMIT', 'raw package JSON exceeds its captured byte limit')
    return result
