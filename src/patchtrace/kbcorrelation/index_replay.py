"""Complete retained Winbindex input and resolver replay (SPEC-31-D/F).

Pure records and calculations. The composition root supplies already parsed rows
from one bounded original byte string; it also owns all filesystem access.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator

from . import resolver
from .contracts import (
    BuildUbr,
    HeadingClass,
    KbId,
    PairProposal,
    ProductScope,
    Record,
    Sha256,
    Short,
    Variant,
)
from .limits import DEFAULT_LIMITS
from .lineage import IndexRow, index_rows

MAX_RAW_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_BYTES = MAX_RAW_BYTES
MAX_REPLAY_ROWS = 1_000_000
MAX_SHARED_VERSIONS = 4096
UInt32 = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
VersionKey = Annotated[str, Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$')]
DateText = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$')]
UrlText = Annotated[str, Field(min_length=1, max_length=2048)]
Count = Annotated[int, Field(ge=0, le=MAX_REPLAY_ROWS)]


class ReplayLimitError(ValueError):
    """Complete capture would exceed a declared source or row budget."""


def digest(value: Any) -> str:
    """Digest canonical JSON without making a second complete encoded copy."""
    result = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    for part in encoder.iterencode(value):
        result.update(part.encode('ascii'))
    return result.hexdigest()


class IndexEntry(Record):
    """Exactly one normalized Winbindex delivery row, not an asserted resolver endpoint."""
    file_name: Short
    sha256: Sha256
    version_key: VersionKey
    kb: KbId | None
    release_date: DateText | None
    release_version: Annotated[str, Field(max_length=20)] | None
    heading: Annotated[str, Field(max_length=300)]
    heading_class: HeadingClass
    other_versions: Annotated[tuple[VersionKey, ...], Field(max_length=MAX_SHARED_VERSIONS)]
    variant: Variant
    download: Literal['direct', 'candidates', 'unavailable']
    size: UInt32 | None
    machine_type: Annotated[int, Field(ge=0, le=0xFFFF)] | None
    timestamp: UInt32 | None
    virtual_size: UInt32 | None
    last_section_va: UInt32 | None
    last_section_raw: UInt32 | None
    file_version: Annotated[str, Field(max_length=200)] | None
    record_sha256: Sha256
    source: Annotated[str, Field(pattern=r'^winbindex@[0-9]{4}-[0-9]{2}-[0-9]{2}$')]
    download_url: UrlText | None = None


class IndexSource(Record):
    sha256: Sha256
    byte_count: Annotated[int, Field(ge=1, le=MAX_RAW_BYTES)]
    file_name: Annotated[str, Field(pattern=r'^[a-z0-9._-]{1,128}$')]
    data_date: DateText
    compressed: bool
    parser_version: Literal['winbindex-rows/1'] = 'winbindex-rows/1'
    lineage_version: Literal['kbc-lineage/1'] = 'kbc-lineage/1'
    resolver_version: Literal['kbc-resolver/1'] = 'kbc-resolver/1'

    @property
    def relative_path(self) -> str:
        return f'kb/winbindex/{self.sha256}.bin'

    @property
    def workspace_path(self) -> str:
        return f'winbindex-objects/{self.sha256}.bin'

    def check_bytes(self, raw: bytes) -> None:
        if len(raw) > MAX_RAW_BYTES:
            raise ReplayLimitError('retained Winbindex bytes exceed the 64 MiB limit')
        if len(raw) != self.byte_count or hashlib.sha256(raw).hexdigest() != self.sha256:
            raise ValueError('retained Winbindex bytes do not match their source identity')


class SourceMembership(Record):
    sha256: Sha256
    version_key: VersionKey
    source_version_key: VersionKey
    kb: KbId | None
    record_sha256: Sha256

    @property
    def pointer(self) -> str:
        return f'/{self.sha256}/windowsVersions/{self.source_version_key}/{self.kb or "BASE"}'

    @classmethod
    def from_row(cls, row: IndexRow) -> SourceMembership:
        return cls(sha256=row.sha256, version_key=row.build.version_key,
                   source_version_key=row.shared_from or row.build.version_key,
                   kb=row.kb, record_sha256=row.build.record_sha256)

    def matches(self, entry: IndexEntry) -> bool:
        return ((self.sha256, self.source_version_key, self.kb, self.record_sha256) ==
                (entry.sha256, entry.version_key, entry.kb, entry.record_sha256) and
                (self.version_key == entry.version_key or self.version_key in entry.other_versions))


@dataclass(frozen=True)
class CapturedIndex:
    source: IndexSource
    raw: bytes
    mappings: tuple[IndexEntry, ...]
    rows: tuple[IndexRow, ...]
    skipped: int
    skipped_bodies: int
    rejected: int

    @classmethod
    def from_rows(cls, raw: bytes, *, file_name: str, data_date: str, compressed: bool,
                  mappings: Sequence[Mapping[str, Any]], skipped: int, skipped_bodies: int) -> CapturedIndex:
        if not raw or len(raw) > MAX_RAW_BYTES:
            raise ReplayLimitError('retained Winbindex bytes exceed the 64 MiB limit or are empty')
        if len(mappings) > MAX_REPLAY_ROWS:
            raise ReplayLimitError('retained Winbindex mappings exceed the replay rows limit')
        if any(len(item.get('other_versions', ())) > MAX_SHARED_VERSIONS for item in mappings):
            raise ReplayLimitError('retained Winbindex copied version keys exceed the per-row limit')
        if sum(1 + len(item.get('other_versions', ())) for item in mappings) > MAX_REPLAY_ROWS:
            raise ReplayLimitError('retained Winbindex potential lineage rows exceed the replay rows limit')
        source = IndexSource(sha256=hashlib.sha256(raw).hexdigest(), byte_count=len(raw), file_name=file_name,
                             data_date=data_date, compressed=compressed)
        frozen = tuple(IndexEntry.model_validate_json(json.dumps(dict(item))) for item in mappings)
        if any((entry.file_name, entry.source) != (file_name, f'winbindex@{data_date}') for entry in frozen):
            raise ValueError('retained Winbindex mappings belong to another source')
        rows, rejected = index_rows((entry.model_dump(mode='json') for entry in frozen), file_name=file_name)
        if len(rows) > MAX_REPLAY_ROWS:
            raise ReplayLimitError('retained Winbindex lineage rows exceed the replay rows limit')
        return cls(source, bytes(raw), frozen, rows, skipped, skipped_bodies, rejected)

    @property
    def gap(self) -> int:
        return self.skipped + self.skipped_bodies + self.rejected

    def entry_for(self, member: SourceMembership) -> IndexEntry:
        eligible = [entry for entry in self.mappings if (entry.sha256, entry.kb) == (member.sha256, member.kb)]
        native = [entry for entry in eligible if entry.version_key == member.version_key]
        copied = [entry for entry in eligible if member.version_key in entry.other_versions]
        found = native or copied
        # Knowing which copied row the resolver encountered first does not remove
        # conflicting source claims in that priority tier. Keep the admission refusal.
        if not found or any(entry != found[0] for entry in found[1:]) or not member.matches(found[0]):
            raise ValueError('replay endpoint has no unique original source membership')
        return found[0]


class ResolverInputs(Record):
    scope: ProductScope
    kb: KbId
    fixed_build: BuildUbr | None
    same_class_only: bool = True
    tier: Literal['A', 'B', 'C', 'D', 'E'] = 'C'
    limit: Annotated[int, Field(ge=1, le=DEFAULT_LIMITS.pairs_per_file)] = DEFAULT_LIMITS.pairs_per_file

    def resolve(self, snapshot: CapturedIndex) -> resolver.Resolution:
        return resolver.resolve(snapshot.rows, kb=self.kb, scope=self.scope, file_name=snapshot.source.file_name,
                                fixed_build=self.fixed_build, skipped_rows=snapshot.gap,
                                same_class_only=self.same_class_only, tier=self.tier, limit=self.limit)


class IndexReplay(Record):
    replay_version: Literal[1] = 1
    source: IndexSource
    inputs: ResolverInputs
    mapping_sha256: Sha256
    mapping_count: Count
    lineage_sha256: Sha256
    lineage_count: Count
    parser_skipped: Annotated[int, Field(ge=0, le=MAX_RAW_BYTES)]
    parser_skipped_bodies: Annotated[int, Field(ge=0, le=MAX_RAW_BYTES)]
    conversion_rejected: Annotated[int, Field(ge=0, le=MAX_RAW_BYTES)]
    resolution_sha256: Sha256
    selected_pair_id: Sha256
    older: SourceMembership
    newer: SourceMembership

    @field_validator('replay_version', mode='before')
    @classmethod
    def _version_type(cls, value):
        if type(value) is not int:
            raise ValueError('replay version must be an integer')
        return value


def resolution_body(result: resolver.Resolution) -> dict:
    return {name: [pair.model_dump(mode='json') for pair in value] if name == 'pairs' else value
            for name in result.__dataclass_fields__ if name != 'memberships'
            for value in (getattr(result, name),)}


def capture_replay(snapshot: CapturedIndex, inputs: ResolverInputs, result: resolver.Resolution,
                   pair: PairProposal) -> IndexReplay:
    snapshot.source.check_bytes(snapshot.raw)
    selected = [member for member in result.memberships if member.pair_id == pair.pair_id]
    if pair not in result.pairs or len(selected) != 1:
        raise ValueError('replay pair is not a member of this resolution')
    member = selected[0]
    older, newer = SourceMembership.from_row(member.older), SourceMembership.from_row(member.newer)
    snapshot.entry_for(older)
    snapshot.entry_for(newer)
    lineage = [{**row.build.model_dump(mode='json'), 'size': row.size, 'machine': row.machine,
                'file_version': row.file_version, 'availability': row.availability,
                'heading_builds': row.heading_builds, 'shared_from': row.shared_from} for row in snapshot.rows]
    return IndexReplay(source=snapshot.source, inputs=inputs,
                       mapping_sha256=digest([row.model_dump(mode='json') for row in snapshot.mappings]),
                       mapping_count=len(snapshot.mappings), lineage_sha256=digest(lineage),
                       lineage_count=len(snapshot.rows), parser_skipped=snapshot.skipped,
                       parser_skipped_bodies=snapshot.skipped_bodies, conversion_rejected=snapshot.rejected,
                       resolution_sha256=digest(resolution_body(result)), selected_pair_id=pair.pair_id,
                       older=older, newer=newer)


def verify_replay(snapshot: CapturedIndex, manifest: IndexReplay, pair: PairProposal) -> resolver.Resolution:
    """Reproduce every frozen binding; never reinterpret a failed replay as a complete result."""
    snapshot.source.check_bytes(snapshot.raw)
    result = manifest.inputs.resolve(snapshot)
    reproduced = capture_replay(snapshot, manifest.inputs, result, pair)
    if reproduced != manifest:
        raise ValueError('retained Winbindex replay differs from the approved source or resolution')
    return result
