"""Bounded acquisition snapshots; source claims and inspected bytes remain separate (SPEC-31-F).

Pure contracts and content identities. A normalized delivery row retains the parser's
metadata and upstream entry digest; it is not a copy of the raw Winbindex entry.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from .contracts import (
    CONTRACT,
    Contract,
    HeadingClass,
    KbId,
    PairProposal,
    Record,
    Sha256,
    Short,
    Timestamp,
    Uuid,
    Variant,
    domain_id,
    https_host,
)

MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_REQUESTS = 514  # existing provider ceiling: 256 HEAD candidates and one GET per side
MAX_SHARED_VERSIONS = 4096
UInt32 = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
VersionKey = Annotated[str, Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$')]
DateText = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$')]
UrlText = Annotated[str, Field(min_length=1, max_length=2048)]


class EvidenceLimitError(ValueError):
    """The snapshot cannot be retained without exceeding its explicit budget."""


def canonical(value: Any) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('utf-8')
    if len(data) > MAX_EVIDENCE_BYTES:
        raise EvidenceLimitError('acquisition evidence exceeds its 1 MiB byte limit')
    return data


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


class AcquisitionSource(Record):
    proposal: PairProposal
    older: IndexEntry
    newer: IndexEntry

    @model_validator(mode='after')
    def _bindings(self):
        if self.proposal.grade == 'X':
            raise ValueError('blocked proposals cannot authorize acquisition')
        for ref, row in ((self.proposal.older, self.older), (self.proposal.newer, self.newer)):
            if (ref.sha256, ref.basename, ref.size) != (row.sha256, row.file_name, row.size):
                raise ValueError('a delivery entry differs from its ordered source proposal')
        return self

    @property
    def source_sha256(self) -> str:
        return domain_id('kbc.acquiresource', 1, self.model_dump(mode='json'))


class AcquisitionRequest(Record):
    method: Literal['GET', 'HEAD']
    target: UrlText


class DownloadReceipt(Record):
    side: Literal['older', 'newer']
    sha256: Sha256
    size: Annotated[int, Field(ge=1)]
    format: Short
    source_url: UrlText
    redirect_host: Annotated[str, Field(max_length=253)] | None
    retrieved_at: Timestamp
    winbindex_record_sha256: Sha256

    @model_validator(mode='after')
    def _locations(self):
        if https_host(self.source_url) is None:
            raise ValueError('download provenance needs an https source URL')
        if self.redirect_host is not None and not re.fullmatch(r'[A-Za-z0-9.-]+', self.redirect_host):
            raise ValueError('redirect provenance retains only the host, never a signed URL')
        return self


def plan_digest(source: AcquisitionSource, hosts: Sequence[str], requests: Sequence[tuple[str, str]]) -> str:
    pair = source.proposal
    return domain_id('kbc.acquireplan', 2, {
        'pair_id': pair.pair_id, 'older': pair.older.sha256, 'newer': pair.newer.sha256,
        'source_sha256': source.source_sha256, 'hosts': list(hosts), 'requests': [list(r) for r in requests]})


class AcquisitionEvidence(Contract):
    evidence_version: Literal[1] = 1
    evidence_id: Sha256
    investigation_id: Uuid
    preview_revision: Annotated[int, Field(ge=1)]
    plan_sha: Sha256
    source: AcquisitionSource
    hosts: Annotated[tuple[Short, ...], Field(min_length=1, max_length=8)]
    requests: Annotated[tuple[AcquisitionRequest, ...], Field(min_length=2, max_length=MAX_REQUESTS)]
    verified_pair: PairProposal
    downloads: Annotated[tuple[DownloadReceipt, ...], Field(min_length=2, max_length=2)]

    @model_validator(mode='after')
    def _bindings(self):
        source, verified = self.source.proposal, self.verified_pair
        if (verified.scope_id, verified.older.sha256, verified.newer.sha256) != (
                source.scope_id, source.older.sha256, source.newer.sha256):
            raise ValueError('verified pair must match the source product and ordered hashes')
        if (verified.grade, verified.tier, verified.bytes_state, verified.lineage_state, verified.fix_boundary) != (
                'B', 'E', 'verified', 'user-asserted', 'unverified'):
            raise ValueError('acquisition evidence must retain the conservative inspected manual pair')
        if verified.window_id != 'manual' or verified.window or verified.window_complete is not None or any(
                (ref.origin, ref.availability, ref.authenticity) != ('local-file', 'local', 'unverified-local-file')
                for ref in (verified.older, verified.newer)):
            raise ValueError('verified pair must retain local inspection and an unspecified manual window')
        requests = tuple((r.method, r.target) for r in self.requests)
        if self.hosts != tuple(sorted(set(self.hosts))) or self.plan_sha != plan_digest(
                self.source, self.hosts, requests):
            raise ValueError('acquisition plan does not bind this source snapshot and requests')
        targets = {request.target for request in self.requests}
        for side, receipt, entry, ref in zip(('older', 'newer'), self.downloads,
                                             (self.source.older, self.source.newer),
                                             (verified.older, verified.newer), strict=True):
            if (receipt.side, receipt.sha256, receipt.size, receipt.winbindex_record_sha256) != (
                    side, ref.sha256, ref.size, entry.record_sha256):
                raise ValueError('download receipt differs from the approved entry or inspected pair')
            if receipt.source_url not in targets or https_host(receipt.source_url) not in self.hosts:
                raise ValueError('download receipt URL was not in the approved request plan')
        payload = self.model_dump(mode='json', exclude={'evidence_id'})
        canonical(payload)
        if self.evidence_id != domain_id('kbc.acquisition', 1, payload):
            raise ValueError('acquisition evidence content identity does not match')
        return self

    def as_bytes(self) -> bytes:
        return canonical(self.model_dump(mode='json'))

    @property
    def relative_path(self) -> str:
        return f'kb/acquisitions/{self.evidence_id}.json'

    def check_owner(self, *, investigation_id: str, base_revision: int, pair_id: str,
                    older_sha: str, newer_sha: str, scope_id: str | None) -> None:
        pair = self.verified_pair
        if (self.investigation_id, pair.pair_id, pair.older.sha256, pair.newer.sha256, pair.scope_id) != (
                investigation_id, pair_id, older_sha, newer_sha, scope_id) or self.preview_revision > base_revision:
            raise ValueError('acquisition evidence belongs to another attachment')


def capture_source(pair: PairProposal, older: Mapping[str, Any], newer: Mapping[str, Any]) -> AcquisitionSource:
    """Validate and freeze all source values, including nested caller-owned collections."""
    data = canonical({'proposal': pair.model_dump(mode='json'), 'older': dict(older), 'newer': dict(newer)})
    return AcquisitionSource.model_validate_json(data)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key in acquisition evidence')
        result[key] = value
    return result


def read_evidence(data: bytes) -> AcquisitionEvidence:
    if len(data) > MAX_EVIDENCE_BYTES:
        raise EvidenceLimitError('acquisition evidence exceeds its 1 MiB byte limit')
    # Pydantic accepts duplicate JSON keys; reject them before validating identity and ownership.
    try:
        json.loads(data, object_pairs_hook=_unique)
    except RecursionError:
        raise ValueError('acquisition evidence is too deeply nested') from None
    return AcquisitionEvidence.model_validate_json(data)


def make_evidence(*, investigation_id: str, preview_revision: int, plan_sha: str, source: AcquisitionSource,
                  hosts: tuple[str, ...], requests: tuple[tuple[str, str], ...], verified_pair: PairProposal,
                  downloads: tuple[dict, ...]) -> AcquisitionEvidence:
    payload = {'contract': CONTRACT, 'evidence_version': 1, 'investigation_id': investigation_id,
               'preview_revision': preview_revision, 'plan_sha': plan_sha, 'source': source.model_dump(mode='json'),
               'hosts': list(hosts), 'requests': [{'method': m, 'target': t} for m, t in requests],
               'verified_pair': verified_pair.model_dump(mode='json'), 'downloads': list(downloads)}
    payload['evidence_id'] = domain_id('kbc.acquisition', 1, payload)
    return read_evidence(canonical(payload))
