"""Strict serial worker accounting; a JSON receipt never qualifies native I/O."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Literal

from pydantic import Field, field_validator, model_validator

from ..enrichment.identity import domain_id
from .contracts import AcquisitionError, Record
from .package_contracts import (
    MAX_ENTRIES,
    UINT64_MAX,
    PackageLimits,
    PackageSource,
    PackageUsage,
    Sha256,
    _json_values,
    parse_record,
)

WORKER_CONTRACT = 'local-package-worker/1'
WORKER_MAX_JSON = 1 << 20
USAGE_LIMITS = {
    'reserved_output_bytes': 'max_expanded_bytes',
    'confirmed_output_bytes': 'max_expanded_bytes',
    'entries': 'max_entries',
    'containers': 'max_containers',
    'callbacks': 'max_callbacks',
    'live_allocated_bytes': 'max_live_allocation_bytes',
    'peak_allocated_bytes': 'max_live_allocation_bytes',
    'metadata_bytes': 'max_metadata_bytes',
}
MONOTONE_COUNTERS = tuple(name for name in USAGE_LIMITS if name != 'live_allocated_bytes') + (
    'hashed_input_bytes',)


def check_usage_limits(usage: PackageUsage, limits: PackageLimits) -> None:
    if any(getattr(usage, name) > getattr(limits, bound) for name, bound in USAGE_LIMITS.items()):
        raise ValueError('worker usage exceeds a captured resource limit')


def worker_grant_identity(values: Mapping) -> str:
    payload = _json_values({key: value for key, value in values.items() if key != 'grant_id'})
    payload.setdefault('contract', WORKER_CONTRACT)
    payload.setdefault('parser_version', 1)
    limit = payload.get('limits', {}).get('max_json_bytes', WORKER_MAX_JSON)
    if type(limit) is not int or limit < 1:
        raise ValueError('invalid worker JSON limit')
    limit = min(limit, WORKER_MAX_JSON)
    size = 0
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    for chunk in encoder.iterencode(payload | {'grant_id': '0' * 64}):
        size += len(chunk.encode('utf-8'))
        if size > limit:
            raise ValueError('worker grant exceeds its serialization limit')
    return domain_id('acquisition.package-worker-grant', 1, payload)


class PackageWorkerBinding(Record):
    operation_id: Sha256
    request_id: Sha256
    attempt_id: Sha256
    source: PackageSource


class _VersionedWorker(Record):
    contract: Literal['local-package-worker/1']
    parser_version: Literal[1]

    @field_validator('parser_version', mode='before')
    @classmethod
    def _version(cls, value):
        if type(value) is not int:
            raise ValueError('worker version must be an integer')
        return value


class PackageWorkerGrant(_VersionedWorker):
    grant_id: Sha256
    grant_nonce: Sha256
    binding: PackageWorkerBinding
    limits: PackageLimits
    started_ns: int = Field(ge=0, le=UINT64_MAX)
    deadline_ns: int = Field(ge=1, le=UINT64_MAX)
    issued_ns: int = Field(ge=0, le=UINT64_MAX)
    baseline: PackageUsage

    @model_validator(mode='after')
    def _grant(self):
        if (self.deadline_ns != self.started_ns + self.limits.max_seconds * 1_000_000_000
                or not self.started_ns <= self.issued_ns < self.deadline_ns
                or self.baseline.elapsed_ns != self.issued_ns - self.started_ns):
            raise ValueError('worker grant does not retain the original clock basis')
        if (self.baseline.failed or self.baseline.live_allocated_bytes
                or self.baseline.reserved_output_bytes != self.baseline.confirmed_output_bytes):
            raise ValueError('worker grant requires a quiescent nonfailed baseline')
        if (self.baseline.callbacks < 1
                or self.baseline.reserved_output_bytes > self.baseline.entries * self.limits.max_entry_bytes):
            raise ValueError('worker grant baseline has impossible issuance or entry usage')
        check_usage_limits(self.baseline, self.limits)
        if self.binding.source.size > self.limits.max_source_bytes:
            raise ValueError('worker source exceeds the captured input limit')
        if self.grant_id != worker_grant_identity(self.model_dump(mode='python')):
            raise ValueError('worker grant identity disagrees with its capture')
        return self


class PackageWorkerReceipt(_VersionedWorker):
    grant_id: Sha256
    binding: PackageWorkerBinding
    status: Literal['complete', 'failed']
    observed_ns: int = Field(ge=0, le=UINT64_MAX)
    usage: PackageUsage
    open_entries: int = Field(ge=0, le=MAX_ENTRIES)
    pending_outputs: int = Field(ge=0, le=MAX_ENTRIES)

    @model_validator(mode='after')
    def _receipt(self):
        if not self.pending_outputs <= self.open_entries <= self.usage.entries:
            raise ValueError('worker pending-resource counts disagree')
        if (self.status == 'failed') != self.usage.failed:
            raise ValueError('worker receipt status and usage failure disagree')
        if self.status == 'complete' and (
                self.open_entries or self.pending_outputs or self.usage.live_allocated_bytes
                or self.usage.reserved_output_bytes != self.usage.confirmed_output_bytes):
            raise ValueError('complete worker receipt has uncompleted resources')
        if len(self.model_dump_json().encode('utf-8')) > WORKER_MAX_JSON:
            raise ValueError('worker receipt exceeds its serialization limit')
        return self


def parse_worker_record[T: Record](model: type[T], raw: bytes) -> T:
    if model not in (PackageWorkerBinding, PackageWorkerGrant, PackageWorkerReceipt):
        raise AcquisitionError('PT-ACQ-INPUT', 'unknown worker accounting record')
    result = parse_record(model, raw, max_bytes=WORKER_MAX_JSON)
    if isinstance(result, PackageWorkerGrant) and len(raw) > result.limits.max_json_bytes:
        raise AcquisitionError('PT-ACQ-LIMIT', 'worker grant exceeds the captured JSON limit')
    return result
