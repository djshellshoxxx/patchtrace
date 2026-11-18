"""One serial local-package operation's monotonic budgets, before native writes."""
from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event

from .contracts import AcquisitionError
from .package_contracts import UINT64_MAX, PackageLimits, PackageUsage
from .package_worker_contracts import (
    MONOTONE_COUNTERS,
    WORKER_CONTRACT,
    PackageWorkerBinding,
    PackageWorkerGrant,
    PackageWorkerReceipt,
    check_usage_limits,
    parse_worker_record,
    worker_grant_identity,
)


@dataclass(frozen=True, slots=True)
class _Token:
    owner: object
    sequence: int
    kind: str


@dataclass(slots=True)
class _Entry:
    declared: int
    reserved: int = 0
    confirmed: int = 0
    pending: int = 0
    closed: bool = False


@dataclass(frozen=True, slots=True)
class _Output:
    entry: _Token
    size: int


class PackageBudget:
    """Failed attempts stay failed; cleanup can release only their own live allocations.

    Reservation is an upper bound charged before I/O. Confirmation records only
    bytes a successful write actually reported. A short/unknown write is fatal;
    no later operation may reclaim that reservation or turn it into verified data.
    """

    def __init__(self, limits: PackageLimits, *, cancel: Event | None = None,
                 clock_ns: Callable[[], int] = time.monotonic_ns):
        self._setup(limits, cancel, clock_ns)
        self._start = self._time()
        self._deadline = self._start + limits.max_seconds * 1_000_000_000
        if self._deadline > UINT64_MAX:
            self._fail('PT-ACQ-INPUT', 'package deadline cannot be represented')
        self.check()

    def _setup(self, limits, cancel, clock_ns):
        self.limits = limits
        self._cancel = cancel
        self._clock = clock_ns
        self._error: AcquisitionError | None = None
        self._owner = object()
        self._sequence = 0
        self._entries: dict[_Token, _Entry] = {}
        self._outputs: dict[_Token, _Output] = {}
        self._allocations: dict[_Token, int] = {}
        self._containers = self._callbacks = self._reserved = self._confirmed = 0
        self._live = self._peak = self._hashed = self._metadata = 0
        self._prior_entries = 0
        self._last = 0
        self._active_grant: PackageWorkerGrant | None = None
        self._grant_capture: bytes | None = None
        self._incoming_grant: PackageWorkerGrant | None = None
        self._worker_closed = self._worker_unknown = False
        self._operation_id: str | None = None
        self._attempts: set[str] = set()

    def _fail(self, code, message):
        if self._error is None:
            self._error = AcquisitionError(code, message)
        raise self._error

    def _time(self):
        try:
            now = self._clock()
        except Exception:
            self._fail('PT-ACQ-VERIFY', 'package monotonic clock is unavailable')
        if type(now) is not int or not self._last <= now <= UINT64_MAX:
            self._fail('PT-ACQ-VERIFY', 'package monotonic clock is invalid or moved backwards')
        self._last = now
        return now

    def check(self) -> None:
        if self._error is not None:
            raise self._error
        if self._worker_closed:
            self._fail('PT-ACQ-VERIFY', 'worker accounting was already closed')
        if self._cancel is not None and self._cancel.is_set():
            self._fail('PT-ACQ-CANCEL', 'local package operation was cancelled')
        if self._time() >= self._deadline:
            self._fail('PT-ACQ-LIMIT', 'local package operation exceeded its original deadline')

    def _local(self) -> None:
        self.check()
        if self._active_grant is not None:
            self._fail('PT-ACQ-VERIFY', 'parent work cannot overlap its outstanding worker grant')

    def _quiescent(self) -> bool:
        return not self._outputs and not self._allocations and all(entry.closed for entry in self._entries.values())

    def _count(self, value, *, minimum=0):
        if type(value) is not int or not minimum <= value <= UINT64_MAX:
            self._fail('PT-ACQ-INPUT', 'package accounting requires bounded integer counts')
        return value

    def _token(self, kind):
        self._sequence += 1
        return _Token(self._owner, self._sequence, kind)

    def _owned(self, token, kind, values):
        if type(token) is not _Token or token.owner is not self._owner or token.kind != kind or token not in values:
            self._fail('PT-ACQ-VERIFY', 'unknown, foreign or already completed package accounting token')
        return values[token]

    def remaining_seconds(self) -> float:
        self.check()
        return (self._deadline - self._last) / 1_000_000_000

    @property
    def deadline_ns(self) -> int:
        return self._deadline

    def callback(self) -> None:
        self._local()
        if self._callbacks >= self.limits.max_callbacks:
            self._fail('PT-ACQ-LIMIT', 'package callback/work budget exhausted')
        self._callbacks += 1

    def begin_container(self, *, size: int, depth: int) -> None:
        self._local()
        self._count(size, minimum=1)
        self._count(depth)
        if (size > self.limits.max_source_bytes or depth > self.limits.max_depth
                or self._containers >= self.limits.max_containers):
            self._fail('PT-ACQ-LIMIT', 'package container size, depth or count exceeds the shared limit')
        self._containers += 1

    def begin_entry(self, declared_size: int):
        self._local()
        self._count(declared_size)
        if (declared_size > self.limits.max_entry_bytes
                or self._prior_entries + len(self._entries) >= self.limits.max_entries):
            self._fail('PT-ACQ-LIMIT', 'package entry declaration or count exceeds the shared limit')
        token = self._token('entry')
        self._entries[token] = _Entry(declared_size)
        return token

    def _entry(self, token):
        entry = self._owned(token, 'entry', self._entries)
        if entry.closed:
            self._fail('PT-ACQ-VERIFY', 'closed package entry cannot receive more output')
        return entry

    def reserve_output(self, entry_token, size: int):
        self._local()
        self._count(size)
        entry = self._entry(entry_token)
        if entry.pending:
            self._fail('PT-ACQ-VERIFY', 'a serial package entry already has an uncompleted write')
        if (entry.reserved + size > min(entry.declared, self.limits.max_entry_bytes)
                or self._reserved + size > self.limits.max_expanded_bytes):
            self._fail('PT-ACQ-LIMIT', 'package expanded bytes exceed the declaration or shared limit')
        token = self._token('output')
        self._outputs[token] = _Output(entry_token, size)
        self._reserved += size
        entry.reserved += size
        entry.pending += 1
        return token

    def complete_output(self, reservation, count: int) -> None:
        if self._worker_closed:
            self._fail('PT-ACQ-VERIFY', 'terminal worker accounting cannot accept output completion')
        # A completed write's known bytes remain evidence even if cancellation
        # or the original deadline became visible while the sink was writing.
        output = self._owned(reservation, 'output', self._outputs)
        entry = self._entry(output.entry)
        del self._outputs[reservation]
        entry.pending -= 1
        if type(count) is int and 0 <= count <= output.size:
            self._confirmed += count
            entry.confirmed += count
        if type(count) is not int or count != output.size:
            self._fail('PT-ACQ-VERIFY', 'package output write was short or its byte count is unknown')
        self.check()

    def fail_output(self, reservation) -> None:
        if self._worker_closed:
            self._fail('PT-ACQ-VERIFY', 'terminal worker accounting cannot consume an output token')
        output = self._owned(reservation, 'output', self._outputs)
        del self._outputs[reservation]
        self._entries[output.entry].pending -= 1
        self._fail('PT-ACQ-VERIFY', 'package output write failed; reserved bytes remain charged')

    def finish_entry(self, token) -> None:
        self._local()
        entry = self._entry(token)
        if entry.pending or entry.confirmed != entry.declared or entry.reserved != entry.declared:
            self._fail('PT-ACQ-VERIFY', 'package member did not finish its exact declared output')
        entry.closed = True

    def skip_entry(self, token) -> None:
        self._local()
        entry = self._entry(token)
        if entry.pending or entry.reserved or entry.confirmed:
            self._fail('PT-ACQ-VERIFY', 'a partially emitted package member cannot become header-only')
        entry.closed = True

    def allocate(self, size: int):
        self._local()
        self._count(size, minimum=1)
        if self._live + size > self.limits.max_live_allocation_bytes:
            self._fail('PT-ACQ-LIMIT', 'package native callback allocation limit exceeded')
        token = self._token('allocation')
        self._allocations[token] = size
        self._live += size
        self._peak = max(self._peak, self._live)
        return token

    def free(self, token) -> None:
        # Native cleanup remains possible after failure/cancellation. It cannot
        # refund output, restore elapsed time, or free a foreign allocation.
        size = self._owned(token, 'allocation', self._allocations)
        del self._allocations[token]
        self._live -= size

    def charge_hash(self, size: int) -> None:
        self._local()
        self._count(size)
        if self._hashed + size > UINT64_MAX:
            self._fail('PT-ACQ-LIMIT', 'package input hash accounting overflow')
        self.callback()
        self._hashed += size

    def charge_metadata(self, size: int) -> None:
        self._local()
        self._count(size)
        if size > self.limits.max_xml_bytes or self._metadata + size > self.limits.max_metadata_bytes:
            self._fail('PT-ACQ-LIMIT', 'package retained metadata exceeds its shared limit')
        self._metadata += size

    def snapshot(self) -> PackageUsage:
        """Retain the last observed clock and counters even when check() now refuses."""
        return PackageUsage(reserved_output_bytes=self._reserved, confirmed_output_bytes=self._confirmed,
                            entries=self._prior_entries + len(self._entries), containers=self._containers,
                            callbacks=self._callbacks,
                            live_allocated_bytes=self._live, peak_allocated_bytes=self._peak,
                            hashed_input_bytes=self._hashed, metadata_bytes=self._metadata,
                            elapsed_ns=self._last - self._start, failed=self._error is not None,
                            failure_code=None if self._error is None else self._error.code)

    @property
    def worker_pending(self) -> bool:
        return self._active_grant is not None

    @property
    def worker_usage_unknown(self) -> bool:
        return self._worker_unknown

    def issue_worker(self, binding: PackageWorkerBinding) -> PackageWorkerGrant:
        self._local()
        if self._incoming_grant is not None or not self._quiescent():
            self._fail('PT-ACQ-VERIFY', 'worker grant requires the quiescent parent operation')
        try:
            if type(binding) is not PackageWorkerBinding:
                raise ValueError('worker binding type')
            captured = parse_worker_record(PackageWorkerBinding,
                                           binding.model_dump_json(warnings='error').encode('utf-8'))
            if (self._operation_id not in (None, captured.operation_id)
                    or captured.attempt_id in self._attempts):
                raise ValueError('operation or attempt binding')
            self.callback()
            values = dict(contract=WORKER_CONTRACT, parser_version=1,
                          binding=captured, limits=self.limits, started_ns=self._start,
                          deadline_ns=self._deadline, issued_ns=self._last, baseline=self.snapshot(),
                          grant_nonce=secrets.token_hex(32))
            candidate = PackageWorkerGrant(grant_id=worker_grant_identity(values), **values)
            raw = candidate.model_dump_json(warnings='error').encode('utf-8')
            grant = parse_worker_record(PackageWorkerGrant, raw)
        except (ValueError, TypeError, AcquisitionError):
            self._fail('PT-ACQ-INPUT', 'invalid worker binding, capture or grant boundary')
        self._operation_id = captured.operation_id
        self._attempts.add(captured.attempt_id)
        self._active_grant, self._grant_capture = grant, raw
        return grant

    @classmethod
    def from_worker_grant(cls, raw: bytes, *, cancel: Event | None = None,
                          clock_ns: Callable[[], int] = time.monotonic_ns) -> PackageBudget:
        grant = parse_worker_record(PackageWorkerGrant, raw)
        child = cls.__new__(cls)
        child._setup(grant.limits, cancel, clock_ns)
        child._start, child._deadline, child._last = grant.started_ns, grant.deadline_ns, grant.issued_ns
        child._incoming_grant = grant
        child._apply_usage(grant.baseline)
        child.check()
        return child

    def _apply_usage(self, usage: PackageUsage) -> None:
        self._prior_entries = usage.entries - len(self._entries)
        self._containers, self._callbacks = usage.containers, usage.callbacks
        self._reserved, self._confirmed = usage.reserved_output_bytes, usage.confirmed_output_bytes
        self._live, self._peak = usage.live_allocated_bytes, usage.peak_allocated_bytes
        self._hashed, self._metadata = usage.hashed_input_bytes, usage.metadata_bytes

    def worker_receipt(self) -> PackageWorkerReceipt:
        if self._incoming_grant is None or self._worker_closed:
            self._fail('PT-ACQ-VERIFY', 'only an open derived worker can produce one receipt')
        try:
            self.check()
            if not self._quiescent():
                self._fail('PT-ACQ-VERIFY', 'worker has unfinished entries, writes or allocations')
        except AcquisitionError:
            pass  # Preserve the first failure and known partial accounting in the terminal record.
        grant = self._incoming_grant
        receipt = PackageWorkerReceipt(contract=WORKER_CONTRACT, parser_version=1,
                                       grant_id=grant.grant_id, binding=grant.binding,
                                       status='failed' if self._error is not None else 'complete',
                                       observed_ns=self._last, usage=self.snapshot(),
                                       open_entries=sum(not item.closed for item in self._entries.values()),
                                       pending_outputs=len(self._outputs))
        self._worker_closed = True
        return receipt

    def _reject_worker(self, message: str) -> None:
        if self._active_grant is not None:
            self._worker_unknown = True
        self._active_grant = self._grant_capture = None
        self._fail('PT-ACQ-VERIFY', message)

    def abandon_worker(self, grant: PackageWorkerGrant) -> None:
        if grant is not self._active_grant or grant is None:
            self._reject_worker('unknown or already reconciled worker grant')
        self._reject_worker('worker receipt unavailable; consumption is unknown and cannot be retried')

    def reconcile_worker(self, grant: PackageWorkerGrant, raw: bytes) -> None:
        if grant is not self._active_grant or grant is None:
            self._reject_worker('foreign, copied or already reconciled worker grant')
        try:
            # The private serialized capture survives even an unsafe mutation of the returned frozen object.
            captured = parse_worker_record(PackageWorkerGrant, self._grant_capture)
            if type(raw) is not bytes or len(raw) > captured.limits.max_json_bytes:
                raise ValueError('worker receipt size/type')
            receipt = parse_worker_record(PackageWorkerReceipt, raw)
            now = self._time()  # Do not discard valid reported bytes just because cancellation arrived later.
            usage, baseline = receipt.usage, captured.baseline
            if (receipt.grant_id != captured.grant_id or receipt.binding != captured.binding
                    or not captured.issued_ns <= receipt.observed_ns <= now
                    or usage.elapsed_ns != receipt.observed_ns - captured.started_ns
                    or usage.elapsed_ns < baseline.elapsed_ns
                    or receipt.status == 'complete' and receipt.observed_ns >= captured.deadline_ns
                    or any(getattr(usage, name) < getattr(baseline, name) for name in MONOTONE_COUNTERS)):
                raise ValueError('worker receipt ownership, clock or monotone accounting')
            check_usage_limits(usage, captured.limits)
            new_entries = usage.entries - baseline.entries
            if (usage.reserved_output_bytes - baseline.reserved_output_bytes
                    > new_entries * captured.limits.max_entry_bytes
                    or receipt.open_entries > new_entries):
                raise ValueError('worker receipt reuses closed entries or exceeds their output capacity')
        except (ValueError, TypeError, AcquisitionError):
            self._reject_worker('worker receipt is invalid; no partial usage was admitted')
        self._apply_usage(usage)
        self._active_grant = self._grant_capture = None
        if receipt.status == 'failed':
            self._fail(usage.failure_code, 'worker reported failure; consumed allowance cannot be retried')
        self.check()
