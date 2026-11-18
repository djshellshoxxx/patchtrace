"""One serial local-package operation's monotonic budgets, before native writes."""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event

from .contracts import AcquisitionError
from .package_contracts import UINT64_MAX, PackageLimits, PackageUsage


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
        self._last = 0
        self._start = self._time()
        self._deadline = self._start + limits.max_seconds * 1_000_000_000
        if self._deadline > UINT64_MAX:
            self._fail('PT-ACQ-INPUT', 'package deadline cannot be represented')
        self.check()

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
        if self._cancel is not None and self._cancel.is_set():
            self._fail('PT-ACQ-CANCEL', 'local package operation was cancelled')
        if self._time() >= self._deadline:
            self._fail('PT-ACQ-LIMIT', 'local package operation exceeded its original deadline')

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
        self.check()
        if self._callbacks >= self.limits.max_callbacks:
            self._fail('PT-ACQ-LIMIT', 'package callback/work budget exhausted')
        self._callbacks += 1

    def begin_container(self, *, size: int, depth: int) -> None:
        self.check()
        self._count(size, minimum=1)
        self._count(depth)
        if (size > self.limits.max_source_bytes or depth > self.limits.max_depth
                or self._containers >= self.limits.max_containers):
            self._fail('PT-ACQ-LIMIT', 'package container size, depth or count exceeds the shared limit')
        self._containers += 1

    def begin_entry(self, declared_size: int):
        self.check()
        self._count(declared_size)
        if declared_size > self.limits.max_entry_bytes or len(self._entries) >= self.limits.max_entries:
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
        self.check()
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
        output = self._owned(reservation, 'output', self._outputs)
        del self._outputs[reservation]
        self._entries[output.entry].pending -= 1
        self._fail('PT-ACQ-VERIFY', 'package output write failed; reserved bytes remain charged')

    def finish_entry(self, token) -> None:
        self.check()
        entry = self._entry(token)
        if entry.pending or entry.confirmed != entry.declared or entry.reserved != entry.declared:
            self._fail('PT-ACQ-VERIFY', 'package member did not finish its exact declared output')
        entry.closed = True

    def skip_entry(self, token) -> None:
        self.check()
        entry = self._entry(token)
        if entry.pending or entry.reserved or entry.confirmed:
            self._fail('PT-ACQ-VERIFY', 'a partially emitted package member cannot become header-only')
        entry.closed = True

    def allocate(self, size: int):
        self.check()
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
        self.check()
        self._count(size)
        if self._hashed + size > UINT64_MAX:
            self._fail('PT-ACQ-LIMIT', 'package input hash accounting overflow')
        self.callback()
        self._hashed += size

    def charge_metadata(self, size: int) -> None:
        self.check()
        self._count(size)
        if size > self.limits.max_xml_bytes or self._metadata + size > self.limits.max_metadata_bytes:
            self._fail('PT-ACQ-LIMIT', 'package retained metadata exceeds its shared limit')
        self._metadata += size

    def snapshot(self) -> PackageUsage:
        """Retain the last observed clock and counters even when check() now refuses."""
        return PackageUsage(reserved_output_bytes=self._reserved, confirmed_output_bytes=self._confirmed,
                            entries=len(self._entries), containers=self._containers, callbacks=self._callbacks,
                            live_allocated_bytes=self._live, peak_allocated_bytes=self._peak,
                            hashed_input_bytes=self._hashed, metadata_bytes=self._metadata,
                            elapsed_ns=self._last - self._start, failed=self._error is not None,
                            failure_code=None if self._error is None else self._error.code)
