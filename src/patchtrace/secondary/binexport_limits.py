"""Resource caps and the cancellation/deadline budget for BinExport2 inspection (SPEC-10b §4-5). Stdlib only."""
from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .contracts import ErrorCode, SecondaryError

MIB = 1024 * 1024
GIB = 1024 * MIB
HARD_MEMORY_MAX = 6 * GIB
TICK_EVERY = 8192

DEFAULT_COUNTS: Mapping[str, int] = MappingProxyType({
    'expression': 40_000_000, 'operand': 30_000_000, 'mnemonic': 65_536, 'instruction': 40_000_000,
    'basic_block': 10_000_000, 'flow_graph': 1_000_000, 'vertex': 2_000_000, 'call_edge': 20_000_000,
    'flow_edge': 40_000_000, 'string_table': 4_000_000, 'comment': 4_000_000, 'string_reference': 4_000_000,
    'expression_substitution': 4_000_000, 'address_comment': 4_000_000, 'data_reference': 20_000_000,
    'section': 4096, 'library': 4096, 'module': 4096, 'md_index': 2_000_000,
})


def err(code: ErrorCode, reason: str, message: str | None = None) -> SecondaryError:
    """Fixed-template error: message carries labels/numbers only, never file strings (<= 200 chars)."""
    return SecondaryError(code, (message or reason.replace('_', ' '))[:200], reason=reason)


def memory_for(file_size: int) -> int:
    """§5: clamp(14 * size + 256 MiB, 512 MiB, 6 GiB) is the default; callers check the unclamped value."""
    return max(512 * MIB, 14 * file_size + 256 * MIB)


OOM_FRACTION = 0.9  # a failure with peak >= 0.9 x cap is reported as worker_oom, not as a bad file


def peak_memory_bytes() -> int | None:
    """This process's peak of the quantity the platform cap limits, or None if unknown.

    Linux: VmPeak (virtual size; RLIMIT_AS limits it). Windows: PeakPagefileUsage (peak committed bytes; the Job
    Object per-process limit counts commit). Other POSIX: ru_maxrss (an RSS proxy)."""
    try:
        if sys.platform.startswith('linux'):
            with open('/proc/self/status', encoding='ascii', errors='replace') as status:
                for line in status:
                    if line.startswith('VmPeak:'):
                        return int(line.split()[1]) * 1024
            return None
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
                    (name, ctypes.c_size_t) for name in (
                        'peak_ws', 'ws', 'peak_paged', 'paged', 'peak_nonpaged', 'nonpaged', 'pagefile',
                        'peak_pagefile')]
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            fn = kernel.K32GetProcessMemoryInfo
            fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            fn.restype = wintypes.BOOL
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            counters = Counters()
            counters.cb = ctypes.sizeof(Counters)
            if not fn(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                return None
            return int(counters.peak_pagefile)
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak if sys.platform == 'darwin' else peak * 1024
    except (OSError, ValueError, AttributeError, ImportError):
        return None


def near_cap(cap: int | None, peak: int | None = None) -> bool:
    if not cap:
        return False
    peak = peak_memory_bytes() if peak is None else peak
    return peak is not None and peak >= OOM_FRACTION * cap


@dataclass(frozen=True, slots=True)
class BinExportLimits:
    max_file_bytes: int = 256 * MIB
    max_record_bytes: int = 32 * MIB
    max_unknown_bytes: int = 64 * 1024
    max_counts: Mapping[str, int] = field(default_factory=lambda: DEFAULT_COUNTS)
    max_string_bytes: int = 64 * 1024
    max_string_total: int = 128 * MIB
    max_meta_bytes: int = 4096
    max_expr_depth: int = 64
    max_operands_per_instr: int = 16
    max_exprs_per_operand: int = 64
    max_ranges_per_block: int = 4096
    max_call_targets: int = 1024
    coverage_factor: int = 4
    coverage_slack: int = 1024
    wall_seconds: float = 600.0
    memory_bytes: int | None = None  # None: derived per file with memory_for()
    max_summary_bytes: int = 64 * MIB

    def __post_init__(self):
        for name in ('max_file_bytes', 'max_record_bytes', 'max_string_bytes', 'max_string_total',
                     'max_meta_bytes', 'max_expr_depth', 'max_operands_per_instr', 'max_exprs_per_operand',
                     'max_ranges_per_block', 'coverage_factor', 'max_summary_bytes'):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f'BinExportLimits.{name} must be a positive integer')
        if not 0 < self.wall_seconds <= 86400:
            raise ValueError('BinExportLimits.wall_seconds must be in (0, 86400]')
        unknown = set(self.max_counts) - set(DEFAULT_COUNTS)
        if unknown:
            raise ValueError(f'unknown count caps {sorted(unknown)}')
        merged = dict(DEFAULT_COUNTS)
        merged.update(self.max_counts)
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in merged.values()):
            raise ValueError('count caps must be non-negative integers')
        object.__setattr__(self, 'max_counts', MappingProxyType(merged))

    def memory_required(self, file_size: int) -> int:
        return self.memory_bytes if self.memory_bytes is not None else memory_for(file_size)

    def cap(self, name: str) -> int:
        return self.max_counts[name]

    def to_json(self) -> dict:
        data = {name: getattr(self, name) for name in self.__dataclass_fields__}
        data['max_counts'] = dict(self.max_counts)
        return data

    @classmethod
    def from_json(cls, data: Mapping) -> BinExportLimits:
        if not isinstance(data, Mapping) or set(data) - set(cls.__dataclass_fields__):
            raise ValueError('limits document has unknown keys')
        return cls(**{k: (dict(v) if k == 'max_counts' else v) for k, v in data.items()})


class Budget:
    """Cheap cooperative cancellation + wall deadline; checks every TICK_EVERY units.

    Raises SecondaryError(CANCEL, reason='cancelled') or (RUN, reason='worker_timeout')."""

    __slots__ = ('_deadline', '_cancel', '_count')

    def __init__(self, deadline: float | None = None, cancel: threading.Event | None = None):
        self._deadline = deadline
        self._cancel = cancel
        self._count = 0

    @classmethod
    def for_seconds(cls, seconds: float, cancel: threading.Event | None = None) -> Budget:
        return cls(time.monotonic() + seconds, cancel)

    def tick(self, n: int = 1) -> None:
        self._count += n
        if self._count >= TICK_EVERY:
            self._count = 0
            self.check()

    def check(self) -> None:
        if self._cancel is not None and self._cancel.is_set():
            raise err('PT-SECONDARY-CANCEL', 'cancelled')
        if self._deadline is not None and time.monotonic() > self._deadline:
            raise err('PT-SECONDARY-RUN', 'worker_timeout', 'inspection deadline exceeded')
