"""Fixed-vocabulary observations of untrusted Ghidriff output; no live raw-log forwarding.

Markers describe the last observed substage, never completion or matching coverage. Receipt
builders are pure; the backend owns their best-effort persistence in its private run directory.
"""
from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID

from .diagnostics import redact_log

if TYPE_CHECKING:
    from .jobs import ProcessProgress, ProcessResult

TAIL_LIMIT = 16 * 1024
RECEIPT_LIMIT = 8192
RECEIPT_NAME = 'backend-execution.json'
RECEIPT_WARNING = 'Backend execution receipt could not be saved; analysis status is unchanged.'
STARTING = 'starting Ghidra'
_MARKERS = (
    ('starting ghidra', STARTING),
    ('importing ', 'importing binaries'),
    ('starting analysis for ', 'analyzing binaries'),
    ('analyzing:', 'analyzing binaries'),
    ('starting ghidra analysis of ', 'analyzing binaries'),
    ('finding symbol matches', 'matching functions'),
    ('finding function matches', 'matching functions'),
    ('running correlator:', 'matching functions'),
    ('starting bsim correlator', 'matching functions'),
    ('generating matches json', 'preparing match data'),
    ('deduping symbols and functions', 'preparing match data'),
    ('sorting symbols and strings', 'preparing match data'),
    ('sorting functions', 'checking candidate function pairs'),
    ('starting esym lookups', 'enhancing function/symbol details'),
)
_STAGES = frozenset(stage for _, stage in _MARKERS)
_VERSION = re.compile(r'(?:[vV]?[0-9][A-Za-z0-9_.+-]*|[A-Fa-f0-9]{7,64})')
_RUNTIMES = ('patchtrace', 'ghidriff', 'python', 'pyghidra', 'ghidra', 'jvm')
_STOP_REASONS = frozenset({'cancelled', 'timeout', 'output-limit', 'output-check-failed'})


def stage_from_tail(text: str, previous: str = STARTING) -> str:
    """Pick the latest recognized marker in a bounded snapshot, preserving a known stage otherwise."""
    stage = previous if previous in _STAGES else STARTING
    tail = text[-TAIL_LIMIT:].lower()
    latest = (-1, 0)
    for marker, name in _MARKERS:
        index = tail.rfind(marker)
        # A specific marker such as "Starting Ghidra analysis of" must beat its
        # generic prefix at the same offset, regardless of the table's ordering.
        position = (index, len(marker))
        if index >= 0 and position > latest:
            latest, stage = position, name
    return stage


def safe_version(value: object) -> str:
    """Unprobed, malformed, path-like or oversized metadata must not become provenance."""
    if (isinstance(value, str) and 1 <= len(value) <= 64 and _VERSION.fullmatch(value)
            and redact_log(value) == value):
        return value
    return 'unverified'


def _seconds(value: object) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return max(0.0, float(value))
    return 0.0


@dataclass
class BackendProgress:
    """Small per-process state, updated on the supervisor thread, containing no retained raw text."""
    timeout_seconds: int
    stage: str = field(default=STARTING, init=False)
    elapsed_seconds: float = field(default=0.0, init=False)
    last_output_elapsed_seconds: float | None = field(default=None, init=False)
    observed: bool = field(default=False, init=False)
    _stdout_total: int = field(default=0, init=False, repr=False)
    _stderr_total: int = field(default=0, init=False, repr=False)

    @property
    def output_age_seconds(self) -> float | None:
        if self.last_output_elapsed_seconds is None:
            return None
        return max(0.0, self.elapsed_seconds - self.last_output_elapsed_seconds)

    def _timing(self, elapsed: float, last_output: float | None) -> None:
        self.elapsed_seconds = _seconds(elapsed)
        self.last_output_elapsed_seconds = None if last_output is None else _seconds(last_output)

    def observe(self, snapshot: ProcessProgress) -> bool:
        """Return whether the fixed stage changed. Unchanged streams cannot reapply stale markers.

        Primary Ghidriff merges stderr into stdout, preserving marker order. For a separate-stream
        snapshot only newly changed streams are inspected; no cross-stream ordering is asserted.
        """
        previous = self.stage
        for text, total, old in ((snapshot.log_tail, snapshot.stdout_total, self._stdout_total),
                                 (snapshot.stderr_tail, snapshot.stderr_total, self._stderr_total)):
            if total > old:
                self.stage = stage_from_tail(text, self.stage)
        self._stdout_total, self._stderr_total = snapshot.stdout_total, snapshot.stderr_total
        self._timing(snapshot.elapsed_seconds, snapshot.last_output_elapsed_seconds)
        self.observed = True
        return previous != self.stage

    def finish(self, result: ProcessResult) -> None:
        # The supervisor normally supplies a drained final snapshot. This also supports older
        # injected runners without fabricating a heartbeat or assuming they supplied timing.
        if not self.observed:
            self.stage = stage_from_tail(result.log_tail, self.stage)
            self.stage = stage_from_tail(result.stderr_tail, self.stage)
        self._timing(result.elapsed_seconds, result.last_output_elapsed_seconds)

    def summary(self) -> str:
        age = self.output_age_seconds
        activity = 'no output yet' if age is None else f'last output {int(age)} seconds ago'
        return (f'Ghidriff: {self.stage} · {int(self.elapsed_seconds)} / {self.timeout_seconds} seconds · '
                f'{activity}')

    def timeout_error(self, run_id: str) -> str:
        relative = f'runs/quarantine-{UUID(run_id)}'
        return (f'PT-BACKEND: analysis timed out; configured limit {self.timeout_seconds} seconds; '
                f'elapsed {self.elapsed_seconds:.1f} seconds; last observed stage: {self.stage}. '
                'Open Analysis > Setup > Backend and desktop > Comparison timeout (seconds) > Save setup, '
                'then start a new run. '
                f'Diagnostics: {relative}/ (analysis.log, failure.txt and {RECEIPT_NAME} when available).')

    def receipt(self, run_id: str, started_at: str, versions: Mapping[str, object], *,
                result: ProcessResult | None = None, stopped_at: str | None = None,
                supervision_error: bool = False) -> dict:
        """Process evidence only: exit zero does not claim valid output or successful normalization.

        UTC timestamps bracket the launch attempt/supervisor return; elapsed_seconds is the
        supervisor's execution clock, excluding cleanup waits. Without a returned process result,
        exit status, actual stop time and execution duration stay unverified (null).
        """
        state, reason, returncode, elapsed, output_age = 'launch-pending', None, None, None, None
        if result is not None:
            state = ('not-started' if result.reason == 'cancelled' and result.elapsed_seconds == 0
                     and not self.observed and not result.log_tail and not result.stderr_tail else 'stopped')
            reason = (result.reason if result.reason in _STOP_REASONS
                      else ('exited' if result.reason is None else 'supervisor-stop'))
            returncode = None if state == 'not-started' else result.returncode
            elapsed, output_age = self.elapsed_seconds, self.output_age_seconds
        elif supervision_error:
            state, reason = 'unverified', 'supervision-error'
        return {
            'contract': 'patchtrace-backend-execution/1',
            'run_id': str(UUID(run_id)),
            'process_state': state,
            'started_at': started_at,
            'stopped_at': stopped_at if result is not None else None,
            'timeout_seconds': self.timeout_seconds,
            'elapsed_seconds': elapsed,
            'returncode': returncode,
            'stop_reason': reason,
            'last_observed_stage': self.stage,
            'last_output_age_seconds': output_age,
            'runtime_versions': {name: safe_version(versions.get(name)) for name in _RUNTIMES},
        }
