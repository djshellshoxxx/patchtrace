"""PIL numbers (P-01..P-11 of PIL-integration-plan.md s7, the single code source), `PilotError` and a cooperative `Budget`.

Stdlib only. Every number is a positive int (identity payloads reject floats); `PilotLimits` is hashed into
`PilotConfig.limits_digest`, so a changed limit makes stored results stale. `PilotError` lives here so `Budget` can
raise it while `contracts.py` (which re-exports it) reads its caps from `DEFAULT_LIMITS`.
"""
from __future__ import annotations

import dataclasses
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

ERROR_CODES = ('PT-PILOT-INPUT', 'PT-PILOT-STALE', 'PT-PILOT-MISMATCH', 'PT-PILOT-ORIENTATION',
               'PT-PILOT-UNSUPPORTED', 'PT-PILOT-RULES', 'PT-PILOT-LIMIT', 'PT-PILOT-STORAGE',
               'PT-PILOT-INTEGRITY', 'PT-PILOT-NOTFOUND', 'PT-PILOT-CANCEL')
# CLI exit codes (enrichment-cli/1): 2 invalid input, 3 runtime or partial, 4 legitimate no result, 5 cancelled.
EXIT_CODES = {'PT-PILOT-INPUT': 2, 'PT-PILOT-MISMATCH': 2, 'PT-PILOT-ORIENTATION': 2, 'PT-PILOT-UNSUPPORTED': 2,
              'PT-PILOT-STALE': 3, 'PT-PILOT-RULES': 3, 'PT-PILOT-LIMIT': 3, 'PT-PILOT-STORAGE': 3,
              'PT-PILOT-INTEGRITY': 3, 'PT-PILOT-NOTFOUND': 4, 'PT-PILOT-CANCEL': 5}
_REASON = re.compile(r'[a-z0-9-]{1,48}')
KIB, MIB, GIB = 1024, 1024 ** 2, 1024 ** 3

# Performance targets of s7 (informative: measured by later slices, never enforced here and never hashed).
TARGETS = {'localize_5000_pairs_x_8_cves_s': 5, 'evidence_base_100k_functions_s': 30, 'first_paint_ms': 200,
           'filter_100k_rows_ms': 100, 'detail_ms': 50}


class PilotError(Exception):
    """Typed failure. `message` is a fixed template (labels and numbers only, never untrusted text);
    `reason` is an optional machine slug."""

    def __init__(self, code: str, message: str, *, reason: str | None = None):
        if code not in ERROR_CODES:
            raise ValueError(f'unknown pilot error code {code!r}')
        if reason is not None and not _REASON.fullmatch(reason):
            raise ValueError('pilot error reason must be a slug [a-z0-9-]{1,48}')
        self.code = code
        self.message = str(message)[:400]
        self.reason = reason
        super().__init__(f'{code}: {self.message}' + (f' [{reason}]' if reason else ''))

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]


class BudgetExhausted(PilotError):
    """Raised by `Budget` on cancel (`PT-PILOT-CANCEL`) or deadline (`PT-PILOT-LIMIT`, reason `deadline`)."""


@dataclass(frozen=True)
class PilotLimits:
    """Every P-xx default of s7; field names are `p<NN>_<slug>`."""
    p01_candidates: int = 250_000
    p02_observations_per_lead: int = 256
    p03_cves: int = 64
    p04_leads_per_context: int = 500
    p04_queue_rows_per_context: int = 200
    p05_text_chars: int = 300
    p05_explanation_lines: int = 64
    p06_sidecar_bytes: int = 64 * MIB
    p06_pointer_bytes: int = 128 * KIB
    p07_rules: int = 64
    p07_changes_per_rule: int = 16
    p07_leaves_per_change: int = 16
    p08_deadline_s: int = 120
    p08_memory_bytes: int = 1 * GIB
    p09_displayed_rows: int = 100_000
    p10_markdown_bytes: int = 2 * MIB
    p10_markdown_leads_per_cve: int = 200
    p10_json_bytes: int = 32 * MIB
    p11_review_text_bytes: int = 2 * KIB

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{field.name} must be a positive int')
        ordered = (('p06_pointer_bytes', 'p06_sidecar_bytes'), ('p10_markdown_leads_per_cve', 'p04_leads_per_context'),
                   ('p04_queue_rows_per_context', 'p09_displayed_rows'))
        for low, high in ordered:
            if getattr(self, low) > getattr(self, high):
                raise ValueError(f'{low} must not exceed {high}')

    def as_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)


DEFAULT_LIMITS = PilotLimits()


class Budget:
    """Cooperative cancel + deadline. `tick(n)` counts work units and checks every `check_every` units; `deadline` is
    an absolute `clock()` value of THIS process (`Budget.after(seconds)` builds one from a timeout). Deadline
    comparisons use `>=` only, never equality of clock readings (Windows `time.monotonic()` is coarse)."""
    __slots__ = ('deadline', 'cancel', 'clock', 'check_every', 'used', '_next')

    def __init__(self, deadline: float | None = None, cancel=None, *, check_every: int = 4096,
                 clock: Callable[[], float] = time.monotonic):
        if type(check_every) is not int or check_every < 1:
            raise ValueError('check_every must be a positive int')
        self.deadline = deadline
        self.cancel = cancel
        self.clock = clock
        self.check_every = check_every
        self.used = 0
        self._next = check_every

    @classmethod
    def after(cls, seconds: float | None, cancel=None, *, check_every: int = 4096,
              clock: Callable[[], float] = time.monotonic) -> Budget:
        return cls(None if seconds is None else clock() + seconds, cancel, check_every=check_every, clock=clock)

    def expired(self) -> bool:
        if self.cancel is not None and self.cancel.is_set():
            return True
        return self.deadline is not None and self.clock() >= self.deadline

    def check(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise BudgetExhausted('PT-PILOT-CANCEL', 'Patch-intent localization was cancelled', reason='cancelled')
        if self.deadline is not None and self.clock() >= self.deadline:
            raise BudgetExhausted('PT-PILOT-LIMIT', 'Patch-intent localization reached its deadline',
                                  reason='deadline')

    def tick(self, n: int = 1) -> None:
        self.used += n
        if self.used >= self._next:
            self._next = self.used + self.check_every
            self.check()
