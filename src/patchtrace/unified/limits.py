"""SPEC-31 numbers (02 s6, the single code source), the `UnifiedError` base and the cooperative `Budget`.

Stdlib only. `UnifiedError` lives here so `Budget` can raise it while `contracts.py` (which re-exports it)
reads its caps from `DEFAULT_LIMITS`. Fractional limits are integers in milli units because identity
payloads reject floats (limits_digest is part of config_digest, 02 s5).
"""
from __future__ import annotations

import dataclasses
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

ERROR_CODES = ('PT-UNIFIED-INPUT', 'PT-UNIFIED-PAIR', 'PT-UNIFIED-ORIENTATION', 'PT-UNIFIED-UNSUPPORTED',
               'PT-UNIFIED-EXTRACT', 'PT-UNIFIED-IR', 'PT-UNIFIED-LIMIT', 'PT-UNIFIED-TIMEOUT', 'PT-UNIFIED-CANCEL',
               'PT-UNIFIED-STALE', 'PT-UNIFIED-STORE', 'PT-UNIFIED-INTERNAL')
EXIT_CODES = {code: 2 for code in ERROR_CODES[:4]} | {code: 3 for code in ERROR_CODES[4:]} | {'PT-UNIFIED-CANCEL': 5}
_REASON = re.compile(r'^[a-z0-9-]{1,48}$')
KIB, MIB, GIB = 1024, 1024 ** 2, 1024 ** 3


class UnifiedError(Exception):
    """Typed failure (01 s6). `message` is a fixed template (labels and numbers only, never untrusted text);
    `reason` is an optional machine slug."""

    def __init__(self, code: str, message: str, *, reason: str | None = None):
        if code not in ERROR_CODES:
            raise ValueError(f'unknown unified error code {code!r}')
        if reason is not None and not _REASON.match(reason):
            raise ValueError('unified error reason must be a slug [a-z0-9-]{1,48}')
        self.code = code
        self.message = str(message)[:400]
        self.reason = reason
        super().__init__(f'{code}: {self.message}' + (f' [{reason}]' if reason else ''))

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]

    @property
    def recoverable(self) -> bool:
        return self.code != 'PT-UNIFIED-INTERNAL'


class BudgetExhausted(UnifiedError):
    """Raised by `Budget` on cancel (`PT-UNIFIED-CANCEL`) or deadline (`PT-UNIFIED-TIMEOUT`)."""


@dataclass(frozen=True)
class UnifiedLimits:
    """Every L-xx default of 02 s6; field names are `l<NN>_<slug>`."""
    l01_functions_per_side: int = 250_000
    l02_instructions_per_side: int = 20_000_000
    l02_warn_instructions: int = 5_000_000
    l03_heap_percent_of_ram: int = 50
    l03_heap_max_mib: int = 16_384
    l04_analyze_timeout_s: int = 7_200
    l04_gzf_timeout_s: int = 1_800
    l04_timeout_min_s: int = 60
    l04_timeout_max_s: int = 86_400
    l05_output_bytes: int = 2 * GIB
    l05_line_bytes: int = 64 * MIB
    l05_string_bytes: int = 64 * KIB
    l06_fn_raw_bytes: int = 16 * MIB
    l06_fn_instructions: int = 100_000
    l07_ir_file_bytes: int = 1 * GIB
    l08_ingest_budget_s: int = 1_800
    l08_ingest_rss_bytes: int = 1536 * MIB
    l09_min_body_bytes: int = 10
    l10_tiny_instructions: int = 5
    l11_md_min_blocks: int = 5
    l12_multiset_min_instructions: int = 10
    l13_string_min_length: int = 5
    l14_string_rare_functions: int = 4
    l15_const_min_abs: int = 0x1000
    l15_const_rare_functions: int = 2
    l16_set_min_elements: int = 2
    l17_hub_fan_in: int = 64
    l18_neighbour_cap: int = 64
    l19_implied_min_votes: int = 2
    l20_cosine_min_milli: int = 950
    l20_confidence_min_milli: int = 10_000
    l20_margin_milli: int = 50
    l21_size_ratio_min_milli: int = 500
    l21_size_ratio_max_milli: int = 2_000
    l22_candidates_per_function: int = 20
    l23_bucket_cap: int = 300
    l24_assign_bucket_cap: int = 200
    l24_assign_budget_s: int = 30
    l24_score_floor_milli: int = 600
    l24_margin_milli: int = 50
    l25_bb_min_votes: int = 2
    l25_bb_min_instructions: int = 4
    l26_gap_functions: int = 1
    l27_align_instructions: int = 20_000
    l28_deltas_per_pair: int = 64
    l29_pseudo_lines: int = 20_000
    l29_pseudo_chars: int = 2_000_000
    l30_part_bytes: int = 512 * MIB
    l30_dir_bytes: int = 1 * GIB
    l31_pointer_body_bytes: int = 128 * KIB
    l31_stderr_tail_bytes: int = 32 * KIB
    l32_results_kept: int = 3
    l33_displayed_rows: int = 100_000
    l34_worker_timeout_s: int = 3_600
    l34_timeout_min_s: int = 60
    l34_timeout_max_s: int = 86_400
    l35_ladder_10k_s: int = 15
    l35_ladder_60k_s: int = 120
    l35_ingest_60k_s: int = 600
    l35_facts_5000_s: int = 60
    l35_worker_rss_bytes: int = 1536 * MIB
    l35_first_paint_ms: int = 200
    l35_filter_ms: int = 100
    l35_sort_ms: int = 150
    l36_retained_gzf_bytes: int = 4 * GIB
    l37_progress_bytes: int = 4 * KIB
    l37_progress_poll_ms: int = 50
    l39_atoms_per_row: int = 64
    l40_votes_kept: int = 8
    l40_data_pairs: int = 1_000_000
    l41_decompile_pairs: int = 64
    l41_decompile_fn_s: int = 60
    l41_decompile_run_s: int = 600
    l42_worker_mem_max_bytes: int = 4 * GIB
    l42_worker_mem_percent_of_ram: int = 50

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{field.name} must be a positive int')
        ordered = (('l02_warn_instructions', 'l02_instructions_per_side'), ('l04_timeout_min_s', 'l04_gzf_timeout_s'),
                   ('l04_gzf_timeout_s', 'l04_timeout_max_s'), ('l04_timeout_min_s', 'l04_analyze_timeout_s'),
                   ('l04_analyze_timeout_s', 'l04_timeout_max_s'), ('l21_size_ratio_min_milli',
                                                                     'l21_size_ratio_max_milli'),
                   ('l34_timeout_min_s', 'l34_worker_timeout_s'), ('l34_worker_timeout_s', 'l34_timeout_max_s'),
                   ('l31_stderr_tail_bytes', 'l31_pointer_body_bytes'), ('l30_part_bytes', 'l30_dir_bytes'))
        for low, high in ordered:
            if getattr(self, low) > getattr(self, high):
                raise ValueError(f'{low} must not exceed {high}')
        if self.l03_heap_percent_of_ram > 100 or self.l42_worker_mem_percent_of_ram > 100:
            raise ValueError('percent-of-RAM limits must be <= 100')

    @property
    def l38_rows_per_result(self) -> int:
        """L-38 is derived: 2 x L-01."""
        return 2 * self.l01_functions_per_side

    def as_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)

    def ingest_dict(self) -> dict[str, int]:
        """The limits that change IR content (L-01, L-02, L-05, L-06, L-07, L-11; 02 s5 `ingest_limits_digest`)."""
        return {name: getattr(self, name) for name in INGEST_LIMIT_FIELDS}

    def worker_memory_cap(self, total_ram_bytes: int | None) -> int:
        """L-42: min(4 GiB, 50 % of RAM); unknown RAM -> the absolute cap."""
        if not total_ram_bytes or total_ram_bytes <= 0:
            return self.l42_worker_mem_max_bytes
        return min(self.l42_worker_mem_max_bytes, total_ram_bytes * self.l42_worker_mem_percent_of_ram // 100)

    def jvm_heap_mib(self, total_ram_bytes: int | None) -> int:
        """L-03: 50 % of RAM, at most 16 GiB, at least 512 MiB (ExtractRequest.max_heap_mb floor)."""
        if not total_ram_bytes or total_ram_bytes <= 0:
            return 512
        return max(512, min(self.l03_heap_max_mib, total_ram_bytes * self.l03_heap_percent_of_ram // 100 // MIB))

    def checked_timeout(self, seconds: int, *, kind: str = 'extract') -> int:
        """L-04 / L-34 ranges (60..86,400 s); out of range -> PT-UNIFIED-INPUT."""
        low, high = ((self.l04_timeout_min_s, self.l04_timeout_max_s) if kind == 'extract'
                     else (self.l34_timeout_min_s, self.l34_timeout_max_s))
        if type(seconds) is not int or not low <= seconds <= high:
            raise UnifiedError('PT-UNIFIED-INPUT', f'timeout must be an integer between {low} and {high} seconds',
                               reason='timeout-range')
        return seconds


INGEST_LIMIT_FIELDS = ('l01_functions_per_side', 'l02_instructions_per_side', 'l05_output_bytes', 'l05_line_bytes',
                       'l05_string_bytes', 'l06_fn_raw_bytes', 'l06_fn_instructions', 'l07_ir_file_bytes',
                       'l11_md_min_blocks')
DEFAULT_LIMITS = UnifiedLimits()


class Budget:
    """Cooperative cancel + deadline (04 I7). `tick(n)` counts work units and checks every `check_every` units;
    `deadline` is an absolute `clock()` value of THIS process (`Budget.after(seconds)` builds one from a timeout).
    Deadline comparisons use `>=` only, never equality of clock readings."""
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
            raise BudgetExhausted('PT-UNIFIED-CANCEL', 'Unified analysis was cancelled', reason='cancelled')
        if self.deadline is not None and self.clock() >= self.deadline:
            raise BudgetExhausted('PT-UNIFIED-TIMEOUT', 'Unified analysis reached its deadline', reason='deadline')

    def tick(self, n: int = 1) -> None:
        self.used += n
        if self.used >= self._next:
            self._next = self.used + self.check_every
            self.check()
