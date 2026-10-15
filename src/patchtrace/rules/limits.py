"""RuleLimits: the numbers of YRX-integration-plan section 7 ("Storage, keys, limits") in one frozen dataclass.

Stdlib only. Plain integers: seconds in ``_s``, bytes in ``_bytes``. ``limits_digest`` enters the matrix cache key and the
proposal key, so a changed limit makes stored results stale instead of silently comparable. Fields marked "beyond the
card" are bounds the plan implies but does not number (a process boundary needs a cap on what it reads); every other
default is the card's number. Window gate thresholds (literal bytes, wildcard ratio, uniqueness growth) are provisional
policy of the candidate slice (R3/R4), not limits, and are not hashed here.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass

KIB, MIB, GIB = 1024, 1024 ** 2, 1024 ** 3


@dataclass(frozen=True)
class RuleLimits:
    # --- rule text -------------------------------------------------------------------------------------------------
    rule_text_bytes: int = 64 * KIB
    patterns_per_rule: int = 12
    hex_patterns_per_rule: int = 4          # ceiling; grammar yrx-gen/1 uses one
    text_patterns_per_rule: int = 8         # ceiling; grammar yrx-gen/1 uses at most four
    hex_pattern_bytes: int = 512
    text_pattern_bytes: int = 256
    meta_string_chars: int = 512
    label_chars: int = 120
    function_bytes: int = 64 * KIB
    window_min_bytes: int = 16
    pins_per_feature: int = 4
    # --- candidates ------------------------------------------------------------------------------------------------
    candidates_per_direction: int = 3
    candidates_per_run: int = 200
    features_per_candidate: int = 64        # beyond the card; provisional
    versions_per_lineage: int = 50
    # --- test runs -------------------------------------------------------------------------------------------------
    series_targets: int = 8
    extra_targets: int = 64
    clean_targets: int = 2_000
    file_bytes: int = 128 * MIB
    run_bytes: int = 8 * GIB
    rules_per_run: int = 50
    cells: int = 105_000
    target_timeout_s: int = 30
    target_timeout_min_s: int = 5
    target_timeout_max_s: int = 300
    run_wall_s: int = 3_600
    max_matches_per_pattern: int = 64
    offsets_per_cell: int = 8
    # --- worker process --------------------------------------------------------------------------------------------
    worker_memory_bytes: int = 1 * GIB
    worker_memory_max_bytes: int = 2 * GIB
    stderr_tail_bytes: int = 8 * KIB
    request_bytes: int = 8 * MIB            # beyond the card: 50 rules of 64 KiB plus 2,072 target rows fit
    result_bytes: int = 32 * MIB            # beyond the card: 105,000 cells of about 150 bytes fit
    diagnostics_per_rule: int = 16          # beyond the card: compiler errors and warnings kept per rule

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{field.name} must be a positive int')
        ordered = (('target_timeout_min_s', 'target_timeout_s'), ('target_timeout_s', 'target_timeout_max_s'),
                   ('worker_memory_bytes', 'worker_memory_max_bytes'), ('file_bytes', 'run_bytes'),
                   ('hex_pattern_bytes', 'function_bytes'), ('window_min_bytes', 'hex_pattern_bytes'),
                   ('target_timeout_s', 'run_wall_s'))
        for low, high in ordered:
            if getattr(self, low) > getattr(self, high):
                raise ValueError(f'{low} must not exceed {high}')
        if self.patterns_per_rule > self.hex_patterns_per_rule + self.text_patterns_per_rule:
            raise ValueError('patterns_per_rule cannot exceed the sum of the hex and text ceilings')
        if 2 * self.candidates_per_direction > self.candidates_per_run:
            raise ValueError('candidates_per_run must hold both directions')
        if self.targets_per_run * self.rules_per_run > self.cells:
            raise ValueError('cells must hold every target against every rule of a run')

    @property
    def targets_per_run(self) -> int:
        return self.series_targets + self.extra_targets + self.clean_targets

    def as_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)


DEFAULT_LIMITS = RuleLimits()


def limits_digest(limits: RuleLimits = DEFAULT_LIMITS) -> str:
    """Domain-separated SHA-256 of the canonical JSON of every limit (hex, 64 characters)."""
    payload = json.dumps(limits.as_dict(), sort_keys=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(b'patchtrace\x00rules-limits\x001\x00' + payload).hexdigest()
