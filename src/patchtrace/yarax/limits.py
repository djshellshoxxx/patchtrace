"""Rule-authoring limits (plan s7). One frozen dataclass; its digest enters the cache keys."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from ..enrichment.identity import domain_id

MIB = 1024 * 1024


@dataclass(frozen=True)
class RuleLimits:
    rule_text_bytes: int = 64 * 1024
    patterns_per_rule: int = 12
    hex_patterns_ceiling: int = 4
    text_patterns_ceiling: int = 8
    hex_patterns_v1: int = 1
    text_patterns_v1: int = 4
    hex_pattern_bytes: int = 512
    hex_pattern_min_bytes: int = 16
    text_pattern_bytes: int = 256
    meta_string_chars: int = 512
    function_bytes: int = 64 * 1024
    context_growth_bytes: int = 128
    windows_per_direction: int = 3
    candidates_per_direction: int = 3
    candidates_per_run: int = 200
    versions_per_lineage: int = 50
    call_pins: int = 4
    series_targets: int = 8
    extra_targets: int = 64
    clean_targets: int = 2000
    target_file_bytes: int = 128 * MIB
    run_bytes: int = 8 * 1024 * MIB
    rules_per_run: int = 50
    cells: int = 105_000
    target_timeout_s: int = 30
    target_timeout_min_s: int = 5
    target_timeout_max_s: int = 300
    run_wall_s: int = 3600
    max_matches_per_pattern: int = 64
    cell_offsets: int = 8
    worker_memory_bytes: int = 1024 * MIB
    worker_memory_hard_max_bytes: int = 2048 * MIB
    stderr_tail_bytes: int = 8 * 1024
    matrix_inline_bytes: int = 1 * MIB
    label_chars: int = 120

    def digest(self) -> str:
        return domain_id('rule-limits', 1, dataclasses.asdict(self))


LIMITS = RuleLimits()
