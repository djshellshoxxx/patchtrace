"""Every provisional number of WB1 section 7 'Limits'; each is enforced by the slice that owns it."""
from __future__ import annotations

from dataclasses import dataclass

KIB, MIB, GIB = 1024, 1024 ** 2, 1024 ** 3
SEGMENT_CONTRACT = 'search-segment/1'
APPLICATION_ID = 0x50545331  # 'PTS1'
SEGMENT_USER_VERSION = 1


@dataclass(frozen=True)
class SearchLimits:
    query_chars: int = 256
    query_terms: int = 8
    query_excludes: int = 4
    page_max: int = 200
    gui_rows_max: int = 5_000
    candidate_cap: int = 20_000  # a count query stops at candidate_cap + 1
    query_timeout_s: float = 2.0
    scan_rows_max: int = 5_000_000
    field_bytes: int = 64 * KIB
    string_field_bytes: int = 256
    segment_build_s: float = 600.0
    total_build_s: float = 1_800.0
    cancel_check_docs: int = 4_096
    segments_per_project: int = 64
    bytes_per_project: int = 768 * MIB
    cache_bytes: int = 4 * GIB
    suggestions: int = 12
    saved_searches: int = 200
    fuzzy_candidates: int = 100_000
    counterpart_hints: int = 2_000
    stale_segment_age_s: float = 600.0  # younger unexpected segments may belong to a running build


DEFAULT_LIMITS = SearchLimits()
