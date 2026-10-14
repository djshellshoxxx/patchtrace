"""KbcLimits (KB-integration-plan 7.4; provisional until live probe L1). Stdlib only.

Plain integers: seconds in ``_s``, bytes in ``_bytes``. Reused unchanged from sibling packages (not duplicated here):
Winbindex 64/256 MiB, 256 probes, 4 HEAD, download 512 MiB; CSAF 16 MiB; SUG/NVD 4 MiB.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass

KIB, MIB, GIB = 1024, 1024 ** 2, 1024 ** 3


@dataclass(frozen=True)
class KbcLimits:
    cvrf_doc_bytes: int = 32 * MIB
    cvrf_depth: int = 64
    cvrf_json_nodes: int = 5_000_000
    cvrf_edges_per_doc: int = 500_000
    docs_per_plan: int = 24
    index_months: int = 60
    fetch_concurrency: int = 1
    request_timeout_s: int = 60
    plan_timeout_s: int = 15 * 60
    attempts: int = 3
    retry_after_max_s: int = 60
    text_field_bytes: int = 64 * KIB
    hints: int = 5_000
    pairs_per_file: int = 1_000
    files_per_investigation: int = 20
    investigations: int = 500
    project_sources_bytes: int = 256 * MIB
    workspace_objects_bytes: int = 4 * GIB

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{field.name} must be a positive int')
        if self.docs_per_plan > self.index_months:
            raise ValueError('docs_per_plan cannot exceed index_months')
        if self.request_timeout_s > self.plan_timeout_s:
            raise ValueError('request_timeout_s cannot exceed plan_timeout_s')


DEFAULT_LIMITS = KbcLimits()
MAX_SEARCH_MONTHS = 24  # one plan; the 60-month index ceiling is reached by repeated plans (7.1 row 4)
