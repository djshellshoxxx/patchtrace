"""FAB numbers (F-01..F-15 of FAB-integration-plan.md s7, the single code source), `FabricError` and the exit codes.

Stdlib only. Every number is a positive int (identity payloads reject floats). `FabricError` carries a fixed message
template and an optional machine slug, never the offending value: keys, labels and advisory text are untrusted.
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass

ERROR_CODES = ('PT-FAB-INPUT', 'PT-FAB-KIND', 'PT-FAB-KEY', 'PT-FAB-ORIENTATION', 'PT-FAB-ORIGIN',
               'PT-FAB-UNSUPPORTED', 'PT-FAB-LIMIT', 'PT-FAB-STALE', 'PT-FAB-STORAGE', 'PT-FAB-INTEGRITY',
               'PT-FAB-NOTFOUND', 'PT-FAB-CANCEL')
# CLI exit codes (enrichment-cli/1): 2 invalid input, 3 runtime or partial, 4 legitimate no result, 5 cancelled.
EXIT_CODES = {'PT-FAB-INPUT': 2, 'PT-FAB-KIND': 2, 'PT-FAB-KEY': 2, 'PT-FAB-ORIENTATION': 2, 'PT-FAB-ORIGIN': 2,
              'PT-FAB-UNSUPPORTED': 2, 'PT-FAB-LIMIT': 3, 'PT-FAB-STALE': 3, 'PT-FAB-STORAGE': 3,
              'PT-FAB-INTEGRITY': 3, 'PT-FAB-NOTFOUND': 4, 'PT-FAB-CANCEL': 5}
_REASON = re.compile(r'[a-z0-9-]{1,48}')


class FabricError(Exception):
    """Typed failure. `message` is a fixed template (labels and numbers only, never untrusted text);
    `reason` is an optional machine slug."""

    def __init__(self, code: str, message: str, *, reason: str | None = None):
        if code not in ERROR_CODES:
            raise ValueError(f'unknown fabric error code {code!r}')
        if reason is not None and not _REASON.fullmatch(reason):
            raise ValueError('fabric error reason must be a slug [a-z0-9-]{1,48}')
        self.code = code
        self.message = str(message)[:400]
        self.reason = reason
        super().__init__(f'{code}: {self.message}' + (f' [{reason}]' if reason else ''))

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]


@dataclass(frozen=True)
class FabricLimits:
    """Every F-xx default of the plan; field names are `f<NN>_<slug>`. Counts (F-01, F-02, F-03, F-09, F-12) are
    enforced by the stores and may be tightened; the text and shape caps (F-04..F-08, F-10, F-11, F-13..F-15) are
    fixed by the contract models, which read `DEFAULT_LIMITS`."""
    f01_anchors_per_publish: int = 20_000
    f02_anchors_per_project: int = 200_000
    f03_witnesses_per_anchor: int = 16
    f04_facets_per_witness: int = 16
    f05_label_chars: int = 200
    f06_key_chars: int = 200
    f07_facet_chars: int = 300
    f08_pair_rvas_per_side: int = 256
    f09_page_rows: int = 500
    f10_origins_per_witness: int = 8
    f11_batch_chars: int = 64
    f12_resolve_candidates: int = 20
    f13_ref_id_chars: int = 256
    f14_pointer_chars: int = 4096
    f15_tool_chars: int = 64

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{field.name} must be a positive int')
        for low, high in (('f01_anchors_per_publish', 'f02_anchors_per_project'),
                          ('f09_page_rows', 'f02_anchors_per_project')):
            if getattr(self, low) > getattr(self, high):
                raise ValueError(f'{low} must not exceed {high}')

    def as_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)


DEFAULT_LIMITS = FabricLimits()
