"""Rules pack: fix-diff rule lineage matrix (LBL s7.6). BLOCKED while YARA-X is unavailable; listed, never skipped."""
from __future__ import annotations

import importlib.util
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from ..evalcore import boot
from .common import PackReport, interval, lineage_count, observations

BLOCKED_REASON = 'YARA-X (yara_x) is not available; the rule matrix cannot be evaluated'
ROLES = ('unpatched', 'patched', 'unrelated')


def yrx_available() -> bool:
    return importlib.util.find_spec('yara_x') is not None


@dataclass(frozen=True)
class RuleMatch:
    rule: str
    lineage: str  # lineage of the image
    image: str
    variant: str  # toolchain variant of the image
    role: str  # unpatched: must match; patched and unrelated: must not
    matched: bool | None  # None = not evaluated: unknown, never a miss

    def __post_init__(self):
        if self.role not in ROLES:
            raise ValueError(f'unknown rule image role {self.role!r}')

    @property
    def pair_id(self) -> str:
        return f'{self.rule}|{self.image}'


def score(rows: Sequence[RuleMatch], b_count: int = boot.B_COUNT, available: bool | None = None) -> PackReport:
    if not (yrx_available() if available is None else available):
        return PackReport('rules', 'blocked', BLOCKED_REASON)
    known = [r for r in rows if r.matched is not None]
    must_match = [r for r in known if r.role == 'unpatched']
    must_not = [r for r in known if r.role != 'unpatched']
    metrics = {
        'tp_rate': interval(observations(must_match, lambda r: r.matched), 'rules', 'tp_rate', b_count),
        'fp_rate': interval(observations(must_not, lambda r: r.matched), 'rules', 'fp_rate', b_count),
    }
    tp = Counter(r.variant for r in must_match if r.matched)
    fn = Counter(r.variant for r in must_match if not r.matched)
    variants = sorted(set(tp) | set(fn))
    counts = {
        'unknown_rows': len(rows) - len(known),
        'fp': sum(bool(r.matched) for r in must_not),
        **{f'tp:{v}': tp[v] for v in variants},
        **{f'fn:{v}': fn[v] for v in variants},
    }
    return PackReport('rules', 'ok', pairs=len(known), lineages=lineage_count(known), metrics=metrics, counts=counts,
                      gate={'no_false_positives': counts['fp'] == 0 if must_not else None})
