"""Build-environment pack: `toolchain_changed` flag recall and specificity, packed/protected, pool purity (LBL s7.6)."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..evalcore import boot
from .common import PackReport, interval, lineage_count, observations, ratio

NEGATIVE_KINDS = ('aa', 'opt-only', 'layout')  # toolchain_changed must be false here
KINDS = ('noise', *NEGATIVE_KINDS)


@dataclass(frozen=True)
class EnvPair:
    pair_id: str
    lineage: str
    kind: str
    toolchain_changed: bool | None  # None when the environment is unknown: not a negative vote
    packed: bool | None = None
    protected: bool | None = None
    environment_unknown: bool = False
    pool_size: int = 0  # lead-list pool functions
    pool_truth_changed: int = 0

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f'unknown environment pair kind {self.kind!r}')


def _purity(p: EnvPair) -> float | None:
    return ratio(p.pool_truth_changed, p.pool_size)


def score(pairs: Sequence[EnvPair], b_count: int = boot.B_COUNT) -> PackReport:
    known = [p for p in pairs if p.toolchain_changed is not None]
    noise = [p for p in known if p.kind == 'noise']
    negative = [p for p in known if p.kind in NEGATIVE_KINDS]
    flagged = [p for p in known if p.toolchain_changed]
    unflagged = [p for p in known if not p.toolchain_changed]
    metrics = {
        'noise_recall': interval(observations(noise, lambda p: p.toolchain_changed), 'environment',
                                 'noise_recall', b_count),
        'specificity': interval(observations(negative, lambda p: not p.toolchain_changed), 'environment',
                                'specificity', b_count),
        'unknown_rate': interval(observations(pairs, lambda p: p.environment_unknown), 'environment',
                                 'unknown_rate', b_count),
        'purity_flagged': interval(observations(flagged, _purity), 'environment', 'purity_flagged', b_count),
        'purity_unflagged': interval(observations(unflagged, _purity), 'environment', 'purity_unflagged', b_count),
    }
    counts = {
        'unknown_pairs': len(pairs) - len(known),
        'packed_true': sum(p.packed is True for p in pairs),
        'protected_true': sum(p.protected is True for p in pairs),
        **{f'pairs_{k}': sum(p.kind == k for p in known) for k in KINDS},
    }
    return PackReport('environment', 'ok', pairs=len(pairs), lineages=lineage_count(pairs), metrics=metrics,
                      counts=counts, gate={'packed_protected_false': counts['packed_true'] + counts['protected_true'] == 0})
