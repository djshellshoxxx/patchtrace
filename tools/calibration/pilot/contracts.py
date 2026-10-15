"""Evaluation value types. An ordering is a list of tie blocks; nothing here carries a score."""
from __future__ import annotations

from dataclasses import dataclass, field

K_VALUES: tuple[int, ...] = (1, 3, 5, 10)
SYMBOL_CONDITIONS: tuple[str, ...] = ('hidden', 'visible')
BASELINE_ARMS: tuple[str, ...] = ('B0', 'B1', 'B2')


@dataclass(frozen=True)
class ArmOrdering:
    """Candidate keys in display order; members of one block are tied (the worst case applies to all of them)."""
    blocks: tuple[tuple[str, ...], ...] = ()

    def __post_init__(self) -> None:
        keys = [key for block in self.blocks for key in block]
        if len(set(keys)) != len(keys):
            raise ValueError('duplicate candidate in ordering')


@dataclass(frozen=True)
class CaseMetrics:
    hit: dict[int, bool] = field(default_factory=dict)
    recall: dict[int, float] = field(default_factory=dict)
    false_leads: int = 0
    worst_rank: int | None = None
    listed: int = 0
    abstained: bool = False


@dataclass(frozen=True)
class CaseOutcome:
    """The paired per-case quantities the gate resamples by lineage (P-full versus the best baseline)."""
    case_id: str
    lineage: str
    p_false_leads: int
    b_false_leads: int
    p_recall10: float
    b_recall10: float
