"""Per-truth-label counts and the flagged lead list of one engine on one pair (LBL-11; plan s7.1).

`LabelCount` partitions the truth records of one label by identity outcome; `flagged` counts correctly paired records the
engine marked changed. Its rate is therefore the false-lead rate for `unchanged`, the cosmetic-flag rate for `cosmetic`
and recall for `changed`; it is undefined (None) for `no-counterpart` and `ambiguous`, which are never correctly paired.
Records an engine abstained on (identity or verdict) are counted apart and never enter a rate.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from . import rank
from .identity import RecordOutcome
from .protocols import EnginePairs

LABELS = ('unchanged', 'changed', 'cosmetic', 'no-counterpart', 'ambiguous')


@dataclass(frozen=True)
class LabelCount:
    paired_correct: int = 0
    paired_wrong: int = 0
    unpaired: int = 0
    abstained: int = 0
    flagged: int = 0

    def add(self, other: LabelCount) -> LabelCount:
        return LabelCount(*(a + b for a, b in zip(self._tuple(), other._tuple(), strict=True)))

    def _tuple(self) -> tuple[int, ...]:
        return (self.paired_correct, self.paired_wrong, self.unpaired, self.abstained, self.flagged)


_FIELD = {'paired-correct': 'paired_correct', 'paired-wrong': 'paired_wrong', 'unpaired': 'unpaired',
          'abstained': 'abstained'}


def count_by_label(outcomes: Iterable[RecordOutcome]) -> dict[str, LabelCount]:
    """All five labels are always present (zero counts included)."""
    raw = {label: dict.fromkeys((*_FIELD.values(), 'flagged'), 0) for label in LABELS}
    for item in outcomes:
        cell = raw[item.record.label]
        cell[_FIELD[item.outcome]] += 1
        cell['flagged'] += bool(item.flagged)
    return {label: LabelCount(**cell) for label, cell in raw.items()}


def merge_counts(parts: Sequence[Mapping[str, LabelCount]]) -> dict[str, LabelCount]:
    total = {label: LabelCount() for label in LABELS}
    for part in parts:
        for label, count in part.items():
            total[label] = total[label].add(count)
    return total


def flag_rate(count: LabelCount) -> float | None:
    """flagged / paired_correct; None when nothing was correctly paired (always so for no-counterpart and ambiguous)."""
    return count.flagged / count.paired_correct if count.paired_correct else None


def flagged_ranks(pairs: EnginePairs) -> dict[tuple[int, int], float]:
    """(old_rva, new_rva) -> midrank in the engine's flagged list (ascending order key; ties share the midrank)."""
    rows = [p for p in pairs.pairs if p.identity == 'paired' and p.flag]
    ranks = rank.midranks([p.order_key for p in rows])
    return {(p.old_rva, p.new_rva): r for p, r in zip(rows, ranks, strict=True)}


def pool_size(pairs: EnginePairs) -> int:
    return sum(1 for p in pairs.pairs if p.identity == 'paired' and p.flag)
