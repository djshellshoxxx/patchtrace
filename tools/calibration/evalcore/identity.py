"""Identity outcome of one truth record against one engine's pairs (LBL-11; plan s7.1).

Outcome per record: `paired-correct`, `paired-wrong`, `unpaired`, `abstained`.
* Same-identity record (old, new): the engine row (old, new) is `paired-correct` and carries the verdict; another
  paired row touching either side is `paired-wrong`; only an abstained row is `abstained`; only unpaired rows are
  `unpaired`; no row at all is `unpaired`, unless the engine lists only modified functions (`implicit_unchanged`), where
  it is `paired-correct` and unflagged.
* A correctly paired record whose verdict is `None` is `abstained`: unknown is never a vote, wrong or right.
* No-counterpart record (one RVA): any paired row touching it is `paired-wrong`; abstained is `abstained`; otherwise
  `unpaired`, which is the right answer.
* Ambiguous truth (identity or label) is never scored: it is `abstained` for every engine and counted aside.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .protocols import EnginePair, EnginePairs, TruthLabelLike

Outcome = Literal['paired-correct', 'paired-wrong', 'unpaired', 'abstained']


@dataclass(frozen=True)
class RecordOutcome:
    record: TruthLabelLike
    outcome: Outcome
    flagged: bool | None = None  # only for paired-correct


def _is_ambiguous(record: TruthLabelLike) -> bool:
    return record.identity == 'ambiguous' or record.label == 'ambiguous'


def _classify_one(record: TruthLabelLike, by_old: dict[int, list[EnginePair]], by_new: dict[int, list[EnginePair]],
                  implicit: bool) -> RecordOutcome:
    if _is_ambiguous(record):
        return RecordOutcome(record, 'abstained')
    touching = (by_old.get(record.old_rva, []) if record.old_rva is not None else []) \
        + (by_new.get(record.new_rva, []) if record.new_rva is not None else [])
    paired = [p for p in touching if p.identity == 'paired']
    if record.identity == 'same':
        right = next((p for p in paired if (p.old_rva, p.new_rva) == (record.old_rva, record.new_rva)), None)
        if right is not None:
            return (RecordOutcome(record, 'abstained') if right.flag is None
                    else RecordOutcome(record, 'paired-correct', right.flag))
        if implicit and not touching:
            return RecordOutcome(record, 'paired-correct', False)
    if paired:
        return RecordOutcome(record, 'paired-wrong')
    if any(p.identity == 'abstained' for p in touching):
        return RecordOutcome(record, 'abstained')
    return RecordOutcome(record, 'unpaired')


def classify(records: Sequence[TruthLabelLike], pairs: EnginePairs) -> list[RecordOutcome]:
    """One `RecordOutcome` per truth record, in input order. Pure and independent of the engine's row order."""
    by_old: dict[int, list[EnginePair]] = {}
    by_new: dict[int, list[EnginePair]] = {}
    for pair in pairs.pairs:
        if pair.old_rva is not None:
            by_old.setdefault(pair.old_rva, []).append(pair)
        if pair.new_rva is not None:
            by_new.setdefault(pair.new_rva, []).append(pair)
    return [_classify_one(r, by_old, by_new, pairs.implicit_unchanged) for r in records]
