"""Tie-aware ordinal metrics (preregistration section 3). A tie block counts at its last position."""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from .contracts import K_VALUES, ArmOrdering, CaseMetrics


def truth_set(labels: Iterable[Mapping], card_changed: Sequence[str]) -> frozenset[str]:
    """Patch-bearing keys: `label == changed` and `check == ok`, intersected with the card's changed functions."""
    labelled = {row['key'] for row in labels if row.get('label') == 'changed' and row.get('check') == 'ok'}
    return frozenset(labelled & set(card_changed))


def case_metrics(ordering: ArmOrdering, truth: frozenset[str]) -> CaseMetrics:
    end_of: dict[str, int] = {}
    position = 0
    for block in ordering.blocks:
        position += len(block)
        end_of.update(dict.fromkeys(block, position))
    hits = sorted(end_of[key] for key in truth if key in end_of)
    hit = {k: bool(hits) and hits[0] <= k for k in K_VALUES}
    recall = {k: (sum(1 for end in hits if end <= k) / len(truth) if truth else 0.0) for k in K_VALUES}
    first_block = next((block for block in ordering.blocks if truth.intersection(block)), None)
    if first_block is None:
        false_leads = position
    else:
        before = sum(len(b) for b in ordering.blocks[:ordering.blocks.index(first_block)])
        false_leads = before + len(set(first_block) - truth)
    return CaseMetrics(hit=hit, recall=recall, false_leads=false_leads, worst_rank=hits[0] if hits else None,
                       listed=position, abstained=position == 0)
