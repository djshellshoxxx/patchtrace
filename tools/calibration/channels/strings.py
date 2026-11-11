"""Strings pack: image-level string delta against `string-literal` truth (LBL s7.6)."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..evalcore import boot
from .common import PackReport, interval, lineage_count, observations, ratio

Delta = tuple[str, str]  # ('+' | '-', text); text is untrusted data, only ever compared


@dataclass(frozen=True)
class StringsPair:
    pair_id: str
    lineage: str
    kind: str  # 'change' | 'aa'
    truth: frozenset[Delta]
    flagged: frozenset[Delta] | None  # None = channel did not run: unknown, never an empty answer
    representation_changed: frozenset[Delta] = frozenset()  # same string, new encoding: flagging it is a misflag
    allowed_noise: frozenset[Delta] = frozenset()  # __DATE__-style adds exempt from the A/A rule


def _precision(p: StringsPair) -> float | None:
    return ratio(len(p.truth & p.flagged), len(p.flagged))


def _recall(p: StringsPair) -> float | None:
    return ratio(len(p.truth & p.flagged), len(p.truth))


def score(pairs: Sequence[StringsPair], b_count: int = boot.B_COUNT) -> PackReport:
    ran = [p for p in pairs if p.flagged is not None]
    change = [p for p in ran if p.kind == 'change']
    aa = [p for p in ran if p.kind == 'aa']
    false_adds = {p.pair_id: len({d for d in p.flagged if d[0] == '+'} - p.allowed_noise) for p in aa}
    metrics = {
        'precision': interval(observations(change, _precision), 'strings', 'precision', b_count),
        'recall': interval(observations(change, _recall), 'strings', 'recall', b_count),
    }
    counts = {
        'unknown_pairs': len(pairs) - len(ran),
        'aa_pairs': len(aa),
        'aa_false_adds': sum(false_adds.values()),
        'aa_pairs_with_false_adds': sum(1 for v in false_adds.values() if v),
        'representation_misflags': sum(len(p.flagged & p.representation_changed) for p in change),
    }
    return PackReport('strings', 'ok', pairs=len(ran), lineages=lineage_count(ran), metrics=metrics, counts=counts,
                      gate={'aa_false_adds_zero': counts['aa_false_adds'] == 0 if aa else None})
