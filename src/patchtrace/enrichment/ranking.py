"""Exact integer `attention/1` ranking (SPEC-07 §6). Pure; no floats anywhere.

Grouping by underlying edit stops one predicate that trips several detectors from
being counted as several independent findings: only the two strongest signals of a
group count, the second at a quarter, and a group is capped at 40. Two independent
40-point groups reach raw 80 → score 100; a single saturated group scores 50.
Integer floor division with +50/+40 offsets is round-half-up for nonnegative values.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

from . import identity
from .contracts import (
    ChangeSignal,
    GroupSubtotal,
    RankingConfig,
    RankingEntry,
    RankingResult,
    SignalSet,
    Status,
)

MULTIPLIER = {'strong': 100, 'moderate': 70, 'weak': 35, 'unavailable': 0}


def config_digest(config: RankingConfig) -> str:
    return identity.domain_id('ranking-config', 1, {
        'formula': config.formula, 'weights': dict(sorted(config.weights.items())),
        'enabled': sorted(config.enabled)})


def adjusted_weight(weight: int, confidence: str) -> int:
    return (weight * MULTIPLIER[confidence] + 50) // 100


def score_signals(signals: Iterable[ChangeSignal], config: RankingConfig) -> tuple[int, int, tuple[GroupSubtotal, ...]]:
    """Return (score, raw, groups) for one pairing's signals."""
    unique = {s.signal_id: s for s in signals if s.detector in config.enabled}
    grouped: dict[str, list[tuple[int, str, ChangeSignal]]] = {}
    for signal in unique.values():
        q = adjusted_weight(config.weights[signal.detector], signal.confidence)
        grouped.setdefault(signal.group_key, []).append((q, signal.signal_id, signal))
    subtotals = []
    for key in sorted(grouped):
        members = sorted(grouped[key], key=lambda item: (-item[0], item[1]))
        a = members[0][0]
        b = members[1][0] if len(members) > 1 else 0
        points = min(40, a + min(12, b // 4))
        subtotals.append(GroupSubtotal(group_key=key, a=a, b=b, points=points,
                                       signal_ids=tuple(m[1] for m in members),
                                       strong=any(m[2].confidence == 'strong' for m in members)))
    raw = min(80, sum(g.points for g in subtotals))
    return (raw * 100 + 40) // 80, raw, tuple(subtotals)


def _evidence_status(signal_set: SignalSet) -> Status:
    statuses = {o.status for o in signal_set.outcomes}
    if not statuses or statuses == {'unavailable'}:
        return 'unavailable'
    return 'partial' if statuses - {'complete'} else 'complete'


def rank(signal_sets: Iterable[SignalSet], config: RankingConfig,
         certainty: Mapping[str, str] | None = None) -> RankingResult:
    sets = sorted(signal_sets, key=lambda s: s.pairing_id)
    if len({s.pairing_id for s in sets}) != len(sets):
        raise ValueError('duplicate pairing in ranking input')
    input_digest = identity.domain_id('ranking-input', 1, [
        {'pairing_id': s.pairing_id, 'signals': sorted(x.signal_id for x in s.signals),
         'outcomes': sorted(f'{o.detector}:{o.status}' for o in s.outcomes)} for s in sets])
    scored = []
    for s in sets:
        score, raw, groups = score_signals(s.signals, config)
        scored.append((score, sum(g.strong for g in groups), s, raw, groups))
    scored.sort(key=lambda item: (-item[0], -item[1], item[2].pairing_id))
    entries = tuple(
        RankingEntry(pairing_id=s.pairing_id, match_id=s.match_id, rank=index, score=score, raw=raw,
                     groups=groups, strong_groups=strong, evidence=_evidence_status(s),
                     match_certainty=(certainty or {}).get(s.match_id, 'unknown'))
        for index, (score, strong, s, raw, groups) in enumerate(scored, 1))
    statuses = {e.evidence for e in entries}
    status: Status = 'complete' if statuses <= {'complete'} else (
        'unavailable' if statuses == {'unavailable'} else 'partial')
    return RankingResult(config_digest=config_digest(config), input_digest=input_digest,
                         entries=entries, status=status)
