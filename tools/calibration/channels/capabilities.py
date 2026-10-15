"""Capabilities pack: `api-use` expected-rule recall and the never-newly-introduced invariant (LBL s7.6)."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..evalcore import boot
from .common import PackReport, interval, lineage_count, observations, ratio

NEWLY_INTRODUCED = 'newly-introduced'


@dataclass(frozen=True)
class CapFunction:
    name: str
    truth_changed: bool
    state: str | None  # capability state the engine gave this function; None = no state (unknown)


@dataclass(frozen=True)
class CapPair:
    pair_id: str
    lineage: str
    kind: str  # 'change' | 'aa'
    expected: frozenset[str]  # rule ids the `api-use` operator should surface
    detected: frozenset[str] | None  # None = channel did not run
    functions: tuple[CapFunction, ...] = ()
    localised: tuple[tuple[str, str], ...] = ()  # (rule id, function name) entries


def _recall(p: CapPair) -> float | None:
    return ratio(len(p.expected & p.detected), len(p.expected))


def _violations(p: CapPair) -> int:
    return sum(f.state == NEWLY_INTRODUCED and not f.truth_changed for f in p.functions)


def _violation_rate(p: CapPair) -> float | None:
    unchanged = [f for f in p.functions if not f.truth_changed and f.state is not None]
    return ratio(_violations(p), len(unchanged))


def _localised_precision(p: CapPair) -> float | None:
    changed = {f.name for f in p.functions if f.truth_changed}
    return ratio(sum(fn in changed for _, fn in p.localised), len(p.localised))


def score(pairs: Sequence[CapPair], b_count: int = boot.B_COUNT) -> PackReport:
    ran = [p for p in pairs if p.detected is not None]
    change = [p for p in ran if p.kind == 'change']
    aa = [p for p in ran if p.kind == 'aa']
    metrics = {
        'recall': interval(observations(change, _recall), 'capabilities', 'recall', b_count),
        'violation_rate': interval(observations(ran, _violation_rate), 'capabilities', 'violation_rate', b_count),
        'localised_precision': interval(observations(change, _localised_precision), 'capabilities',
                                        'localised_precision', b_count),
    }
    counts = {
        'unknown_pairs': len(pairs) - len(ran),
        'violations': sum(_violations(p) for p in ran),
        'aa_pairs': len(aa),
        'aa_deltas': sum(len(p.detected) for p in aa),
    }
    return PackReport('capabilities', 'ok', pairs=len(ran), lineages=lineage_count(ran), metrics=metrics,
                      counts=counts, gate={'no_violations': counts['violations'] == 0 if ran else None})
