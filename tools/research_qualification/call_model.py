"""RQ-01b: deterministic call-count model of the suspected Ghidriff post-correlation slow path.

This is a MODEL, not a measurement. It encodes the hypothesis recorded in docs/qa/ghidriff-timeout-20261106.md
(PT-TIMEOUT-2): after correlation the code converts every candidate pair (resolving the Ghidra functions on both
sides), then traverses the matched pairs `traversals` times, each time evaluating a predicate that resolves and
inspects both functions again. If that is right, cross-language (Python to JVM) calls scale with the number of
candidate PAIRS, while immutable per-function metadata only needs one lookup per distinct FUNCTION.

The per-call counts below are assumptions taken from that note, NOT verified against the pinned upstream source
(the source host is not reachable from the authoring session). Change them with the flags and watch the result:
the conclusion that matters is the ratio, and it holds across a wide parameter range. To convert calls to time,
supply a measured microseconds-per-call from the RQ-01 harness; no time is claimed otherwise.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

UNVERIFIED = 'model_per_call_counts_assumed_from_qa_note_not_verified_against_upstream_source'


@dataclass(frozen=True)
class Params:
    pairs: int                     # candidate pairs after correlation (the log's 2,161,955 "entries" is an upstream count)
    old_functions: int             # distinct functions on the older side that appear in any pair
    new_functions: int
    traversals: int = 2            # traversals of the matched pairs after "Sorting functions"
    conversion_resolves_per_pair: int = 2   # candidate conversion resolves one function per side
    predicate_resolves_per_call: int = 2    # the predicate resolves both functions again
    predicate_inspects_per_call: int = 2    # and inspects both bodies/references

    def check(self) -> None:
        if min(self.pairs, self.old_functions, self.new_functions) < 1 or self.traversals < 0:
            raise ValueError('pairs and function counts must be >= 1, traversals >= 0')
        if self.pairs > self.old_functions * self.new_functions:
            raise ValueError('pairs cannot exceed old_functions * new_functions (one pair per function combination)')


def analytic(p: Params, us_per_call: float | None = None) -> dict[str, Any]:
    """Closed-form counts. `cached` memoizes immutable per-function metadata (one lookup per distinct function)
    and the predicate decision per pair (evaluated once, reused by every later traversal)."""
    p.check()
    resolves = p.pairs * (p.conversion_resolves_per_pair + p.traversals * p.predicate_resolves_per_call)
    inspects = p.pairs * p.traversals * p.predicate_inspects_per_call
    baseline = resolves + inspects
    distinct = p.old_functions + p.new_functions
    cached = distinct * (1 if p.traversals == 0 else 2)  # one resolve and one inspect per distinct function
    out: dict[str, Any] = {
        'params': p.__dict__ | {}, 'baseline_cross_language_calls': baseline, 'cached_cross_language_calls': cached,
        'amplification': round(baseline / cached, 2), 'baseline_predicate_evaluations': p.pairs * p.traversals,
        'cached_predicate_evaluations': p.pairs if p.traversals else 0, 'unverified': [UNVERIFIED],
    }
    if us_per_call is not None:
        out['estimated_baseline_seconds'] = round(baseline * us_per_call / 1e6, 1)
        out['estimated_cached_seconds'] = round(cached * us_per_call / 1e6, 1)
        out['time_basis'] = f'{us_per_call:g} us per call supplied by the operator, not measured here'
    return out


class _Facade:
    """Stands in for the JVM: every call is counted; metadata is immutable and a pure function of (side, id)."""

    def __init__(self) -> None:
        self.resolves = 0
        self.inspects = 0

    def resolve(self, side: str, fid: int) -> tuple[str, int]:
        self.resolves += 1
        return side, fid

    def inspect(self, side: str, fid: int) -> bool:
        self.inspects += 1
        return (fid * 2654435761 + (1 if side == 'new' else 0)) % 7 == 0   # "default-named" flag, deterministic


def _pairs(p: Params, seed: int) -> list[tuple[int, int]]:
    rng = random.Random(seed)
    seen: set[tuple[int, int]] = set()
    while len(seen) < p.pairs:
        seen.add((rng.randrange(p.old_functions), rng.randrange(p.new_functions)))
    return sorted(seen)


def simulate(p: Params, seed: int = 1) -> dict[str, Any]:
    """Run both strategies over a synthetic pair set; counts must equal `analytic` and decisions must be identical.

    Only for small sizes (it really loops). Distinct-function counts come from the pairs actually drawn."""
    p.check()
    pairs = _pairs(p, seed)

    def need(f: _Facade, o: int, n: int) -> bool:
        f.resolve('old', o), f.resolve('new', n)
        old_flag, new_flag = f.inspect('old', o), f.inspect('new', n)   # both inspected: no short-circuit
        return old_flag or new_flag

    base = _Facade()
    for o, n in pairs:
        base.resolve('old', o), base.resolve('new', n)
    base_decisions = [[need(base, o, n) for o, n in pairs] for _ in range(p.traversals)]

    fast = _Facade()
    meta: dict[tuple[str, int], bool] = {}

    def flag(side: str, fid: int) -> bool:
        if (side, fid) not in meta:
            fast.resolve(side, fid)
            meta[(side, fid)] = fast.inspect(side, fid)
        return meta[(side, fid)]

    decided = [flag('old', o) or flag('new', n) for o, n in pairs]   # once per pair
    fast_decisions = [decided for _ in range(p.traversals)]
    distinct_old, distinct_new = len({o for o, _ in pairs}), len({n for _, n in pairs})
    return {
        'pairs': len(pairs), 'distinct_old': distinct_old, 'distinct_new': distinct_new,
        'baseline_calls': base.resolves + base.inspects, 'cached_calls': fast.resolves + fast.inspects,
        'decisions_identical': base_decisions == fast_decisions,
        'expected_baseline': analytic(Params(len(pairs), distinct_old, distinct_new, p.traversals,
                                             p.conversion_resolves_per_pair, p.predicate_resolves_per_call,
                                             p.predicate_inspects_per_call))['baseline_cross_language_calls'],
        'expected_cached': (distinct_old + distinct_new) * (1 if p.traversals == 0 else 2),
    }


def sensitivity(p: Params) -> list[dict[str, Any]]:
    """Amplification across plausible per-call assumptions, to show the ratio does not hinge on one guess."""
    rows = []
    for conv in (1, 2):
        for res in (1, 2):
            for ins in (1, 2):
                q = Params(p.pairs, p.old_functions, p.new_functions, p.traversals, conv, res, ins)
                rows.append({'conversion': conv, 'predicate_resolves': res, 'predicate_inspects': ins,
                             'amplification': analytic(q)['amplification']})
    return rows
