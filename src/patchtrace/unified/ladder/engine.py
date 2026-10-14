"""The ladder driver (SPEC-31 04 s1, s3): anchors, stage groups, drill-down `find`, propagation, soft candidates.

Portions derived from google/bindiff v8 (Apache-2.0), Copyright 2011-2023 Google LLC (the drill-down semantics of
`Diff`/`find` in differ.cc and match/call_graph.cc: strongest key first, a pair only when its key is unique on both
sides, ambiguity drills into the next keys INSIDE the bucket, otherwise abstains); algorithms re-expressed in Python
and modified for PatchTrace (2026-10-14); licence text under third_party/notices/bindiff-v8-*/ (slice S1).

Contract (04 s1): I1 a function is in at most one pair or one group; I2 a pair needs a key unique among the
still-unmatched functions of its pool; I3 an accepted pair is never re-opened; I4 the output is a pure function of
(IR content, anchors, pass table, limits); I5 tier-M anchors win over every pass; I6 thunks, imports and tiny
functions are never matched by content keys; I7 work is bounded by the `Budget`: on exhaustion the result is
`partial` with the passes completed so far (a pass or a propagation wave is applied completely or not at all).

Deviations from the pseudocode of 04 s3 (documented in docs/modules.md, [S2:ladder]): tier-C results are kept as
soft candidates and only become pairs at the very end, so weak evidence never blocks a later stronger pass; wave
decisions are made after the whole wave was collected (mirror symmetry, no queue-order dependence).
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence

from ..limits import DEFAULT_LIMITS, Budget, BudgetExhausted, UnifiedError, UnifiedLimits
from .groups import build_groups
from .passes import FAMILY_STRUCT, P00, PASSES, PassSpec, classify_pair
from .ports import IrSide
from .propagate import propagate_to_fixpoint
from .side import SideData
from .state import SoftCand, State
from .types import Correspondence, CorrPair, weaker


def run_ladder(older: IrSide, newer: IrSide, *, anchors: Iterable[CorrPair] = (),
               limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None,
               passes: Sequence[PassSpec] = PASSES,
               exports: tuple[Mapping[int, str], Mapping[int, str]] | None = None) -> Correspondence:
    """Match two IR sides. `exports` = (older, newer) mappings rva -> export key (name, else `#ordinal`) from
    `pe_overview`; without them P02 yields nothing. `anchors` are tier-M pairs in FIDs (04 s1)."""
    a = SideData.from_ir(older, limits, exports=exports[0] if exports else None)
    b = SideData.from_ir(newer, limits, exports=exports[1] if exports else None)
    return run_ladder_data(a, b, anchors=anchors, limits=limits, budget=budget, passes=passes)


def run_ladder_data(a: SideData, b: SideData, *, anchors: Iterable[CorrPair] = (),
                    limits: UnifiedLimits = DEFAULT_LIMITS, budget: Budget | None = None,
                    passes: Sequence[PassSpec] = PASSES) -> Correspondence:
    groups_of_passes = stage_groups(passes)
    budget = budget if budget is not None else Budget()
    st = State(a, b, limits, budget, passes)
    status, stop = 'complete', None
    completed: list[str] = []
    final_round = 1
    try:
        _apply_anchors(st, anchors)
        completed.append('P00')
        rnd = 0
        for group in groups_of_passes:
            rnd += 1
            for idx, spec in enumerate(group):
                mark = st.begin()
                try:
                    if spec.run is not None:
                        spec.run(st, rnd)
                    else:
                        _run_key_pass(st, spec, group[idx + 1:], rnd)
                except BudgetExhausted:
                    st.rollback(mark)
                    raise
                completed.append(spec.id)
            propagate_to_fixpoint(st, rnd)
            completed.append(f'prop:{rnd}')
        final_round = rnd + 1
    except BudgetExhausted as exc:
        status, stop = 'partial', ('cancelled' if exc.code == 'PT-UNIFIED-CANCEL' else 'deadline')
    if status == 'complete':
        finalize_soft(st, final_round)
    try:
        groups, left_a, left_b = build_groups(st, partial=status == 'partial')
    except BudgetExhausted as exc:                           # the budget ended inside the group stage
        status, stop = 'partial', ('cancelled' if exc.code == 'PT-UNIFIED-CANCEL' else 'deadline')
        groups, left_a, left_b = build_groups(st, partial=True)
    return _correspondence(st, status, stop, completed, groups, left_a, left_b)


def stage_groups(passes: Sequence[PassSpec]) -> list[tuple[PassSpec, ...]]:
    ids = [p.id for p in passes]
    if len(set(ids)) != len(ids) or P00.id in ids:
        raise UnifiedError('PT-UNIFIED-INPUT', 'pass table ids must be unique and exclude P00', reason='pass-table')
    out: list[list[PassSpec]] = []
    for spec in passes:
        if spec.keys is None and spec.run is None:
            raise UnifiedError('PT-UNIFIED-INPUT', 'a pass needs a key function or a run hook', reason='pass-table')
        if out and spec.stage < out[-1][0].stage:
            raise UnifiedError('PT-UNIFIED-INPUT', 'pass stages must not decrease', reason='pass-table')
        if out and spec.stage == out[-1][0].stage:
            out[-1].append(spec)
        else:
            out.append([spec])
    return [tuple(g) for g in out]


# ---- anchors (P00) ---------------------------------------------------------------------------------------------------------

def _apply_anchors(st: State, anchors: Iterable) -> None:
    given = []
    for p in anchors:
        x, y = (p.older_fid, p.newer_fid) if hasattr(p, 'older_fid') else p
        if type(x) is not int or type(y) is not int or not 0 <= x < st.a.n or not 0 <= y < st.b.n:
            raise UnifiedError('PT-UNIFIED-INPUT', 'manual anchor outside the IR', reason='anchor-range')
        given.append((x, y))
    seen_a: dict[int, int] = {}
    seen_b: dict[int, int] = {}
    for x, y in sorted(set(given)):
        if x in seen_a or y in seen_b:
            raise UnifiedError('PT-UNIFIED-INPUT', 'manual anchors contradict each other', reason='anchor-conflict')
        seen_a[x], seen_b[y] = y, x
    for x, y in sorted(seen_a.items()):
        st.accept(x, y, pass_id=P00.id, step=P00.step, tier='M', family=P00.family, cls=P00.cls, rnd=0)


# ---- one pass: global find with drill-down ---------------------------------------------------------------------------------------

def _run_key_pass(st: State, spec: PassSpec, tail: Sequence[PassSpec], rnd: int) -> None:
    find(st, spec, st.pool_a(spec), st.pool_b(spec), tuple(tail), rnd, 'A', ())


def _bucket(keys: list, pool: Iterable[int]) -> dict:
    out: dict = {}
    for fid in pool:
        key = keys[fid]
        if key is not None:
            lst = out.get(key)
            if lst is None:
                out[key] = [fid]
            else:
                lst.append(fid)
    return out


def find(st: State, spec: PassSpec, pool_a: Sequence[int], pool_b: Sequence[int], tail: Sequence[PassSpec],
         rnd: int, cap: str, chain: tuple[PassSpec, ...]) -> None:
    """BinDiff `find` (04 s3): bucket both pools by this pass's key; a bucket with exactly one function per side is a
    pair; an ambiguous bucket drills down with the NEXT keys of the stage inside the bucket; otherwise abstain.
    `cap` is the weakest tier of the keys already used (a drill-down pair never gets a stronger tier than any key
    of its chain)."""
    if spec.keys is None:
        return
    data = st.pass_data(spec)
    by_a = _bucket(data.keys_a, pool_a)
    by_b = _bucket(data.keys_b, pool_b)
    keyed_tail = tuple(t for t in tail if t.keys is not None)
    mate_a, mate_b = st.mate_a, st.mate_b
    for key in sorted(by_a.keys() & by_b.keys()):
        st.budget.tick()
        older = [x for x in by_a[key] if mate_a[x] < 0]        # a drill-down may have consumed members
        newer = [y for y in by_b[key] if mate_b[y] < 0]
        if len(older) == 1 and len(newer) == 1:
            _accept_global(st, spec, older[0], newer[0], key, rnd, cap, chain)
        elif older and newer and keyed_tail:
            find(st, keyed_tail[0], older, newer, keyed_tail[1:], rnd, weaker(cap, spec.tier), (*chain, spec))
        elif older and newer:
            st.bump(f'ambiguous:{spec.id}')


def _accept_global(st: State, spec: PassSpec, x: int, y: int, key: object, rnd: int, cap: str,
                   chain: tuple[PassSpec, ...]) -> None:
    tier = weaker(cap, spec.tier)
    hints: tuple[str, ...] = ()
    if spec.guard is not None:
        verdict = spec.guard(st, x, y, key)
        if verdict is None:
            st.bump(f'guard-rejected:{spec.id}')
            return
        tier, hints = weaker(tier, verdict.tier), verdict.hints
    family, cls = classify_pair(spec, chain, bool(st.a.pdata[x] and st.b.pdata[y]))
    chain_ids = tuple(c.id for c in chain)
    if tier == 'C':
        st.add_soft(SoftCand(x, y, spec.id, spec.step, family, cls, rnd, chain_ids, (), hints))
        return
    st.accept(x, y, pass_id=spec.id, step=spec.step, tier=tier, family=family, cls=cls, rnd=rnd, chain=chain_ids,
              hints=hints)


# ---- soft candidates -------------------------------------------------------------------------------------------------------------

def finalize_soft(st: State, rnd: int) -> None:
    """Tier-C candidates become pairs only now, if both endpoints are still unmatched and no other candidate shares
    an endpoint (two weak opinions about one function cancel each other: precision first). Conflict-free implied-match
    votes below the L-19 bar (04 s5.1: exactly one vote at the default) are derived here from the persistent vote
    table."""
    cands = dict(st.soft)
    need = st.limits.l19_implied_min_votes
    for (x, y), anchors in sorted(st.votes.anchors.items()):
        if 0 < len(anchors) < need and (x, y) not in cands and not st.votes.conflicts(x, y):
            cands[(x, y)] = SoftCand(x, y, 'PV', 'PV-implied-match', FAMILY_STRUCT, 'E-CALL', rnd, (),
                                     tuple(sorted(anchors))[:4], (), len(anchors))
    live = [cands[k] for k in sorted(cands) if st.mate_a[k[0]] < 0 and st.mate_b[k[1]] < 0]
    count_x = Counter(c.older_fid for c in live)
    count_y = Counter(c.newer_fid for c in live)
    for cand in live:
        if count_x[cand.older_fid] > 1 or count_y[cand.newer_fid] > 1:
            st.bump('soft-conflicts')
            st.note_conflict(cand.older_fid, cand.newer_fid, 'candidate-conflict')
            continue
        st.accept(cand.older_fid, cand.newer_fid, pass_id=cand.pass_id, step=cand.step, tier='C',
                  family=cand.family, cls=cand.cls, rnd=cand.round if cand.round else rnd, votes=cand.votes,
                  chain=cand.chain, anchors=cand.anchors, hints=cand.hints)
    for (x, y), _anchors in sorted(st.votes.anchors.items()):
        if st.mate_a[x] < 0 and st.mate_b[y] < 0 and st.votes.conflicts(x, y):
            st.note_conflict(x, y, 'implied-conflict')


# ---- result ----------------------------------------------------------------------------------------------------------------------------

def _correspondence(st: State, status: str, stop: str | None, completed: list[str], groups, left_a, left_b):
    pairs = tuple(sorted(st.pairs, key=lambda p: (p.older_fid, p.newer_fid)))
    accepted = Counter(p.pass_id for p in st.pairs)
    stats = dict(st.stats)
    stats.update({f'accepted:{k}': v for k, v in accepted.items()})
    stats.update({'ticks': st.budget.used, 'pairs': len(st.pairs), 'soft-pairs': sum(1 for p in st.pairs
                                                                                    if p.tier == 'C')})
    return Correspondence(
        pairs=pairs, groups=tuple(groups), older_only=tuple(left_a), newer_only=tuple(left_b), status=status,
        stop_reason=stop, passes_completed=tuple(completed), limits_hit=tuple(sorted(st.limits_hit.items())),
        stats=tuple(sorted(stats.items())), older_rva=st.a.rva, newer_rva=st.b.rva,
        older_hubs=tuple(f for f in range(st.a.n) if st.a.hub[f]),
        newer_hubs=tuple(f for f in range(st.b.n) if st.b.hub[f]))
