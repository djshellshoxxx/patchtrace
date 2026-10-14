"""Propagation to a fixpoint (SPEC-31 04 s5, s5.1): neighbour cascade, thunk targets, implied matches.

Portions derived from google/bindiff v8 (Apache-2.0), Copyright 2011-2023 Google LLC (the callees-then-callers
cascade around fixed points of match/call_graph.cc and `Diff` in differ.cc); algorithms re-expressed in Python and
modified for PatchTrace (2026-10-14); licence text under third_party/notices/bindiff-v8-*/ (slice S1). The implied
match voting is clean-room from the Ghidra Version Tracking help text (conflict-free votes, 04 s5.1).

Design points (all deliberate, all tested):

* Deterministic waves. A wave reads the state as it was at the wave start, collects every candidate pair, and only
  then decides: no decision depends on queue order, and swapping the two sides mirrors the result.
* Candidates compete by strength (A exact key > B two agreeing keys / two votes / thunk of a B pair > C). A
  candidate survives only if it is strictly stronger than every rival sharing exactly one endpoint; equals drop
  each other. Tier A/B survivors are accepted, tier C survivors become soft candidates (never consume pools).
* Seeds are accepted pairs only. A newly accepted pair re-queues the matched pairs adjacent to it ("dirty"
  anchors) because their neighbour sets just shrank; BinDiff gets the same effect by re-visiting every fixed point.
* Hubs (fan-in > L-17) are neither neighbours nor voters; neighbour lists are cut at L-18 by ascending fid and the
  cut is recorded in `limits_hit`.
* Implied matches align call-site sequences between the anchors of a pair. The alignment is the order-independent
  subset of an LCS: unique matched/imported tokens split the sequences, and each gap is paired positionally only if
  both gaps have the same length and every position is compatible (otherwise it yields no vote). Bound: 512 sites.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field

from ..limits import BudgetExhausted
from .passes import FAMILY_STRUCT
from .state import SoftCand, State

MAX_CALL_SITES = 512
_RANK = {'A': 3, 'B': 2, 'C': 1}


@dataclass(slots=True)
class Cand:
    older_fid: int
    newer_fid: int
    passes: set = field(default_factory=set)         # neighbour-key pass ids that produced it
    anchors: set = field(default_factory=set)
    votes: int = 0
    thunk_tier: str | None = None
    hints: set = field(default_factory=set)

    def tier(self, st: State) -> str:
        best = 'C'
        if 'P04' in self.passes or 'P05' in self.passes:
            best = 'A'
        elif len(self.passes) >= 2:
            best = 'B'
        if self.votes >= st.limits.l19_implied_min_votes:
            best = max(best, 'B', key=_RANK.__getitem__)
        if self.thunk_tier is not None:
            best = max(best, self.thunk_tier, key=_RANK.__getitem__)
        return best


# ---- dirty anchors ---------------------------------------------------------------------------------------------------------

def dirty_anchors(st: State, x: int, y: int) -> set[tuple[int, int]]:
    """Matched pairs (u, v) that are call-graph neighbours of both x and y: their neighbour sets just changed."""
    out: set[tuple[int, int]] = set()
    a, b = st.a, st.b
    neighbours_b = {*b.callees[y], *b.callers[y]}
    for u in (*a.callees[x], *a.callers[x]):
        v = st.mate_a[u]
        if v >= 0 and v in neighbours_b:
            out.add((u, v))
    return out


def _initial_wave(st: State) -> list[tuple[int, int]]:
    wave: set[tuple[int, int]] = set()
    for pair in st.new_pairs():
        wave.add((pair.older_fid, pair.newer_fid))
        wave |= dirty_anchors(st, pair.older_fid, pair.newer_fid)
    return sorted(wave)


# ---- entry point -----------------------------------------------------------------------------------------------------------

def propagate_to_fixpoint(st: State, rnd: int) -> None:
    wave = _initial_wave(st)
    st.mark_propagated()
    while wave:
        mark = st.begin()
        try:
            accepted = _process_wave(st, wave, rnd)
        except BudgetExhausted:
            st.rollback(mark)
            raise
        st.bump('waves')
        nxt: set[tuple[int, int]] = set()
        for x, y in accepted:
            nxt.add((x, y))
            nxt |= dirty_anchors(st, x, y)
        st.mark_propagated()
        wave = sorted(p for p in nxt if st.mate_a[p[0]] == p[1])


def _process_wave(st: State, wave: list[tuple[int, int]], rnd: int) -> list[tuple[int, int]]:
    cands: dict[tuple[int, int], Cand] = {}
    datas = [(spec, st.pass_data(spec)) for spec in st.neighbour_passes]
    for a, b in wave:
        st.budget.tick()
        if st.mate_a[a] != b:
            continue
        _local_candidates(st, a, b, cands, datas)
        _cast_votes(st, a, b)
    for a, b in wave:
        if st.mate_a[a] == b:
            _thunk_candidate(st, a, b, cands)
    _vote_candidates(st, cands)
    return _resolve_and_accept(st, cands, rnd)


# ---- neighbour-set matching --------------------------------------------------------------------------------------------------

def _neighbour_set(st: State, side_letter: str, fid: int, rel: str) -> list[int]:
    side = st.a if side_letter == 'a' else st.b
    mate = st.mate_a if side_letter == 'a' else st.mate_b
    members = (side.callees if rel == 'callees' else side.callers)[fid]
    hub = side.hub
    out = [x for x in members if mate[x] < 0 and not hub[x]]
    cap = st.limits.l18_neighbour_cap
    if len(out) > cap:
        st.limit_hit('neighbour-cap')
        del out[cap:]
    return out


def _add_candidate(st: State, cands: dict[tuple[int, int], Cand], spec, x: int, y: int, key: object,
                   anchor: tuple[int, int]) -> None:
    if spec.guard is not None and spec.guard(st, x, y, key) is None:
        return
    cand = cands.get((x, y))
    if cand is None:
        cand = cands[(x, y)] = Cand(x, y)
    cand.passes.add(spec.id)
    cand.anchors.add(anchor)


def _local_candidates(st: State, a: int, b: int, cands: dict[tuple[int, int], Cand], datas: list) -> None:
    for rel in ('callees', 'callers'):
        na = _neighbour_set(st, 'a', a, rel)
        if not na:
            continue
        nb = _neighbour_set(st, 'b', b, rel)
        if not nb:
            continue
        st.budget.tick(len(na) + len(nb))
        if len(na) == 1 and len(nb) == 1:                  # the common case: uniqueness is trivial, compare keys
            x, y = na[0], nb[0]
            for spec, data in datas:
                key = data.keys_a[x]
                if key is not None and key == data.keys_b[y]:
                    _add_candidate(st, cands, spec, x, y, key, (a, b))
            continue
        for spec, data in datas:
            by_a: dict = {}
            for x in na:
                key = data.keys_a[x]
                if key is not None:
                    by_a.setdefault(key, []).append(x)
            if not by_a:
                continue
            by_b: dict = {}
            for y in nb:
                key = data.keys_b[y]
                if key is not None and key in by_a:
                    by_b.setdefault(key, []).append(y)
            for key, ys in by_b.items():
                xs = by_a[key]
                if len(xs) == 1 and len(ys) == 1:
                    _add_candidate(st, cands, spec, xs[0], ys[0], key, (a, b))


# ---- thunks ----------------------------------------------------------------------------------------------------------------

def _thunk_candidate(st: State, a: int, b: int, cands: dict[tuple[int, int], Cand]) -> None:
    """Thunks of two paired targets pair with each other when each target has exactly one unmatched thunk."""
    older = [t for t in st.a.thunks_of.get(a, ()) if st.mate_a[t] < 0]
    newer = [t for t in st.b.thunks_of.get(b, ()) if st.mate_b[t] < 0]
    if len(older) != 1 or len(newer) != 1:
        return
    tier = 'A' if st.pairs[st.pair_a[a]].tier in ('M', 'A') else 'B'
    cand = cands.get((older[0], newer[0]))
    if cand is None:
        cand = cands[(older[0], newer[0])] = Cand(older[0], newer[0])
    cand.thunk_tier = tier if cand.thunk_tier is None else max(cand.thunk_tier, tier, key=_RANK.__getitem__)
    cand.anchors.add((a, b))
    cand.hints.add('thunk-target')


# ---- implied matches (votes) -----------------------------------------------------------------------------------------------------

def _tokens(st: State, side_letter: str, fid: int) -> list[tuple]:
    """(class, ident, jump, callee) per call site in site order. Classes: I import key, P matched pair, U unmatched
    callee (wildcard), H unmatched hub (neutral), S self call, ? unresolved/indirect."""
    side = st.a if side_letter == 'a' else st.b
    mate = st.mate_a if side_letter == 'a' else st.mate_b
    out = []
    for callee, ikey, jump in side.sites[fid]:
        if ikey:
            out.append(('I', ikey, jump, -1))
        elif callee < 0:
            out.append(('?', None, jump, -1))
        elif callee == fid:
            out.append(('S', None, jump, -1))
        elif mate[callee] >= 0:
            pair = (callee, mate[callee]) if side_letter == 'a' else (mate[callee], callee)
            out.append(('P', pair, jump, -1))
        elif side.hub[callee]:
            out.append(('H', None, jump, callee))
        else:
            out.append(('U', None, jump, callee))
    return out


def _compatible(ta: tuple, tb: tuple) -> bool:
    if ta[0] != tb[0] or ta[2] != tb[2]:
        return False
    return ta[1] == tb[1] if ta[0] in ('I', 'P') else True


def _unique_anchor_pairs(ta: list[tuple], tb: list[tuple]) -> list[tuple[int, int]]:
    """Positions (i, j) of tokens that occur exactly once on each side, thinned to an increasing chain (LIS)."""
    first_a: dict[tuple, int] = {}
    count_a: dict[tuple, int] = {}
    for i, t in enumerate(ta):
        if t[0] in ('I', 'P'):
            k = (t[0], t[1], t[2])
            count_a[k] = count_a.get(k, 0) + 1
            first_a.setdefault(k, i)
    first_b: dict[tuple, int] = {}
    count_b: dict[tuple, int] = {}
    for j, t in enumerate(tb):
        if t[0] in ('I', 'P'):
            k = (t[0], t[1], t[2])
            count_b[k] = count_b.get(k, 0) + 1
            first_b.setdefault(k, j)
    pairs = sorted((first_a[k], first_b[k]) for k in first_a if count_a[k] == 1 and count_b.get(k) == 1)
    if not pairs:
        return []
    tails: list[int] = []            # LIS over j (strictly increasing), patience sorting with back links
    tail_idx: list[int] = []
    prev = [-1] * len(pairs)
    for idx, (_i, j) in enumerate(pairs):
        pos = bisect_left(tails, j)
        if pos == len(tails):
            tails.append(j)
            tail_idx.append(idx)
        else:
            tails[pos] = j
            tail_idx[pos] = idx
        prev[idx] = tail_idx[pos - 1] if pos else -1
    chain = []
    k = tail_idx[-1]
    while k >= 0:
        chain.append(pairs[k])
        k = prev[k]
    chain.reverse()
    return chain


def _has_open_callee(side, mate: list[int], fid: int) -> bool:
    hub = side.hub
    for callee, ikey, _jump in side.sites[fid]:
        if not ikey and callee >= 0 and callee != fid and mate[callee] < 0 and not hub[callee]:
            return True
    return False


def _cast_votes(st: State, a: int, b: int) -> None:
    if not (_has_open_callee(st.a, st.mate_a, a) and _has_open_callee(st.b, st.mate_b, b)):
        return
    ta = _tokens(st, 'a', a)
    tb = _tokens(st, 'b', b)
    if not any(t[0] == 'U' for t in ta) or not any(t[0] == 'U' for t in tb):
        return
    if len(ta) > MAX_CALL_SITES or len(tb) > MAX_CALL_SITES:
        st.limit_hit('callsite-cap')
        return
    anchors = [*_unique_anchor_pairs(ta, tb), (len(ta), len(tb))]
    i0 = j0 = 0
    for i1, j1 in anchors:
        gap_a, gap_b = ta[i0:i1], tb[j0:j1]
        i0, j0 = i1 + 1, j1 + 1
        if not gap_a and not gap_b:
            continue
        if len(gap_a) != len(gap_b) or not all(_compatible(x, y) for x, y in zip(gap_a, gap_b, strict=True)):
            st.bump('callsite-gap-skipped')
            continue
        for x, y in zip(gap_a, gap_b, strict=True):
            if x[0] == 'U':
                st.votes.add(x[3], y[3], (a, b))


def _vote_candidates(st: State, cands: dict[tuple[int, int], Cand]) -> None:
    touched = sorted(st.votes.touched)
    st.votes.touched.clear()
    need = st.limits.l19_implied_min_votes
    for x, y in touched:
        if st.mate_a[x] >= 0 or st.mate_b[y] >= 0:
            continue
        n = len(st.votes.anchors[(x, y)])
        if st.votes.conflicts(x, y):
            st.bump('implied-conflicts')
            continue
        if n >= need:
            cand = cands.get((x, y))
            if cand is None:
                cand = cands[(x, y)] = Cand(x, y)
            cand.votes = n
            cand.anchors.update(st.votes.votes_of(x, y))


# ---- resolution and acceptance ------------------------------------------------------------------------------------------------------

def _resolve_and_accept(st: State, cands: dict[tuple[int, int], Cand], rnd: int) -> list[tuple[int, int]]:
    by_x: dict[int, list[Cand]] = {}
    by_y: dict[int, list[Cand]] = {}
    ordered = [cands[k] for k in sorted(cands)]
    for cand in ordered:
        by_x.setdefault(cand.older_fid, []).append(cand)
        by_y.setdefault(cand.newer_fid, []).append(cand)
    tiers = {(c.older_fid, c.newer_fid): c.tier(st) for c in ordered}
    accepted: list[tuple[int, int]] = []
    for cand in ordered:
        mine = _RANK[tiers[(cand.older_fid, cand.newer_fid)]]
        rivals = [r for r in by_x[cand.older_fid] if r is not cand] + [r for r in by_y[cand.newer_fid]
                                                                       if r is not cand]
        if any(_RANK[tiers[(r.older_fid, r.newer_fid)]] >= mine for r in rivals):
            st.bump('local-conflicts')
            st.note_conflict(cand.older_fid, cand.newer_fid, 'candidate-conflict')
            continue
        tier = tiers[(cand.older_fid, cand.newer_fid)]
        _commit(st, cand, tier, rnd)
        if tier != 'C':
            accepted.append((cand.older_fid, cand.newer_fid))
    return accepted


def _commit(st: State, cand: Cand, tier: str, rnd: int) -> None:
    anchors = tuple(sorted(cand.anchors))[:4]
    order = st.pass_order
    keyed = sorted(cand.passes, key=lambda pid: order.get(pid, 999))
    hints = tuple(sorted(cand.hints))
    if keyed:
        spec = st.pass_by_id[keyed[0]]
        pass_id, step, chain = spec.id, spec.step, tuple(keyed[1:])
    elif cand.votes:
        pass_id, step, chain = 'PV', 'PV-implied-match', ()
    else:
        pass_id, step, chain = 'PT', 'PT-thunk-target', ()
    family, cls = FAMILY_STRUCT, 'E-CALL'      # propagated pairs inherit the call-graph dependency (05 s1.1)
    if tier == 'C':
        st.add_soft(SoftCand(cand.older_fid, cand.newer_fid, pass_id, step, family, cls, rnd, chain, anchors, hints,
                             cand.votes))
        return
    st.accept(cand.older_fid, cand.newer_fid, pass_id=pass_id, step=step, tier=tier, family=family, cls=cls,
              rnd=rnd, votes=cand.votes, chain=chain, anchors=anchors, hints=hints)


__all__ = ['Cand', 'MAX_CALL_SITES', 'dirty_anchors', 'propagate_to_fixpoint']
