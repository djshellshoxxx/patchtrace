"""Mutable run state of the ladder: pools, accepted pairs, soft candidates, vote table, journal.

Invariants kept here (04 s1): (I1) a function is in at most one accepted pair; (I3) an accepted pair is never
re-opened - the only way to undo an accept is `rollback`, used when a pass is interrupted by the budget so that no
pass is ever half applied (04 s8). Tier-C results never enter the pools: they live in `soft` until the very end
(see `engine.finalize_soft`), so weaker evidence can never block a later, stronger pass.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from ..limits import Budget, UnifiedLimits
from .passspec import PassSpec
from .side import SideData
from .types import CorrPair


@dataclass(slots=True)
class PassData:
    keys_a: list
    keys_b: list
    elig_a: list[int]
    elig_b: list[int]


@dataclass(slots=True)
class SoftCand:
    """A tier-C candidate. Several evidence sources may add the same (older, newer) pair; the first one keeps its
    provenance, later ones only contribute hints and anchors."""
    older_fid: int
    newer_fid: int
    pass_id: str
    step: str
    family: str
    cls: str
    round: int
    chain: tuple[str, ...] = ()
    anchors: tuple[tuple[int, int], ...] = ()
    hints: tuple[str, ...] = ()
    votes: int = 0


class VoteTable:
    """Implied-match votes (04 s5.1). A vote is (older fid x, newer fid y, anchor pair). Conflicts are symmetric:
    two voted pairs that share exactly one endpoint conflict. Nothing is ever removed, so a later wave can only add
    conflicts, never erase one."""

    def __init__(self) -> None:
        self.anchors: dict[tuple[int, int], set[tuple[int, int]]] = {}
        self.by_x: dict[int, set[int]] = {}
        self.by_y: dict[int, set[int]] = {}
        self.touched: set[tuple[int, int]] = set()

    def add(self, x: int, y: int, anchor: tuple[int, int]) -> None:
        key = (x, y)
        votes = self.anchors.get(key)
        if votes is None:
            votes = self.anchors[key] = set()
            self.by_x.setdefault(x, set()).add(y)
            self.by_y.setdefault(y, set()).add(x)
            for y2 in self.by_x[x]:
                self.touched.add((x, y2))
            for x2 in self.by_y[y]:
                self.touched.add((x2, y))
        if anchor not in votes:
            votes.add(anchor)
            self.touched.add(key)

    def conflicts(self, x: int, y: int) -> int:
        return len(self.by_x[x]) - 1 + len(self.by_y[y]) - 1

    def votes_of(self, x: int, y: int) -> tuple[tuple[int, int], ...]:
        return tuple(sorted(self.anchors[(x, y)]))


class State:
    def __init__(self, a: SideData, b: SideData, limits: UnifiedLimits, budget: Budget,
                 passes: Sequence[PassSpec] = ()):
        self.a, self.b = a, b
        self.limits = limits
        self.budget = budget
        self.pass_by_id: dict[str, PassSpec] = {p.id: p for p in passes}
        self.pass_order: dict[str, int] = {p.id: i for i, p in enumerate(passes)}
        self.neighbour_passes: list[PassSpec] = [p for p in passes if p.neighbour and p.keys is not None]
        self.hints_a: dict[int, set[str]] = {}
        self.hints_b: dict[int, set[str]] = {}
        self.mate_a = [-1] * a.n
        self.mate_b = [-1] * b.n
        self.pair_a = [-1] * a.n          # index into `pairs` of the pair holding the function, -1 if unmatched
        self.pair_b = [-1] * b.n
        self.pairs: list[CorrPair] = []
        self.seq = 0
        self.cursor = 0                   # `pairs[cursor:]` were accepted since the last propagation
        self.soft: dict[tuple[int, int], SoftCand] = {}
        self.votes = VoteTable()
        self.limits_hit: Counter[str] = Counter()
        self.stats: Counter[str] = Counter()
        self.pass_start_seq = 0           # pairs with seq below this existed before the current pass began
        self._pass_data: dict[str, PassData] = {}
        self.icf_a, self.icf_b = icf_suspects(a, b)
        self._icf_fids_a = [f for f, flag in enumerate(self.icf_a) if flag]
        self._icf_fids_b = [f for f, flag in enumerate(self.icf_b) if flag]

    # ---- accepted pairs ---------------------------------------------------------------------------------------------
    def accept(self, x: int, y: int, *, pass_id: str, step: str, tier: str, family: str, cls: str, rnd: int,
               votes: int = 0, chain: tuple[str, ...] = (), anchors: tuple[tuple[int, int], ...] = (),
               hints: tuple[str, ...] = ()) -> CorrPair:
        if self.mate_a[x] >= 0 or self.mate_b[y] >= 0:
            raise AssertionError('an accepted pair is never re-opened (I3)')
        self.seq += 1
        pair = CorrPair(x, y, pass_id, step, tier, family, cls, rnd, votes, chain, anchors, hints, self.seq)
        self.mate_a[x], self.mate_b[y] = y, x
        self.pair_a[x] = self.pair_b[y] = len(self.pairs)
        self.pairs.append(pair)
        return pair

    def begin(self) -> int:
        """Journal mark: everything accepted after it can be rolled back."""
        self.pass_start_seq = self.seq + 1
        return len(self.pairs)

    def rollback(self, mark: int) -> None:
        for pair in self.pairs[mark:]:
            self.mate_a[pair.older_fid] = self.mate_b[pair.newer_fid] = -1
            self.pair_a[pair.older_fid] = self.pair_b[pair.newer_fid] = -1
        del self.pairs[mark:]
        self.cursor = min(self.cursor, mark)

    def new_pairs(self) -> list[CorrPair]:
        return self.pairs[self.cursor:]

    def mark_propagated(self) -> None:
        self.cursor = len(self.pairs)

    # ---- soft (tier C) candidates --------------------------------------------------------------------------------------
    def add_soft(self, cand: SoftCand) -> None:
        old = self.soft.get((cand.older_fid, cand.newer_fid))
        if old is None:
            self.soft[(cand.older_fid, cand.newer_fid)] = cand
            return
        merged_hints = tuple(sorted({*old.hints, *cand.hints}))
        merged_anchors = tuple(sorted({*old.anchors, *cand.anchors}))[:4]
        old.hints, old.anchors = merged_hints, merged_anchors

    def note_conflict(self, x: int, y: int, hint: str) -> None:
        """Remember why a function stayed unmatched (reported as a leftover hint)."""
        self.hints_a.setdefault(x, set()).add(hint)
        self.hints_b.setdefault(y, set()).add(hint)

    # ---- per-pass key tables ---------------------------------------------------------------------------------------------
    def pass_data(self, spec: PassSpec) -> PassData:
        data = self._pass_data.get(spec.id)
        if data is None:
            keys_a = self._static_keys(spec, self.a, self._icf_fids_a)
            keys_b = self._static_keys(spec, self.b, self._icf_fids_b)
            data = self._pass_data[spec.id] = PassData(
                keys_a, keys_b, [f for f, k in enumerate(keys_a) if k is not None],
                [f for f, k in enumerate(keys_b) if k is not None])
        return data

    def _static_keys(self, spec: PassSpec, side: SideData, icf_fids: list[int]) -> list:
        keys = list(spec.keys(side, self.limits))
        if not spec.hubs:
            for f in side.cached('hub_fids', lambda: [g for g in range(side.n) if side.hub[g]]):
                keys[f] = None
        for f in icf_fids:
            keys[f] = None
        return keys

    def pool_a(self, spec: PassSpec) -> list[int]:
        mate = self.mate_a
        return [f for f in self.pass_data(spec).elig_a if mate[f] < 0]

    def pool_b(self, spec: PassSpec) -> list[int]:
        mate = self.mate_b
        return [f for f in self.pass_data(spec).elig_b if mate[f] < 0]

    # ---- counters -------------------------------------------------------------------------------------------------------------
    def limit_hit(self, name: str, count: int = 1) -> None:
        self.limits_hit[name] += count

    def bump(self, name: str, count: int = 1) -> None:
        self.stats[name] += count

    def pair_tier_a(self, fid: int) -> str:
        return self.pairs[self.pair_a[fid]].tier

    def pair_tier_b(self, fid: int) -> str:
        return self.pairs[self.pair_b[fid]].tier


def icf_suspects(a: SideData, b: SideData) -> tuple[list[bool], list[bool]]:
    """ICF fold sets that changed (04 s7): an alias-bearing function whose names map to >= 2 functions on the other
    side. Such functions are never paired 1:1 (the alias evidence says N:M); the group stage reports them."""
    index_a, index_b = a.name_index(), b.name_index()

    def flags(side: SideData, other_index: dict[str, tuple[int, ...]]) -> list[bool]:
        out = [False] * side.n
        for fid in range(side.n):
            names = side.names[fid]
            if len(names) >= 2:
                partners: set[int] = set()
                for name in names:
                    partners.update(other_index.get(name, ()))
                out[fid] = len(partners) >= 2
        return out
    return flags(a, index_b), flags(b, index_a)

