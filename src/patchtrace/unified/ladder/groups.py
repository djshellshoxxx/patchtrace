"""Groups and leftovers (SPEC-31 04 s7): what the ladder refuses to pair 1:1.

* `duplicate`: content-identical unmatched functions (`h1` buckets present on both sides with more than one member
  on a side) - never cross-multiplied (contrast Ghidriff pass 11).
* `icf`: alias-bearing functions whose names map to several functions on the other side (a changed COMDAT fold set,
  R04 s6). Connected components over shared usable names; reported as N:M, never as added/removed.
* `inlined-into` / `outlined-from` (R05 F11): an unmatched function whose >= L-25 rare blocks all occur inside ONE
  matched function of the other build. Only the contained (unmatched) function is exclusive to the group; the
  container usually sits in its own 1:1 pair. Partial containment only adds the hint `moved-or-inlined`.
* leftovers: every other unmatched function with a reason (`no-unique-evidence`, `tiny`, `oversize`,
  `thunk-unresolved`; `unfinished` after a budget stop) and the hints collected during the run.
"""
from __future__ import annotations

from collections import Counter

from .side import K_NORMAL, K_THUNK, SideData
from .state import State
from .types import CorrGroup, Leftover


class _Dsu:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[max(rx, ry)] = min(rx, ry)


def _icf_groups(st: State, used_a: set[int], used_b: set[int]) -> list[CorrGroup]:
    a, b = st.a, st.b
    index_a, index_b = a.name_index(), b.name_index()
    dsu = _Dsu(a.n + b.n)
    touched: set[int] = set()
    for name, fids_a in index_a.items():
        fids_b = index_b.get(name)
        if not fids_b:
            continue
        members = [f for f in fids_a if st.mate_a[f] < 0] + [a.n + f for f in fids_b if st.mate_b[f] < 0]
        if len(members) < 2 or not any(m < a.n for m in members) or not any(m >= a.n for m in members):
            continue
        for m in members[1:]:
            dsu.union(members[0], m)
        touched.update(members)
    components: dict[int, list[int]] = {}
    for m in sorted(touched):
        components.setdefault(dsu.find(m), []).append(m)
    out = []
    for root in sorted(components):
        members = components[root]
        older = tuple(m for m in members if m < a.n)
        newer = tuple(m - a.n for m in members if m >= a.n)
        if not older or not newer or (len(older) == 1 and len(newer) == 1):
            continue
        if not (any(len(a.names[f]) >= 2 for f in older) or any(len(b.names[f]) >= 2 for f in newer)):
            continue
        out.append(CorrGroup('icf', older, newer, 'alias-fold-changed'))
        used_a.update(older)
        used_b.update(newer)
    return out


def _duplicate_groups(st: State, used_a: set[int], used_b: set[int]) -> list[CorrGroup]:
    a, b = st.a, st.b
    by_a: dict[int, list[int]] = {}
    by_b: dict[int, list[int]] = {}
    for f in range(a.n):
        if st.mate_a[f] < 0 and a.content_ok[f] and a.h1[f] is not None and f not in used_a:
            by_a.setdefault(a.h1[f], []).append(f)
    for f in range(b.n):
        if st.mate_b[f] < 0 and b.content_ok[f] and b.h1[f] is not None and f not in used_b:
            by_b.setdefault(b.h1[f], []).append(f)
    out = []
    for key in sorted(by_a.keys() & by_b.keys()):
        st.budget.tick()
        older, newer = tuple(by_a[key]), tuple(by_b[key])
        if len(older) == 1 and len(newer) == 1:
            continue
        exact = len({a.h0[f] for f in older} | {b.h0[f] for f in newer}) == 1
        out.append(CorrGroup('duplicate', older, newer, 'h0' if exact else 'h1'))
        used_a.update(older)
        used_b.update(newer)
    return out


def _containment(st: State, contained: SideData, container: SideData, mate_container: list[int],
                 mate_contained: list[int], used: set[int], hints: dict[int, set[str]],
                 ) -> list[tuple[int, int, int]]:
    """(contained fid, container fid, rare block count) for fully contained functions; adds hint
    `moved-or-inlined` for partial containment."""
    limits = st.limits
    need = limits.l25_bb_min_votes
    own = Counter()
    for blocks in contained.blocks:
        own.update(blocks)
    rare: dict[int, tuple[int, ...]] = {}
    for f in range(contained.n):
        if mate_contained[f] >= 0 or f in used or contained.kind[f] != K_NORMAL:
            continue
        r = tuple(h for h in contained.blocks[f] if own[h] == 1)
        if len(r) >= need:
            rare[f] = r
    if not rare:
        return []
    wanted = {h for r in rare.values() for h in r}
    where: dict[int, list[int]] = {}
    for g in range(container.n):
        if mate_container[g] < 0:
            continue
        for h in container.blocks[g]:
            if h in wanted:
                where.setdefault(h, []).append(g)
    out = []
    for f in sorted(rare):
        st.budget.tick()
        hits = Counter()
        for h in rare[f]:
            hits.update(where.get(h, ()))
        if not hits:
            continue
        full = sorted(g for g, c in hits.items() if c == len(rare[f]))
        if len(full) == 1:
            out.append((f, full[0], len(rare[f])))
        elif not full and max(hits.values()) >= need:
            hints.setdefault(f, set()).add('moved-or-inlined')
    return out


def build_groups(st: State, *, partial: bool = False) -> tuple[list[CorrGroup], list[Leftover], list[Leftover]]:
    """Groups plus the leftover lists of both sides. After a budget stop (`partial`) no group is built and the
    leftovers say `unfinished`: missing is unknown, never a negative vote."""
    a, b = st.a, st.b
    used_a: set[int] = set()
    used_b: set[int] = set()
    groups: list[CorrGroup] = []
    inline_hints_a: dict[int, set[str]] = {}
    inline_hints_b: dict[int, set[str]] = {}
    if not partial:
        groups += _icf_groups(st, used_a, used_b)
        groups += _duplicate_groups(st, used_a, used_b)
        for f, g, count in _containment(st, a, b, st.mate_b, st.mate_a, used_a, inline_hints_a):
            groups.append(CorrGroup('inlined-into', (f,), (g,), f'blocks:{count}'))
            used_a.add(f)
        for f, g, count in _containment(st, b, a, st.mate_a, st.mate_b, used_b, inline_hints_b):
            groups.append(CorrGroup('outlined-from', (g,), (f,), f'blocks:{count}'))
            used_b.add(f)
    groups.sort(key=lambda g: (g.kind, g.older_fids, g.newer_fids))
    return groups, _leftovers(st, 'a', used_a, inline_hints_a, partial), _leftovers(st, 'b', used_b, inline_hints_b,
                                                                                    partial)


def _leftovers(st: State, letter: str, used: set[int], extra: dict[int, set[str]], partial: bool) -> list[Leftover]:
    side = st.a if letter == 'a' else st.b
    mate = st.mate_a if letter == 'a' else st.mate_b
    noted = st.hints_a if letter == 'a' else st.hints_b
    tiny = st.limits.l10_tiny_instructions
    out = []
    for fid in range(side.n):
        if mate[fid] >= 0 or fid in used:
            continue
        if partial:
            reason = 'unfinished'
        elif side.kind[fid] == K_THUNK:
            reason = 'thunk-unresolved'
        elif side.oversize[fid]:
            reason = 'oversize'
        elif side.kind[fid] == K_NORMAL and side.n_insn[fid] <= tiny:
            reason = 'tiny'
        else:
            reason = 'no-unique-evidence'
        hints = tuple(sorted({*noted.get(fid, ()), *extra.get(fid, ())}))
        out.append(Leftover(fid, reason, hints))
    return out
