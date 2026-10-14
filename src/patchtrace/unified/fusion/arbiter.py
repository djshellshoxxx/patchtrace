"""The arbiter (05 s1.3, 02 s10 items 4-5): atoms and groups -> decided rows. Pure, deterministic, rule-based.

No number is ever computed, summed or compared across sources; native text is never read. Corroboration needs two
independence components AND two evidence classes (D-32). Any source pairing an endpoint differently makes a row
`contested` (weak or strong, for ordering only); a one-sided observation is absence of evidence and never contests.
Claims are processed in priority order: manual (analyst control) > engine groups (abstention on ambiguity) > the
strength-ordered greedy choice of 1:1 edges; every atom that loses stays in the audit trail of a row it touches.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import combinations

from .. import keys
from ..contracts import Atom, Contest, SideRef, Support, UnifiedMatch
from ..limits import DEFAULT_LIMITS, Budget, UnifiedError, UnifiedLimits
from ..registry import REGISTRY, TIER_RANK, Registry
from ..sources import NodeRecord, SourceGroup
from .components import components_for

MAX_HINTS = 32
ONE_SIDED_SORT = 2**33
STRONG_TIERS = ('M', 'A', 'B')


@dataclass(frozen=True)
class NodeInfo:
    name: str | None
    kind: str = 'function'


@dataclass(frozen=True)
class Decided:
    """A decided row before facts. `pair` is the chosen 1:1 edge; `mapped` says the row may map a call/data target
    for proofs (matched with a tier A or M support, 05 s2.7)."""
    older: tuple[int, ...]
    newer: tuple[int, ...]
    decision: str
    support: tuple[Support, ...]
    contest: Contest | None
    atoms: tuple[Atom, ...]
    hints: tuple[str, ...]
    ghidriff_match_id: str | None = None
    pair: tuple[int, int] | None = None
    mapped: bool = False


@dataclass
class _Claim:
    kind: str                       # pair | one | group
    older: set[int]
    newer: set[int]
    atoms: list[Atom]
    decision: str
    hints: list[str] = field(default_factory=list)
    manual: bool = False
    pair: tuple[int, int] | None = None


def merge_nodes(outputs: Iterable[Iterable[NodeRecord]]) -> dict[tuple[str, int], NodeInfo]:
    """Display names per (side, rva); the first non-empty name in source priority order wins."""
    merged: dict[tuple[str, int], NodeInfo] = {}
    for records in outputs:
        for record in records:
            key = (record.side, record.rva)
            current = merged.get(key)
            if current is None or (current.name is None and record.name is not None):
                merged[key] = NodeInfo(record.name, record.kind)
    return merged


def decide(atoms: Sequence[Atom], groups: Sequence[SourceGroup], nodes: Mapping | None = None, *,
           registry: Registry = REGISTRY, budget: Budget | None = None,
           limits: UnifiedLimits = DEFAULT_LIMITS) -> list[Decided]:
    budget = budget or Budget()
    comps = components_for(registry)

    def component(a: Atom) -> str:
        return comps.of(registry, a.source, a.step)

    def key(a: Atom) -> tuple:
        return (int(component(a)[1:]), -TIER_RANK[a.tier], a.source, a.step,
                -1 if a.older_rva is None else a.older_rva, -1 if a.newer_rva is None else a.newer_rva, a.cls,
                a.cardinality, a.ref or '')

    for group in groups:  # an unregistered source is a bug, found before anything is decided
        for a in group.atoms:
            component(a)
    edges: dict[tuple[int, int], list[Atom]] = defaultdict(list)
    one_old: dict[int, list[Atom]] = defaultdict(list)
    one_new: dict[int, list[Atom]] = defaultdict(list)

    def file_atom(a: Atom) -> None:
        if a.older_rva is not None and a.newer_rva is not None:
            edges[(a.older_rva, a.newer_rva)].append(a)
        elif a.older_rva is not None:
            one_old[a.older_rva].append(a)
        else:
            one_new[a.newer_rva].append(a)

    for a in sorted(set(atoms), key=key):
        budget.tick()
        file_atom(a)

    claim_old: dict[int, _Claim] = {}
    claim_new: dict[int, _Claim] = {}
    claims: list[_Claim] = []

    def add_claim(claim: _Claim) -> None:
        if any(o in claim_old for o in claim.older) or any(n in claim_new for n in claim.newer):
            raise UnifiedError('PT-UNIFIED-INPUT', 'Two manual corrections claim the same function',
                               reason='manual-overlap')
        claims.append(claim)
        claim_old.update(dict.fromkeys(claim.older, claim))
        claim_new.update(dict.fromkeys(claim.newer, claim))

    # -- stage M: analyst claims ------------------------------------------------------------------------------------
    chosen: set[tuple[int, int]] = set()
    for edge in sorted(e for e, al in edges.items() if any(a.tier == 'M' for a in al)):
        add_claim(_Claim('pair', {edge[0]}, {edge[1]}, [], 'matched', manual=True, pair=edge))
        chosen.add(edge)
    for side, table in (('older', one_old), ('newer', one_new)):
        for rva in sorted(r for r, al in table.items() if any(a.tier == 'M' for a in al)):
            add_claim(_Claim('one', {rva} if side == 'older' else set(), {rva} if side == 'newer' else set(), [],
                             'older-only' if side == 'older' else 'newer-only', ['manual-one-sided'], manual=True))
    for group in sorted((g for g in groups if g.source == 'manual'), key=lambda g: (g.older, g.newer, g.kind)):
        add_claim(_Claim('group', set(group.older), set(group.newer), list(group.atoms), group.decision,
                         [f'manual-group:{group.kind.removeprefix("manual-")}'], manual=True))

    # -- stage G: engine groups (abstention on ambiguity) -----------------------------------------------------------
    pools: list[tuple[set[int], set[int], list[Atom], str]] = []
    for group in sorted((g for g in groups if g.source != 'manual'), key=lambda g: (g.older, g.newer, g.kind)):
        budget.tick()
        free_old = {o for o in group.older if o not in claim_old}
        free_new = {n for n in group.newer if n not in claim_new}
        kept: list[Atom] = []
        for a in group.atoms:
            touches_claim = (a.older_rva in claim_old) or (a.newer_rva in claim_new)
            if touches_claim or a.older_rva not in free_old or a.newer_rva not in free_new:
                file_atom(a)  # a loose proposal now: it is attached to the claim it touches
            else:
                kept.append(a)
        if free_old and free_new:
            pools.append((free_old, free_new, kept, group.kind))
        else:
            for a in kept:
                file_atom(a)
    pools = _merge_pools(pools)
    for older, newer, group_atoms, _kind in pools:
        add_claim(_Claim('group', older, newer, group_atoms, 'ambiguous'))

    # -- stage E: strength-ordered greedy choice of 1:1 edges --------------------------------------------------------
    adj_old: dict[int, list[tuple[int, int]]] = defaultdict(list)
    adj_new: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for edge in sorted(edges):
        adj_old[edge[0]].append(edge)
        adj_new[edge[1]].append(edge)
    free = [e for e in edges if e[0] not in claim_old and e[1] not in claim_new]

    def strength(edge: tuple[int, int]) -> tuple:
        al = edges[edge]
        return (max(TIER_RANK[a.tier] for a in al), len({component(a) for a in al}),
                any(a.source == 'ghidriff' for a in al), -edge[0], -edge[1])
    used_old: set[int] = set()
    used_new: set[int] = set()
    for edge in sorted(free, key=strength, reverse=True):
        budget.tick()
        if edge[0] in used_old or edge[1] in used_new:
            continue
        used_old.add(edge[0])
        used_new.add(edge[1])
        chosen.add(edge)

    def base_decision(al: Sequence[Atom]) -> str:
        if any(a.tier == 'M' for a in al):
            return 'matched'
        best: dict[str, Atom] = {}
        for a in al:
            have = best.get(component(a))
            if have is None or TIER_RANK[a.tier] > TIER_RANK[have.tier]:
                best[component(a)] = a
        if any(a.tier == 'A' for a in best.values()):
            return 'matched'
        usable = [a for a in al if a.tier in ('A', 'B') and a.cls != 'E-UNKNOWN']
        if any(component(x) != component(y) and x.cls != y.cls for x, y in combinations(usable, 2)):
            return 'matched'
        return 'tentative' if usable else 'candidate'

    def assemble(older, newer, decision, chosen_atoms, against_atoms, extra_atoms, hints, *, pair=None,
                 supported=True) -> Decided:
        return _assemble(older, newer, decision, chosen_atoms, against_atoms, extra_atoms, hints, pair, key,
                         component, limits, supported)

    def observations(older: Iterable[int], newer: Iterable[int]) -> list[Atom]:
        return [a for o in older for a in one_old.get(o, ())] + [a for n in newer for a in one_new.get(n, ())]

    rows: list[Decided] = []
    for edge in sorted(chosen):
        budget.tick()
        own = edges[edge]
        losing = sorted({f for f in (*adj_old[edge[0]], *adj_new[edge[1]]) if f != edge})
        against = [a for f in losing for a in edges[f]]
        obs = observations([edge[0]], [edge[1]])
        manual_pair = any(a.tier == 'M' for a in own)
        base = 'matched' if manual_pair else base_decision(own)
        hints = [f'one-sided-by:{s}' for s in sorted({a.source for a in obs})]
        decision = base
        if against and not manual_pair:
            decision = 'contested'
            hints.append(f'uncontested:{base}')
        rows.append(assemble((edge[0],), (edge[1],), decision, own, against, obs, hints, pair=edge))
    for claim in claims:
        budget.tick()
        if claim.kind == 'pair':
            continue
        older, newer = sorted(claim.older), sorted(claim.newer)
        attached = sorted({f for o in older for f in adj_old.get(o, ())} | {f for n in newer for f in adj_new.get(n, ())})
        extra = [a for f in attached for a in edges[f]] + observations(older, newer)
        rows.append(assemble(tuple(older), tuple(newer), claim.decision, claim.atoms, [], extra, claim.hints,
                             supported=False))
    covered_old = set(claim_old) | {e[0] for e in chosen}
    covered_new = set(claim_new) | {e[1] for e in chosen}
    group_old = {o for c in claims if c.kind == 'group' for o in c.older}
    group_new = {n for c in claims if c.kind == 'group' for n in c.newer}
    uncovered_old = sorted(({o for o in one_old} | set(adj_old)) - covered_old)
    uncovered_new = sorted(({n for n in one_new} | set(adj_new)) - covered_new)
    for side, nodes_, adj, table in (('older', uncovered_old, adj_old, one_old),
                                     ('newer', uncovered_new, adj_new, one_new)):
        for rva in nodes_:
            budget.tick()
            lost = adj.get(rva, [])
            hints = []
            if lost:
                others = [(e[1] if side == 'older' else e[0]) for e in lost]
                other_group = group_new if side == 'older' else group_old
                if any(x in other_group for x in others):
                    hints.append('lost-to-group')
                if any(x not in other_group for x in others):
                    hints.append('partner-taken')
                hints.append(f'proposal-lost:{len(lost)}')
            extra = [a for f in lost for a in edges[f]]
            rows.append(assemble((rva,) if side == 'older' else (), (rva,) if side == 'newer' else (),
                                 'older-only' if side == 'older' else 'newer-only', list(table.get(rva, ())), [], extra,
                                 hints))
    if len(rows) > limits.l38_rows_per_result:
        raise UnifiedError('PT-UNIFIED-LIMIT', 'The unified result would exceed L-38 rows', reason='rows-cap')
    rows.sort(key=lambda r: (min(r.older, default=ONE_SIDED_SORT), min(r.newer, default=ONE_SIDED_SORT),
                             r.older, r.newer))
    return rows


def _merge_pools(pools: list[tuple[set[int], set[int], list[Atom], str]]):
    """Engine groups that share a function are one group (union-find over their members)."""
    parent: dict[tuple[str, int], tuple[str, int]] = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for older, newer, _atoms, _kind in pools:
        members = [('o', o) for o in sorted(older)] + [('n', n) for n in sorted(newer)]
        for other in members[1:]:
            parent[find(other)] = find(members[0])
    merged: dict[tuple[str, int], list] = {}
    for older, newer, atoms, kind in pools:
        root = find(('o', min(older))) if older else find(('n', min(newer)))
        bucket = merged.setdefault(root, [set(), set(), [], kind])
        bucket[0] |= older
        bucket[1] |= newer
        bucket[2].extend(atoms)
        bucket[3] = min(bucket[3], kind)
    return [(o, n, a, k) for o, n, a, k in sorted(merged.values(), key=lambda b: (min(b[0]), min(b[1])))]


def _assemble(older, newer, decision, chosen_atoms, against_atoms, extra_atoms, hints, pair, key: Callable,
              component: Callable, limits: UnifiedLimits, supported: bool = True) -> Decided:
    cap = limits.l39_atoms_per_row
    chosen = sorted(set(chosen_atoms), key=key)
    against = sorted(set(against_atoms) - set(chosen), key=lambda a: (-TIER_RANK[a.tier], key(a)))
    extra = sorted(set(extra_atoms) - set(chosen) - set(against), key=key)
    reserve = 1 if against else 0
    strongest: dict[str, Atom] = {}
    for a in chosen:  # `chosen` is sorted by (component, tier desc), so the first per component is the strongest
        strongest.setdefault(component(a), a)
    must = list(strongest.values())
    rest = sorted((a for a in chosen if a not in must), key=lambda a: (-TIER_RANK[a.tier], key(a)))
    keep_chosen = must + rest[:max(0, cap - reserve - len(must))]
    room = cap - len(keep_chosen)
    keep_against = against[:room]
    keep_extra = extra[:max(0, room - len(keep_against))]
    omitted = len(chosen) + len(against) + len(extra) - len(keep_chosen) - len(keep_against) - len(keep_extra)
    final = sorted([*keep_chosen, *keep_against, *keep_extra], key=key)
    chosen_set, against_set = set(keep_chosen), set(keep_against)
    support: dict[str, Support] = {}
    for index, a in enumerate(final):
        if supported and a in chosen_set and a.older_rva is not None and a.newer_rva is not None:
            support.setdefault(component(a), Support(component=component(a), tier=a.tier, atom_index=index))
    against_index = tuple(i for i, a in enumerate(final) if a in against_set)
    contest = None
    if against_index:
        strong = any(final[i].tier in STRONG_TIERS for i in against_index)
        contest = Contest(strength='strong' if strong else 'weak', against=against_index)
    all_hints = set(hints)
    if omitted:
        all_hints.add(f'atoms-omitted:{omitted}')
    supports = tuple(sorted(support.values(), key=lambda s: int(s.component[1:])))
    ref = next((a.ref for a in final if a in chosen_set and a.source == 'ghidriff' and a.ref
                and not a.ref.startswith('raw:')), None)
    mapped = decision == 'matched' and pair is not None and any(s.tier in ('A', 'M') for s in supports)
    return Decided(older=tuple(older), newer=tuple(newer), decision=decision, support=supports, contest=contest,
                   atoms=tuple(final), hints=tuple(sorted(all_hints))[:MAX_HINTS], ghidriff_match_id=ref, pair=pair,
                   mapped=mapped)


def to_match(d: Decided, nodes: Mapping, older_sha256: str, newer_sha256: str, *, materiality: str | None = None,
             change_classes: Sequence[str] = (), extra_hints: Sequence[str] = ()) -> UnifiedMatch:
    """The validated persisted row. One-sided and group rows default to `not-applicable` (facts are v1-skipped)."""
    def refs(side: str, rvas: Iterable[int]) -> tuple[SideRef, ...]:
        out = []
        for rva in rvas:
            info = nodes.get((side, rva))
            out.append(SideRef(rva=rva, name=info.name if info else None, kind=info.kind if info else 'unknown'))
        return tuple(out)
    pair_row = d.pair is not None and d.decision in ('matched', 'tentative', 'candidate', 'contested')
    return UnifiedMatch(
        row_id=keys.row_id(older_sha256, newer_sha256, d.older, d.newer), older=refs('older', d.older),
        newer=refs('newer', d.newer), decision=d.decision, support=d.support, contest=d.contest, atoms=d.atoms,
        ghidriff_match_id=d.ghidriff_match_id,
        materiality=materiality or ('unknown' if pair_row else 'not-applicable'),
        change_classes=tuple(change_classes), hints=tuple(sorted({*d.hints, *extra_hints}))[:MAX_HINTS])
