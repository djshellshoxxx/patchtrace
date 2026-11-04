"""Mirror property of the fusion arbiter (SPEC-31 05 s1.3, 08 G-U4, audit U7-08): deciding the swapped input gives
the mirror image of the forward rows. SYNTHETIC atoms and groups only; derandomised (docs/qa.md T-29).

The generated inputs mix sources of both independence components, every tier including analyst tier-M atoms,
one-sided observations, engine groups (which merge into pools when they share a function) and analyst groups. Both
sides draw from the same RVA numbers, so equal-strength ties between the two orientations are common. Rows are
compared as values: endpoints, decision (older-only and newer-only trade places), the pair, `mapped`, hints, the set
of atoms, and support and contest through the atoms their indices name (an index depends on the row's atom order,
the atom it names does not). `ghidriff_match_id` is not compared: an ambiguous row of two merged Ghidriff groups
names the first match id in atom order, and a swapped Ghidriff run has its own match ids anyway.

A failing property is a defect in src: it is marked strict xfail with a one-line reason, never weakened.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Sequence

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion import arbiter
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.sources import SourceGroup

MIRROR = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                  suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])

RVAS = tuple(0x1000 + 16 * i for i in range(6))     # the same numbers on both sides
EDGE = (('ghidriff', 'SymbolsHash', 'A', 'E-NAME'), ('ghidriff', 'ExactMnemonicsFunctionHasher', 'B', 'E-BODY'),
        ('ghidriff', 'StringsRefsHasher', 'B', 'E-DATA'), ('ghidriff', 'StructuralGraphHash', 'C', 'E-CFG'),
        ('ghidriff', 'Implied Match', 'C', 'E-UNKNOWN'), ('bindiff', 'name hash matching', 'A', 'E-NAME'),
        ('bindiff', 'prime signature matching', 'B', 'E-BODY'), ('pt-ladder', 'P04-bytes-exact', 'A', 'E-BODY'),
        ('pt-bytes', 'P08-mnemonic-seq', 'B', 'E-BODY'), ('rz-diff', 'levenshtein-bytes', 'W', 'E-BODY'))
GROUP_SPECS = EDGE[:3] + EDGE[5:9]
ONE_SIDED = (('ghidriff', 'added', 'W', 'E-UNKNOWN'), ('rz-diff', 'unmatched', 'W', 'E-UNKNOWN'))
MANUAL = ('manual', 'manual-correction', 'M', 'E-MANUAL')
FLIP_DECISION = {'older-only': 'newer-only', 'newer-only': 'older-only'}
FLIP_CARD = {'1:N': 'N:1', 'N:1': '1:N'}


def make(spec: tuple[str, str, str, str], old: int | None, new: int | None, card: str = '1:1',
         ref: str | None = None) -> Atom:
    source, step, tier, cls = spec
    return Atom(source=source, step=step, tier=tier, cls=cls, cardinality=card, older_rva=old, newer_rva=new, ref=ref)


def mirror_atom(a: Atom) -> Atom:
    return a.model_copy(update={'older_rva': a.newer_rva, 'newer_rva': a.older_rva,
                                'cardinality': FLIP_CARD.get(a.cardinality, a.cardinality)})


def mirror_group(g: SourceGroup) -> SourceGroup:
    return dataclasses.replace(g, older=g.newer, newer=g.older, atoms=tuple(mirror_atom(a) for a in g.atoms))


def shape_card(older: Sequence[int], newer: Sequence[int]) -> str:
    if len(older) == 1:
        return '1:N'
    return 'N:1' if len(newer) == 1 else 'N:M'


@st.composite
def inputs(draw) -> tuple[list[Atom], list[SourceGroup]]:
    rvas = RVAS[:draw(st.integers(min_value=1, max_value=len(RVAS)))]
    rva = st.sampled_from(rvas)
    atoms: list[Atom] = []
    for _ in range(draw(st.integers(min_value=0, max_value=18))):
        kind = draw(st.sampled_from(('edge',) * 6 + ('one-sided', 'one-sided', 'manual')))
        if kind == 'edge':
            spec = draw(st.sampled_from(EDGE))
            card = draw(st.sampled_from(('1:1', 'non-exclusive'))) if spec[2] == 'W' else '1:1'
            ref = draw(st.sampled_from((None, 'm1', 'm2'))) if spec[0] == 'ghidriff' else None
            atoms.append(make(spec, draw(rva), draw(rva), card, ref))
            continue
        spec = MANUAL if kind == 'manual' else draw(st.sampled_from(ONE_SIDED))
        side = draw(st.sampled_from(('pair', 'older', 'newer') if kind == 'manual' else ('older', 'newer')))
        old = draw(rva) if side in ('pair', 'older') else None
        new = draw(rva) if side in ('pair', 'newer') else None
        atoms.append(make(spec, old, new, ref='mm' if kind == 'manual' else None))
    groups: list[SourceGroup] = []
    for _ in range(draw(st.integers(min_value=0, max_value=3))):
        older = tuple(sorted(draw(st.sets(rva, min_size=1, max_size=2))))
        newer = tuple(sorted(draw(st.sets(rva, min_size=1, max_size=3))))
        if len(older) == len(newer) == 1:
            continue
        card = shape_card(older, newer)
        if draw(st.integers(min_value=0, max_value=3)) == 0:
            groups.append(SourceGroup(kind=draw(st.sampled_from(('manual-split', 'manual-merge'))), source='manual',
                                      older=older, newer=newer, decision='matched', reason='synthetic',
                                      atoms=tuple(make(MANUAL, o, n, card, 'mg') for o in older for n in newer)))
            continue
        spec = draw(st.sampled_from(GROUP_SPECS))
        kept = tuple(make(spec, o, n, card) for o in older for n in newer if draw(st.booleans()) or o == older[0])
        groups.append(SourceGroup(kind=draw(st.sampled_from(('ghidriff-1n', 'ladder-nm', 'icf'))), source=spec[0],
                                  older=older, newer=newer, decision='ambiguous', reason='synthetic', atoms=kept))
    return atoms, groups


def view(row: arbiter.Decided, *, mirror: bool) -> tuple:
    atoms = [mirror_atom(a) if mirror else a for a in row.atoms]
    older, newer = (row.newer, row.older) if mirror else (row.older, row.newer)
    pair = row.pair[::-1] if mirror and row.pair is not None else row.pair
    support = frozenset((s.component, s.tier, atoms[s.atom_index]) for s in row.support)
    contest = None if row.contest is None else (row.contest.strength, frozenset(atoms[i] for i in row.contest.against))
    decision = FLIP_DECISION.get(row.decision, row.decision) if mirror else row.decision
    return older, newer, decision, support, contest, pair, row.mapped, row.hints, frozenset(atoms)


def outcome(atoms: Sequence[Atom], groups: Sequence[SourceGroup], *, mirror: bool) -> tuple:
    try:
        rows = arbiter.decide(atoms, groups)
    except UnifiedError as exc:            # two analyst claims on one function: the swap must refuse it the same way
        return 'error', exc.code, exc.reason
    views = [view(r, mirror=mirror) for r in rows]
    return 'rows', len(views), frozenset(views)


@MIRROR
@given(inputs())
def test_swapped_inputs_give_the_mirrored_rows(case: tuple[list[Atom], list[SourceGroup]]) -> None:
    atoms, groups = case
    forward = outcome(atoms, groups, mirror=True)
    swapped = outcome([mirror_atom(a) for a in atoms], [mirror_group(g) for g in groups], mirror=False)
    assert forward == swapped


def test_an_equal_strength_tie_resolves_to_the_same_pairs_in_both_orientations() -> None:
    """The (-older, -newer) tie-break of `strength` reads the sides in a fixed order, yet both orientations choose
    the same pairs: within one strength level each side ranks the other side by RVA alone (a master list), so the
    greedy choice is the unique stable matching and does not depend on which side is called older."""
    spec = EDGE[1]
    atoms = [make(spec, 0x1000, 0x1010), make(spec, 0x1010, 0x1000), make(spec, 0x1000, 0x1000),
             make(spec, 0x1010, 0x1010)]
    forward = arbiter.decide(atoms, [])
    swapped = arbiter.decide([mirror_atom(a) for a in atoms], [])
    assert {(r.older, r.newer) for r in forward} == {((0x1000,), (0x1000,)), ((0x1010,), (0x1010,))}
    assert {view(r, mirror=True) for r in forward} == {view(r, mirror=False) for r in swapped}
    assert all(r.decision == 'contested' for r in forward)
