"""SPEC-31 05 s1 / U7-08: the arbiter is orientation-symmetric (older<->newer swap mirrors every row, every decision
kind) and input-order invariant (D-16). Synthetic atoms, derandomised."""
from __future__ import annotations

import random

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion import arbiter
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.sources import SourceGroup

SETTINGS = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                    suppress_health_check=[HealthCheck.too_slow])

SPECS = (
    ('ghidriff', 'SymbolsHash', 'A', 'E-NAME'),
    ('ghidriff', 'ExactMnemonicsFunctionHasher', 'B', 'E-BODY'),
    ('ghidriff', 'StructuralGraphHash', 'C', 'E-CFG'),
    ('ghidriff', 'Weird', 'C', 'E-UNKNOWN'),
    ('bindiff', 'prime signature matching', 'B', 'E-BODY'),
    ('bindiff', 'string references', 'C', 'E-DATA'),
    ('pt-bytes', 'P08-mnemonic-seq', 'B', 'E-BODY'),
    ('pt-ladder', 'P11-md-callgraph', 'B', 'E-CALL'),
    ('rz-diff', 'levenshtein-bytes', 'W', 'E-BODY'),
    ('manual', 'manual-correction', 'M', 'E-MANUAL'),
)
RVA = st.integers(min_value=0, max_value=4)
CARD = {'1:1': '1:1', '1:N': 'N:1', 'N:1': '1:N', 'N:M': 'N:M', 'non-exclusive': 'non-exclusive'}
FLIP = {'older-only': 'newer-only', 'newer-only': 'older-only'}


def make(spec, old, new, card='1:1'):
    source, step, tier, cls = spec
    return Atom(source=source, step=step, tier=tier, cls=cls, older_rva=old, newer_rva=new, cardinality=card)


def mirror_atom(a: Atom) -> Atom:
    return a.model_copy(update={'older_rva': a.newer_rva, 'newer_rva': a.older_rva,
                                'cardinality': CARD[a.cardinality]})


def mirror_group(g: SourceGroup) -> SourceGroup:
    return SourceGroup(kind=g.kind, source=g.source, older=g.newer, newer=g.older, decision=g.decision,
                       reason=g.reason, atoms=tuple(mirror_atom(a) for a in g.atoms))


def project(row, mirrored: bool):
    older, newer = (row.newer, row.older) if mirrored else (row.older, row.newer)
    decision = FLIP.get(row.decision, row.decision) if mirrored else row.decision
    contest = None if row.contest is None else (row.contest.strength, len(row.contest.against))
    return (tuple(sorted(older)), tuple(sorted(newer)), decision, contest,
            tuple(sorted((s.component, s.tier) for s in row.support)),
            tuple(sorted(row.hints)), row.ghidriff_match_id)


atoms_st = st.lists(st.tuples(st.sampled_from(SPECS), st.one_of(st.none(), RVA), st.one_of(st.none(), RVA))
                    .filter(lambda t: t[1] is not None or t[2] is not None), min_size=1, max_size=14)
groups_st = st.lists(st.tuples(st.sets(RVA, min_size=1, max_size=3), st.sets(RVA, min_size=1, max_size=3)),
                     max_size=2)


def build(raw_atoms, raw_groups):
    atoms = [make(s, o, n) for s, o, n in raw_atoms]
    groups = []
    for older, newer in raw_groups:
        gatoms = tuple(make(SPECS[0], o, n, 'N:M') for o in sorted(older) for n in sorted(newer))
        groups.append(SourceGroup(kind='test', source='ghidriff', older=tuple(sorted(older)),
                                  newer=tuple(sorted(newer)), decision='ambiguous', reason='test', atoms=gatoms))
    return atoms, groups


@SETTINGS
@given(atoms_st, groups_st)
def test_orientation_swap_mirrors_every_row(raw_atoms, raw_groups):
    atoms, groups = build(raw_atoms, raw_groups)
    try:
        rows = arbiter.decide(atoms, groups)
    except UnifiedError as exc:  # two manual claims on one function: the mirror must refuse alike
        with pytest.raises(UnifiedError) as again:
            arbiter.decide([mirror_atom(a) for a in atoms], [mirror_group(g) for g in groups])
        assert again.value.reason == exc.reason
        return
    mirrored = arbiter.decide([mirror_atom(a) for a in atoms], [mirror_group(g) for g in groups])
    left = sorted((project(r, True) for r in rows), key=repr)
    right = sorted((project(r, False) for r in mirrored), key=repr)
    assert left == right


@SETTINGS
@given(atoms_st, groups_st, st.randoms(use_true_random=False))
def test_input_order_is_invisible_with_groups(raw_atoms, raw_groups, rnd: random.Random):
    atoms, groups = build(raw_atoms, raw_groups)
    try:
        base = arbiter.decide(atoms, groups)
    except UnifiedError:
        return
    a2, g2 = list(atoms), list(groups)
    rnd.shuffle(a2)
    rnd.shuffle(g2)
    assert arbiter.decide(a2, g2) == base
