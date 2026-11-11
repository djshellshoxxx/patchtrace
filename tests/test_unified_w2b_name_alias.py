"""LAD-6: P03 indexes a function under each of its names, so a changed ICF fold set keeps the name match.

SYNTHETIC IR only. Rules under test (04 s4 P03, I2): a pair needs a name that is unique on both sides among the
still-unmatched functions AND no other unmatched function shares ANY name of the pair; otherwise abstain.
"""
from __future__ import annotations

import dataclasses
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import SyntheticIr, tag_pairs  # noqa: E402

from patchtrace.unified.ladder import passes  # noqa: E402
from patchtrace.unified.ladder.engine import run_ladder  # noqa: E402
from patchtrace.unified.ladder.passes import PASS_BY_ID, PASS_TABLE_DIGEST, pass_table_digest  # noqa: E402


def solo_p03():
    return [dataclasses.replace(PASS_BY_ID['P03'], neighbour=False, stage=0)]


def world(older_fns, newer_fns):
    older, newer = SyntheticIr(), SyntheticIr()
    for ir, fns in ((older, older_fns), (newer, newer_fns)):
        for tag, name, aliases, extra in fns:
            ir.add(tag, seed=hash_seed(tag), name=name, aliases=aliases, **extra)
    return older, newer


def hash_seed(tag):
    return sum(ord(c) * 31 ** i for i, c in enumerate(tag)) % 100000 + 1


def pairs_of(older, newer):
    return tag_pairs(run_ladder(older, newer, passes=solo_p03()), older, newer)


def test_a_changed_fold_set_keeps_the_name_match():
    older, newer = world([('o', 'Alpha', ('Beta',), {})], [('n', 'Alpha', ('Beta', 'Gamma'), {})])
    corr = run_ladder(older, newer, passes=solo_p03())
    (pair,) = corr.pairs
    assert (pair.pass_id, pair.tier, pair.family) == ('P03', 'A', 'F-PT-NAMES')


def test_a_shrunk_fold_set_keeps_the_name_match_and_is_symmetric():
    older, newer = world([('o', 'Alpha', ('Beta', 'Gamma'), {})], [('n', 'Alpha', (), {})])
    assert pairs_of(older, newer) == {('o', 'n')}
    assert pairs_of(newer, older) == {('n', 'o')}


def test_the_tier_rule_is_unchanged_under_a_changed_fold_set():
    older, newer = world([('o', 'Alpha', ('Beta',), {'n_insn': 10})],
                         [('n', 'Alpha', ('Beta', 'Gamma'), {'n_insn': 100})])
    corr = run_ladder(older, newer, passes=solo_p03())
    (pair,) = corr.pairs
    assert (pair.pass_id, pair.tier, pair.hints) == ('P03', 'C', ('name-body-mismatch',))


@pytest.mark.parametrize('older_fns,newer_fns', [
    ([('o1', 'Dup', (), {}), ('o2', 'Dup', (), {})], [('n', 'Dup', (), {})]),
    ([('o', 'Dup', (), {})], [('n1', 'Dup', (), {}), ('n2', 'Dup', (), {})]),
    ([('o', 'Alpha', ('Beta',), {})], [('n', 'Alpha', ('Gamma',), {}), ('n2', 'Gamma', (), {})]),
    ([('o', 'Alpha', ('Beta',), {}), ('o2', 'Beta', (), {})], [('n', 'Alpha', ('Beta', 'Gamma'), {})]),
    ([('o', 'Alpha', (), {}), ('o2', 'Gamma', (), {})], [('n', 'Alpha', ('Gamma',), {})]),
], ids=['two-older', 'two-newer', 'alias-taken-newer', 'alias-taken-older', 'two-names-two-partners'])
def test_a_name_shared_with_another_unmatched_function_abstains(older_fns, newer_fns):
    older, newer = world(older_fns, newer_fns)
    assert pairs_of(older, newer) == set()
    assert pairs_of(newer, older) == set()


def test_an_overlapping_but_unrelated_function_does_not_block_a_clean_pair():
    older, newer = world([('o', 'Alpha', ('Beta',), {}), ('x', 'Other', (), {})],
                         [('n', 'Alpha', ('Beta', 'Gamma'), {}), ('y', 'Third', (), {})])
    assert pairs_of(older, newer) == {('o', 'n')}


def test_result_is_independent_of_function_order_and_side():
    fns_o = [('f1', 'Alpha', ('Beta',), {}), ('f2', 'Cat', (), {}), ('f3', 'Dog', ('Eel', 'Fox'), {}),
             ('f4', 'Gnu', (), {}), ('f5', 'Gnu', (), {}), ('f6', 'Hen', ('Ibis',), {}), ('f7', 'Ibis', (), {})]
    fns_n = [('g1', 'Alpha', ('Beta', 'Gamma'), {}), ('g2', 'Cat', ('Cow',), {}), ('g3', 'Dog', ('Eel',), {}),
             ('g4', 'Gnu', (), {}), ('g6', 'Hen', (), {}), ('g8', 'Jay', (), {})]
    older, newer = world(fns_o, fns_n)
    base = pairs_of(older, newer)
    assert ('f1', 'g1') in base and ('f2', 'g2') in base and ('f3', 'g3') in base
    assert not any(t[0] in ('f4', 'f5', 'f6', 'f7') for t in base)           # Gnu twice; Hen/Ibis overlap
    rng = random.Random(7)
    for _ in range(6):
        a, b = list(fns_o), list(fns_n)
        rng.shuffle(a)
        rng.shuffle(b)
        o2, n2 = world(a, b)
        assert pairs_of(o2, n2) == base
        assert {(y, x) for x, y in pairs_of(n2, o2)} == base


def test_the_name_pass_digest_moved_with_the_alias_index(monkeypatch):
    assert passes.LADDER_VERSION == 'ladder/4'
    current = pass_table_digest()
    assert current == PASS_TABLE_DIGEST
    monkeypatch.setattr(passes, 'LADDER_VERSION', 'ladder/3')
    assert pass_table_digest() != current                                     # the version is part of the digest
    assert PASS_BY_ID['P03'].run is not None                                  # and the pass now has its own run hook
    rows = [dataclasses.replace(p, run=None) if p.id == 'P03' else p for p in passes.PASSES]
    assert pass_table_digest(rows) != pass_table_digest()
