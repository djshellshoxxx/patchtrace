"""Pair and nuisance truth tests; UNVERIFIED until run. No generated image is executed."""
from __future__ import annotations

import struct

import pytest
from hypothesis import given, settings, strategies as st
from unified_support.nuisance import KINDS as NUISANCES
from unified_support.nuisance import nuisance_pair
from unified_support.pairs import KINDS, corpus, pair_for


@pytest.mark.parametrize("kind", KINDS, ids=list(KINDS))
def test_each_transformation_has_total_explicit_identity_truth(kind: str) -> None:
    pair = pair_for(kind, 7)
    older, newer = set(dict(pair.older.functions)), set(dict(pair.newer.functions))
    assert {n for r in pair.relations for n in r.older} == older
    assert {n for r in pair.relations for n in r.newer} == newer
    old_rvas = [r for relation in pair.rva_relations() for r in relation[0]]
    new_rvas = [r for relation in pair.rva_relations() for r in relation[1]]
    assert len(old_rvas) == len(set(old_rvas))
    assert len(new_rvas) == len(set(new_rvas))
    assert pair == pair_for(kind, 7)
    assert pair.older.data.startswith(b"MZ") and pair.newer.data.startswith(b"MZ")
    assert (pair.digests[0] == pair.digests[1]) == (kind == "unchanged")


def test_n_to_m_transformations_never_pretend_to_be_single_pair_truth() -> None:
    expected = {"inlined": (2, 1), "split": (1, 3), "merged": (3, 1)}
    for kind, shape in expected.items():
        [relation] = pair_for(kind).relations
        assert (len(relation.older), len(relation.newer)) == shape


@pytest.mark.parametrize("kind", NUISANCES, ids=list(NUISANCES))
def test_nuisance_pair_changes_bytes_and_keeps_authored_identity(kind: str) -> None:
    pair = nuisance_pair(kind, 11)
    assert pair.digests[0] != pair.digests[1]
    assert all(r.older == r.newer and r.change == "nuisance" for r in pair.relations)
    assert pair == nuisance_pair(kind, 11)


@settings(max_examples=16, derandomize=True, deadline=None)
@given(st.integers(min_value=0, max_value=9999))
def test_moved_relative_call_still_targets_its_counterpart(seed: int) -> None:
    pair = nuisance_pair("address-shift", seed)
    targets = []
    for image in (pair.older, pair.newer):
        functions = dict(image.functions)
        caller = functions["entry"]
        offset = image.offset(caller)
        assert image.data[offset] == 0xe8
        target = caller + 5 + struct.unpack_from("<i", image.data, offset + 1)[0]
        assert target == functions["helper"]
        targets.append(target)
    assert targets[1] - targets[0] == 64


def test_corpus_count_and_seed_boundaries() -> None:
    assert len(corpus(2)) == len(KINDS) * 2
    assert len({(p.kind, p.seed) for p in corpus(2)}) == len(KINDS) * 2
    for n in (0, 101, True):
        with pytest.raises(ValueError):
            corpus(n)
    with pytest.raises(ValueError):
        pair_for("invented")
