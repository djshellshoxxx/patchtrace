"""Hypothesis properties of the fusion arbiter (SPEC-31 05 s1): determinism, input-order invariance, unknown is no
negative vote, shared-origin and same-class evidence count once. SYNTHETIC atoms only; derandomised (docs/qa.md T-29).

A failing property is a defect in src: it is marked strict xfail with a one-line reason, never weakened.
"""
from __future__ import annotations

import random
from collections.abc import Sequence

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion import arbiter

FAST = settings(max_examples=40, deadline=None, derandomize=True, database=None,
                suppress_health_check=[HealthCheck.too_slow])

STRONG = ('ghidriff', 'SymbolsHash', 'A', 'E-NAME')
BODY_A = ('ghidriff', 'ExactMnemonicsFunctionHasher', 'B', 'E-BODY')
BODY_B = ('pt-bytes', 'P08-mnemonic-seq', 'B', 'E-BODY')
WEAK = ('rz-diff', 'levenshtein-bytes', 'W', 'E-BODY')
SHARED = ('ghidriff', 'StringsRefsHasher', 'B', 'E-DATA')
SHARED_B = ('bindiff', 'prime signature matching', 'B', 'E-BODY')


def atom(spec: tuple[str, str, str, str], old: int | None, new: int | None,
         native: tuple[tuple[str, str], ...] = ()) -> Atom:
    source, step, tier, cls = spec
    return Atom(source=source, step=step, tier=tier, cls=cls, older_rva=old, newer_rva=new, cardinality='1:1',
                native=native)


def shape(rows: Sequence) -> list:
    return [(r.older, r.newer, r.decision, r.support, r.contest, r.hints) for r in rows]


@FAST
@given(st.integers(min_value=0, max_value=255), st.integers(min_value=0, max_value=255))
def test_same_input_gives_same_rows_twice(offset: int, shift: int) -> None:
    old, new = 0x1000 + offset * 16, 0x10000 + shift * 16
    atoms = [atom(STRONG, old, new), atom(WEAK, old, new + 8), atom(SHARED, old, new)]
    assert shape(arbiter.decide(atoms, [])) == shape(arbiter.decide(list(atoms), []))


@FAST
@given(st.integers(min_value=0, max_value=255), st.randoms(use_true_random=False))
def test_input_order_is_invisible(offset: int, rnd: random.Random) -> None:
    old, new = 0x1000 + offset * 16, 0x10000 + offset * 16
    atoms = [atom(STRONG, old, new), atom(WEAK, old, new + 8), atom(BODY_A, old, new),
             atom(BODY_B, old, new), atom(SHARED, old, new)]
    shuffled = list(atoms)
    rnd.shuffle(shuffled)
    assert shape(arbiter.decide(atoms, [])) == shape(arbiter.decide(shuffled, []))


@FAST
@given(st.integers(min_value=0, max_value=255), st.integers(min_value=1, max_value=6))
def test_one_sided_unknown_observations_never_vote_against_a_match(offset: int, extra: int) -> None:
    old, new = 0x1000 + offset * 16, 0x10000 + offset * 16
    strong = atom(STRONG, old, new)
    [before] = arbiter.decide([strong], [])
    noise = [atom(WEAK, old, None) for _ in range(extra)] + [atom(WEAK, None, new) for _ in range(extra)]
    [after] = arbiter.decide([strong, *noise], [])
    assert before.decision == after.decision == 'matched'
    assert before.support == after.support
    assert after.contest is None


@FAST
@given(st.integers(min_value=0, max_value=255), st.integers(min_value=1, max_value=8))
def test_same_class_sources_never_make_a_match(offset: int, copies: int) -> None:
    old, new = 0x1000 + offset * 16, 0x10000 + offset * 16
    rows = arbiter.decide([atom(BODY_A, old, new)] * copies + [atom(BODY_B, old, new)], [])
    [row] = rows
    assert row.decision == 'tentative'
    assert row.decision != 'matched'


@pytest.mark.xfail(strict=True, reason='support lists both same-class E-BODY atoms (K1, K2); spec 05 s1.1 says they do not corroborate')
def test_same_class_support_lists_one_atom() -> None:
    old, new = 0x1000, 0x2000
    [row] = arbiter.decide([atom(BODY_A, old, new), atom(BODY_B, old, new)], [])
    assert len(row.support) == 1


@FAST
@given(st.integers(min_value=0, max_value=255), st.integers(min_value=1, max_value=8))
def test_shared_origin_duplicates_count_once(offset: int, copies: int) -> None:
    old, new = 0x1000 + offset * 16, 0x10000 + offset * 16
    common = [atom(SHARED, old, new), atom(SHARED_B, old, new)]
    [row] = arbiter.decide(common * copies, [])
    assert row.decision == 'tentative'
    assert len(row.support) == 1


@FAST
@given(st.sampled_from(('0', '0.001', '0.5', '0.999', '1', 'nan')),
       st.sampled_from(('0', '0.001', '0.5', '0.999', '1')))
def test_native_scores_never_change_shape(first: str, second: str) -> None:
    old, new = 0x1000, 0x2000
    atoms = [atom(SHARED, old, new), atom(BODY_B, old, new), atom(WEAK, old, new + 0x100)]
    changed = [a.model_copy(update={'native': (('similarity', first), ('confidence', second))}) for a in atoms]
    assert shape(arbiter.decide(atoms, [])) == shape(arbiter.decide(changed, []))
