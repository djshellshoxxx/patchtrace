"""PIL-D1 metrics: tie-aware ordinal metrics over fixed orderings (hermetic, no engine)."""
from __future__ import annotations

import pytest

from tools.calibration.pilot.contracts import ArmOrdering
from tools.calibration.pilot.metrics import case_metrics, truth_set


def m(blocks, truth):
    return case_metrics(ArmOrdering(blocks=tuple(tuple(b) for b in blocks)), frozenset(truth))


@pytest.mark.parametrize(('blocks', 'truth', 'hit1', 'hit3', 'false_leads', 'worst'),
                         [([['a'], ['b'], ['t']], {'t'}, False, True, 2, 3),
                          ([['t'], ['a']], {'t'}, True, True, 0, 1),
                          ([['a', 't', 'b'], ['c']], {'t'}, False, True, 2, 3),
                          ([['a'], ['b']], {'t'}, False, False, 2, None),
                          ([], {'t'}, False, False, 0, None)],
                         ids=['third', 'first', 'tie-worst-case', 'missing', 'abstained'])
def test_first_hit_metrics(blocks, truth, hit1, hit3, false_leads, worst):
    got = m(blocks, truth)
    assert (got.hit[1], got.hit[3], got.false_leads, got.worst_rank) == (hit1, hit3, false_leads, worst)


def test_tie_block_straddling_k_is_not_a_hit_at_k():
    got = m([['a', 'b', 't', 'c']], {'t'})
    assert not got.hit[3] and got.hit[5]


def test_recall_counts_truth_whose_block_ends_within_k():
    got = m([['t1'], ['a'], ['t2', 'b']], {'t1', 't2'})
    assert got.recall[1] == 0.5 and got.recall[3] == 0.5 and got.recall[5] == 1.0


def test_abstained_is_flagged_and_lists_nothing():
    got = m([], {'t'})
    assert got.abstained and got.listed == 0


def test_duplicate_candidates_in_an_ordering_are_rejected():
    with pytest.raises(ValueError, match='duplicate'):
        ArmOrdering(blocks=(('a',), ('a',)))


def test_truth_is_label_changed_and_ok_intersected_with_card():
    labels = [{'key': 'f1', 'label': 'changed', 'check': 'ok'}, {'key': 'f2', 'label': 'changed', 'check': 'disputed'},
              {'key': 'f3', 'label': 'unchanged', 'check': 'ok'}, {'key': 'f4', 'label': 'changed', 'check': 'ok'}]
    assert truth_set(labels, card_changed=['f1', 'f2', 'f3']) == frozenset({'f1'})
