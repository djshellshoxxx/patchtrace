"""LBL-13 strings pack: hand-computed goldens."""
from __future__ import annotations

import pytest

from tools.calibration.channels import strings
from tools.calibration.channels.strings import StringsPair as P


def _d(*texts, op='+'):
    return frozenset((op, t) for t in texts)


def _pairs():
    return [
        P('p1', 'L1', 'change', _d('a', 'b') | _d('c', op='-'), _d('a', 'x'), representation_changed=_d('x')),
        P('p2', 'L2', 'change', _d('d'), _d('d')),
        P('p3', 'L2', 'change', _d('e'), frozenset()),
        P('p4', 'L1', 'aa', frozenset(), _d('z', 'date'), allowed_noise=_d('date')),
        P('p5', 'L3', 'aa', frozenset(), frozenset()),
        P('p6', 'L3', 'change', _d('q'), None),
    ]


def test_golden_precision_recall():
    r = strings.score(_pairs(), b_count=50)
    # precision: p1 flagged {+a,+x} hits 1 of 2 = 1/2; p2 1; p3 undefined (nothing flagged)
    assert r.metrics['precision']['point'] == pytest.approx(0.75)
    assert r.metrics['precision']['n'] == 2
    # recall: p1 1/3, p2 1, p3 0 -> 4/9
    assert r.metrics['recall']['point'] == pytest.approx(4 / 9)
    assert r.metrics['recall']['n'] == 3


def test_golden_counts_and_unknown_is_not_negative():
    r = strings.score(_pairs(), b_count=50)
    assert r.counts == {'unknown_pairs': 1, 'aa_pairs': 2, 'aa_false_adds': 1, 'aa_pairs_with_false_adds': 1,
                        'representation_misflags': 1}
    assert (r.pairs, r.lineages, r.status) == (5, 3, 'ok')  # p6 (None) is neither a hit nor a miss
    assert r.gate == {'aa_false_adds_zero': False}


def test_interval_is_anti_conservative_below_30_lineages():
    iv = strings.score(_pairs(), b_count=50).metrics['recall']
    assert iv['anti_conservative'] is True
    assert iv['lo'] <= iv['point'] <= iv['hi']


def test_empty_input_has_undefined_metrics():
    r = strings.score([], b_count=10)
    assert r.metrics['precision']['point'] is None and r.gate == {'aa_false_adds_zero': None}
