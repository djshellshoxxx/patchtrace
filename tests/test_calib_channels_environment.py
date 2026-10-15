"""LBL-13 environment pack: hand-computed goldens."""
from __future__ import annotations

import pytest

from tools.calibration.channels import environment as env
from tools.calibration.channels.environment import EnvPair as P


def _pairs(packed=None):
    return [
        P('e1', 'L1', 'noise', True, pool_size=10, pool_truth_changed=2),
        P('e2', 'L1', 'noise', False, pool_size=10, pool_truth_changed=1),
        P('e3', 'L2', 'noise', True, pool_size=20, pool_truth_changed=8),
        P('e4', 'L2', 'noise', None, environment_unknown=True),
        P('e5', 'L3', 'aa', False, pool_size=10, pool_truth_changed=5),
        P('e6', 'L3', 'opt-only', False, pool_size=10, pool_truth_changed=2),
        P('e7', 'L4', 'layout', True, packed=packed, pool_size=4, pool_truth_changed=1),
    ]


def test_golden_recall_specificity_unknown():
    r = env.score(_pairs(), b_count=50)
    assert r.metrics['noise_recall']['point'] == pytest.approx(2 / 3)  # e4 unknown is excluded, not a miss
    assert r.metrics['noise_recall']['n'] == 3
    assert r.metrics['specificity']['point'] == pytest.approx(2 / 3)  # e5, e6 correct; e7 false alarm
    assert r.metrics['unknown_rate']['point'] == pytest.approx(1 / 7)


def test_golden_purity_by_flag_group():
    r = env.score(_pairs(), b_count=50)
    assert r.metrics['purity_flagged']['point'] == pytest.approx((0.2 + 0.4 + 0.25) / 3)  # e1 e3 e7
    assert r.metrics['purity_unflagged']['point'] == pytest.approx((0.1 + 0.5 + 0.2) / 3)  # e2 e5 e6


def test_packed_must_be_false_everywhere():
    clean = env.score(_pairs(packed=False), b_count=20)
    assert (clean.gate, clean.counts['unknown_pairs'], clean.counts['pairs_noise']) == (
        {'packed_protected_false': True}, 1, 3)
    bad = env.score(_pairs(packed=True), b_count=20)
    assert (bad.counts['packed_true'], bad.gate) == (1, {'packed_protected_false': False})


def test_unknown_kind_rejected():
    with pytest.raises(ValueError):
        P('x', 'L', 'bogus', None)
