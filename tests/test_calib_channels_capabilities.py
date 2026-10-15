"""LBL-13 capabilities pack: hand-computed goldens."""
from __future__ import annotations

import pytest

from tools.calibration.channels import capabilities as cap
from tools.calibration.channels.capabilities import CapFunction as F
from tools.calibration.channels.capabilities import CapPair as P

NEW = 'newly-introduced'


def _pairs():
    return [
        P('c1', 'L1', 'change', frozenset({'r1', 'r2'}), frozenset({'r1'}),
          (F('f1', True, NEW), F('f2', False, 'unchanged'), F('f3', False, None)),
          (('r1', 'f1'), ('r1', 'f2'))),
        P('c2', 'L2', 'change', frozenset({'r3'}), frozenset({'r3'}),
          (F('g1', False, NEW), F('g2', False, 'unchanged'), F('g3', True, NEW)), (('r3', 'g3'),)),
        P('c3', 'L2', 'aa', frozenset(), frozenset({'r9'})),
        P('c4', 'L3', 'change', frozenset({'r4'}), None),
    ]


def test_golden_metrics():
    r = cap.score(_pairs(), b_count=50)
    assert r.metrics['recall']['point'] == pytest.approx(0.75)  # (1/2 + 1) / 2
    assert r.metrics['localised_precision']['point'] == pytest.approx(0.75)  # (1/2 + 1) / 2
    # unchanged known-state functions: c1 {f2} -> 0/1, c2 {g1, g2} -> 1/2, c3 none (undefined)
    assert r.metrics['violation_rate']['point'] == pytest.approx(0.25)
    assert r.metrics['violation_rate']['n'] == 2


def test_golden_counts_and_invariant_gate():
    r = cap.score(_pairs(), b_count=50)
    assert r.counts == {'unknown_pairs': 1, 'violations': 1, 'aa_pairs': 1, 'aa_deltas': 1}
    assert r.gate == {'no_violations': False}  # g1 is truth-unchanged yet newly-introduced


def test_correct_pairing_has_zero_violations():
    clean = [P('c1', 'L1', 'change', frozenset({'r1'}), frozenset({'r1'}), (F('f1', True, NEW), F('f2', False, 'unchanged')))]
    r = cap.score(clean, b_count=20)
    assert (r.counts['violations'], r.gate, r.metrics['violation_rate']['point']) == (0, {'no_violations': True}, 0.0)
