"""QA-S2 rules gates: the pure eligibility predicates over large, boundary and pathological numbers, and the
first-blocking scan over 10k-gate lists. The YARA-X compile path is optional and not exercised here.
"""
from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.rules import gates as g
from patchtrace.rules.contracts import Gate

SCALE = int(os.environ.get('PATCHTRACE_STRESS_SCALE', '1'))
SETTINGS = settings(max_examples=300, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
NUMBERS = st.integers(min_value=0, max_value=10**15)


@SETTINGS
@given(NUMBERS, NUMBERS)
def test_long_enough_passes_exactly_at_both_thresholds(literal, run):
    gate = g.long_enough(literal, run)
    expected = literal >= g.MIN_LITERAL_BYTES and run >= g.MIN_LITERAL_RUN
    assert g.passed(gate) is expected
    assert gate.state in {'pass', 'fail'}


@SETTINGS
@given(st.integers(min_value=1, max_value=10**12), st.data())
def test_wildcard_share_boundary_is_exact(length, data):
    literal = data.draw(st.integers(min_value=0, max_value=length))
    wild = length - literal
    gate = g.not_mostly_wildcards(length, literal)
    assert g.passed(gate) is (wild * 100 <= g.MAX_WILDCARD_PERCENT * length)
    assert gate.measured == wild * 100 // length


@pytest.mark.parametrize('source_hits', [None, 0, 1, 2, 10**18], ids=['none', 'zero', 'one', 'two', 'huge'])
def test_uniqueness_gate_states_are_never_a_silent_pass(source_hits):
    gate = g.one_place(source_hits)
    if source_hits is None:
        assert gate.state == 'unknown' and not g.passed(gate)
    else:
        assert g.passed(gate) is (source_hits == 1)


@SETTINGS
@given(st.one_of(st.none(), NUMBERS))
def test_separation_gate_unknown_is_not_a_negative_vote(other_hits):
    gate = g.absent_elsewhere(other_hits)
    if other_hits is None:
        assert gate.state == 'unknown'
    else:
        assert g.passed(gate) is (other_hits == 0)


def test_first_blocking_returns_the_first_failing_gate_in_a_long_list():
    passing = [Gate(gate_id='len', state='pass', measured=1) for _ in range(10_000 * SCALE)]
    failing = Gate(gate_id='sep', state='fail', measured=3)
    later = Gate(gate_id='compile', state='fail', measured=4)
    found = g.first_blocking(passing + [failing, later])
    assert found is failing


def test_first_blocking_is_none_when_every_gate_is_waived_or_passed():
    gates = [Gate(gate_id='elig', state='waived', measured='confirmed'),
             Gate(gate_id='len', state='pass', measured=20)] * (5_000 * SCALE)
    assert g.first_blocking(gates) is None


@pytest.mark.xfail(strict=True, reason='QA-S2-5: not_mostly_wildcards(0, 0) divides by a zero window length and raises '
                   'ZeroDivisionError instead of returning a failed gate')
def test_empty_window_fails_the_wildcard_gate_without_raising():
    gate = g.not_mostly_wildcards(0, 0)
    assert not g.passed(gate)
