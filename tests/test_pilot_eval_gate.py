"""PIL-D1 pre-registered gate, ablation arms, report determinism, single-use lock (hermetic)."""
from __future__ import annotations

import pytest

from patchtrace.pilot.contracts import CHANNELS
from tools.calibration.pilot.ablation import arm_names, drop_channel
from tools.calibration.pilot.contracts import CaseOutcome
from tools.calibration.pilot.gate import evaluate_gate, locked_gate, relative_false_lead_reduction
from tools.calibration.pilot.report import PREREG_PATH, build_report, render_markdown
from tools.calibration.run_locked_test import LockedTestError


def outcomes(n, p_false, b_false, p_r10=1.0, b_r10=1.0):
    return [CaseOutcome(case_id=f'c{i}', lineage=f'L{i}', p_false_leads=p_false, b_false_leads=b_false,
                        p_recall10=p_r10, b_recall10=b_r10) for i in range(n)]


def test_relative_reduction_is_ratio_of_totals():
    assert relative_false_lead_reduction(outcomes(2, 1, 4)) == pytest.approx(0.75)
    assert relative_false_lead_reduction(outcomes(2, 0, 0)) is None


def test_fewer_than_thirty_lineages_is_insufficient_data_even_with_a_huge_win():
    assert evaluate_gate(outcomes(29, 0, 9), b_count=50, seed='s')['status'] == 'insufficient-data'


def test_thirty_lineages_with_a_clear_win_passes():
    gate = evaluate_gate(outcomes(30, 1, 10), b_count=200, seed='s')
    assert gate['status'] == 'pass' and gate['conditions']['lineages_ok']


def test_no_reduction_fails_with_enough_lineages():
    assert evaluate_gate(outcomes(30, 5, 5), b_count=200, seed='s')['status'] == 'fail'


def test_recall_loss_fails_even_when_false_leads_drop():
    assert evaluate_gate(outcomes(30, 1, 10, p_r10=0.0, b_r10=1.0), b_count=200, seed='s')['status'] == 'fail'


def test_gate_is_deterministic():
    assert evaluate_gate(outcomes(30, 2, 9), b_count=100, seed='s') == evaluate_gate(outcomes(30, 2, 9), b_count=100,
                                                                                      seed='s')


def test_loco_has_one_arm_per_channel_and_drops_exactly_that_channel():
    names = arm_names()
    assert {f'loco-{c}' for c in CHANNELS} <= set(names) and len(set(names)) == len(names)
    assert drop_channel(CHANNELS, CHANNELS[0]) == CHANNELS[1:]
    with pytest.raises(ValueError, match='unknown channel'):
        drop_channel(CHANNELS, 'nope')


def test_prereg_file_exists_and_report_is_byte_identical():
    assert PREREG_PATH.is_file()
    gate = evaluate_gate(outcomes(3, 1, 2), b_count=10, seed='s')
    kw = dict(prereg_sha='a' * 64, corpus_sha='b' * 64, tool_sha='c' * 40, arms={}, gate=gate, exclusions={})
    one, two = build_report(**kw), build_report(**kw)
    assert one == two and render_markdown(one) == render_markdown(two)
    assert 'insufficient-data' in render_markdown(one)


def test_locked_gate_runs_once_per_preregistration(tmp_path):
    sha = 'd' * 64
    first = locked_gate(tmp_path, sha, outcomes(3, 1, 2), b_count=10, seed='s')
    assert first['result']['status'] == 'insufficient-data'
    with pytest.raises(LockedTestError):
        locked_gate(tmp_path, sha, outcomes(3, 1, 2), b_count=10, seed='s')
