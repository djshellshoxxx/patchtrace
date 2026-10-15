"""LBL-13 rules pack: BLOCKED while YARA-X is missing; hand-computed matrix goldens when it is available."""
from __future__ import annotations

import importlib.util

import pytest

from tools.calibration.channels import rules
from tools.calibration.channels.rules import RuleMatch as M


def _rows():
    return [
        M('A', 'L1', 'u1', 'gcc', 'unpatched', True),
        M('A', 'L1', 'u2', 'clang', 'unpatched', False),
        M('A', 'L1', 'p1', 'gcc', 'patched', False),
        M('A', 'L2', 'x1', 'gcc', 'unrelated', True),
        M('B', 'L2', 'u3', 'gcc', 'unpatched', True),
        M('B', 'L2', 'p3', 'gcc', 'patched', None),
        M('B', 'L3', 'x2', 'clang', 'unrelated', False),
    ]


def test_blocked_is_listed_with_reason_not_skipped():
    r = rules.score(_rows(), available=False)
    assert (r.pack, r.status, r.reason, r.metrics, r.pairs) == ('rules', 'blocked', rules.BLOCKED_REASON, {}, 0)


def test_default_availability_follows_yara_x(monkeypatch):
    monkeypatch.setattr(importlib.util, 'find_spec', lambda name: None)
    assert rules.score(_rows()).status == 'blocked'
    monkeypatch.setattr(importlib.util, 'find_spec', lambda name: object())
    assert rules.score(_rows(), b_count=20).status == 'ok'


def test_golden_matrix():
    r = rules.score(_rows(), b_count=50, available=True)
    assert r.metrics['tp_rate']['point'] == pytest.approx(2 / 3)  # u1, u3 match; u2 missed
    assert r.metrics['fp_rate']['point'] == pytest.approx(1 / 3)  # x1 matches; p1, x2 do not; p3 unknown
    assert r.counts == {'unknown_rows': 1, 'fp': 1, 'tp:clang': 0, 'tp:gcc': 2, 'fn:clang': 1, 'fn:gcc': 0}
    assert r.gate == {'no_false_positives': False}


def test_unknown_role_rejected():
    with pytest.raises(ValueError):
        M('A', 'L', 'i', 'gcc', 'other', True)
