"""SPEC-31 harness audit (card har): a stored bench report whose gates, checks or verdict no longer follow from its own
measurements is refused (the counts digest alone protects only the counts); U-05 decision_ready needs the gates to exist."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS.parent), str(TESTS), str(TESTS.parent / 'src')]
from unified_s6_helpers import evaluated, row  # noqa: E402

from tools.calibration.tier_r.contracts import ContractError  # noqa: E402
from tools.unified import bench, gates_u  # noqa: E402


def stored(*rows, mutate=None):
    data = json.loads(bench.dump(bench.report(evaluated(*rows), bench.environment())))
    if mutate:
        mutate(data)
    return json.dumps(data).encode('utf-8')


def test_an_untampered_report_loads():
    built = bench.load(stored(row(n=10_000, ticks=60_000), row(n=60_000, ticks=360_000), row('ingest', 60_000)))
    assert built.verdict == 'pass' and all(g.verdict == 'pass' for r in built.rows for g in r.gates)


@pytest.mark.parametrize('edit', ['verdict', 'gate-verdict', 'seconds', 'check', 'rss', 'allowed'])
def test_a_report_edited_after_generation_is_refused_though_the_counts_digest_still_matches(edit):
    def tamper(data):
        slow = data['rows'][0]
        if edit == 'verdict':
            data['verdict'] = 'pass'
        elif edit == 'gate-verdict':
            slow['gates'][0]['verdict'] = 'pass'
        elif edit == 'seconds':
            slow['seconds']['total'] = 0.001
        elif edit == 'check':
            for check in slow['checks']:
                check['ok'] = True
        elif edit == 'rss':
            data['rows'][1]['peak_rss_bytes'] = 1
        elif edit == 'allowed':
            slow['gates'][0]['allowed'] = 10**9
    slow_rows = (row(n=10_000, ladder=10**6, wrong=1), row(n=60_000, ticks=360_000, rss=10**12))
    with pytest.raises(ContractError, match='no longer follow'):
        bench.load(stored(*slow_rows, mutate=tamper))


def test_decision_ready_needs_every_u05_gate_present_not_just_none_failing():
    assert gates_u.decision_ready([]) is False
    report = gates_u.build_report(gates_u.Inputs())
    assert report.flag.decision_ready is False
