"""LBL-13 lead-list pack and the no-pooling rule: hand-computed goldens."""
from __future__ import annotations

import pytest

from tools.calibration import channels
from tools.calibration.channels import capabilities, environment, leadlist, rules, strings
from tools.calibration.channels.leadlist import LeadAA
from tools.calibration.channels.leadlist import LeadPair as P

OTHERS = {f'o{i}': i for i in range(1, 11)}


def _pairs():
    return [
        P('l1', 'L1', 's1', 'f', frozenset({'f', 'a'}), {'f': 1, 'a': 2, 'b': 3, 'c': 4},
          {'f': 3, 'a': 1, 'b': 2, 'c': 4}, frozenset({'f', 'c'})),
        P('l2', 'L2', 's1', 'g', frozenset({'g'}), {'g': 1, 'x': 2, 'y': 3}, {'g': 1, 'x': 2, 'y': 3},
          frozenset({'g'})),
        P('l3', 'L3', 's2', 'h', frozenset({'h'}), {**OTHERS, 'h': 0}, {**OTHERS, 'h': 11}, frozenset({'h'})),
    ]


def test_golden_hit_at_k_with_and_without_reported_separately():
    r = leadlist.score(_pairs(), [], b_count=50)
    m = {k: v['point'] for k, v in r.metrics.items()}
    # ranks with: 1, 1, 1; without: 3, 1, 11
    assert (m['hit@1:with'], m['hit@3:with'], m['hit@10:with']) == (1.0, 1.0, 1.0)
    assert m['hit@1:without'] == pytest.approx(1 / 3)
    assert m['hit@3:without'] == pytest.approx(2 / 3)
    assert m['hit@10:without'] == pytest.approx(2 / 3)
    assert m['hit@20:without'] == 1.0
    assert m['hit@10_delta'] == pytest.approx(1 / 3)
    # precision minus base rate: l1 1/2 - 2/4, l2 1 - 1/3, l3 1 - 1/11
    assert m['precision_minus_base'] == pytest.approx(52 / 99)


def test_three_lineages_never_become_a_claim():
    r = leadlist.score(_pairs(), [LeadAA('a1', 'L1', 0, 500)], b_count=50)
    assert r.gate == {'precision_above_base': None, 'aa_false_lead_rate': True, 'hit10_non_inferior': None,
                      'improves_a_slice': True, 'verdict': 'inconclusive'}


def _many(n, improves):
    out = []
    for i in range(n):
        good, bad = {**OTHERS, 'h': 0}, {**OTHERS, 'h': 11}
        out.append(P(f'm{i}', f'LL{i}', 's1', 'h', frozenset({'h'}), good if improves else bad,
                     bad if improves else good, frozenset({'h'})))
    return out


@pytest.mark.parametrize('improves, flagged, verdict', [
    (True, 0, 'pass'), (True, 1, 'fail'), (False, 0, 'fail')], ids=['pass', 'aa-fail', 'regress-fail'])
def test_gate_verdicts_with_30_lineages(improves, flagged, verdict):
    r = leadlist.score(_many(30, improves), [LeadAA('a', 'LL0', flagged, 100)], b_count=100)
    assert r.gate['verdict'] == verdict


def test_aa_false_lead_rate_boundary_is_inclusive():
    r = leadlist.score(_many(30, True), [LeadAA('a', 'LL0', 1, 1000)], b_count=100)
    assert (r.gate['aa_false_lead_rate'], r.gate['verdict']) == (True, 'pass')


def test_fix_absent_from_pool_is_a_miss():
    p = P('z', 'L', 's', 'gone', frozenset({'gone'}), {'a': 1}, {'a': 1}, frozenset())
    r = leadlist.score([p], [], b_count=20)
    assert r.metrics['hit@20:with']['point'] == 0.0


def test_packs_are_listed_and_never_pooled():
    assert channels.PACKS == ('strings', 'capabilities', 'environment', 'rules', 'leadlist')
    reports = [strings.score([], 10), capabilities.score([], 10), environment.score([], 10),
               rules.score([], available=False), leadlist.score([], [], 10)]
    assert [r.pack for r in reports] == list(channels.PACKS)
    assert all(not hasattr(r, 'mean') and 'overall' not in r.metrics for r in reports)
