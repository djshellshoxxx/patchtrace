"""LBL-22: Tier-W blind audit sampler, queue and error report (SPEC-33 s7). Hand-computed goldens."""
from __future__ import annotations

import sys

import pytest
from tier_w_builders import ROOT

sys.path.insert(0, str(ROOT))
from tools.calibration.common import det_uniform  # noqa: E402
from tools.calibration.stats import clopper_pearson_upper  # noqa: E402
from tools.calibration.tier_w import audit as A  # noqa: E402
from tools.calibration.tier_w.contracts import AuditItem, AuditKey  # noqa: E402
from tools.calibration.tier_w.paths import TierWError  # noqa: E402


def cand(i, answer='same', old=100, new=100, pair='tw.p.1'):
    return A.AuditCandidate(pair, f'm{i:03d}', answer, i, i + 1, old, new)


def test_census_boundary_and_rate_one():
    rows = [cand(1, new=150), cand(2, new=140), cand(3, new=30), cand(4, 'different', new=300), cand(5, old=0, new=9)]
    key = A.sample_audit(rows, [], corpus_id='tw-c', seed='s', rate=1.0)
    strata = {i.match_id: (i.stratum, i.p_incl) for i in key.items}
    # +50% and -70% exceed 0.40; +40% does not (strict); `different` never joins the census; old size 0 never does
    assert strata == {'m001': ('census', 1.0), 'm002': ('random', 1.0), 'm003': ('census', 1.0),
                      'm004': ('random', 1.0), 'm005': ('random', 1.0)}
    assert key.population == 'candidates' and key.population_counts == {'census': 2, 'random': 3}


def test_random_stratum_follows_det_uniform():
    rows = [cand(i) for i in range(200)]
    key = A.sample_audit(rows, [], corpus_id='tw-c', seed='seed1', rate=0.25)
    expect = {r.match_id for r in rows if det_uniform('seed1', 'audit', r.pair, r.match_id) < 0.25}
    assert {i.match_id for i in key.items} == expect and 20 < len(expect) < 80
    assert all(i.p_incl == 0.25 for i in key.items)
    assert A.sample_audit(list(reversed(rows)), [], corpus_id='tw-c', seed='seed1', rate=0.25) == key


def test_truth_only_when_no_candidates():
    key = A.sample_audit([], [cand(1)], corpus_id='tw-c', seed='s', rate=1.0)
    assert key.population == 'truth' and len(key.items) == 1


@pytest.mark.parametrize('rate,size_change', [(0, 0.4), (1.5, 0.4), (0.1, 0)], ids=['zero', 'over', 'size'])
def test_sampler_rejects_bad_params(rate, size_change):
    with pytest.raises(TierWError):
        A.sample_audit([cand(1)], [], corpus_id='tw-c', seed='s', rate=rate, size_change=size_change)


class Reader:
    def read(self, pair, side, rva):
        return A.SideView(100, 'cd' * 32, bytes(range(200)))


def test_queue_is_blind_and_preview_capped():
    key = A.sample_audit([cand(i, new=150) for i in range(5)], [], corpus_id='tw-c', seed='s', rate=1.0)
    sides = {(i.pair, i.match_id): (int(i.match_id[1:]), int(i.match_id[1:]) + 1) for i in key.items}
    queue = A.queue_records(key, sides, Reader())
    assert len(queue) == 5 and {r['match_id'] for r in queue} == {i.match_id for i in key.items}
    assert set(queue[0]) == {'pair', 'match_id', 'stratum', 'older', 'newer'}  # no label, name or engine
    assert set(queue[0]['older']) == {'rva', 'size', 'body_sha256', 'preview_hex'}
    assert len(queue[0]['older']['preview_hex']) == 256 and queue == A.queue_records(key, sides, Reader())
    assert A.queue_header(key)['contract'] == 'tier-w-review/1'


def key_of(census_pop, random_pop, census_n, random_n, truth='same'):
    items = [AuditItem(pair='tw.p.1', match_id=f'c{i}', A=truth, stratum='census', p_incl=1.0) for i in range(census_n)]
    items += [AuditItem(pair='tw.p.1', match_id=f'r{i}', A=truth, stratum='random', p_incl=0.1) for i in range(random_n)]
    return AuditKey(contract='tier-w-audit-key/1', tier='test', corpus_id='tw-c', population='candidates', seed='s',
                    rate=0.1, size_change=0.4, created='', population_counts={'census': census_pop, 'random': random_pop},
                    items=tuple(items))


def answers(key, wrong=(), indeterminate=()):
    out = {}
    for i in key.items:
        out[(i.pair, i.match_id)] = ('indeterminate' if i.match_id in indeterminate
                                     else 'different' if i.match_id in wrong else 'same')
    return out


def test_report_weighted_golden():
    key = key_of(2, 98, 2, 40)
    report = A.audit_report(key, answers(key, wrong={'r0', 'r1'}))
    # census 0/2 errors, random 2/40 = 0.05; weights 0.02 and 0.98 -> 0.049
    assert report.symbol_audit_error == pytest.approx(0.049)
    assert report.symbol_audit_error_upper == pytest.approx(
        0.02 * clopper_pearson_upper(0, 2) + 0.98 * clopper_pearson_upper(2, 40))
    assert (report.reviewed, report.status) == (42, 'weak')  # 0.049 > 0.02 demotes the source


def test_report_ok_and_insufficient():
    key = key_of(2, 98, 2, 40)
    assert A.audit_report(key, answers(key)).status == 'ok'
    small = key_of(2, 98, 2, 10)
    assert A.audit_report(small, answers(small)).status == 'insufficient'  # 12 < 30 reviewed


def test_report_indeterminate_excluded_and_unknown_counted():
    key = key_of(2, 98, 2, 40)
    given = answers(key, indeterminate={'r0', 'r1', 'r2'})
    given[('tw.p.1', 'ghost')] = 'same'
    report = A.audit_report(key, given)
    assert (report.indeterminate, report.reviewed, report.unknown_items) == (3, 39, 1)
    assert report.strata['random'].reviewed == 37 and report.symbol_audit_error == 0.0


def test_report_unreviewed_stratum_gives_no_point_estimate():
    key = key_of(2, 98, 2, 40)
    partial = {k: v for k, v in answers(key).items() if k[1].startswith('r')}
    report = A.audit_report(key, partial)
    assert report.symbol_audit_error is None and report.status == 'insufficient'


def test_no_counterpart_counts_as_not_same_and_bad_answer_rejected():
    key = key_of(0, 40, 0, 40, truth='different')
    given = {k: 'no-counterpart' for k in answers(key)}
    assert A.audit_report(key, given).symbol_audit_error == 0.0
    with pytest.raises(TierWError):
        A.audit_report(key, {('tw.p.1', 'r0'): 'maybe'})
