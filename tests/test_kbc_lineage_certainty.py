"""Source chronology and boundary contradictions stay separate from display order."""
from __future__ import annotations

from dataclasses import replace

import pytest

from patchtrace.kbcorrelation import lineage as ln
from patchtrace.kbcorrelation import resolver as rs


def rows(*, older_date='2099-01-01', newer_date='2099-02-01',
         older_build='26100.100', newer_build='26100.200'):
    values = []
    for sha, kb, date, build in (('a', 'KB5000000', older_date, older_build),
                                 ('b', 'KB5000001', newer_date, newer_build)):
        values.append({'sha256': sha * 64, 'kb': kb, 'version_key': '11-24H2',
                       'release_date': date, 'release_version': build, 'machine_type': 0x8664,
                       'size': 100, 'heading_class': 'standard', 'variant': 'full',
                       'download': 'direct', 'record_sha256': 'e' * 64})
    parsed, rejected = ln.index_rows(values, file_name='example.sys')
    assert rejected == 0
    by_kb = {row.kb: row for row in parsed}
    return by_kb['KB5000000'], by_kb['KB5000001']


def proposal(older, newer):
    return rs.propose_index_pair(older, newer, scope_id='1' * 64, fixed_build='26100.200')


@pytest.mark.parametrize('old_build', ['26100.200', '26100.300', '026100.200', '26100.0200'])
def test_matching_newer_build_does_not_override_an_older_build_at_or_above_the_advisory_build(old_build):
    older, newer = rows(older_build=old_build)
    pair = proposal(older, newer)
    assert pair.grade == 'A'  # chronology and bytes remain independent of fix attribution
    assert pair.fix_boundary == 'contradicted'
    assert pair.older.sha256 != pair.newer.sha256


def test_conflicting_older_build_claims_withhold_a_boundary():
    older, newer = rows()
    older = replace(older, heading_builds=('26100.300',))
    assert proposal(older, newer).fix_boundary == 'unverified'


def test_conflicting_newer_build_claims_withhold_a_boundary():
    older, newer = rows()
    newer = replace(newer, heading_builds=('26100.300',))
    assert proposal(older, newer).fix_boundary == 'unverified'


def test_an_explicit_shared_build_prefix_does_not_fabricate_a_contradiction():
    older, newer = rows()
    older = replace(older, heading_builds=('26200.300',))
    newer = replace(newer, heading_builds=('26200.400',))
    assert proposal(older, newer).fix_boundary == 'source-supported'


def test_build_comparisons_use_numeric_components_with_equivalent_source_spellings():
    older, newer = rows(newer_build='026100.0200')
    newer = replace(newer, heading_builds=('26100.0200',))
    assert proposal(older, newer).fix_boundary == 'source-supported'


def test_direct_boundary_query_preserves_unknown_chronology():
    older, newer = rows(older_date=None)
    assert rs.fix_boundary(older, newer, '26100.200', ()) == 'unverified'


@pytest.mark.parametrize('kw', [
    {'older_date': None, 'older_build': None},
    {'older_date': None},
    {'newer_date': None},
    {'older_date': '2099-02-01', 'older_build': None},
    {'older_date': '2099-02-01', 'newer_build': None},
    {'older_date': '2099-02-01', 'older_build': '26100.200'},
    {'older_date': '2099-03-01'},
], ids=['missing-old-date-and-build', 'missing-old-date', 'missing-new-date',
        'same-date-missing-old-build', 'same-date-missing-new-build', 'same-date-build', 'reversed-date'])
def test_missing_or_tied_order_is_not_a_supported_index_boundary(kw):
    pair = proposal(*rows(**kw))
    assert (pair.grade, pair.lineage_state, pair.fix_boundary) == ('X', 'incompatible', 'unverified')
    assert 'ORDER_UNVERIFIED' in pair.reason_codes


@pytest.mark.parametrize('kw', [
    {},
    {'older_build': None},  # an explicit earlier release date still orients a base image
    {'older_date': '2099-02-01'},  # equal dates, two known increasing numeric builds
])
def test_explicit_chronology_keeps_valid_index_pairs(kw):
    pair = proposal(*rows(**kw))
    assert pair.grade == 'A' and pair.lineage_state == 'index-adjacent'
    assert 'ORDER_UNVERIFIED' not in pair.reason_codes


@pytest.mark.parametrize('kw', [
    {'older_date': None, 'older_build': None},
    {'older_date': None},
    {'older_date': '2099-02-01', 'older_build': None},
    {'older_date': '2099-02-01', 'older_build': '26100.200'},
])
def test_missing_or_tied_predecessor_cannot_claim_the_file_changed_in_a_kb(kw):
    older, newer = rows(**kw)
    result = ln.change_in_kb(ln.timeline((older, newer), '11-24H2'), newer.kb)
    assert (result.state, result.reason, result.last_changed_in) == ('unknown', 'order-unverified', None)
    assert result.target_rows == (newer,)


@pytest.mark.parametrize('target', ['KB5000000', 'KB5000001'])
def test_sha_or_kb_sorting_never_resolves_competing_bytes_at_one_chronological_position(target):
    older, newer = rows(older_date='2099-02-01', older_build='26100.200')
    earlier, _ = rows(older_date='2098-12-01', older_build='26100.50')
    earlier = replace(earlier, build=earlier.build.model_copy(update={'kb': 'KB4999999', 'sha256': 'c' * 64}))
    line = ln.timeline((older, earlier, newer), '11-24H2')
    result = ln.change_in_kb(line, target)
    assert (result.state, result.reason) == ('unknown', 'order-unverified')


def test_an_unchanged_run_with_unknown_first_date_does_not_claim_a_last_change_kb():
    older, newer = rows(older_date=None, older_build=None)
    older = replace(older, build=older.build.model_copy(update={'sha256': newer.sha256}))
    result = ln.change_in_kb(ln.timeline((older, newer), '11-24H2'), newer.kb)
    assert (result.state, result.reason, result.last_changed_in) == ('unknown', 'order-unverified', None)
