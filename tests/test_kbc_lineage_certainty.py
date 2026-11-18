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


@pytest.mark.parametrize('date', ['2099-13-01', '2099-02-30', '2100-02-29', '0000-01-01'])
@pytest.mark.parametrize('side', ['older', 'newer'])
def test_impossible_index_dates_remain_unknown_instead_of_establishing_order(date, side):
    older, newer = rows(**{f'{side}_date': date})
    invalid = older if side == 'older' else newer
    assert invalid.build.release_date is None
    pair = proposal(older, newer)
    assert pair.grade == 'X' and pair.fix_boundary == 'unverified'
    assert 'ORDER_UNVERIFIED' in pair.reason_codes
    result = ln.change_in_kb(ln.timeline((older, newer), '11-24H2'), newer.kb)
    assert result.state == 'unknown'


def typed_timestamp(row, text):
    # The shared persisted Timestamp contract checks shape only. Validate normally;
    # this exercises the direct IndexRow seam without bypassing model validation.
    return replace(row, build=type(row.build).model_validate(row.build.model_dump() | {'release_date': text}))


@pytest.mark.parametrize('stamp', ['2099-13-01T00:00:00Z', '2099-02-30T00:00:00Z',
                                  '2100-02-29T00:00:00Z', '2099-01-01T25:00:00Z',
                                  '2099-02-01T00:00:00+00:99'])
@pytest.mark.parametrize('side', ['older', 'newer'])
def test_direct_typed_rows_cannot_claim_order_from_impossible_timestamps(stamp, side):
    older, newer = rows()
    older, newer = (typed_timestamp(older, stamp), newer) if side == 'older' else (
        older, typed_timestamp(newer, stamp))
    assert not ln.chronologically_before(older, newer)
    pair = proposal(older, newer)
    assert pair.grade == 'X' and pair.fix_boundary == 'unverified'
    assert ln.change_in_kb(ln.timeline((older, newer), '11-24H2'), newer.kb).state == 'unknown'


@pytest.mark.parametrize(('older_date', 'newer_date'), [('2000-02-28', '2000-02-29'),
                                                       ('2000-02-29', '2000-03-01')])
def test_valid_century_leap_day_retains_the_supported_pair(older_date, newer_date):
    older, newer = rows(older_date=older_date, newer_date=newer_date)
    assert older.build.release_date is not None and newer.build.release_date is not None
    pair = proposal(older, newer)
    assert pair.grade == 'A' and pair.fix_boundary == 'source-supported'
    assert ln.change_in_kb(ln.timeline((older, newer), '11-24H2'), newer.kb).state == 'yes'


def test_direct_timestamp_offsets_order_by_instant_instead_of_text():
    older, newer = rows()
    older = typed_timestamp(older, '2099-02-01T01:00:00+02:00')
    newer = typed_timestamp(newer, '2099-02-01T00:30:00Z')
    line = ln.timeline((newer, older), '11-24H2')
    assert line == (older, newer) and ln.chronologically_before(older, newer)
    assert proposal(older, newer).fix_boundary == 'source-supported'
    assert ln.change_in_kb(line, newer.kb).state == 'yes'


@pytest.mark.parametrize('forward', [False, True])
def test_direct_timestamp_order_retains_all_nine_fractional_digits(forward):
    older, newer = rows()
    small, large = '2099-02-01T00:00:00.000000001Z', '2099-02-01T00:00:00.000000002Z'
    older = typed_timestamp(older, small if forward else large)
    newer = typed_timestamp(newer, large if forward else small)
    assert ln.chronologically_before(older, newer) is forward
    assert (ln.order_key(older) < ln.order_key(newer)) is forward
    assert proposal(older, newer).grade == ('A' if forward else 'X')


@pytest.mark.parametrize('target', ['KB5000000', 'KB5000001'])
def test_equal_instants_with_different_offset_spellings_cannot_resolve_competing_bytes(target):
    older, newer = rows(older_build='26100.200')
    older = typed_timestamp(older, '2099-02-01T01:00:00+01:00')
    newer = typed_timestamp(newer, '2099-02-01T00:00:00Z')
    earlier, _ = rows(older_date='2099-01-01', older_build='26100.50')
    earlier = replace(earlier, build=type(earlier.build).model_validate(
        earlier.build.model_dump() | {'kb': 'KB4999999', 'sha256': 'c' * 64}))
    assert not ln.chronologically_before(older, newer)
    result = ln.change_in_kb(ln.timeline((older, earlier, newer), '11-24H2'), target)
    assert (result.state, result.reason) == ('unknown', 'order-unverified')
