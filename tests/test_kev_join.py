"""kev/1 join: exact CVE lookup with honest statuses, UTC calendar-day freshness, snapshot delta."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from kev_helpers import (
    ABSENT,
    NOW,
    SYNTHETIC,
    at,
    entry,
    fixture_document,
    mutated,
    parse_document,
    parse_fixture,
    socket_guard,
)

from patchtrace.kev import limits
from patchtrace.kev.contracts import KevEntry, KevError, KevLookup, is_cve_id
from patchtrace.kev.join import diff, freshness_of, lookup, split_cve_ids

RELEASED = '2099-03-01T18:00:00Z'
FAST = settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)


@pytest.fixture(scope='module')
def catalog():
    return parse_fixture(SYNTHETIC)


# --- lookup -------------------------------------------------------------------------------------------------

def test_lookup_answers_listed_and_not_listed_in_input_order(catalog):
    rows = lookup(catalog, ['CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10004'], NOW)
    assert [(row.cve_id, row.status) for row in rows] == [
        ('CVE-2099-10001', 'listed'), ('CVE-2099-10002', 'not-listed'), ('CVE-2099-10004', 'listed')]
    listed = rows[0]
    assert isinstance(listed.entry, KevEntry) and listed.entry is catalog.by_cve['CVE-2099-10001']
    assert rows[1].entry is None
    assert {row.snapshot_id for row in rows} == {catalog.meta.snapshot_id}
    assert all(isinstance(row, KevLookup) for row in rows)


def test_a_decoy_in_the_catalog_but_in_no_kb_is_still_listed(catalog):
    row = lookup(catalog, ['CVE-2099-10009'], NOW)[0]
    assert row.status == 'listed' and (row.entry.vendor_project, row.entry.product) == ('Adobe', 'Reader')


@pytest.mark.parametrize('text', [
    'CVE-２０９９-10001', 'CVE-2099-１００１', 'CVE-2099-١٠٠٠١', 'ＣＶＥ-2099-10001', 'cve-2099-10001',
    ' CVE-2099-10001', 'CVE-2099-10001\n', 'CVE-2099-10001 ', '', 'CVE-2099-1', 'x' * 500, 'CVE‑2099-10001'],
    ids=['fullwidth-year', 'fullwidth-sequence', 'arabic-indic-sequence', 'fullwidth-prefix', 'lowercase',
         'leading-space', 'trailing-newline', 'trailing-space', 'empty', 'short', 'long', 'non-breaking-hyphen'])
def test_fullwidth_and_arabic_indic_cve_ids_are_invalid_not_unlisted(catalog, text):
    row = lookup(catalog, [text], NOW)[0]
    assert row.status == 'invalid-id'                        # never "Not listed": the text names no CVE at all
    assert row.entry is None and row.snapshot_id is None and row.freshness == 'unknown' and row.age_days is None
    assert row.notes == ('expected CVE-YYYY-NNNN with ASCII digits',)
    assert len(row.cve_id) <= limits.MAX_ECHO_CHARS


def test_an_invalid_id_is_echoed_cleaned_and_capped(catalog):
    row = lookup(catalog, ['bad\x1b[31m‮id' + 'x' * 100], NOW)[0]
    assert '\x1b' not in row.cve_id and '‮' not in row.cve_id and len(row.cve_id) == 64


def test_without_a_catalog_nothing_is_known_about_a_valid_id():
    rows = lookup(None, ['CVE-2099-10001', 'nonsense'], NOW)
    assert [(row.status, row.snapshot_id, row.freshness) for row in rows] == [
        ('unavailable', None, 'unknown'), ('invalid-id', None, 'unknown')]
    assert rows[0].notes == ('no catalog is loaded',)


def test_lookup_is_distinct_and_keeps_first_occurrence_order(catalog):
    rows = lookup(catalog, ['CVE-2099-10004', 'CVE-2099-10001', 'CVE-2099-10004', 'bad', 'bad'], NOW)
    assert [row.cve_id for row in rows] == ['CVE-2099-10004', 'CVE-2099-10001', 'bad']


def test_lookup_accepts_five_thousand_and_refuses_one_more(catalog):
    ids = [f'CVE-2099-{n:05d}' for n in range(limits.MAX_LOOKUP_CVES + 1)]
    assert len(lookup(catalog, ids[:limits.MAX_LOOKUP_CVES], NOW)) == limits.MAX_LOOKUP_CVES
    with pytest.raises(KevError) as caught:
        lookup(catalog, ids, NOW)
    assert caught.value.code == 'PT-KEV-LIMIT'


def test_lookup_of_a_future_catalog_says_so(catalog):
    row = lookup(catalog, ['CVE-2099-10001'], at(2099, 2, 27))[0]
    assert (row.status, row.freshness, row.age_days) == ('listed', 'future', -2)
    assert row.notes == ("the catalog's release time is in the future; treat results as unverified",)


@given(st.lists(st.text(max_size=40), max_size=30))
@FAST
def test_lookup_is_total_over_arbitrary_strings(texts):
    rows = lookup(parse_fixture(SYNTHETIC), texts, NOW)
    assert len(rows) == len(dict.fromkeys(texts))
    assert all(row.status in ('listed', 'not-listed', 'invalid-id') for row in rows)
    assert {row.cve_id for row in rows if row.status != 'invalid-id'} == {text for text in texts if is_cve_id(text)}


# --- typed or pasted text -----------------------------------------------------------------------------------

@pytest.mark.parametrize(('text', 'expected'), [
    ('CVE-2024-1234', ('CVE-2024-1234',)),
    ('cve-2024-1234 , CVE-2024-5678;CVE-2024-1234\nCVE-2024-9999', ('CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9999')),
    ('  \n ;, ', ()), ('', ()),
    ('CVE-2024-1234 CVE-2024-5678　CVE-2024-9', ('CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9')),
    ('CVE-２０２４-1234 x', ('CVE-２０２４-1234', 'X'))],
    ids=['single', 'mixed-separators-and-case', 'only-separators', 'empty', 'unicode-spaces',
         'fullwidth-stays-invalid'])
def test_split_cve_ids(text, expected):
    assert split_cve_ids(text) == expected


def test_split_cve_ids_refuses_more_than_the_lookup_limit():
    text = ' '.join(f'CVE-2099-{n:05d}' for n in range(limits.MAX_LOOKUP_CVES + 1))
    assert len(split_cve_ids(' '.join(text.split()[:limits.MAX_LOOKUP_CVES]))) == limits.MAX_LOOKUP_CVES
    with pytest.raises(KevError) as caught:
        split_cve_ids(text)
    assert caught.value.code == 'PT-KEV-LIMIT'


# --- freshness: UTC calendar days since the release ---------------------------------------------------------

@pytest.mark.parametrize(('now', 'state', 'age'), [
    (at(2099, 3, 1, 18, 0, 0), 'fresh', 0), (at(2099, 3, 1, 23, 59, 59), 'fresh', 0),
    (at(2099, 3, 4), 'fresh', 3), (at(2099, 3, 5), 'aging', 4), (at(2099, 3, 15), 'aging', 14),
    (at(2099, 3, 16), 'stale', 15), (at(2099, 3, 16, 0, 0, 0), 'stale', 15), (at(2100, 3, 1), 'stale', 365),
    (at(2099, 3, 1, 17, 59, 59), 'future', 0), (at(2099, 2, 28), 'future', -1), (at(2098, 3, 1), 'future', -365)],
    ids=['at-release', 'same-day-late', 'day-3-fresh', 'day-4-aging', 'day-14-aging', 'day-15-stale', 'day-15-midnight',
         'a-year', 'one-second-before', 'day-before', 'year-before'])
def test_freshness_is_a_utc_calendar_day_difference(now, state, age):
    assert freshness_of(RELEASED, now) == (state, age)


def test_freshness_uses_utc_whatever_the_zone_of_now():
    plus_nine = timezone(timedelta(hours=9))
    just_after_midnight_in_tokyo = datetime(2099, 3, 5, 8, 30, tzinfo=plus_nine)       # still 2099-03-04 in UTC
    assert freshness_of(RELEASED, just_after_midnight_in_tokyo) == ('fresh', 3)
    assert freshness_of(RELEASED, datetime(2099, 3, 5, 9, 30, tzinfo=plus_nine)) == ('aging', 4)


def test_freshness_refuses_a_clock_without_a_zone():
    with pytest.raises(ValueError, match='timezone'):
        freshness_of(RELEASED, datetime(2099, 3, 4))
    assert freshness_of(RELEASED, datetime(2099, 3, 4, tzinfo=UTC))[0] == 'fresh'


# --- delta --------------------------------------------------------------------------------------------------

def changed_document():
    base = fixture_document(SYNTHETIC)
    new = mutated(base, ('vulnerabilities', 1, 'knownRansomwareCampaignUse'), 'Known')       # 10004
    new = mutated(new, ('vulnerabilities', 0, 'cwes'), ['CWE-20'])                             # 10010
    new = mutated(new, ('vulnerabilities', 0, 'forensicTriage'), 'Yes')
    new = mutated(new, ('vulnerabilities', 3, 'requiredAction'), 'Edited wording only.')       # 10001: not tracked
    del new['vulnerabilities'][2]                                                              # 10009 removed
    new['vulnerabilities'].insert(0, entry(11, cveID='CVE-2099-10011', dateAdded='2099-02-28', dueDate='2099-03-14'))
    new['count'] = len(new['vulnerabilities'])
    return new


def test_diff_reports_added_removed_and_changed_by_tracked_fields(catalog):
    delta = diff(catalog, parse_document(changed_document()))
    assert delta.from_snapshot_id == catalog.meta.snapshot_id
    assert delta.added == ('CVE-2099-10011',) and delta.removed == ('CVE-2099-10009',)
    assert (delta.added_count, delta.removed_count, delta.changed_count) == (1, 1, 2)
    first, second = delta.changed
    assert first.cve_id == 'CVE-2099-10004'
    assert (first.before.ransomware_use, first.after.ransomware_use) == ('unknown', 'known')
    assert first.before.cwes == first.after.cwes == ('CWE-416',)
    assert second.cve_id == 'CVE-2099-10010'
    assert (second.before.forensic_triage, second.after.forensic_triage) == ('absent', 'yes')
    assert (second.before.cwes, second.after.cwes) == ((), ('CWE-20',))
    assert 'CVE-2099-10001' not in {item.cve_id for item in delta.changed}           # wording alone is not a change


def test_diff_with_itself_and_in_reverse(catalog):
    other = parse_document(changed_document())
    nothing = diff(catalog, catalog)
    assert (nothing.added, nothing.removed, nothing.changed) == ((), (), ())
    forward, backward = diff(catalog, other), diff(other, catalog)
    assert forward.added == backward.removed and forward.removed == backward.added
    assert [c.cve_id for c in forward.changed] == [c.cve_id for c in backward.changed]
    assert forward.changed[0].before == backward.changed[0].after


def test_diff_lists_the_newest_additions_first_and_cuts_at_the_cap(catalog):
    base = fixture_document(SYNTHETIC)
    grown = dict(base)
    extra = [entry(n, cveID=f'CVE-2099-{20000 + n}', dateAdded=f'2099-02-{10 + n % 18:02d}', dueDate='2099-03-30')
             for n in range(1, 601)]
    grown['vulnerabilities'] = base['vulnerabilities'] + extra
    grown['count'] = len(grown['vulnerabilities'])
    newer = parse_document(grown)
    delta = diff(catalog, newer)
    assert delta.added_count == 600 and len(delta.added) == limits.MAX_DELTA_IDS
    dates = [newer.by_cve[cve].date_added for cve in delta.added]
    assert dates == sorted(dates, reverse=True)
    ties = [cve for cve, date in zip(delta.added, dates, strict=True) if date == dates[0]]
    assert ties == sorted(ties)                                                  # equal dates keep CVE order


def test_diff_ignores_unknown_fields_and_padding(catalog):
    noisy = mutated(fixture_document(SYNTHETIC), ('vulnerabilities', 0, 'epss'), 0.9)
    noisy = mutated(noisy, ('vulnerabilities', 1, 'vendorProject'), '  Microsoft  ')
    delta = diff(catalog, parse_document(noisy))
    assert (delta.added_count, delta.removed_count, delta.changed_count) == (0, 0, 0)
    assert delta.to_snapshot_id != delta.from_snapshot_id                          # the bytes differ, the facts do not


def test_diff_marks_a_dropped_optional_field_as_absent_not_as_no(catalog):
    dropped = mutated(fixture_document(SYNTHETIC), ('vulnerabilities', 3, 'knownRansomwareCampaignUse'), ABSENT)
    change = diff(catalog, parse_document(dropped)).changed[0]
    assert (change.cve_id, change.before.ransomware_use, change.after.ransomware_use) == (
        'CVE-2099-10001', 'known', 'absent')
