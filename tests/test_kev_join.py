"""kev/1 join: exact CVE wording, ASCII-only IDs, freshness with injected clocks, delta and project row."""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.kev.contracts import KevContext, KevError
from patchtrace.kev.join import diff, freshness, lookup, make_context, normalize_cve_id
from patchtrace.kev.parse import parse_catalog

FIXTURES = Path(__file__).parent / 'fixtures' / 'kev'
UTC = datetime.UTC
RELEASE = datetime.datetime(2099, 3, 1, 12, 0, 0, tzinfo=UTC)


def catalog(name: str = 'kev-synthetic-2099.json', mutate=None):
    data = json.loads((FIXTURES / name).read_text(encoding='utf-8'))
    if mutate:
        mutate(data)
        data['count'] = len(data['vulnerabilities'])
    return parse_catalog(json.dumps(data).encode('utf-8'), source='local-import', retrieved_at='2099-03-01T13:00:00Z')


def at(**delta) -> datetime.datetime:
    return RELEASE + datetime.timedelta(**delta)


def test_fullwidth_and_arabic_indic_cve_ids_are_invalid_not_unlisted():
    cat = catalog()
    for bad in ('CVE-２０９９-１０００１', 'CVE-٢٠٩٩-١٠٠٠١',
                'CVE-2099-1000١', 'CVE‐2099-10001', '', '   ', 'CVE-2099-10001 extra', 'CVE-2099-10001\n10002'):
        [result] = lookup(cat, [bad], at())
        assert result.status == 'invalid-id', repr(bad)
        assert result.entry is None


def test_lookup_listed_and_not_listed_with_age():
    cat = catalog()
    listed, missing = lookup(cat, ['CVE-2099-10001', 'CVE-2099-99999'], at(days=2))
    assert (listed.status, listed.entry.cve_id, listed.freshness, listed.age_days) == ('listed', 'CVE-2099-10001',
                                                                                      'fresh', 2)
    assert (missing.status, missing.entry, missing.snapshot_id) == ('not-listed', None, cat.meta.snapshot_id)


def test_lookup_trims_and_uppercases_ascii_ids_and_collapses_duplicates():
    results = lookup(catalog(), [' cve-2099-10001 ', 'CVE-2099-10001', 'CVE-2099-10002', 'bogus', 'bogus'], at())
    assert [(r.cve_id, r.status) for r in results] == [('CVE-2099-10001', 'listed'), ('CVE-2099-10002', 'listed'),
                                                       ('bogus', 'invalid-id')]


def test_lookup_without_catalog_is_unavailable_but_still_flags_invalid_ids():
    good, bad = lookup(None, ['CVE-2099-10001', 'nope'], at())
    assert (good.status, good.freshness, good.snapshot_id) == ('unavailable', 'unknown', None)
    assert bad.status == 'invalid-id'


def test_invalid_id_text_is_sanitised_and_capped():
    [result] = lookup(catalog(), ['‮<b>' + 'x' * 500 + '\x1b[31m'], at())
    assert len(result.cve_id) <= 64 and '‮' not in result.cve_id and '\x1b' not in result.cve_id


def test_lookup_limit_is_enforced():
    with pytest.raises(KevError) as err:
        lookup(catalog(), ['CVE-2099-10001'] * 5001, at())
    assert err.value.code == 'PT-KEV-LIMIT'
    assert len(lookup(catalog(), [f'CVE-2099-{n:05}' for n in range(5000)], at())) == 5000


@pytest.mark.parametrize(('delta', 'state', 'days'), [
    ({}, 'fresh', 0), ({'days': 3}, 'fresh', 3), ({'days': 4}, 'aging', 4), ({'days': 14}, 'aging', 14),
    ({'days': 15}, 'stale', 15), ({'days': 400}, 'stale', 400), ({'seconds': -1}, 'future', None),
    ({'hours': 11, 'minutes': 59}, 'fresh', 0),
], ids=['same', 'three', 'four', 'fourteen', 'fifteen', 'old', 'future', 'same-day'])
def test_freshness_thresholds(delta, state, days):
    assert freshness(catalog().meta, at(**delta)) == (state, days)


def test_freshness_counts_utc_calendar_days_not_elapsed_hours():
    late = datetime.datetime(2099, 3, 1, 23, 59, tzinfo=UTC)
    meta = catalog().meta
    assert freshness(meta, late + datetime.timedelta(minutes=2))[1] == 1
    local = datetime.timezone(datetime.timedelta(hours=-8))
    assert freshness(meta, datetime.datetime(2099, 3, 1, 20, 0, tzinfo=local))[1] == 1  # 04:00 UTC next day


def test_freshness_without_catalog_is_unknown():
    assert freshness(None, at()) == ('unknown', None)


def test_future_catalog_flags_the_lookup():
    [result] = lookup(catalog(), ['CVE-2099-10001'], at(days=-1))
    assert (result.freshness, result.age_days) == ('future', None)
    assert result.notes == ('The catalog release time is in the future.',)


def test_normalize_cve_id():
    assert normalize_cve_id(' cve-2024-38063\t') == 'CVE-2024-38063'
    assert normalize_cve_id('CVE-2024-38063') == 'CVE-2024-38063'
    assert normalize_cve_id('CVE-2024-123') is None
    assert normalize_cve_id('CVE-2024-' + '1' * 20) is None


@settings(max_examples=100, deadline=None)
@given(st.text(max_size=60))
def test_lookup_is_total_over_arbitrary_strings(text):
    [result] = lookup(catalog(), [text], at())
    assert result.status in {'listed', 'not-listed', 'invalid-id'}
    assert (result.status == 'listed') == (result.entry is not None)


def test_diff_added_removed_changed():
    old = catalog()

    def change(data):
        data['vulnerabilities'].pop(3)
        data['vulnerabilities'][0]['knownRansomwareCampaignUse'] = 'Unknown'
        data['vulnerabilities'][1]['cwes'] = ['CWE-287']
        data['vulnerabilities'].append({**data['vulnerabilities'][2], 'cveID': 'CVE-2099-20001'})
    new = catalog(mutate=change)
    delta = diff(old, new)
    assert (delta.added, delta.removed) == (('CVE-2099-20001',), ('CVE-2099-10004',))
    assert (delta.added_count, delta.removed_count, delta.changed_count) == (1, 1, 2)
    first = delta.changed[0]
    assert (first.cve_id, first.before.ransomware_use, first.after.ransomware_use) == ('CVE-2099-10001', 'known',
                                                                                    'unknown')
    assert (delta.changed[1].before.cwes, delta.changed[1].after.cwes) == ((), ('CWE-287',))
    assert (delta.from_snapshot_id, delta.to_snapshot_id) == (old.meta.snapshot_id, new.meta.snapshot_id)
    assert delta.from_catalog_version == '2099.03.01'


def test_diff_of_identical_catalogs_is_empty():
    cat = catalog()
    delta = diff(cat, cat)
    assert (delta.added, delta.removed, delta.changed) == ((), (), ())


def test_diff_caps_lists_but_keeps_exact_counts():
    old = catalog()

    def many(data):
        template = data['vulnerabilities'][0]
        data['vulnerabilities'] += [{**template, 'cveID': f'CVE-2098-{n:05}'} for n in range(1, 701)]
    delta = diff(old, catalog(mutate=many))
    assert (len(delta.added), delta.added_count) == (500, 700)
    assert delta.added == tuple(sorted(delta.added))


def test_context_row_is_slim_and_identity_ignores_clock_and_order():
    cat = catalog()
    first = make_context(cat, ['CVE-2099-10002', 'CVE-2099-10001', 'nope', 'CVE-2099-99999'], at(days=1), kb='KB5099001',
                         release_date='2099-02-10', orientation_verified=True)
    second = make_context(cat, ['CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-99999'], at(days=9))
    assert first.context_id == second.context_id and first.created_at != second.created_at
    assert [row.cve_id for row in first.lookups] == ['CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-99999']
    assert first.lookups[0].entry.model_dump().keys() & {'notes', 'required_action', 'short_description'} == set()
    assert first.lookups[2].status == 'not-listed'
    assert (first.kb, first.orientation_verified, first.snapshot_id) == ('KB5099001', True, cat.meta.snapshot_id)
    assert KevContext.model_validate_json(first.model_dump_json()) == first


def test_context_row_limit_and_size():
    cat = catalog()
    ids = [f'CVE-2099-{n:05}' for n in range(256)]
    row = make_context(cat, ids, at())
    assert len(row.lookups) == 256 and len(row.model_dump_json()) <= 256 * 1024
    with pytest.raises(KevError) as err:
        make_context(cat, ids + ['CVE-2099-90000'], at())
    assert err.value.code == 'PT-KEV-LIMIT'
