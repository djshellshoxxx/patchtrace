from __future__ import annotations

from dataclasses import replace

import pytest
from search_builders import make_service

from patchtrace.search import build, paths
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import DEFAULT_LIMITS
from patchtrace.search.query import match_words, parse_query
from patchtrace.search.segment import open_segment

GROUPS = ['ann', 'fnd', 'pe:older', 'pe:newer', 'fn', 'raw', 'ir']
BUILT = ('ann', 'fnd', 'pe:older', 'pe:newer', 'fn', 'raw')


@pytest.fixture
def cache(tmp_path):
    return tmp_path / 'cache'


@pytest.fixture
def service(tmp_path):
    return make_service(tmp_path / 'project')


def status(report):
    return {entry.group: entry.status for entry in report.coverage}


def segment_file(request, cache_root, group):
    spec = next(s for s in request.specs if s.group == group)
    return paths.segment_path(build.segment_directory(request, cache_root), group, spec.digest16)


def content(request, cache_root):
    """Every segment's rows, without the build timestamps."""
    out = {}
    for group in (s.group for s in request.specs if s.buildable):
        with open_segment(segment_file(request, cache_root, group)) as segment:
            db = segment.conn
            tables = ['doc'] + [row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE name IN ('fts_name', 'fts_code', 'fts_text') ORDER BY name")]
            out[group] = {t: list(db.execute(f'SELECT * FROM {t} ORDER BY {"id" if t == "doc" else "rowid"}'))
                          for t in tables}
    return out


def test_request_orders_groups_cheap_first_and_names_every_one(service):
    assert [s.group for s in build.build_request(service).specs] == GROUPS


def test_a_full_build_indexes_every_group_and_reports_exact_coverage(service, cache):
    request = build.build_request(service)
    report = build.build_index(request, cache)
    assert status(report) == {'ann': 'indexed', 'fnd': 'indexed', 'pe:older': 'indexed', 'pe:newer': 'indexed',
                              'fn': 'indexed', 'raw': 'indexed', 'ir': 'unavailable'}
    entries = {e.group: e for e in report.coverage}
    assert entries['ir'].reason == ("Instruction text is not searchable: Ghidriff keeps only a hash of each "
                                    "function's instructions. Run unified extraction to add it.")
    assert entries['ir'].kinds == ('asm',) and entries['ir'].digest16 is None
    assert entries['raw'].reason == 'unchanged functions: not indexed'
    assert entries['pe:older'].side == 'older' and entries['fn'].docs > 0 and entries['fn'].built_utc
    assert report.built == BUILT and report.reused == ()
    assert build.coverage(request, cache) == report.coverage


def test_built_segments_answer_queries(service, cache):
    request = build.build_request(service)
    build.build_index(request, cache)
    with open_segment(segment_file(request, cache, 'fn')) as segment:
        rows = segment.conn.execute('SELECT rowid FROM fts_name WHERE fts_name MATCH ?',
                                    (match_words(parse_query('copy'), 'fts_name'),)).fetchall()
    assert len(rows) == 1  # RtlCopyMemoryHelper, found by its CamelCase word


def test_second_build_reuses_everything(service, cache):
    request = build.build_request(service)
    build.build_index(request, cache)
    again = build.build_index(request, cache)
    assert again.built == () and again.reused == BUILT


def test_incremental_build_equals_from_scratch(service, tmp_path, cache):
    build.build_index(build.build_request(service), cache)
    service.project.annotations[0].text = 'Edited note about the length check'
    request = build.build_request(service)
    changed = build.build_index(request, cache)
    assert changed.built == ('ann',) and changed.reused == BUILT[1:]
    build.build_index(request, tmp_path / 'fresh')
    assert content(request, cache) == content(request, tmp_path / 'fresh')


def test_segments_are_independent_of_source_order(tmp_path):
    a, b = make_service(tmp_path / 'a'), make_service(tmp_path / 'b', seed=7)
    ra, rb = build.build_request(a), build.build_request(b)
    assert ra.index_key == rb.index_key
    build.build_index(ra, tmp_path / 'ca')
    build.build_index(rb, tmp_path / 'cb')
    assert content(ra, tmp_path / 'ca') == content(rb, tmp_path / 'cb')


def test_a_changed_group_changes_the_index_key_only_for_that_group(service):
    before = build.build_request(service)
    service.project.annotations[0].text = 'different'
    after = build.build_request(service)
    assert before.index_key != after.index_key
    changed = {b.group for b, a in zip(before.specs, after.specs, strict=True) if b.digest16 != a.digest16}
    assert changed == {'ann'}


def test_a_failing_group_does_not_stop_the_others(tmp_path, cache):
    service = make_service(tmp_path / 'project', raw={'functions': {}})
    report = build.build_index(build.build_request(service), cache)
    entries = {e.group: e for e in report.coverage}
    assert entries['raw'].status == 'failed' and 'no strings or symbols' in entries['raw'].reason
    assert entries['fn'].status == 'indexed' and 'raw' not in report.built


def test_unexpected_source_errors_are_isolated_too(service, cache):
    request = build.build_request(service)

    def boom():
        raise RuntimeError('hostile')

    spec = replace(request.specs[0], documents=boom)
    report = build.build_index(replace(request, specs=(spec, *request.specs[1:])), cache)
    assert status(report)['ann'] == 'failed' and status(report)['fn'] == 'indexed'
    assert 'RuntimeError' in next(e for e in report.coverage if e.group == 'ann').reason


def test_cancel_stops_the_build_and_keeps_finished_groups(service, cache):
    request = build.build_request(service)
    calls = []

    def cancel():
        calls.append(1)
        return len(calls) > 4

    with pytest.raises(SearchError) as caught:
        build.build_index(request, cache, cancel=cancel)
    assert caught.value.code == 'PT-SEARCH-CANCEL'
    done = {e.group for e in build.coverage(request, cache) if e.status == 'indexed'}
    assert 'ann' in done and 'raw' not in done
    leftovers = [p.name for p in build.segment_directory(request, cache).iterdir() if p.name.startswith('.staging')]
    assert leftovers == []


def test_total_time_limit_marks_remaining_groups_failed(service, cache):
    ticks = iter(range(0, 100_000, 1000))
    limits = replace(DEFAULT_LIMITS, total_build_s=1500.0, segment_build_s=1e9)
    report = build.build_index(build.build_request(service), cache, limits=limits, clock=lambda: float(next(ticks)))
    by_group = {e.group: e for e in report.coverage}
    assert by_group['ann'].status == 'indexed' and by_group['fn'].status == 'failed'
    assert 'time limit' in by_group['fn'].reason


def test_groups_filter_and_progress(service, cache):
    request = build.build_request(service)
    seen = []
    report = build.build_index(request, cache, groups={'ann', 'pe:older'},
                               progress=lambda group, done, total: seen.append((group, done, total)))
    assert seen == [('ann', 0, 2), ('pe:older', 1, 2)] and report.built == ('ann', 'pe:older')
    assert status(report)['fn'] == 'missing'


def test_rebuild_builds_again(service, cache):
    request = build.build_request(service)
    build.build_index(request, cache)
    again = build.build_index(request, cache, rebuild=True, groups={'ann'})
    assert again.built == ('ann',) and again.reused == ()


def test_corrupt_segment_is_rebuilt(service, cache):
    request = build.build_request(service)
    build.build_index(request, cache)
    segment_file(request, cache, 'ann').write_bytes(b'junk')
    assert next(e for e in build.coverage(request, cache) if e.group == 'ann').status == 'missing'
    assert build.build_index(request, cache).built == ('ann',)


def test_cache_inside_the_project_is_refused(service):
    with pytest.raises(SearchError) as caught:
        build.build_index(build.build_request(service), service.root / 'cache')
    assert caught.value.code == 'PT-SEARCH-STORE'


def test_expected_segments_feed_garbage_collection(service):
    expected = build.build_request(service).expected()
    assert [group for group, _ in expected] == list(BUILT)
    assert all(len(digest) == 16 for _, digest in expected)


def test_no_run_marks_run_groups_not_applicable(tmp_path, cache):
    report = build.build_index(build.build_request(make_service(tmp_path / 'p', completed=False)), cache)
    assert status(report)['fn'] == status(report)['raw'] == 'not-applicable'
    assert status(report)['ann'] == 'indexed'
