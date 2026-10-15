"""K5: file-index lineage (plan 6 traps, RK2 s2.3). Pure; synthetic records."""
from __future__ import annotations

import json

import pytest
from kbc_k5_support import SHA, record, rows_of

from patchtrace.acquisition import winbindex as wb
from patchtrace.kbcorrelation import lineage as ln


def line(name='exampledrv.sys', key='11-24H2'):
    rows, _ = rows_of(record(name), name)
    return ln.timeline(rows, key)


def test_order_ignores_file_version():
    doc = record()
    # a file version that would sort KB5096000 after KB5099001 must not change chronology
    doc[SHA['X']]['fileInfo']['version'] = '10.0.99999.9'
    doc[SHA['X']]['fileInfo']['timestamp'] = 4_294_000_000
    rows, _ = rows_of(doc)
    assert [r.kb for r in ln.timeline(rows, '11-24H2')] == [None, 'KB5096000', 'KB5097000', 'KB5098000', 'KB5099001']


def test_version_keys_include_the_shared_sibling():
    rows, skipped = rows_of(record())
    assert ln.version_keys(rows) == ('10-22H2', '11-24H2', '11-25H2') and skipped == 2
    sibling = next(r for r in rows if r.build.version_key == '11-25H2')
    own = next(r for r in ln.timeline(rows, '11-24H2') if r.kb == 'KB5099001')
    assert sibling.shared_from == '11-24H2' and own.shared_from is None and sibling.sha256 == own.sha256


@pytest.mark.parametrize('kb, state, reason, last', [
    ('KB5096000', 'yes', 'new-build', None),
    ('KB5097000', 'yes', 'new-build', None),
    ('KB5098000', 'no', 'unchanged', 'KB5097000'),
    ('KB5099001', 'yes', 'new-build', None),
    ('KB5000000', 'unknown', 'no-row', None)],
    ids=['first-after-base', 'new-sha', 'unchanged-preview', 'newest-md5-only', 'absent'])
def test_changed_in_kb(kb, state, reason, last):
    info = ln.change_in_kb(line(), kb)
    assert (info.state, info.reason, info.last_changed_in) == (state, reason, last)


def test_unchanged_in_kb_reports_where_it_last_changed():
    info = ln.change_in_kb(line('examplenet.sys'), 'KB5099001')
    assert (info.state, info.last_changed_in) == ('no', 'KB5097000')


def test_first_row_without_predecessor_is_unknown_not_yes():
    rows, _ = rows_of(record('examplenet.sys'), 'examplenet.sys')
    info = ln.change_in_kb(ln.timeline(rows, '11-24H2'), 'KB5096000')
    assert (info.state, info.reason) == ('unknown', 'first-row')


def test_two_shas_for_one_kb_are_unknown_variants():
    doc = record()
    doc[SHA['V']]['windowsVersions'] = {'11-24H2': doc[SHA['Z']]['windowsVersions']['11-24H2']}
    rows, _ = rows_of(doc)
    info = ln.change_in_kb(ln.timeline(rows, '11-24H2'), 'KB5099001')
    assert (info.state, info.reason) == ('unknown', 'variants') and len(info.target_rows) == 2


def test_predecessor_skips_other_class_but_keeps_it_out_of_the_window_when_bytes_match():
    rows = line()
    newest = rows[-1]
    older, between = ln.predecessor(rows, newest)
    assert older.kb == 'KB5098000' and older.sha256 == SHA['Y'] and between == ()


def test_predecessor_of_unchanged_row_starts_at_the_run_start():
    rows = line('examplenet.sys')
    older, between = ln.predecessor(rows, rows[-1])
    assert older.kb == 'KB5096000' and [r.kb for r in between] == ['KB5097000', 'KB5098000']


def test_shared_with_lists_the_other_kbs_of_the_same_bytes():
    preview = next(r for r in line() if r.kb == 'KB5098000')
    assert preview.build.shared_with == ('KB5097000',)


def test_hostile_mappings_are_counted_not_guessed():
    good = next(iter(mappings()))
    bad = [{'sha256': 'zz', 'version_key': '11-24H2'}, 'not a mapping', dict(good, kb='kb12')]
    rows, rejected = ln.index_rows([good, *bad], file_name='exampledrv.sys')
    assert len(rows) == 1 and rejected == 3


def mappings():
    parsed = wb.parse_rows(json.dumps(record()).encode(), 'exampledrv.sys', '2099-02-12', compressed=False)
    return (r.as_mapping() for r in parsed.rows)


def test_machine_and_availability_come_from_the_row():
    newest = line()[-1]
    assert (newest.machine, newest.availability, newest.build.variant) == ('amd64', 'candidates', 'delta')
    assert newest.heading_builds == ('26100.120', '26200.120') and newest.build.release_version == '26200.120'
