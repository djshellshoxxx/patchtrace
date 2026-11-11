"""Regression tests for issue #105 BUG-KBC-1..11 (KB/CVE correlator). Offline; synthetic documents only."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_kbc_recovery as recovery_support

from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.lineage import index_rows
from patchtrace.kbcorrelation.recovery import repair
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.sources import cvrf
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import KbcStoreError, ProjectAttachment, WorkspaceStore

NOW = '2099-03-01T00:00:00Z'
PRODUCT = 'Windows 11 Version 24H2 for x64-based Systems'
NS = 'https://example.invalid/synthetic-cvrf/1'


def json_doc(vulnerability: dict, *, products=None, date=None) -> bytes:
    document = {'release_id': '2099-Feb', **({'current_release_date': date} if date else {})}
    return json.dumps({'dialect': 'cvrf-json/0', 'document': document,
                       'product_tree': products or [{'product_id': 'P1', 'name': PRODUCT}],
                       'vulnerabilities': [vulnerability]}).encode()


@pytest.mark.parametrize('value', [5, True, 3.5])
def test_kbc1_a_non_list_remediations_is_a_row_problem_not_a_crash(value):
    parsed = cvrf.parse_cvrf(json_doc({'cve': 'CVE-2099-0001', 'remediations': value}))
    edges = cvrf.build_edges(parsed, 'a' * 64)
    assert edges.edges == () and 'ROW_SHAPE' in [p.code for p in edges.problems] + [p.code for p in parsed.problems]


def test_kbc2_edge_work_is_bounded_before_it_is_done(monkeypatch):
    calls = []
    real = cvrf.make_edge

    def counting(**kwargs):
        calls.append(1)
        return real(**kwargs)

    monkeypatch.setattr(cvrf, 'make_edge', counting)
    products = [{'product_id': f'P{i}', 'name': f'Windows 11 Version 24H2 build {i} for x64-based Systems'}
                for i in range(2000)]
    description = '\n'.join(f'KB{1000 + k}' for k in range(50))
    raw = json_doc({'cve': 'CVE-2099-0001', 'remediations': [
        {'type': 2, 'description': description, 'product_ids': [p['product_id'] for p in products]}]},
        products=products)
    limits = KbcLimits(cvrf_edges_per_doc=1000)
    with pytest.raises(cvrf.SourceError, match='more than 1000 edges'):
        cvrf.build_edges(cvrf.parse_cvrf(raw, limits), 'a' * 64, limits)
    assert len(calls) == 0                          # main built all 100,000 before refusing


@pytest.mark.parametrize('content', ['{"months": [["x"]]}', '{"months": ["2099-Feb", 5]}', '{"doc_ids": [["x"]]}',
                                     '{"months": "2099-Feb"}', '{"months": ["2099-Jan"], "months": ["2099-Feb"]}',
                                     '{"months": ["2099-Feb"], "x": NaN}', '{"x":' + '[' * 100000 + '}'])
def test_kbc3_scope_files_are_strict_json_and_fail_with_the_scope_code(tmp_path, content):
    path = tmp_path / 'scope.json'
    path.write_text(content, encoding='utf-8')
    with pytest.raises(KbcStoreError) as info:
        KbService.__new__(KbService)._scope(ReverseIndex(), None, path)
    assert info.value.code == 'PT-KBC-SCOPE'


def test_kbc3_invalid_utf8_scope_file_is_refused(tmp_path):
    path = tmp_path / 'scope.json'
    path.write_bytes(b'{"months": ["2099-Feb"], "x": "\xff"}')
    with pytest.raises(KbcStoreError):
        KbService.__new__(KbService)._scope(ReverseIndex(), None, path)


def test_kbc3_a_valid_scope_file_still_works(tmp_path):
    path = tmp_path / 'scope.json'
    path.write_text('{"months": ["2099-Feb"], "note": "kept for people"}', encoding='utf-8')
    scope = KbService.__new__(KbService)._scope(ReverseIndex(), None, path)
    assert scope.months == ('2099-Feb',)


def test_kbc4_repair_writes_the_sidecars_a_failed_attach_left_out(tmp_path):
    ws, request = recovery_support.prepared(tmp_path, limits=KbcLimits(project_sources_bytes=1))
    with ws:
        port = recovery_support.adapter(tmp_path / 'project')
        first = ProjectAttachment(ws, port).attach(request)
        assert first.value.state == 'context-pending'
        ws.limits = KbcLimits()
        result = repair(ws, port, context_for=lambda op, body: ((recovery_support.CONTEXT_KEY,
                                                                 recovery_support.CONTEXT_BODY.encode()),))
        assert result.value[0].state == 'attached'
        assert list((tmp_path / 'project' / 'kb' / 'sources').glob('*.json.gz'))


def test_kbc5_an_os_error_writing_sidecars_is_a_typed_partial_attach(tmp_path):
    ws, request = recovery_support.prepared(tmp_path)
    with ws:
        port = recovery_support.adapter(tmp_path / 'project')
        create = port.create_project

        def blocked(*args, **kwargs):
            made = create(*args, **kwargs)
            (tmp_path / 'project' / 'kb').write_text('a file where a folder belongs', encoding='utf-8')
            return made

        port.create_project = blocked
        result = ProjectAttachment(ws, port).attach(request)
    assert result.status == 'partial' and [i.code for i in result.issues] == ['PT-KBC-STORAGE']


def _active(first: str, second: str) -> str:
    index = ReverseIndex()
    older = import_bytes(json_doc({'cve': 'CVE-2099-0001', 'remediations': [
        {'type': 2, 'description': 'KB1111', 'product_ids': ['P1']}]}, date=first), now=NOW)
    newer = import_bytes(json_doc({'cve': 'CVE-2099-0001', 'remediations': [
        {'type': 2, 'description': 'KB2222', 'product_ids': ['P1']}]}, date=second), now=NOW)
    index.add(older)
    index.add(newer)
    return 'second' if newer.doc_id in index.active_ids() else 'first'


@pytest.mark.parametrize('first, second', [('2099-02-13T00:00:00Z', '2099-02-13T00:00:00.5Z'),
                                           ('2099-02-13T10:00:00+05:00', '2099-02-13T08:00:00Z')])
def test_kbc6_the_later_instant_is_the_active_revision(first, second):
    assert _active(first, second) == 'second'


@pytest.mark.parametrize('bad', ['2099-13-45', '2099-02-13T25:61:61Z'])
def test_kbc6_impossible_release_dates_are_reported(bad):
    parsed = cvrf.parse_cvrf(json_doc({'cve': 'CVE-2099-0001'}, date=bad))
    assert parsed.current_release_date is None and 'DATE_INVALID' in [p.code for p in parsed.problems]


def test_kbc7_non_ascii_digits_in_lineage_rows_are_rejected():
    def row(kb, sha, date, ubr):
        return {'sha256': sha * 64, 'kb': kb, 'version_key': '11-24H2', 'release_date': date, 'release_version': ubr,
                'heading': 'h', 'heading_class': 'standard', 'variant': 'full', 'download': 'direct',
                'record_sha256': 'c' * 64, 'size': 1, 'machine_type': 0x8664}
    rows, rejected = index_rows([row('KB5000001', 'a', '2099-01-01', '26100.1'),
                                 row('KB5000002', 'b', '2099-02-01', '٢٦١٠٠.٢')], file_name='ntdll.dll')
    assert [r.build.release_version for r in rows] == ['26100.1', None]     # unreadable build: unknown, not 26100
    from patchtrace.kbcorrelation.products import scope_for
    from patchtrace.kbcorrelation.resolver import resolve
    resolve(rows, kb='KB5000002', scope=scope_for('a' * 64, 'P', PRODUCT), file_name='ntdll.dll')   # main crashed


def _xml(body: str, root_extra: str = '') -> bytes:
    return (f'<?xml version="1.0" encoding="UTF-8"?><CvrfDoc xmlns="{NS}" ReleaseId="2099-Feb"{root_extra}>'
            f'<Vulnerabilities>{body}</Vulnerabilities></CvrfDoc>').encode()


def test_kbc8_a_large_token_cannot_hide_deep_nesting_from_the_xml_limits():
    big = '<Vulnerability CVE="CVE-2099-0002" Title="' + 'y' * 300_000 + '"/>'
    deep = '<Vulnerability CVE="CVE-2099-0001">' + '<n>' * 2000 + '</n>' * 2000 + '</Vulnerability>'
    with pytest.raises(cvrf.SourceError) as info:
        import_bytes(_xml(big + deep), now=NOW)
    assert info.value.code == 'PT-KBC-LIMIT'


def test_kbc8_a_long_root_attribute_is_not_read_as_an_empty_document():
    document = import_bytes(_xml('', f' Pad="{"x" * 140_000}"'), now=NOW)
    assert document.source.release_id == '2099-Feb'


def test_kbc9_pair_prefixes_must_be_unique_and_long_enough():
    found = [SimpleNamespace(pairs=tuple(SimpleNamespace(pair_id=pid, grade='A')
                                         for pid in ('ab' + '1' * 62, 'ab' + '2' * 62, 'cd' + '3' * 62)))]
    for prefix in ('', 'a', 'ab', 'ab111'):
        with pytest.raises(KbcStoreError):
            KbService._pick_pair(found, prefix)
    assert KbService._pick_pair(found, 'ab111111').pair_id == 'ab' + '1' * 62
    with pytest.raises(KbcStoreError, match='select one with --pair'):
        KbService._pick_pair(found, None)


@pytest.mark.parametrize('separator', ['\x0b', '\x1c', '\x85', ' '])
def test_kbc10_only_newlines_separate_type2_kb_lines(separator):
    raw = json_doc({'cve': 'CVE-2099-0001', 'remediations': [
        {'type': 2, 'description': f'KB5000001{separator}KB5000002', 'product_ids': ['P1']}]})
    edges = cvrf.build_edges(cvrf.parse_cvrf(raw), 'a' * 64)
    assert not [e for e in edges.edges if e.relation == 'vendor-remediation']
    assert 'KB_UNPARSED' in [p.code for p in edges.problems]


def test_kbc11_a_newer_store_opens_read_only_through_a_relative_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    WorkspaceStore(Path('ws')).close()
    connection = sqlite3.connect(os.path.join('ws', 'kbc.sqlite3'))
    connection.execute('PRAGMA user_version=99')
    connection.commit()
    connection.close()
    store = WorkspaceStore(Path('ws'))
    try:
        assert store.read_only
    finally:
        store.close()


def test_kbc13_two_product_ids_of_one_scope_count_as_one_scope():
    raw = json.dumps({'dialect': 'cvrf-json/0', 'document': {'release_id': '2099-Feb'},
                      'product_tree': [{'product_id': 'A', 'name': PRODUCT}, {'product_id': 'B', 'name': PRODUCT}],
                      'vulnerabilities': [{'cve': 'CVE-2099-0001', 'remediations': [
                          {'type': 2, 'description': 'KB5000001', 'product_ids': ['A', 'B']}]}]}).encode()
    assert import_bytes(raw, now=NOW).counts()['scopes'] == 1
