"""WB1 S5: `patchtrace search` dispatcher: envelope, exit-code table, probe, status, hostile arguments."""
from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest
from search_synergy_builders import attention, extra_specs, make_project

from patchtrace.search import cli
from patchtrace.search.cli import exit_for


def run(tmp_path, *argv, project=True, specs=extra_specs):
    service = make_project(tmp_path / 'project')
    out, err = io.StringIO(), io.StringIO()
    code = cli.main([*(['PROJECT'] if project else []), '--cache-dir', str(tmp_path / 'cache'), *argv],
                    opener=lambda _path: (service, attention), extra_specs=specs, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def document(out: str) -> dict:
    assert out.count('\n') == 1
    return json.loads(out)


def test_json_envelope_and_ok_exit(tmp_path):
    code, out, _ = run(tmp_path, '--query', 'container size', '--json')
    doc = document(out)
    assert code == 0 and doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'search'
    assert doc['status'] == 'ok' and doc['result']['contract'] == 'search/1' and doc['result']['total'] == 3
    assert doc['result']['hits'][0]['evidence'][0]['title'] == 'ClfsValidateContainerSize'
    assert str(tmp_path) not in out


def test_text_output_lists_leads(tmp_path):
    code, out, _ = run(tmp_path, '--query', 'container size')
    assert code == 0 and 'ClfsValidateContainerSize' in out and out.startswith('ok:')


def test_no_results_with_everything_indexed_exits_4(tmp_path):
    code, out, _ = run(tmp_path, '--query', 'zzqqxx', '--kind', 'function', '--json')
    assert code == 4 and document(out)['status'] == 'no-results'


def test_no_index_build_has_no_usable_index_exit_3(tmp_path):
    code, out, _ = run(tmp_path, '--query', 'container', '--no-index-build', '--json')
    assert code == 3 and document(out)['status'] in ('indexing', 'partial')


def test_filters_reach_the_plan(tmp_path):
    code, out, _ = run(tmp_path, '--query', 'container', '--kind', 'string', '--side', 'newer', '--scope', 'changed',
                       '--json')
    result = document(out)['result']
    assert code == 0 and [h['evidence'][0]['kind'] for h in result['hits']] == ['string']
    assert 'side: newer' in result['interpreted_as'] and 'scope: changed' in result['interpreted_as']


def test_cursor_pages(tmp_path):
    _, first, _ = run(tmp_path, '--query', 'container size', '--limit', '1', '--json')
    cursor = document(first)['result']['cursor']
    assert cursor
    code, second, _ = run(tmp_path, '--query', 'container size', '--limit', '1', '--cursor', cursor, '--json')
    titles = [h['evidence'][0]['title'] for h in document(second)['result']['hits']]
    assert code == 0 and titles == ['CVE-2099-10001']


def test_rebuild_reports_progress_on_stderr(tmp_path):
    code, out, err = run(tmp_path, '--query', 'container', '--rebuild', '--json')
    assert code == 0 and 'indexing' in err and document(out)['status'] == 'ok'


def test_status_lists_coverage(tmp_path):
    code, out, _ = run(tmp_path, '--status', '--json')
    result = document(out)['result']
    assert code == 0 and len(result['index_key']) == 16
    assert {'fn', 'adv'} <= {row['group'] for row in result['coverage']}


@pytest.mark.parametrize('argv', [
    ('--query', 'a**'), ('--query', '"unbalanced'), ('--query', 'a', '--kind', 'bogus'),
    ('--query', 'a', '--limit', '201'), ('--query', 'a', '--limit', '0'), (), ('--status', '--query', 'a'),
    ('--query', 'a', '--mode', 'fuzzy')],
    ids=['star', 'quote', 'kind', 'limit-hi', 'limit-lo', 'no-query', 'status-query', 'mode'])
def test_invalid_input_exits_2_with_one_document(tmp_path, argv):
    code, out, err = run(tmp_path, *argv, '--json')
    doc = document(out)
    assert code == 2 and doc['status'] == 'failed' and doc['result'] is None and doc['error']
    assert 'Traceback' not in err


def test_bad_cursor_is_input_error(tmp_path):
    code, out, _ = run(tmp_path, '--query', 'container', '--cursor', '!!', '--json')
    assert code == 2 and 'PT-SEARCH-INPUT' in document(out)['error']


def test_cache_inside_the_project_is_refused(tmp_path):
    service = make_project(tmp_path / 'project')
    out = io.StringIO()
    code = cli.main(['P', '--query', 'container', '--cache-dir', str(service.root / 'cache'), '--json'],
                    opener=lambda _p: (service, attention), stdout=out, stderr=io.StringIO())
    assert code == 3 and 'PT-SEARCH-STORE' in document(out.getvalue())['error']


def test_locked_project_exits_2_without_paths(tmp_path):
    def locked(_path):
        raise cli.SearchUsage(cli.LOCKED)
    out = io.StringIO()
    code = cli.main(['P', '--query', 'x', '--json'], opener=locked, stdout=out, stderr=io.StringIO())
    assert code == 2 and 'close the desktop' in document(out.getvalue())['error']


def _anchor_set(*values, cve='CVE-2099-10001'):
    from patchtrace.intelligence.anchors import _anchor
    from patchtrace.intelligence.contracts import AnchorSet
    items = tuple(_anchor(kind, value, 'csaf-title', '/vulnerabilities/0/title', 'derived', 'test anchor')
                  for kind, value in values)
    return AnchorSet(cve=cve, anchors=tuple(sorted(items, key=lambda a: (a.kind, a.value))))


def run_anchors(tmp_path, anchor_set, *extra, cve='CVE-2099-10001'):
    service = make_project(tmp_path / 'project')
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(['PROJECT', '--cache-dir', str(tmp_path / 'cache'), '--anchors-from', cve, *extra],
                    opener=lambda _path: (service, attention), extra_specs=extra_specs,
                    anchors=lambda _service, _cve: (anchor_set, []), stdout=out, stderr=err)
    return code, out.getvalue()


def test_anchors_from_returns_per_anchor_coverage(tmp_path):
    anchors = _anchor_set(('feature', 'ClfsValidateContainerSize'), ('feature', 'zzqqxx'))
    code, out = run_anchors(tmp_path, anchors, '--json')
    doc = document(out)
    assert code == 0 and doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'search'
    assert doc['status'] == 'complete' and doc['result']['cve'] == 'CVE-2099-10001'
    by_value = {row['value']: row for row in doc['result']['anchors']}
    assert by_value['ClfsValidateContainerSize']['status'] in ('changed', 'indexed-only')
    assert by_value['ClfsValidateContainerSize']['hits'] >= 1
    # the synthetic project has no IR group indexed, so a miss is `unknown`, never a proven `none`
    assert by_value['zzqqxx']['status'] == 'unknown' and by_value['zzqqxx']['unindexed']
    assert str(tmp_path) not in out


def test_anchors_from_text_mode_is_one_line_per_anchor(tmp_path):
    code, out = run_anchors(tmp_path, _anchor_set(('feature', 'ClfsValidateContainerSize')))
    assert code == 0 and out.startswith('CVE-2099-10001: 1 anchor') and 'ClfsValidateContainerSize' in out


def test_anchors_from_with_no_stored_advisory_exits_4(tmp_path):
    code, out = run_anchors(tmp_path, None, '--json')
    assert code == 4 and document(out)['result']['anchors'] == []


def test_anchors_from_rejects_a_malformed_cve_and_a_query(tmp_path):
    code, out = run_anchors(tmp_path, None, '--json', cve='not-a-cve')
    assert code == 2 and 'CVE' in document(out)['error']
    code, out = run_anchors(tmp_path, _anchor_set(), '--query', 'x', '--json')
    assert code == 2 and 'anchors-from' in document(out)['error']


def test_unexpected_failure_is_exit_3_without_traceback(tmp_path):
    def broken(_path):
        raise RuntimeError('boom /secret/path')
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(['P', '--query', 'x', '--json'], opener=broken, stdout=out, stderr=err)
    assert code == 3 and document(out.getvalue())['error'] == 'RuntimeError' and '/secret' not in err.getvalue()


def test_interrupt_exits_5(tmp_path):
    def interrupted(_path):
        raise KeyboardInterrupt
    out = io.StringIO()
    code = cli.main(['P', '--query', 'x', '--json'], opener=interrupted, stdout=out, stderr=io.StringIO())
    assert code == 5 and document(out.getvalue())['status'] == 'cancelled'


def test_probe_needs_no_project(tmp_path):
    out = io.StringIO()
    code = cli.main(['--probe', '--json', '--cache-dir', str(tmp_path / 'c')], stdout=out, stderr=io.StringIO())
    result = document(out.getvalue())['result']
    assert code == 0 and result['usable'] is True and result['cache_root_writable'] is True
    assert {'sqlite_version', 'fts5', 'unicode61', 'trigram', 'rapidfuzz_version', 'rapidfuzz_backend'} <= set(result)


def test_probe_text(tmp_path):
    out = io.StringIO()
    code = cli.main(['--probe', '--cache-dir', str(tmp_path / 'c')], stdout=out, stderr=io.StringIO())
    assert code == 0 and re.match(r'search-runtime: ok sqlite=\S+ fts5=True', out.getvalue())


def test_help_exits_0_with_usage(capsys):
    assert cli.main(['--help']) == 0
    assert 'usage: patchtrace search' in capsys.readouterr().out


def _result(status, hits=(), coverage=()):
    return SimpleNamespace(status=status, hits=hits, coverage=coverage)


def _entry(status, kinds=('function',), side=None):
    return SimpleNamespace(status=status, kinds=kinds, side=side)


@pytest.mark.parametrize('result, kinds, expected', [
    (_result('ok'), (), 0), (_result('too-broad'), (), 0), (_result('stale'), (), 0),
    (_result('partial', hits=(1,)), (), 0), (_result('partial'), (), 3),
    (_result('no-results', coverage=(_entry('indexed'), _entry('unavailable', ('asm',)))), (), 4),
    (_result('no-results', coverage=(_entry('indexed'), _entry('building'))), (), 3),
    (_result('no-results', coverage=(_entry('indexed'), _entry('missing', ('string',)))), ('function',), 4),
    (_result('no-results', coverage=(_entry('unavailable', ('asm',)),)), ('asm',), 3),
    (_result('indexing'), (), 3), (_result('cancelled'), (), 5), (_result('unsupported'), (), 2),
    (_result('error'), (), 3)],
    ids=['ok', 'broad', 'stale', 'partial-hits', 'partial-none', 'absent-proven', 'absent-building', 'kind-scoped',
         'asm-unavailable', 'indexing', 'cancelled', 'unsupported', 'error'])
def test_exit_table(result, kinds, expected):
    assert exit_for(result, SimpleNamespace(kinds=kinds, sides=())) == expected


def test_search_cli_never_imports_qt():
    code = ("import sys; import patchtrace.search.cli as c; c.main(['--probe']); "
            "sys.exit(any(m.startswith(('PySide', 'PyQt')) for m in sys.modules))")
    done = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr


def test_stored_anchors_come_from_the_imported_advisory(tmp_path):
    from pathlib import Path

    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.intelligence.storage import AdvisoryStore
    from patchtrace.search.anchor_cli import stored_anchors
    from patchtrace.service import ProjectService
    raw = (Path(__file__).parent / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json').read_bytes()
    with ProjectService.sample(tmp_path / 'case') as service:
        assert stored_anchors(service, 'CVE-2099-10001')[0] is None
        AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                      service.project.revision).add(raw, origin='local-import', uri=None, file_name='a.json',
                                                    retrieved_at='2099-03-01T00:00:00Z')
        found, _ = stored_anchors(service, 'CVE-2099-10001')
    assert found is not None and found.cve == 'CVE-2099-10001' and found.anchors


def test_text_mode_never_prints_control_or_bidi_characters(tmp_path):
    code, out, err = run(tmp_path, '--query', 'zz\x1b[31m‮qq')
    assert code in (0, 2, 3, 4)
    assert not [c for c in out + err if c != '\n' and c in '\x1b‮'], (out, err)
