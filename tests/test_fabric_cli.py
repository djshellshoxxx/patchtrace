"""`patchtrace fabric list|show|resolve|stats` (FAB-5, FAB-integration-plan.md s8 and s9): the read-only CLI over the
anchors of a saved project. Every test builds a real project from synthetic PE bytes and publishes its anchors through
the enrichment store, so the reader, the envelope and the exit codes are the shipped ones. Nothing here is live evidence.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from typing import NamedTuple

import fabric_support as fs
import pytest

from patchtrace import cli, cli_commands
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.fabric import ids
from patchtrace.fabric.contracts import Resolution
from patchtrace.fabric.store import EnrichmentAnchorStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

SRC = Path(__file__).resolve().parents[1] / 'src'
ADAPTER = SRC / 'patchtrace' / 'cli_commands' / 'fabric.py'
IMPORT_NAME = 'kernel32.dll!CreateFileW'
ROW_KEYS = {'anchor_id', 'kind', 'key', 'side', 'role', 'subject', 'label', 'witnesses', 'independent', 'producers'}


class Built(NamedTuple):
    root: Path
    pid: str
    ids: dict[str, str]


def build_project(tmp_path: Path) -> Built:
    """A saved project with four anchors: an import seen by two producers with one origin (counted once), two
    functions named alike on both sides, and one stated CWE. The observed anchors carry the real input hashes."""
    older, newer = tmp_path / 'older.exe', tmp_path / 'newer.exe'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    service = ProjectService.create(older, newer, 'fabric cli', tmp_path / 'case')
    sha = {artifact.side: artifact.sha256 for artifact in service.project.artifacts}
    shared = ids.make_anchor(kind='import', key=ids.api_key(IMPORT_NAME), side='newer', role='observed', witnesses=(
        fs.wit('core', 'capa', batch='run2', label='CreateFileW', input_sha=sha['newer']),
        fs.wit('cap', 'capa', batch='run1', label='CreateFileW', input_sha=sha['newer'])))
    newer_fn = fs.anchor('function', ids.image_key(sha['newer'], fs.F_NEW), 'newer', 'observed', producer='ue',
                         source='pairing', label='RtlULongAdd', facets=(('name', 'RtlULongAdd'),), input_sha=sha['newer'])
    older_fn = fs.anchor('function', ids.image_key(sha['older'], fs.F_OLD), 'older', 'observed', producer='ue',
                         source='pairing', label='RtlULongAdd', facets=(('name', 'RtlULongAdd'),), input_sha=sha['older'])
    cwe = fs.cwe_anchor(190)
    named = {'import': shared, 'function-newer': newer_fn, 'function-older': older_fn, 'cwe': cwe}
    EnrichmentAnchorStore(EnrichmentStore(service.store)).publish(service.project.id, list(named.values()))
    service.store.close()
    return Built(service.root, service.project.id, {name: anchor.anchor_id for name, anchor in named.items()})


@pytest.fixture
def project(tmp_path) -> Built:
    return build_project(tmp_path)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(['fabric', *argv])
    out, err = capsys.readouterr()
    return code, out, err


def tamper(root: Path, sql: str, *params: str) -> None:
    """Damage the stored rows directly (a stale guard, a body that no longer matches its hash, a foreign id)."""
    db = sqlite3.connect(root / 'project.sqlite3')
    try:
        db.execute(sql, params)
        db.commit()
    finally:
        db.close()


def child(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, '-m', 'patchtrace', 'fabric', *argv], capture_output=True, text=True,
                          encoding='utf-8', env={**os.environ, 'PYTHONPATH': str(SRC)})


def test_list_writes_one_enrichment_cli_document(project, capsys):
    code, out, _err = invoke(capsys, 'list', '--project', str(project.root), '--json')
    document = json.loads(out)  # raises unless stdout is exactly one JSON document
    assert code == 0
    assert document['contract'] == 'enrichment-cli/1' and document['command'] == 'fabric list'
    assert document['status'] == 'complete' and document['warnings'] == []
    assert document['result']['project'] == project.pid and document['result']['total'] == 4
    assert len(document['result']['items']) == 4


def test_list_rows_count_witnesses_by_independent_origin(project, capsys):
    _code, out, _err = invoke(capsys, 'list', '--project', str(project.root), '--json')
    rows = json.loads(out)['result']['items']
    row = next(item for item in rows if item['kind'] == 'import')
    assert set(row) == ROW_KEYS
    assert row['anchor_id'] == project.ids['import'] and row['label'] == 'CreateFileW'
    assert row['witnesses'] == 2 and row['independent'] == 1  # two producers, one origin: counted once
    assert row['producers'] == ['core', 'cap']


def test_list_text_mode_prints_rows_and_no_document(project, capsys):
    code, out, _err = invoke(capsys, 'list', '--project', str(project.root))
    assert code == 0 and 'CreateFileW' in out and not out.lstrip().startswith('{')


@pytest.mark.parametrize('extra, code, total', [
    pytest.param(['--kind', 'function', '--side', 'newer'], 0, 1, id='kind-and-side'),
    pytest.param(['--role', 'hint'], 4, 0, id='no-hint-anchors'),
    pytest.param(['--subject', 'pair:nothing'], 4, 0, id='unknown-subject'),
    pytest.param(['--limit', '1'], 0, 4, id='first-page-only'),
])
def test_list_filters_and_empty_lists(project, capsys, extra, code, total):
    got, out, _err = invoke(capsys, 'list', '--project', str(project.root), *extra, '--json')
    document = json.loads(out)
    assert got == code and document['result']['total'] == total
    assert document['status'] == 'complete' and (got == 4) == (not document['result']['items'])


@pytest.mark.parametrize('extra', [
    pytest.param(['--kind', 'bogus'], id='unknown-kind'),
    pytest.param(['--side', 'left'], id='unknown-side'),
    pytest.param(['--role', 'absent'], id='absent-is-no-role'),
    pytest.param(['--limit', '0'], id='limit-below-one'),
    pytest.param(['--limit', '501'], id='limit-above-f09'),
])
def test_bad_filters_are_invalid_input_exit_2(project, capsys, extra):
    code, out, _err = invoke(capsys, 'list', '--project', str(project.root), *extra, '--json')
    document = json.loads(out)
    assert code == 2 and document['status'] == 'failed' and document['result'] is None
    assert document['error'].startswith('PT-FAB-')


@pytest.mark.parametrize('name', [
    pytest.param('missing', id='directory-missing'),
    pytest.param('empty', id='directory-not-a-project'),
])
def test_a_path_that_is_not_a_project_is_refused_and_not_created(tmp_path, capsys, name):
    root = tmp_path / name
    if name == 'empty':
        root.mkdir()
    code, out, _err = invoke(capsys, 'stats', '--project', str(root), '--json')
    assert code == 2 and json.loads(out)['status'] == 'failed'
    assert not (root / 'project.sqlite3').exists()


def test_show_returns_the_anchor_with_its_witnesses(project, capsys):
    code, out, _err = invoke(capsys, 'show', project.ids['import'], '--project', str(project.root), '--json')
    anchor = json.loads(out)['result']['anchor']
    assert code == 0 and anchor['anchor_id'] == project.ids['import']
    assert {witness['producer'] for witness in anchor['witnesses']} == {'core', 'cap'}


def test_show_of_an_unknown_id_is_a_legitimate_no_result(project, capsys):
    code, out, _err = invoke(capsys, 'show', '0' * 64, '--project', str(project.root), '--json')
    document = json.loads(out)
    assert code == 4 and document['status'] == 'complete' and document['result']['anchor'] is None


@pytest.mark.parametrize('anchor_id', [
    pytest.param('not-a-digest', id='not-hex'),
    pytest.param('A' * 64, id='upper-case'),
    pytest.param('0' * 63, id='too-short'),
])
def test_show_refuses_a_malformed_anchor_id_with_exit_2(project, capsys, anchor_id):
    code, out, _err = invoke(capsys, 'show', anchor_id, '--project', str(project.root), '--json')
    assert code == 2 and json.loads(out)['status'] == 'failed'


@pytest.mark.parametrize('argv, code, status, named', [
    pytest.param(['--kind', 'import', '--side', 'newer', IMPORT_NAME], 0, 'found', 'import', id='found'),
    pytest.param(['--kind', 'function', '--side', 'older', 'RtlULongAdd'], 0, 'found', 'function-older', id='one-side'),
    pytest.param(['--kind', 'function', 'RtlULongAdd'], 0, 'ambiguous', None, id='ambiguous-never-first'),
    pytest.param(['--kind', 'import', 'user32.dll!MessageBoxA'], 4, 'unknown', None, id='unknown-is-no-result'),
])
def test_resolve_answers_found_ambiguous_or_unknown(project, capsys, argv, code, status, named):
    got, out, _err = invoke(capsys, 'resolve', *argv, '--project', str(project.root), '--json')
    document = json.loads(out)
    assert got == code and document['status'] == 'complete'
    result = document['result']
    assert result['status'] == status
    if named is not None:
        assert result['anchor_id'] == project.ids[named]
    else:
        assert result['anchor_id'] is None and result['count'] == (2 if status == 'ambiguous' else 0)
        assert len(result['candidates']) == result['count']


def test_resolve_refuses_an_unsupported_reader_with_exit_2(project, capsys, monkeypatch):
    monkeypatch.setattr(EnrichmentAnchorStore, 'resolve', lambda self, *args: Resolution('unsupported'))
    code, out, _err = invoke(capsys, 'resolve', '--kind', 'import', IMPORT_NAME, '--project', str(project.root), '--json')
    document = json.loads(out)
    assert code == 2 and document['status'] == 'failed' and 'PT-FAB-UNSUPPORTED' in document['error']


def test_stats_counts_anchors_and_lists_each_batch(project, capsys):
    code, out, _err = invoke(capsys, 'stats', '--project', str(project.root), '--json')
    result = json.loads(out)['result']
    assert code == 0 and result['anchors'] == 4 and len(result['digest']) == 64
    assert {batch['row_id'] for batch in result['batches']} == {
        'fabric:cap:run1', 'fabric:core:run2', 'fabric:ue:run1', 'fabric:kb:run1'}
    assert all(batch['readable'] and not batch['stale'] and batch['skipped'] == 0 for batch in result['batches'])


def test_a_stale_batch_is_listed_and_makes_the_read_partial(project, capsys):
    tamper(project.root, 'UPDATE enrichment_entries SET stale=1 WHERE id=?', 'fabric:ue:run1')
    code, out, _err = invoke(capsys, 'list', '--project', str(project.root), '--json')
    document = json.loads(out)
    assert code == 3 and document['status'] == 'partial'
    assert document['result']['total'] == 4  # a stale batch is out of date, not wrong: its anchors are still returned
    assert any('fabric:ue:run1' in warning and 'stale' in warning for warning in document['warnings'])


def test_missing_is_not_a_negative_vote_when_a_batch_is_unreadable(project, capsys):
    tamper(project.root, 'UPDATE enrichment_entries SET body=? WHERE id=?', '{"tampered":true}', 'fabric:kb:run1')
    code, out, _err = invoke(capsys, 'show', project.ids['cwe'], '--project', str(project.root), '--json')
    document = json.loads(out)
    assert code == 3 and document['status'] == 'partial' and document['result']['anchor'] is None
    assert any('fabric:kb:run1' in warning and 'unreadable' in warning for warning in document['warnings'])


def test_text_output_escapes_a_damaged_row_id(project, capsys):
    tamper(project.root, 'UPDATE enrichment_entries SET id=? WHERE id=?', 'fabric:kb:run1\x1b[31m', 'fabric:kb:run1')
    code, out, err = invoke(capsys, 'stats', '--project', str(project.root))
    assert code == 3 and 'kb:run1' in err
    assert '\x1b' not in out + err


def test_a_cancelled_read_emits_a_cancelled_envelope(project, capsys):
    argv = ['fabric', 'list', '--project', str(project.root), '--json']
    args = cli._parser(argv).parse_args(argv)
    cancelled = threading.Event()
    cancelled.set()
    code = args.handler(args, cancelled)
    document = json.loads(capsys.readouterr().out)
    assert code == 5 and document['status'] == 'cancelled' and document['command'] == 'fabric list'


EXIT_CASES = [
    pytest.param(['list'], 0, id='list-ok'),
    pytest.param(['list', '--role', 'hint'], 4, id='list-empty'),
    pytest.param(['list', '--kind', 'bogus'], 2, id='list-bad-kind'),
    pytest.param(['show', '0' * 64], 4, id='show-unknown'),
    pytest.param(['resolve', '--kind', 'import', 'user32.dll!MessageBoxA'], 4, id='resolve-unknown'),
    pytest.param(['stats'], 0, id='stats-ok'),
]


@pytest.mark.parametrize('argv, expected', EXIT_CASES)
def test_exit_codes_in_a_child_process(project, argv, expected):
    result = child(*argv, '--project', str(project.root), '--json')
    assert result.returncode == expected, result.stderr
    assert json.loads(result.stdout)['contract'] == 'enrichment-cli/1'  # exactly one document


def test_a_partial_read_exits_3_in_a_child_process(project):
    tamper(project.root, 'UPDATE enrichment_entries SET stale=1 WHERE id=?', 'fabric:cap:run1')
    result = child('list', '--project', str(project.root), '--json')
    assert result.returncode == 3 and json.loads(result.stdout)['status'] == 'partial'


def test_the_fabric_verbs_never_import_qt(project):
    code = ('import sys\nfrom patchtrace.cli import main\n'
            'rc = main(["fabric", "list", "--project", sys.argv[1], "--json"])\n'
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "PyQt", "patchtrace.ui"))]\n'
            'raise SystemExit(90 if bad else rc)\n')
    result = subprocess.run([sys.executable, '-c', code, str(project.root)], capture_output=True, text=True,
                            encoding='utf-8', env={**os.environ, 'PYTHONPATH': str(SRC)})
    assert result.returncode == 0, result.stderr


def test_the_adapter_is_a_short_registry_entry_that_loads_the_feature_lazily():
    assert len(ADAPTER.read_text(encoding='utf-8').splitlines()) <= 25
    code = ('import sys\nimport patchtrace.cli_commands.fabric\n'
            'print("patchtrace.fabric.cli" in sys.modules)\n')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, encoding='utf-8',
                            env={**os.environ, 'PYTHONPATH': str(SRC)})
    assert result.stdout.strip() == 'False', result.stderr
    verbs, failed = cli_commands.discover()
    assert 'fabric' in verbs and 'fabric' not in failed
