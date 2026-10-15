"""SPEC-07 §11 headless CLI: no Qt, one JSON document, exit-code contract."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from patchtrace import cli
from patchtrace.service import ProjectService


@pytest.fixture
def project(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    service.close()
    return root


def run(args, capsys):
    code = cli.main(args)
    out, err = capsys.readouterr()
    return code, out, err


def test_headless_entry_never_imports_qt(project):
    code = ('import sys\nsys.argv=["patchtrace","rank",sys.argv[1],"--json","--dry-run"]\n'
            'from patchtrace.__main__ import main\nrc=main()\n'
            'bad=[m for m in sys.modules if m.startswith(("PySide6","patchtrace.ui"))]\n'
            'print("BAD",bad,file=sys.stderr); raise SystemExit(90 if bad else rc)\n')
    result = subprocess.run([sys.executable, '-c', code, str(project)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    doc = json.loads(result.stdout)
    assert doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'rank'


def test_rank_json_is_single_document_and_matches_pipeline(project, capsys):
    code, out, err = run(['rank', str(project), '--json'], capsys)
    assert code == 0
    doc = json.loads(out)
    assert out.count('\n') == 1
    entries = doc['result']['entries']
    assert [e['rank'] for e in entries] == sorted(e['rank'] for e in entries)
    assert entries[0]['score'] > 0 and 'read_item' in entries[0]['function']
    from patchtrace.enrichment import pipeline
    service = ProjectService.open(project)
    try:
        direct = pipeline.run(service.project)
    finally:
        service.close()
    assert {e.match_id: e.score for e in direct.ranking.entries} == {e['match_id']: e['score'] for e in entries}


def test_rank_persists_unless_dry_run(project, capsys):
    from patchtrace.enrichment import pipeline
    from patchtrace.enrichment.storage import EnrichmentStore
    assert run(['rank', str(project), '--dry-run'], capsys)[0] == 0
    service = ProjectService.open(project)
    try:
        assert EnrichmentStore(service.store).entries('ranking') == []
    finally:
        service.close()
    assert run(['rank', str(project)], capsys)[0] == 0
    service = ProjectService.open(project)
    try:
        assert EnrichmentStore(service.store).current('ranking', pipeline.guard_for(service.project))
    finally:
        service.close()


@pytest.mark.parametrize('args', [['rank'], ['bogus'], ['rank', 'x', '--limit', 'n'],
                                  ['flags', 'x', '--feature-id', '-1']])
def test_invalid_arguments_exit_2(args, capsys, tmp_path):
    args = [a if a != 'x' else str(tmp_path) for a in args]
    assert run(args, capsys)[0] == 2


def test_weights_validation_and_effect(project, capsys, tmp_path):
    bad = tmp_path / 'w.json'
    bad.write_text('{"BND": 30.5}')
    assert run(['rank', str(project), '--weights', str(bad), '--dry-run'], capsys)[0] == 2
    bad.write_text('{"NOPE": 1}')
    assert run(['rank', str(project), '--weights', str(bad), '--dry-run'], capsys)[0] == 2
    zero = tmp_path / 'z.json'
    zero.write_text(json.dumps({k: 0 for k in ['BND', 'INT', 'OVF', 'VAL', 'ERR', 'SIZE', 'WIL', 'SCRUB']}))
    code, out, _ = run(['rank', str(project), '--weights', str(zero), '--json', '--dry-run'], capsys)
    assert code == 0 and all(e['score'] == 0 for e in json.loads(out)['result']['entries'])


def test_missing_project_is_environment_error(tmp_path, capsys):
    code, out, err = run(['rank', str(tmp_path / 'absent'), '--json'], capsys)
    assert code == 2 and json.loads(out)['status'] == 'failed' and 'error' in err


def test_flags_no_results_exit_4(project, capsys):
    code, out, _ = run(['flags', str(project), '--json', '--dry-run'], capsys)
    assert code == 4 and json.loads(out)['result']['transitions'] == []


def test_correlate_offline_without_snapshot_keeps_base(project, capsys):
    code, out, _ = run(['correlate', str(project), '--cve', 'CVE-2024-38063', '--json', '--dry-run'], capsys)
    doc = json.loads(out)
    assert code == 4 and any('no snapshot' in w for w in doc['warnings'])


def test_correlate_fetch_requires_matching_consent(project, capsys):
    assert run(['correlate', str(project), '--cve', 'CVE-2024-38063', '--fetch'], capsys)[0] == 2
    assert run(['correlate', str(project), '--cve', 'CVE-2024-38063', '--fetch',
                '--consent-providers', 'nvd'], capsys)[0] == 2


def test_correlate_invalid_cve_rejected_before_network(project, capsys, monkeypatch):
    from patchtrace.enrichment import intelligence
    monkeypatch.setattr(intelligence, 'fetch', lambda *a, **k: pytest.fail('network attempted'))
    code = run(['correlate', str(project), '--cve', 'CVE-24-1', '--fetch', '--consent-providers',
                'nvd,msrc'], capsys)[0]
    assert code == 2


def test_correlate_with_saved_snapshot(project, capsys, tmp_path):
    from pathlib import Path

    from patchtrace.enrichment import cve
    fixtures = Path(__file__).parent / 'fixtures' / 'cve'
    snapshot = cve.normalize('CVE-2024-38063', {'nvd': (fixtures / 'nvd_CVE-2024-38063.json').read_bytes()},
                             '2026-10-12T00:00:00+00:00')
    path = tmp_path / 's.json'
    path.write_text(json.dumps([snapshot.model_dump(mode='json')]))
    code, out, _ = run(['correlate', str(project), '--cve', 'CVE-2024-38063', '--snapshot', str(path),
                        '--json', '--dry-run'], capsys)
    doc = json.loads(out)
    assert code == 0
    for entry in doc['result']['entries']:
        assert entry['context_score'] >= entry['base_score']


def test_keyboard_interrupt_exits_5(project, capsys, monkeypatch):
    def interrupt(*_a, **_k):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, 'cmd_rank', interrupt)
    monkeypatch.setitem(cli.HANDLERS, 'rank', interrupt)
    assert run(['rank', str(project)], capsys)[0] == 5


def test_rank_with_cache_and_cache_commands(project, capsys, tmp_path):
    cache = tmp_path / 'cache'
    first = run(['rank', str(project), '--json', '--dry-run', '--cache-dir', str(cache)], capsys)
    second = run(['rank', str(project), '--json', '--dry-run', '--cache-dir', str(cache)], capsys)
    assert first[0] == second[0] == 0
    assert json.loads(first[1])['result']['entries'] == json.loads(second[1])['result']['entries']
    code, out, _ = run(['cache', 'status', '--cache-dir', str(cache), '--json'], capsys)
    assert code == 0 and json.loads(out)['result']['entries'] >= 2
    code, out, _ = run(['cache', 'verify', '--cache-dir', str(cache), '--json'], capsys)
    assert code == 0
    code, out, _ = run(['cache', 'prune', '--cache-dir', str(cache), '--target-bytes', '0', '--json'], capsys)
    assert code == 0
    assert json.loads(run(['cache', 'status', '--cache-dir', str(cache), '--json'], capsys)[1])['result']['entries'] == 0


def test_refresh_without_cache_dir_is_invalid(project, capsys):
    assert run(['rank', str(project), '--refresh', '--dry-run'], capsys)[0] == 2


def test_unknown_first_argument_is_a_cli_usage_error_not_a_gui_launch(monkeypatch, capsys):
    import sys

    from patchtrace.__main__ import main
    monkeypatch.setattr(sys, 'argv', ['patchtrace', 'rnak', 'x'])
    assert main() == 2


def test_rank_limit_rejects_negative(capsys):
    from patchtrace import cli
    assert cli.main(['rank', '--limit', '-1', 'x']) == 2


def test_unexpected_exception_maps_to_runtime_exit_with_json(monkeypatch, capsys):
    import json

    from patchtrace import cli

    def boom(args, cancel):
        raise ValueError('boom')
    monkeypatch.setitem(cli.HANDLERS, 'rank', boom)
    assert cli.main(['rank', '--json', 'x']) == 3
    document = json.loads(capsys.readouterr().out)
    assert document['status'] == 'failed' and 'boom' in document['error']


def test_text_mode_names_are_terminal_safe_wp01():
    from types import SimpleNamespace as NS
    hostile = 'f\x1b[2J\nforged‮evil\x9b'
    match = NS(match_id='m', older=[NS(name=hostile)], newer=[])
    names = cli._match_names([match])
    assert names['m'] and not any(ord(c) < 32 or 0x7f <= ord(c) < 0xa0 or c == '‮' for c in names['m'])
    assert '\\u001b' in names['m']
