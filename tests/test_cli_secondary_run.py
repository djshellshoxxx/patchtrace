"""SPEC-28 §7: `secondary run` exit codes, JSON document, cache and alias (fake rz-diff executables)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from test_secondary_bindiff import build

from patchtrace import cli
from patchtrace.service import ProjectService

GOOD = json.dumps([{'similarity': 0.5, 'type': 'PARTIAL', 'original': {'addr': 1, 'name': 'f', 'size': 1},
                    'modified': {'addr': 2, 'name': 'g', 'size': 1}}])
posix = pytest.mark.skipif(os.name == 'nt', reason='shebang fake executables are POSIX-only')


@pytest.fixture
def project(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    root = service.root
    service.close()
    return root, sides


def fake_rz(tmp_path, output=GOOD, code=0):
    path = tmp_path / 'bin' / 'rz-diff'
    path.parent.mkdir(exist_ok=True)
    path.write_text(f'#!{Path(sys.executable).resolve()}\nimport sys\n'
                    f"if sys.argv[1:] == ['-v']:\n    print('rz-diff 0.9.1')\n    sys.exit(0)\n"
                    f'print({output!r})\nsys.exit({code})\n')
    path.chmod(0o755)
    return str(path)


def run_cli(root, *extra, capsys):
    code = cli.main(['secondary', 'run', str(root), '--json', *extra])
    return code, json.loads(capsys.readouterr().out)


@posix
def test_run_json_complete_then_cached_then_reconcile_after_reruns(project, tmp_path, capsys):
    root, _ = project
    exe = fake_rz(tmp_path)
    code, doc = run_cli(root, '--rz-diff', exe, '--engine', 'rz-diff', capsys=capsys)
    assert code == 0 and doc['status'] == 'complete'
    [row] = doc['result']['runs']
    assert row['engine'] == 'rz-diff' and row['status'] == 'ok' and row['matches'] == 1 and not row['cache']
    code, doc = run_cli(root, '--rz-diff', exe, '--engine', 'rz-diff', capsys=capsys)
    assert code == 0 and doc['result']['runs'][0]['status'] == 'cached' and doc['result']['runs'][0]['cache']
    assert run_cli(root, '--rz-diff', exe, '--no-cache', capsys=capsys)[1]['result']['runs'][0]['status'] == 'ok'
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 0
    reports = json.loads(capsys.readouterr().out)['result']['reports']
    assert [r['engine'] for r in reports] == ['rz-diff']


@posix
def test_run_partial_exits_3(project, tmp_path, capsys):
    root, _ = project
    code, doc = run_cli(root, '--rz-diff', fake_rz(tmp_path), '--engine', 'rz-diff', '--engine', 'bindiff',
                        capsys=capsys)
    assert code == 3 and doc['status'] == 'partial'
    assert [r['status'] for r in doc['result']['runs']] == ['ok', 'unsupported']
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 0  # the ok set was stored


@posix
def test_run_all_zero_matches_exits_4(project, tmp_path, capsys):
    root, _ = project
    code, doc = run_cli(root, '--rz-diff', fake_rz(tmp_path, output='[]'), capsys=capsys)
    assert code == 4 and doc['result']['runs'][0]['matches'] == 0


@posix
def test_run_engine_crash_exits_3(project, tmp_path, capsys):
    root, _ = project
    code, doc = run_cli(root, '--rz-diff', fake_rz(tmp_path, output='boom', code=1), '--engine', 'rz-diff',
                        capsys=capsys)
    assert code == 3 and doc['status'] == 'failed'
    assert doc['result']['runs'][0]['error_code'] == 'PT-SECONDARY-RUN'


def test_run_cancel_exits_5(project, monkeypatch, capsys):
    from patchtrace.secondary import cli_run

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_run, 'execute', interrupted)
    root, _ = project
    assert cli.main(['secondary', 'run', str(root), '--json']) == 5
    assert json.loads(capsys.readouterr().out)['status'] == 'cancelled'


def test_run_unsupported_only_exits_2(project, capsys):
    root, _ = project
    code, doc = run_cli(root, '--engine', 'bindiff', capsys=capsys)
    assert code == 2 and doc['result']['runs'][0]['status'] == 'unsupported'


def test_run_timeout_out_of_range_exits_2(project):
    root, _ = project
    assert cli.main(['secondary', 'run', str(root), '--timeout', '5']) == 2


def test_run_max_parallel_three_exits_2(project):
    root, _ = project
    assert cli.main(['secondary', 'run', str(root), '--max-parallel', '3']) == 2


@posix
def test_rzdiff_alias_matches_run_output(project, tmp_path, capsys):
    root, _ = project
    exe = fake_rz(tmp_path)
    code, via_run = run_cli(root, '--rz-diff', exe, '--engine', 'rz-diff', '--no-cache', capsys=capsys)
    assert cli.main(['secondary', 'rzdiff', str(root), '--rz-diff', exe, '--json']) == code
    alias = json.loads(capsys.readouterr().out)
    assert alias['command'] == 'secondary rzdiff'
    assert set(alias['result']) == set(via_run['result'])
    assert set(alias['result']['runs'][0]) == set(via_run['result']['runs'][0])


def test_reimport_bindiff_twice_then_reconcile_exit_0(project, tmp_path, capsys):
    root, sides = project
    for name in ('one', 'two'):
        db = build(tmp_path / f'{name}.BinDiff', hashes=(sides['older'], sides['newer']))
        assert cli.main(['secondary', 'import-bindiff', str(root), str(db), '--json']) == 0
        capsys.readouterr()
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 0
    assert len(json.loads(capsys.readouterr().out)['result']['reports']) == 1
