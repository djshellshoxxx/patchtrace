"""H7 qualifier controls; authored/stubbed runners are never native acceptance."""
from __future__ import annotations

import importlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest

from patchtrace.jobs import ProcessResult, run_process

ROOT = Path(__file__).resolve().parents[1]


def tool():
    return importlib.import_module('tools.live_primary_environment_check')


def test_existing_workflows_require_native_h7_on_both_hosts():
    yaml = pytest.importorskip('yaml')
    windows = yaml.safe_load((ROOT / '.github/workflows/live-backend.yml').read_text())
    linux = yaml.safe_load((ROOT / '.github/workflows/live-unified.yml').read_text())
    for job in (windows['jobs']['native'], linux['jobs']['linux']):
        steps = [step for step in job['steps']
                 if 'tools/live_primary_environment_check.py' in str(step.get('run', ''))]
        assert len(steps) == 1
        assert not steps[0].get('continue-on-error') and not job.get('continue-on-error')
        assert '--out ' in steps[0]['run']
    assert "matrix.variant == 'raw-cache-hit'" in next(
        step['if'] for step in windows['jobs']['native']['steps']
        if 'tools/live_primary_environment_check.py' in str(step.get('run', '')))
    assert any('tools/live_cache_check.py' in str(step.get('run', ''))
               for step in windows['jobs']['native']['steps'])


def test_authored_parent_values_are_restored_and_never_added_to_child(tmp_path, monkeypatch):
    module = tool()
    monkeypatch.setenv('GITHUB_TOKEN', 'preexisting-test-value')
    original = module.backend.run_process
    with module.observe_primary(tmp_path, []) as probe:
        assert os.environ['GITHUB_TOKEN'] == module.SENTINELS['GITHUB_TOKEN']
        assert module.backend.run_process == probe.run
    assert os.environ['GITHUB_TOKEN'] == 'preexisting-test-value'
    assert module.backend.run_process is original


@pytest.mark.parametrize('name', ['GITHUB_TOKEN', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS'])
def test_retained_sentinel_fails_before_any_delegate_launch(tmp_path, monkeypatch, name):
    module = tool()
    launches = []
    monkeypatch.setattr(module.backend, 'run_process', lambda *args, **kwargs: launches.append(args))
    observations = []
    with module.observe_primary(tmp_path, observations) as probe:
        with pytest.raises(module.QualificationFailure, match='retained'):
            probe.run([sys.executable, '-I', '-X', 'utf8', '-m', 'ghidriff', 'old', 'new'],
                      env={name: 'authored value'})
    assert launches == []
    assert observations[0]['sentinel_absent'][name] is False
    assert 'authored value' not in json.dumps(observations)


def test_bootstrap_keeps_environment_object_and_all_native_engine_arguments(tmp_path, monkeypatch):
    module = tool()
    environment = {'PATH': os.defpath}
    native = [sys.executable, '-I', '-X', 'utf8', '-m', 'ghidriff',
              'old path.dll', 'new path.dll', '--no-symbols', '--output-path', 'output path']
    delegated = []

    def actual(argv, **options):
        delegated.append(argv)
        assert options['env'] is environment
        assert argv[:4] == native[:4] and argv[4] == '-c'
        assert argv[8:] == native[6:]
        Path(argv[6]).write_text(json.dumps({'schema': 'patchtrace/h7-child/1', 'attempt': argv[7],
                                           'pid': 17, 'sentinel_absent': dict.fromkeys(module.SENTINELS, True)}))
        return ProcessResult(0, '', None)

    monkeypatch.setattr(module.backend, 'run_process', actual)
    observations = []
    with module.observe_primary(tmp_path, observations) as probe:
        probe.run(native, env=environment)
    assert len(delegated) == 1 and probe.primary_calls == 1
    assert observations[0]['child']['pid'] == 17
    assert all(observations[0]['child']['sentinel_absent'].values())


@pytest.mark.parametrize('bad', ['missing', 'stale', 'oversized', 'retained', 'wrong_type'])
def test_successful_process_without_current_valid_child_receipt_cannot_qualify(tmp_path, monkeypatch, bad):
    module = tool()

    def incomplete(argv, **options):
        if bad != 'missing':
            row = {'schema': 'patchtrace/h7-child/1', 'attempt': argv[7], 'pid': 17,
                   'sentinel_absent': dict.fromkeys(module.SENTINELS, True)}
            if bad == 'stale':
                row['attempt'] = '0' * 32
            if bad == 'retained':
                row['sentinel_absent']['GITHUB_TOKEN'] = False
            if bad == 'wrong_type':
                row['sentinel_absent']['GITHUB_TOKEN'] = 1
            Path(argv[6]).write_text('x' * 8193 if bad == 'oversized' else json.dumps(row))
        return ProcessResult(0, '', None)

    monkeypatch.setattr(module.backend, 'run_process', incomplete)
    with module.observe_primary(tmp_path, []) as probe:
        with pytest.raises(module.QualificationFailure, match='receipt'):
            probe.run([sys.executable, '-I', '-X', 'utf8', '-m', 'ghidriff', 'old', 'new'], env={})


def test_actual_python_entry_refuses_retained_dummy_without_importing_an_engine(tmp_path):
    module = tool()
    receipt = tmp_path / 'child.json'
    dummy = 'authored-secret-value-should-not-appear'
    env = {key: value for key, value in os.environ.items() if key not in module.SENTINELS}
    env['GITHUB_TOKEN'] = dummy
    result = run_process([sys.executable, '-I', '-X', 'utf8', '-c', module.CHILD_PROBE,
                          str(receipt), 'a' * 32, 'never-executed.dll'], cwd=tmp_path, env=env,
                         cancel=threading.Event(), timeout_seconds=15)
    assert result.returncode != 0 and result.reason is None
    record = json.loads(receipt.read_text())
    assert record['sentinel_absent']['GITHUB_TOKEN'] is False
    assert dummy not in receipt.read_text() + result.log_tail
    assert 'ModuleNotFoundError' not in result.log_tail


@pytest.mark.parametrize('change', ['fresh_hit', 'second_miss', 'raw', 'matches', 'extra_native', 'no_native'])
def test_cache_qualification_rejects_incomplete_or_changed_native_outcomes(change):
    module = tool()
    first = {'cache_hit': False, 'raw_sha256': 'a' * 64, 'matches_sha256': 'b' * 64, 'match_count': 1}
    second = {**first, 'cache_hit': True}
    calls = 1
    if change == 'fresh_hit':
        first['cache_hit'] = True
    elif change == 'second_miss':
        second['cache_hit'] = False
    elif change in ('raw', 'matches'):
        second[f'{change}_sha256'] = 'c' * 64
    else:
        calls = 2 if change == 'extra_native' else 0
    with pytest.raises(module.QualificationFailure):
        module.require_cache_reuse(first, second, calls)


def test_missing_native_prerequisites_write_blocked_receipt(tmp_path):
    module = tool()
    receipt = tmp_path / 'qualification.json'
    assert module.main(['--old', str(tmp_path / 'old.dll'), '--new', str(tmp_path / 'new.dll'),
                        '--ghidra-dir', str(tmp_path / 'absent'), '--out', str(receipt),
                        '--source-sha', 'a' * 40]) == 2
    record = json.loads(receipt.read_text())
    assert record['status'] == 'blocked' and record['mocked'] is False
    assert not record['observations']


def test_unvalidated_source_value_is_not_copied_into_receipt(tmp_path):
    module = tool()
    receipt = tmp_path / 'qualification.json'
    value = 'authored-value-that-is-not-a-commit'
    assert module.main(['--old', 'old.dll', '--new', 'new.dll', '--ghidra-dir', str(tmp_path),
                        '--out', str(receipt), '--source-sha', value]) == 2
    assert value not in receipt.read_text()
    assert json.loads(receipt.read_text())['source_sha'] is None
