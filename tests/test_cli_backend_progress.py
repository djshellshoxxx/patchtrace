"""Synthetic long-run events through real CLI listeners; no native backend or target execution."""
from __future__ import annotations

import hashlib
import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from patchtrace import backend, backend_cli, cli
from patchtrace.backend import BackendConfig
from patchtrace.models import AnalysisRun, JobEvent, uid
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

HEARTBEATS = 7200


def emit_long_run(listener, run_id, terminal):
    """Two hours' worth of one-second heartbeats, without sleeping or invoking a process."""
    visible = [
        ('analysis', 'Starting comparison'),
        ('analysis-stage', 'Ghidriff stage: analyzing binaries'),
        ('analysis-stage', 'Ghidriff stage: matching functions'),
        ('analysis-stopped', 'Ghidriff subprocess supervision ended'),
        ('warning', 'Diagnostic warning retained'),
        ('log', 'Retained backend log'),
        ('analysis-progress-detail', 'Distinct event retained'),
        (terminal, f'Comparison {terminal}'),
    ]

    def emit(item):
        listener(JobEvent(run_id=run_id, stage=item[0], message=item[1]))

    emit(visible[0])
    emit(visible[1])
    for elapsed in range(HEARTBEATS):
        if elapsed == HEARTBEATS // 2:
            emit(visible[2])
        emit(('analysis-progress', f'HEARTBEAT {elapsed} / {HEARTBEATS} seconds'))
    for item in visible[3:]:
        emit(item)
    return visible


def assert_visible_output(stderr, prefix, visible):
    lines = stderr.splitlines()
    assert len(lines) == len(visible), 'CLI output grew with per-second heartbeats'
    assert lines == [f'{prefix}: {stage}: {message}' for stage, message in visible]
    assert 'HEARTBEAT' not in stderr


def test_selftest_listener_suppresses_only_analysis_progress(capsys):
    visible = emit_long_run(backend_cli._event_printer, uid(), 'failed')
    for stage in ('cancelled', 'completed', 'cache', 'identical'):
        backend_cli._event_printer(JobEvent(run_id='test-run', stage=stage, message='Terminal event retained'))
        visible.append((stage, 'Terminal event retained'))
    captured = capsys.readouterr()
    assert captured.out == ''
    assert_visible_output(captured.err, 'selftest', visible)


@pytest.fixture
def pair(tmp_path):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    return older, newer


def install_event_engine(monkeypatch, status):
    """Replace only the external backend; production service normalization/persistence still run."""
    seen = {}

    def run(config, project, root, cancel, on_event):
        run_id = uid()
        seen.update(config=config, root=root, cancel=cancel, run_id=run_id)
        seen['visible'] = emit_long_run(on_event, run_id, status)
        if status != 'completed':
            if status == 'cancelled':
                cancel.set()
            quarantine = root / 'runs' / f'quarantine-{run_id}'
            quarantine.mkdir(parents=True)
            return quarantine, AnalysisRun(id=run_id, status=status, error=f'Fixture comparison {status}')
        raw = root / 'runs' / run_id / 'raw' / 'result.ghidriff.json'
        raw.parent.mkdir(parents=True)
        hashes = {artifact.side: artifact.sha256 for artifact in project.artifacts}
        raw.write_text(json.dumps({
            'old_meta': {'SHA256': hashes['older']}, 'new_meta': {'SHA256': hashes['newer']},
            'functions': {'added': [{'name': 'patched_fn', 'address': '1000'}],
                          'deleted': [], 'modified': []},
        }), encoding='utf-8')
        return raw, AnalysisRun(id=run_id, status='completed', raw_path=raw.relative_to(root).as_posix(),
                                raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest())

    monkeypatch.setattr(backend, 'run_comparison', run)
    return seen


@pytest.mark.parametrize('status', ['completed', 'failed', 'cancelled'])
def test_pair_callback_bounds_long_run_output_and_preserves_results(tmp_path, pair, monkeypatch, capsys, status):
    root = tmp_path / 'pair-project'
    ProjectService.create(*pair, 'CLI progress fixture', root).close()
    config = BackendConfig(str(Path(sys.executable).resolve()), str(tmp_path / 'unused-ghidra'))
    cancel = threading.Event()
    seen = install_event_engine(monkeypatch, status)

    error = cli._run_pair(config, root, cancel)
    captured = capsys.readouterr()
    assert captured.out == ''
    assert_visible_output(captured.err, root.name, seen['visible'])
    assert seen['config'] is config and seen['cancel'] is cancel and seen['root'] == root.resolve()
    assert error == (None if status == 'completed' else f'Fixture comparison {status}')
    service = ProjectService.open(root)
    try:
        assert service.project.runs[-1].id == seen['run_id']
        assert service.project.runs[-1].status == status
        if status == 'completed':
            assert [function.name for match in service.project.matches for function in match.newer] == ['patched_fn']
        else:
            assert service.project.matches == []
            assert service.project.runs[-1].error == error
    finally:
        service.close()


@pytest.mark.parametrize(('status', 'expected_exit', 'expected_envelope'), [
    ('completed', 0, 'complete'), ('failed', 3, 'failed'), ('cancelled', 5, 'cancelled'),
])
def test_selftest_callback_bounds_long_run_output_and_keeps_exit_contract(
        tmp_path, pair, monkeypatch, capsys, status, expected_exit, expected_envelope):
    root = tmp_path / 'selftest-project'
    args = SimpleNamespace(action='selftest', json=True, older=pair[0], newer=pair[1],
                           expect_function=['patched_fn'])
    config = BackendConfig(str(Path(sys.executable).resolve()), str(tmp_path / 'unused-ghidra'))
    cancel = threading.Event()
    seen = install_event_engine(monkeypatch, status)

    result = backend_cli._run_selftest(args, cancel, config, SimpleNamespace(runtime_id='test-runtime'), root)
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert result == expected_exit
    assert document['contract'] == 'enrichment-cli/1' and document['command'] == 'backend selftest'
    assert document['status'] == expected_envelope and document['result']['run_status'] == status
    assert_visible_output(captured.err, 'selftest', seen['visible'])
    assert seen['config'] is config and seen['cancel'] is cancel
    if status == 'completed':
        assert document['result']['matches'] == 1
        assert document['result']['expected_functions'] == {'patched_fn': True}
    else:
        assert document['result']['error'] == f'Fixture comparison {status}'
