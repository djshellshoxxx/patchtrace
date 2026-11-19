"""Authored connection observations; no process, thread, socket or compared image is executed."""
from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import bundle_acceptance as ba


def _monitor(values):
    values = list(values)
    pending = iter(values)

    def sample():
        value = next(pending)
        if isinstance(value, Exception):
            raise value
        return value

    monitor = ba.ConnectionMonitor(sample)
    for _ in values:
        monitor.poll()
    return monitor


def _acceptance(tmp_path, monkeypatch, monitor, *, control_proven=True):
    root = tmp_path / 'Patch Trace é中'
    for path in (root / 'backend' / 'manifest.json', ba.bundle_python(root, 'windows'),
                 ba.default_launcher(root, 'windows')):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'authored inert placeholder')
    calls = []

    def run(argv, env, timeout, cwd=None):
        if list(argv[-3:]) == list(ba.EXEC_PROBE):
            return subprocess.CompletedProcess(argv, 0, '1\n', '')
        if 'CONNECTED' in argv[-1]:
            calls.append(1)
            connected = len(calls) == 1 or not control_proven
            return subprocess.CompletedProcess(argv, 0 if connected else 1,
                                               'CONNECTED\n' if connected else 'BLOCKED\n', '')
        return subprocess.CompletedProcess(argv, 0, '{}\n', '')

    def monitored(argv, env, timeout, os_name):
        result = tmp_path / 'work' / 'out' / 'authored.ghidriff.json'
        result.write_text('{}', encoding='utf-8')
        return subprocess.CompletedProcess(argv, 0, '{}\n', ''), monitor

    def forbidden(*args, **kwargs):
        pytest.fail('this authored evidence test must not start a process or thread')

    monkeypatch.setattr(ba.subprocess, 'run', forbidden)
    monkeypatch.setattr(ba.subprocess, 'Popen', forbidden)
    monkeypatch.setattr(ba.threading.Thread, 'start', forbidden)
    monkeypatch.setattr(ba, '_run', run)
    monkeypatch.setattr(ba, '_run_monitored', monitored)
    monkeypatch.setattr(ba, 'path_tool_hits', lambda *args: [])
    monkeypatch.setattr(ba, 'writable_probe', lambda *args: False)
    return ba.run_acceptance(
        root, tmp_path / 'older.dll', tmp_path / 'newer.dll', 'authored_function', os_name='windows',
        work=tmp_path / 'work', host_run=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, '', ''),
    )


@pytest.mark.parametrize('values', [[], [[]], [[], []], [OSError('authored failure')] * 3,
                                   [[], OSError('authored failure'), []]])
def test_incomplete_observations_never_pass_connection_step(tmp_path, monkeypatch, values):
    evidence = _acceptance(tmp_path, monkeypatch, _monitor(values))
    steps = {step.name: step for step in evidence.steps}
    assert steps['control-after'].ok
    assert not steps['no-external-connections'].ok
    assert not evidence.ok
    assert 'passed with OS network block' not in evidence.wording()


def test_successful_empty_samples_are_counted_separately_from_errors(tmp_path, monkeypatch):
    monitor = _monitor([[], OSError('authored failure'), [], []])
    evidence = _acceptance(tmp_path, monkeypatch, monitor)
    step = next(step for step in evidence.steps if step.name == 'no-external-connections')
    assert evidence.ok and step.ok
    assert step.data == {'polls': 4, 'successful_polls': 3, 'sample_errors': 1,
                         'unavailable_polls': 0, 'seen': []}


def test_observed_external_endpoint_survives_later_sample_errors(tmp_path, monkeypatch):
    monitor = _monitor([['203.0.113.9:443'], OSError('authored failure'), [], []])
    evidence = _acceptance(tmp_path, monkeypatch, monitor)
    step = next(step for step in evidence.steps if step.name == 'no-external-connections')
    assert not step.ok and not evidence.ok
    assert step.data['seen'] == ['203.0.113.9:443']
    assert step.data['successful_polls'] == 3 and step.data['sample_errors'] == 1


def test_sample_success_never_replaces_positive_control(tmp_path, monkeypatch):
    evidence = _acceptance(tmp_path, monkeypatch, _monitor([[], [], []]), control_proven=False)
    steps = {step.name: step for step in evidence.steps}
    assert not evidence.ok and not steps['control-after'].ok
    assert 'no-external-connections' not in steps


@pytest.mark.parametrize('namespace', ['net:[host]', FileNotFoundError('child exited')])
def test_linux_race_or_exited_child_is_unavailable(monkeypatch, namespace):
    def readlink(path):
        if isinstance(namespace, Exception):
            raise namespace
        return namespace

    monkeypatch.setattr(ba.os, 'readlink', readlink)
    monkeypatch.setattr(Path, 'read_text', lambda *a, **kw: pytest.fail('no connection-table read expected'))
    monitor = ba.ConnectionMonitor(ba.linux_sampler(123, 'net:[host]'))
    monitor.poll()
    assert monitor.successful_polls == 0 and monitor.unavailable_polls == 1 and monitor.sample_errors == 0


@pytest.mark.parametrize('failed_table', ['tcp', 'tcp6'])
@pytest.mark.parametrize('failure, field', [(PermissionError('denied'), 'sample_errors'),
                                          (FileNotFoundError('child exited'), 'unavailable_polls')])
def test_partial_linux_observation_keeps_endpoints_without_success(monkeypatch, failed_table, failure, field):
    monkeypatch.setattr(ba.os, 'readlink', lambda path: 'net:[child]')

    def read(path, *args, **kwargs):
        if path.name == failed_table:
            raise failure
        return 'header\n0: 0A00000A:9C40 0101A8C0:01BB 01 0:0\n'

    monkeypatch.setattr(Path, 'read_text', read)
    monitor = ba.ConnectionMonitor(ba.linux_sampler(123, 'net:[host]'))
    monitor.poll()
    assert monitor.seen == {'0101A8C0:01BB'}
    assert monitor.successful_polls == 0 and getattr(monitor, field) == 1


def test_linux_complete_empty_tables_are_successful(monkeypatch):
    monkeypatch.setattr(ba.os, 'readlink', lambda path: 'net:[child]')
    monkeypatch.setattr(Path, 'read_text', lambda *args, **kwargs: 'header\n')
    monitor = ba.ConnectionMonitor(ba.linux_sampler(123, 'net:[host]'))
    monitor.poll()
    assert monitor.seen == set() and monitor.successful_polls == 1
    assert monitor.sample_errors == monitor.unavailable_polls == 0


@pytest.mark.parametrize('outcome', [1, subprocess.TimeoutExpired('authored sampler', 1), OSError('unavailable')])
def test_windows_failed_sampler_is_not_empty_success(monkeypatch, outcome):
    child = SimpleNamespace(pid=123, returncode=0, communicate=lambda timeout: ('authored', ''))
    monkeypatch.setattr(ba.subprocess, 'Popen', lambda *a, **kw: child)

    def run(argv, **kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        return subprocess.CompletedProcess(argv, outcome, '', 'authored sampler failure')

    def enter(monitor):
        for _ in range(3):
            monitor.poll()
        return monitor

    monkeypatch.setattr(ba.subprocess, 'run', run)
    monkeypatch.setattr(ba.ConnectionMonitor, '__enter__', enter)
    monkeypatch.setattr(ba.ConnectionMonitor, '__exit__', lambda *args: None)
    _, monitor = ba._run_monitored(['authored-launcher'], {}, 1, 'windows')
    assert monitor.polls == 3 and monitor.successful_polls == 0 and monitor.sample_errors == 3


def test_windows_successful_empty_sampler_is_bounded_and_observable(monkeypatch):
    child = SimpleNamespace(pid=123, returncode=0, communicate=lambda timeout: ('authored', ''))
    monkeypatch.setattr(ba.subprocess, 'Popen', lambda *a, **kw: child)

    def run(argv, **kwargs):
        assert 0 < kwargs['timeout'] <= 5
        assert '-ErrorAction Stop' in argv[-1] and 'SilentlyContinue' not in argv[-1]
        return subprocess.CompletedProcess(argv, 0, '', '')

    def enter(monitor):
        monitor.poll()
        return monitor

    monkeypatch.setattr(ba.subprocess, 'run', run)
    monkeypatch.setattr(ba.ConnectionMonitor, '__enter__', enter)
    monkeypatch.setattr(ba.ConnectionMonitor, '__exit__', lambda *args: None)
    _, monitor = ba._run_monitored(['authored-launcher'], {}, 1, 'windows')
    assert monitor.successful_polls == 1 and monitor.sample_errors == 0


@pytest.mark.parametrize('outcome', [
    subprocess.CompletedProcess(['authored sampler'], 1, '203.0.113.9:443\n', 'authored error'),
    subprocess.TimeoutExpired('authored sampler', 1, output=b'203.0.113.9:443\n'),
    subprocess.TimeoutExpired('authored sampler', 1, output='203.0.113.9:443\n'),
])
def test_windows_partial_endpoints_survive_failure_and_recovery(tmp_path, monkeypatch, outcome):
    child = SimpleNamespace(pid=123, returncode=0, communicate=lambda timeout: ('authored', ''))
    monkeypatch.setattr(ba.subprocess, 'Popen', lambda *a, **kw: child)

    def run(argv, **kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def enter(monitor):
        monitor.poll()
        return monitor

    monkeypatch.setattr(ba.subprocess, 'run', run)
    monkeypatch.setattr(ba.ConnectionMonitor, '__enter__', enter)
    monkeypatch.setattr(ba.ConnectionMonitor, '__exit__', lambda *args: None)
    _, monitor = ba._run_monitored(['authored-launcher'], {}, 1, 'windows')
    monitor.sample = lambda: []
    for _ in range(3):
        monitor.poll()
    evidence = _acceptance(tmp_path, monkeypatch, monitor)
    step = next(step for step in evidence.steps if step.name == 'no-external-connections')
    assert not step.ok and not evidence.ok
    assert step.data['seen'] == ['203.0.113.9:443']
    assert step.data['successful_polls'] == 3 and step.data['sample_errors'] == 1
