"""Authored probe outcomes exercise live-harness evidence; these are not native acceptance."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import intel_probe_diagnostics as diagnostics
import pytest
import test_live_intel_tools as live

from patchtrace.intelligence.tools import process


@pytest.mark.parametrize('engine', ['capa', 'floss'])
def test_failed_probe_retains_existing_output_and_original_failure(
        engine, tmp_path, monkeypatch, record_live_status):
    executable = tmp_path / f'{engine}.exe'
    executable.write_bytes(b'authored executable placeholder; never executed')
    status = tmp_path / 'status'
    monkeypatch.setenv(live.ENV[engine], str(executable))
    monkeypatch.setenv('PATCHTRACE_LIVE_STATUS_DIR', str(status))
    monkeypatch.setenv('PATCHTRACE_LIVE_MOCKED', '1')
    outputs = [process.Execution(1, None, 'version stdout', 'loader error', False, 12),
               process.Execution(0, None, 'help stdout', 'help stderr', False, 8)]
    calls = []

    def original(exe, args, **kwargs):
        calls.append((exe, args, kwargs))
        return outputs[len(calls) - 1]

    monkeypatch.setattr(process, 'run_version_probe', original)

    def probe(engine, config, cancel, runner):
        for args in (['--version'], ['--help']):
            result = process.run_version_probe(config.executable, args, cancel=cancel, runner=runner,
                                               environ={'SECRET_TOKEN': 'must-not-be-recorded'})
            assert result is outputs[len(calls) - 1]
        return SimpleNamespace(supported=False, pin_status='pinned', reason='version failed (exit 1)')

    monkeypatch.setattr(live.runner, 'probe_engine', probe)
    with pytest.raises(pytest.fail.Exception, match=r'version failed \(exit 1\)'):
        live.test_pinned_tool_probes_and_reproduces_the_goldens(engine, tmp_path, record_live_status)
    document = json.loads((status / f'intel-tools-{engine}.json').read_text())
    assert document['status'] == 'failed' and document['mocked'] is True
    assert len(calls) == 2 and process.run_version_probe is original
    assert 'probe_diagnostics' in document, 'live failure discarded existing version/help probe outputs'
    probes = document['probe_diagnostics']['probes']
    assert [p['returncode'] for p in probes] == [1, 0]
    assert [p['stdout'] for p in probes] == ['version stdout', 'help stdout']
    assert [p['stderr'] for p in probes] == ['loader error', 'help stderr']
    assert [p['argv'] for p in probes] == [[executable.name, '--version'], [executable.name, '--help']]
    assert 'must-not-be-recorded' not in json.dumps(document)
    assert str(tmp_path) not in json.dumps(document)


def test_observer_forwards_objects_and_returns_identical_result(monkeypatch):
    executable = Path('/private/location/capa.exe')
    args = ['--version']
    cancel, runner = threading.Event(), object()
    environment = {'SECRET_TOKEN': 'do-not-record-the-environment'}
    output = process.Execution(0, None, 'capa.exe 9.4.0', '', False, 3)
    calls = []

    def original(exe, argv, **kwargs):
        calls.append((exe, argv, kwargs))
        return output

    monkeypatch.setattr(process, 'run_version_probe', original)
    with diagnostics.capture_version_probes() as document:
        assert process.run_version_probe(executable, args, cancel=cancel, runner=runner,
                                         environ=environment, timeout=7) is output
    assert process.run_version_probe is original and len(calls) == 1
    assert calls[0][0] is executable and calls[0][1] is args
    assert calls[0][2] == {'cancel': cancel, 'runner': runner, 'environ': environment, 'timeout': 7}
    assert calls[0][2]['environ'] is environment
    entry = document['probes'][0]
    assert entry['argv'] == ['capa.exe', '--version']
    assert entry['returncode'] == 0 and entry['elapsed_ms'] == 3
    assert entry['stdout'] == output.stdout and entry['stdout_chars'] == len(output.stdout)
    assert entry['spawn_error'] is None and entry['spawn_error_truncated'] is False
    assert not entry['stdout_truncated'] and not entry['stderr_truncated']
    assert '/private' not in json.dumps(document) and 'do-not-record' not in json.dumps(document)


@pytest.mark.parametrize('failure', [OSError('original failure'), KeyboardInterrupt(), SystemExit(2)])
def test_observer_preserves_original_exception_and_restores_callable(monkeypatch, failure):
    calls = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        raise failure

    monkeypatch.setattr(process, 'run_version_probe', original)
    with pytest.raises(type(failure)) as caught, diagnostics.capture_version_probes() as document:
        process.run_version_probe(Path('/private/floss.exe'), ['-H'], runner=object())
    assert caught.value is failure and process.run_version_probe is original
    assert len(calls) == 1
    assert document['probes'][0]['exception_class'] == type(failure).__name__
    assert 'original failure' not in json.dumps(document)


def test_bounds_redaction_and_omission_do_not_change_underlying_calls(monkeypatch):
    output = process.Execution(1, 'timeout' * 100,
                               '\u03bb' * 10_000 + ' password=stdout-private',
                               '\x00' * 10_000 + ' token=stderr-private',
                               True, 61, spawn_error='x' * 5000 + ' secret=spawn-private')
    calls = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        return output

    monkeypatch.setattr(process, 'run_version_probe', original)
    with diagnostics.capture_version_probes() as document:
        for _ in range(7):
            assert process.run_version_probe(Path('/private') / ('q' * 180 + '.exe'), ['--version']) is output
    assert len(calls) == 7 and len(document['probes']) == 4 and document['probes_omitted'] == 3
    encoded = json.dumps(document)
    assert len(encoded.encode('utf-8')) < 256 * 1024
    assert all(value not in encoded for value in ('stdout-private', 'stderr-private', 'spawn-private', '/private'))
    for entry in document['probes']:
        assert len(entry['argv'][0]) <= 128 and entry['command_truncated']
        assert len(entry['reason']) <= 256 and entry['reason_truncated']
        assert len(entry['spawn_error']) <= 1024 and entry['spawn_error_truncated']
        for field in ('stdout', 'stderr'):
            assert len(entry[field]) <= 4096 and entry[field + '_truncated']
            assert entry[field + '_chars'] == len(getattr(output, field))
            assert '[redacted]' in entry[field]
        assert entry['returncode'] == 1 and entry['oversize'] is True


def test_unrecognized_arguments_are_forwarded_without_observation(monkeypatch):
    args = ['--analyse', 'private-input-name', '--token', 'not-to-be-recorded']
    output = process.Execution(0, None, 'unchanged', '', False, 0)
    calls = []

    def original(exe, argv, **kwargs):
        calls.append((exe, argv, kwargs))
        return output

    monkeypatch.setattr(process, 'run_version_probe', original)
    with diagnostics.capture_version_probes() as document:
        assert process.run_version_probe(Path('/private/floss.exe'), args) is output
    assert len(calls) == 1 and calls[0][1] is args
    assert document == {'contract': 'intel-version-probes/1', 'probes': [], 'probes_omitted': 0}


def test_observation_failure_does_not_replace_original_result(monkeypatch):
    output = process.Execution(1, None, '', 'native failure', False, 1)
    monkeypatch.setattr(process, 'run_version_probe', lambda *a, **kw: output)

    def fail_format(*args):
        raise ValueError('diagnostic-only secret=never-record-this')

    monkeypatch.setattr(diagnostics, 'redact_log', fail_format)
    with diagnostics.capture_version_probes() as document:
        assert process.run_version_probe(Path('/private/floss.exe'), ['--version']) is output
    assert document['probes'] == [{'observation_error_class': 'ValueError'}]
    assert 'never-record-this' not in json.dumps(document)


@pytest.mark.parametrize('scenario, expected', [
    ('success', 'passed'), ('unpinned', 'failed'), ('blocked-die', 'blocked'),
    ('run-failure', 'failed'), ('golden-mismatch', 'failed'), ('cached-probe', 'passed'),
])
def test_existing_live_acceptance_outcomes_keep_probe_evidence(
        scenario, expected, tmp_path, monkeypatch, record_live_status):
    engine = 'diec' if scenario == 'blocked-die' else 'floss'
    executable = tmp_path / f'{engine}.exe'
    executable.write_bytes(b'authored placeholder; never executed')
    status = tmp_path / 'status'
    monkeypatch.setenv(live.ENV[engine], str(executable))
    monkeypatch.setenv('PATCHTRACE_LIVE_STATUS_DIR', str(status))
    monkeypatch.setenv('PATCHTRACE_LIVE_MOCKED', '1')
    monkeypatch.setattr(live, 'REQUIRE', False)
    calls, runs, comparisons = [], [], []
    output = process.Execution(0, None, 'version output', 'probe diagnostic', False, 3)

    def original(exe, args, **kwargs):
        calls.append((exe, args, kwargs))
        return output

    monkeypatch.setattr(process, 'run_version_probe', original)

    def probe(_engine, config, cancel, runner):
        if scenario != 'cached-probe':
            assert process.run_version_probe(config.executable, ['--version'],
                                             cancel=cancel, runner=runner) is output
        return SimpleNamespace(supported=scenario != 'blocked-die',
                               pin_status='unpinned' if scenario == 'unpinned' else 'pinned',
                               reason='controlled unsupported probe', version='controlled')

    def run_tools(*args):
        runs.append(args)
        return [SimpleNamespace(evidence={'same'},
                                run=SimpleNamespace(side=side,
                                                    status='failed' if scenario == 'run-failure' else 'ok',
                                                    error='controlled run error'))
                for side in ('older', 'newer')]

    def golden(*args):
        comparisons.append(args)
        return {'different'} if scenario == 'golden-mismatch' else {'same'}

    monkeypatch.setattr(live.runner, 'probe_engine', probe)
    monkeypatch.setattr(live.runner, 'run_tools', run_tools)
    monkeypatch.setattr(live, 'golden_content', golden)
    monkeypatch.setattr(live, 'comparable', lambda value: value)
    if expected == 'passed':
        live.test_pinned_tool_probes_and_reproduces_the_goldens(engine, tmp_path, record_live_status)
        assert len(comparisons) == 2
    else:
        failure = pytest.skip.Exception if expected == 'blocked' else pytest.fail.Exception
        with pytest.raises(failure):
            live.test_pinned_tool_probes_and_reproduces_the_goldens(engine, tmp_path, record_live_status)
    document = json.loads((status / f'intel-tools-{engine}.json').read_text())
    assert document['status'] == expected and document['mocked'] is True
    assert process.run_version_probe is original
    probes = document['probe_diagnostics']['probes']
    assert len(probes) == len(calls) == (0 if scenario == 'cached-probe' else 1)
    if probes:
        assert probes[0]['stderr'] == 'probe diagnostic'
    assert len(runs) == (0 if scenario in ('unpinned', 'blocked-die') else 1)
