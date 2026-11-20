"""Native cache harness diagnostics with injected projects and processes, never native analysis."""
from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from patchtrace import backend
from patchtrace.jobs import ProcessResult
from patchtrace.service import ProjectService

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'live_cache_check.py'


@pytest.fixture
def fake_native(monkeypatch):
    state = SimpleNamespace(roots=[], services=[], process_calls=[], hit=False, fail_first=False,
                            java_output='java probe timed out', java_reason='timeout', raw_mismatch=False,
                            event_count=1, event_message='cache lookup completed')
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', '/fake/ghidra')
    monkeypatch.setattr(backend, '_java_executable', lambda _config: '/fake/java')
    monkeypatch.setattr(backend, '_environment', lambda _config: {'SECRET_TOKEN': 'never-record-this'})

    def process(argv, **kwargs):
        state.process_calls.append((list(argv), kwargs))
        return ProcessResult(-1 if state.java_reason else 0, state.java_output,
                             reason=state.java_reason, elapsed_seconds=0.1)

    monkeypatch.setattr(backend, 'run_process', process)
    state.process = process

    def create(_older, _newer, _name, root):
        root.mkdir()
        state.roots.append(root)
        service = SimpleNamespace(project=SimpleNamespace(matches=[]), closed=False)

        def apply(_path, _run):
            service.project.matches = [SimpleNamespace(category='modified', older=[SimpleNamespace(name='old')],
                                                       newer=[SimpleNamespace(name='new')])]

        service.apply_analysis = apply
        service.close = lambda: setattr(service, 'closed', True)
        state.services.append(service)
        return service

    monkeypatch.setattr(ProjectService, 'create', create)

    def compare(config, _project, root, cancel, on_event):
        version = backend._java_version(config, cancel)
        settings = {'java_runtime_version': 'unverified' if version == 'unknown' else version,
                    'python_version': '3.12', 'ghidra_version': 'fake', 'pyghidra_version': 'fake',
                    'secret_token': 'never-record-this'}
        second = len(state.roots) == 2
        if second and state.hit:
            settings['cache_origin'] = {'key': 'a' * 64, 'created': '2026-11-20T00:00:00Z'}
        for _ in range(state.event_count):
            on_event(SimpleNamespace(stage='cache', message=state.event_message, created='now'))
        raw = b'{"synthetic": true}' if not (second and state.raw_mismatch) else b'{"synthetic": false}'
        (root / 'raw.json').write_bytes(raw)
        run = SimpleNamespace(id=f'run-{len(state.roots)}', status='failed' if state.fail_first else 'completed',
                              error='controlled backend failure' if state.fail_first else None,
                              backend_version='fake-ghidriff', settings=settings, raw_path='raw.json')
        return root, run

    monkeypatch.setattr(backend, 'run_comparison', compare)
    return state


def invoke(monkeypatch, output: Path | None):
    arguments = [str(SCRIPT)]
    if output is not None:
        arguments += ['--diagnostics-dir', str(output)]
    monkeypatch.setattr(sys, 'argv', arguments)
    return runpy.run_path(str(SCRIPT), run_name='__main__')


def test_cache_miss_keeps_both_runs_and_original_java_probe_results(tmp_path, monkeypatch, fake_native):
    output = tmp_path / 'diagnostics'
    with pytest.raises(AssertionError, match='second run was not a cache hit; java=unverified'):
        invoke(monkeypatch, output)
    assert (output / 'first.json').is_file(), 'temporary first-run diagnostics were discarded'
    first, second, final = [json.loads((output / name).read_text())
                            for name in ('first.json', 'second.json', 'result.json')]
    assert first['run']['status'] == second['run']['status'] == 'completed'
    assert first['run']['settings']['java_runtime_version'] == 'unverified'
    assert final['status'] == 'failed' and final['exception_class'] == 'AssertionError'
    for record in (first, second):
        assert [probe['timeout_seconds'] for probe in record['java_probes']] == [15, 30]
        assert all(probe['reason'] == 'timeout' for probe in record['java_probes'])
        assert all(probe['log_tail'] == 'java probe timed out' for probe in record['java_probes'])
        assert record['raw_sha256'] and record['match_count'] == 1
    assert [kwargs['timeout_seconds'] for _argv, kwargs in fake_native.process_calls] == [15, 30, 15, 30]
    assert backend.run_process is fake_native.process
    assert all(service.closed for service in fake_native.services)
    assert all(not root.exists() for root in fake_native.roots)
    assert 'never-record-this' not in ''.join(path.read_text() for path in output.glob('*.json'))


def test_success_records_acceptance_without_extra_probes(tmp_path, monkeypatch, fake_native, capsys):
    fake_native.hit = True
    fake_native.java_reason = None
    fake_native.java_output = 'openjdk version "25.0.1" 2026-01-01'
    output = tmp_path / 'diagnostics'
    invoke(monkeypatch, output)
    records = [json.loads((output / name).read_text()) for name in ('first.json', 'second.json', 'result.json')]
    assert records[2]['status'] == 'passed'
    assert records[0]['run']['settings']['java_runtime_version'] == '25.0.1'
    assert 'cache_origin' not in records[0]['run']['settings']
    assert records[1]['run']['settings']['cache_origin']['key'] == 'a' * 64
    assert len(fake_native.process_calls) == 2
    assert 'Raw cache hit verified:' in capsys.readouterr().out


def test_no_option_keeps_temporary_cleanup_and_original_gate(tmp_path, monkeypatch, fake_native):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(AssertionError, match='second run was not a cache hit; java=unverified'):
        invoke(monkeypatch, None)
    assert list(tmp_path.iterdir()) == []
    assert all(not root.exists() for root in fake_native.roots)
    assert backend.run_process is fake_native.process
    assert [kwargs['timeout_seconds'] for _argv, kwargs in fake_native.process_calls] == [15, 30, 15, 30]


def test_failed_first_run_is_retained_and_second_run_is_not_started(tmp_path, monkeypatch, fake_native):
    fake_native.fail_first = True
    output = tmp_path / 'diagnostics'
    with pytest.raises(RuntimeError, match='controlled backend failure'):
        invoke(monkeypatch, output)
    first = json.loads((output / 'first.json').read_text())
    assert first['run']['status'] == 'failed' and first['exception_class'] == 'RuntimeError'
    assert first['java_probes'] and first['events']
    assert not (output / 'second.json').exists()
    assert json.loads((output / 'result.json').read_text())['status'] == 'failed'
    assert len(fake_native.roots) == 1 and fake_native.services[0].closed
    assert backend.run_process is fake_native.process


def test_byte_mismatch_keeps_original_failure_and_both_digests(tmp_path, monkeypatch, fake_native):
    fake_native.hit = fake_native.raw_mismatch = True
    output = tmp_path / 'diagnostics'
    with pytest.raises(AssertionError, match='cache hit differs from the fresh run'):
        invoke(monkeypatch, output)
    first, second = [json.loads((output / name).read_text()) for name in ('first.json', 'second.json')]
    assert first['raw_sha256'] != second['raw_sha256']
    assert json.loads((output / 'result.json').read_text())['status'] == 'failed'


def test_existing_directory_is_refused_before_work_and_kept_unchanged(tmp_path, monkeypatch, fake_native):
    output = tmp_path / 'existing-project'
    output.mkdir()
    previous = output / 'result.json'
    previous.write_bytes(b'preserve these project bytes')
    with pytest.raises(FileExistsError):
        invoke(monkeypatch, output)
    assert previous.read_bytes() == b'preserve these project bytes'
    assert list(output.iterdir()) == [previous]
    assert fake_native.roots == fake_native.process_calls == []


def test_diagnostic_tails_are_bounded_and_redacted(tmp_path, monkeypatch, fake_native):
    fake_native.hit = True
    fake_native.event_count = 100
    fake_native.event_message = 'x' * 800 + ' password=event-secret'
    fake_native.java_output = 'x' * 10_000 + ' token=java-secret'
    output = tmp_path / 'diagnostics'
    invoke(monkeypatch, output)
    for path in output.glob('*.json'):
        raw = path.read_bytes()
        assert len(raw) <= 512 * 1024
        assert b'event-secret' not in raw and b'java-secret' not in raw and b'never-record-this' not in raw
    first = json.loads((output / 'first.json').read_text())
    assert len(first['events']) == 64 and first['events_omitted'] == 36
    assert all(len(event['message']) <= 512 for event in first['events'])
    assert all(len(probe['log_tail']) <= 4096 for probe in first['java_probes'])
    assert '[redacted]' in first['events'][-1]['message']
    assert '[redacted]' in first['java_probes'][-1]['log_tail']


def test_write_failure_is_explicit_and_does_not_suppress_native_failure(tmp_path, monkeypatch,
                                                                       fake_native, capsys):
    output = tmp_path / 'diagnostics'
    original_open = Path.open

    def fail_reports(path, *args, **kwargs):
        if path.parent == output and path.suffix == '.json':
            raise OSError('controlled unavailable destination')
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', fail_reports)
    with pytest.raises(AssertionError, match='second run was not a cache hit; java=unverified'):
        invoke(monkeypatch, output)
    assert capsys.readouterr().err.count('Cache diagnostics could not be written') == 3
    assert all(service.closed for service in fake_native.services)
    assert backend.run_process is fake_native.process


def test_java_observer_preserves_call_objects_results_exceptions_and_restoration(monkeypatch):
    observe = runpy.run_path(str(SCRIPT))['_observe_java']
    environment, positional = {'SECRET_TOKEN': 'never-record-this'}, object()
    result = ProcessResult(0, 'openjdk version "25.0.1"')
    failure = OSError('controlled Java launch failure')
    calls = []
    fail = False

    def original(argv, *args, **kwargs):
        calls.append((argv, args, kwargs))
        if fail:
            raise failure
        return result

    monkeypatch.setattr(backend, 'run_process', original)
    record = {'java_probes': []}
    argv = ['/fake/java', '-version']
    with pytest.raises(OSError) as caught, observe(record):
        for _ in range(6):
            assert backend.run_process(argv, positional, env=environment, timeout_seconds=15) is result
        assert backend.run_process(['/fake/python', '-c', 'pass'], env=environment) is result
        fail = True
        backend.run_process(argv, positional, env=environment, timeout_seconds=30)
    assert caught.value is failure and backend.run_process is original
    assert calls[0][0] is argv and calls[0][1] == (positional,) and calls[0][2]['env'] is environment
    assert len(calls) == 8 and len(record['java_probes']) == 4 and record['java_probes_omitted'] == 3


def test_java_spawn_exception_is_recorded_without_changing_it(monkeypatch):
    observe = runpy.run_path(str(SCRIPT))['_observe_java']
    failure = OSError('controlled Java launch failure')

    def original(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(backend, 'run_process', original)
    record = {'java_probes': []}
    with pytest.raises(OSError) as caught, observe(record):
        backend.run_process(['/fake/java', '-version'], timeout_seconds=15)
    assert caught.value is failure and backend.run_process is original
    assert record['java_probes'][0]['exception_class'] == 'OSError'


def test_workflow_uploads_diagnostics_even_when_native_acceptance_fails():
    workflow = yaml.safe_load((SCRIPT.parents[1] / '.github/workflows/live-backend.yml').read_text())
    steps = workflow['jobs']['native']['steps']
    cache = next(step for step in steps if step.get('if') == "matrix.variant == 'raw-cache-hit'")
    assert cache['run'] == 'python tools/live_cache_check.py --diagnostics-dir live-cache-diagnostics'
    upload = next(step for step in steps if step.get('uses') == 'actions/upload-artifact@v4')
    assert upload['if'] == 'always()'
    assert 'live-cache-diagnostics/*.json' in upload['with']['path'].splitlines()
