"""Independent review controls; injected projects/processes only, never native analyzers."""
from __future__ import annotations

import importlib.util
import json
import math
import runpy
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from patchtrace import backend
from patchtrace.jobs import ProcessResult
from patchtrace.service import ProjectService

ROOT = Path('/workspace/scratch/b1d1356aa953/patchtrace-cache-review')
HERE = Path(__file__).parent


@pytest.fixture
def harness():
    spec = importlib.util.spec_from_file_location('independent_cache_harness', ROOT / 'tools/live_cache_check.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('failure', [OSError('spawn secret=hidden'), RuntimeError('ordinary'),
                                    KeyboardInterrupt('interrupt'), SystemExit(17)])
def test_observer_preserves_exception_identity_and_restores(harness, monkeypatch, failure):
    argv = ['/fake/java', '-version']
    environment = {'PRIVATE_SENTINEL': 'do-not-export-env'}
    cancel, positional = threading.Event(), object()
    calls = []

    def original(got_argv, *args, **kwargs):
        calls.append((got_argv, args, kwargs))
        raise failure

    monkeypatch.setattr(backend, 'run_process', original)
    document = {'java_probes': []}
    with pytest.raises(type(failure)) as caught:
        with harness._observe_java(document):
            backend.run_process(argv, positional, env=environment, cancel=cancel, timeout_seconds=15,
                                log_limit=4096)
    assert caught.value is failure
    assert backend.run_process is original
    assert len(calls) == 1 and calls[0][0] is argv and calls[0][1] == (positional,)
    assert calls[0][2]['env'] is environment and calls[0][2]['cancel'] is cancel
    assert calls[0][2]['timeout_seconds'] == 15 and calls[0][2]['log_limit'] == 4096
    assert document['java_probes'][0]['exception_class'] == type(failure).__name__
    assert 'do-not-export-env' not in json.dumps(document)
    assert 'hidden' not in json.dumps(document)


def test_observer_returns_original_result_and_bypasses_unrelated_calls(harness, monkeypatch):
    result = ProcessResult(3, 'opaque result token=hidden', 'cancelled', elapsed_seconds=0.5)
    calls = []

    def original(argv, *args, **kwargs):
        calls.append((argv, args, kwargs))
        return result

    monkeypatch.setattr(backend, 'run_process', original)
    document = {'java_probes': []}
    unrelated = ['/fake/python', '-c', 'private-argument']
    with harness._observe_java(document):
        assert backend.run_process(unrelated, opaque=object()) is result
        assert document == {'java_probes': []}
        for _ in range(9):
            assert backend.run_process(['/fake/java', '-version'], timeout_seconds=15) is result
    assert backend.run_process is original
    assert calls[0][0] is unrelated and len(calls) == 10
    assert len(document['java_probes']) == 4 and document['java_probes_omitted'] == 5
    assert 'private-argument' not in json.dumps(document) and 'hidden' not in json.dumps(document)


def test_bad_result_observation_cannot_replace_result(harness, monkeypatch):
    class ResultWithUnreadableDiagnostics:
        @property
        def returncode(self):
            raise ValueError('diagnostic property unavailable')

    result = ResultWithUnreadableDiagnostics()
    original = lambda *args, **kwargs: result
    monkeypatch.setattr(backend, 'run_process', original)
    document = {'java_probes': []}
    with harness._observe_java(document):
        assert backend.run_process(['/fake/java', '-version'], timeout_seconds=15) is result
    assert backend.run_process is original
    assert document['java_probes'][0]['observation_error_class'] == 'ValueError'


@pytest.mark.parametrize('case,expected,limits', [
    ('success', '25.0.5', [15]),
    ('timeout_success', '25.0.5', [15, 30]),
    ('timeout_twice', 'unknown', [15, 30]),
    ('cancelled_timeout', 'unknown', [15]),
    ('nonzero', 'unknown', [15]),
    ('oserror', 'unknown', [15]),
    ('missing', 'unknown', []),
])
def test_real_version_helper_policy_is_identical_with_observer(harness, monkeypatch, tmp_path,
                                                             case, expected, limits):
    monkeypatch.setattr(backend, '_java_executable', lambda config: None if case == 'missing' else '/fake/java')
    environment = {'PRIVATE_SENTINEL': 'not-recorded'}
    monkeypatch.setattr(backend, '_environment', lambda config: environment)
    observations = []
    for enabled in (False, True):
        cancel, calls = threading.Event(), []

        def original(argv, **kwargs):
            calls.append((argv, kwargs))
            assert kwargs['cancel'] is cancel and kwargs['env'] is environment
            assert kwargs['cwd'] == tmp_path and kwargs['log_limit'] == 4096
            if case == 'oserror':
                raise OSError('probe launch failed')
            if case == 'cancelled_timeout':
                cancel.set()
            timeout = case in ('timeout_twice', 'cancelled_timeout') or (
                case == 'timeout_success' and len(calls) == 1)
            return ProcessResult(-1 if timeout else 2 if case == 'nonzero' else 0,
                                 'openjdk version "25.0.5" 2026-10-01',
                                 reason='timeout' if timeout else None)

        monkeypatch.setattr(backend, 'run_process', original)
        document = {'java_probes': []}
        config = backend.BackendConfig('/fake/python', str(tmp_path))
        if enabled:
            with harness._observe_java(document):
                outcome = backend._java_version(config, cancel)
        else:
            outcome = backend._java_version(config, cancel)
        assert outcome == expected
        assert [kwargs['timeout_seconds'] for argv, kwargs in calls] == limits
        assert backend.run_process is original
        observations.append((outcome, [(argv, kw['timeout_seconds']) for argv, kw in calls]))
    assert observations[0] == observations[1]


def install_fake_analysis(monkeypatch, harness, mode, event_count=3, event_message='ordinary event'):
    state = SimpleNamespace(roots=[], closed=[], configs=[], trace=[], calls=0)
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', '/fake/ghidra')

    def create(older, newer, name, root):
        state.trace.append(('create', older.as_posix(), newer.as_posix(), name, root.name))
        if mode == 'create_error':
            raise OSError('controlled create failure')
        root.mkdir()
        state.roots.append(root)
        service = SimpleNamespace(project=SimpleNamespace(matches=[]))

        def apply(path, run):
            state.trace.append(('apply', root.name))
            if mode == 'apply_error':
                raise ValueError('controlled normalization failure')
            name = 'different' if mode == 'match_mismatch' and root.name == 'two' else 'same'
            service.project.matches = [SimpleNamespace(category='modified',
                                                       older=[SimpleNamespace(name=name)], newer=[])]

        def close():
            state.closed.append(root.name)
            state.trace.append(('close', root.name))

        service.apply_analysis, service.close = apply, close
        return service

    def compare(config, project, root, cancel, on_event):
        state.calls += 1
        state.configs.append(config)
        state.trace.append(('compare', root.name, config.python_executable, config.ghidra_dir,
                            config.timeout_seconds, config.no_cache, config.refresh,
                            Path(config.cache_dir).name, cancel.is_set()))
        if mode == 'comparison_error':
            raise OSError('controlled comparison failure')
        settings = {'java_runtime_version': 'unverified', 'python_version': '3.12',
                    'private_setting': 'do-not-export-settings'}
        if (root.name == 'two' and mode != 'second_miss') or mode == 'first_hit':
            settings['cache_origin'] = {'key': 'a' * 64, 'created': '2026-11-20',
                                        'private': 'do-not-export-origin'}
        for index in range(event_count):
            on_event(SimpleNamespace(stage='cache', message=event_message, sequence=index,
                                     private='do-not-export-event'))
        raw = b'different raw' if mode == 'raw_mismatch' and root.name == 'two' else b'authored raw'
        (root / 'raw.json').write_bytes(raw)
        status = 'failed' if mode == 'run_failed' else 'completed'
        run = SimpleNamespace(id='fake-' + root.name, settings=settings, status=status,
                              error='controlled analysis failure' if status == 'failed' else None,
                              backend_version='fake-version', raw_path='raw.json')
        return root / 'raw.json', run

    monkeypatch.setattr(ProjectService, 'create', create)
    monkeypatch.setattr(backend, 'run_comparison', compare)
    monkeypatch.setattr(harness, 'run_comparison', compare)
    return state


def outcome(call):
    try:
        call()
        return None
    except Exception as exc:
        return (type(exc), str(exc))


@pytest.mark.parametrize('mode', ['pass', 'first_hit', 'second_miss', 'raw_mismatch', 'match_mismatch',
                                 'run_failed', 'comparison_error', 'apply_error', 'create_error'])
def test_no_option_matches_original_harness(harness, monkeypatch, tmp_path, capsys, mode):
    monkeypatch.chdir(tmp_path)
    baseline = install_fake_analysis(monkeypatch, harness, mode)
    before = outcome(lambda: runpy.run_path(str(HERE / 'baseline-live-cache-check.py')))
    before_stdout = capsys.readouterr().out
    current = install_fake_analysis(monkeypatch, harness, mode)
    after = outcome(lambda: harness.main([]))
    after_stdout = capsys.readouterr().out
    assert before == after and before_stdout == after_stdout
    assert baseline.trace == current.trace and baseline.closed == current.closed
    assert all(not root.exists() for root in baseline.roots + current.roots)
    assert list(tmp_path.iterdir()) == []
    assert all(config.timeout_seconds == 900 for config in current.configs)
    if len(current.configs) == 2:
        assert current.configs[0].cache_dir == current.configs[1].cache_dir


@pytest.mark.parametrize('mode,attempted', [('first_hit', 1), ('second_miss', 2), ('raw_mismatch', 2),
                                         ('match_mismatch', 2), ('run_failed', 1),
                                         ('comparison_error', 1), ('apply_error', 1), ('create_error', 1)])
def test_enabled_receipts_preserve_all_original_failures(harness, monkeypatch, tmp_path, mode, attempted):
    state = install_fake_analysis(monkeypatch, harness, mode)
    target = tmp_path / 'new-diagnostics'
    actual = outcome(lambda: harness.main(['--diagnostics-dir', str(target)]))
    assert actual is not None
    final = json.loads((target / 'result.json').read_text())
    assert final['status'] == 'failed' and final['exception_class'] == actual[0].__name__
    assert final['message'] == actual[1]
    assert (target / 'first.json').is_file()
    assert (target / 'second.json').is_file() == (attempted == 2)
    assert all(not root.exists() for root in state.roots)


@pytest.mark.parametrize('kind', ['directory', 'file', 'directory_symlink', 'dangling_symlink'])
def test_create_only_destination_refusal(harness, monkeypatch, tmp_path, kind):
    state = install_fake_analysis(monkeypatch, harness, 'pass')
    target = tmp_path / 'destination'
    if kind == 'directory':
        target.mkdir()
        (target / 'prior.json').write_bytes(b'unchanged')
    elif kind == 'file':
        target.write_bytes(b'unchanged')
    else:
        linked = tmp_path / 'linked'
        if kind == 'directory_symlink':
            linked.mkdir()
            (linked / 'prior.json').write_bytes(b'unchanged')
        target.symlink_to(linked, target_is_directory=True)
    before = [(path.relative_to(tmp_path).as_posix(), path.is_symlink(),
               path.read_bytes() if path.is_file() else None) for path in sorted(tmp_path.rglob('*'))]
    with pytest.raises(FileExistsError):
        harness.main(['--diagnostics-dir', str(target)])
    after = [(path.relative_to(tmp_path).as_posix(), path.is_symlink(),
              path.read_bytes() if path.is_file() else None) for path in sorted(tmp_path.rglob('*'))]
    assert before == after and state.trace == []


def test_receipt_allowlist_event_tail_and_unicode_byte_bound(harness, monkeypatch, tmp_path):
    state = install_fake_analysis(monkeypatch, harness, 'pass', event_count=100,
                                  event_message='\U0001f600' * 1500 + ' password=event-hidden')
    target = tmp_path / 'diagnostics'
    harness.main(['--diagnostics-dir', str(target)])
    for name in ('first', 'second'):
        raw = (target / f'{name}.json').read_bytes()
        document = json.loads(raw)
        assert len(raw) <= harness.MAX_DOCUMENT_BYTES
        assert len(document['events']) == 64 and document['events_omitted'] == 36
        assert all(len(event['message']) <= 512 for event in document['events'])
        assert document['events'][-1]['message'].endswith('password=[redacted]')
        assert document['run']['settings'].keys() <= set(harness.SETTINGS) | {'cache_origin'}
        assert b'event-hidden' not in raw and b'do-not-export-' not in raw
        assert b'authored raw' not in raw and 'raw_sha256' in document
    assert len(state.closed) == 2


@pytest.mark.parametrize('value', [True, False, math.nan, math.inf, -math.inf, 10 ** 500, '5', None])
def test_numbers_remain_strict_json(harness, value):
    assert harness._number(value) is None
    json.dumps({'value': harness._number(value)}, allow_nan=False)


@pytest.mark.parametrize('case', ['oversized', 'nonfinite', 'existing'])
def test_exclusive_bounded_document_writes(harness, tmp_path, capsys, case):
    destination = tmp_path / 'evidence.json'
    document = {'contract': harness.CONTRACT}
    if case == 'oversized':
        document['data'] = 'x' * (harness.MAX_DOCUMENT_BYTES + 1)
    elif case == 'nonfinite':
        document['data'] = float('nan')
    else:
        destination.write_bytes(b'prior evidence')
    harness._write_diagnostics(tmp_path, destination.name, document)
    assert 'could not be written' in capsys.readouterr().err
    assert destination.read_bytes() == b'prior evidence' if case == 'existing' else not destination.exists()


def test_diagnostic_write_failure_keeps_original_comparison_exception(harness, monkeypatch, tmp_path, capsys):
    install_fake_analysis(monkeypatch, harness, 'comparison_error')
    original_open = Path.open
    target = tmp_path / 'evidence'

    def unavailable(path, *args, **kwargs):
        if path.parent == target:
            raise OSError('token=do-not-echo-write-failure-secret')
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', unavailable)
    with pytest.raises(OSError, match='^controlled comparison failure$'):
        harness.main(['--diagnostics-dir', str(target)])
    stderr = capsys.readouterr().err
    assert stderr.count('Cache diagnostics could not be written') == 2
    assert 'do-not-echo-write-failure-secret' not in stderr


def test_workflow_semantics_change_only_invocation_and_artifact_glob():
    previous = yaml.safe_load((HERE / 'baseline-live-backend.yml').read_text())
    current = yaml.safe_load((ROOT / '.github/workflows/live-backend.yml').read_text())
    expected = previous
    steps = expected['jobs']['native']['steps']
    command = next(step for step in steps if step.get('run') == 'python tools/live_cache_check.py')
    command['run'] += ' --diagnostics-dir live-cache-diagnostics'
    upload = next(step for step in steps if step.get('uses') == 'actions/upload-artifact@v4')
    upload['with']['path'] += 'live-cache-diagnostics/*.json\n'
    assert current == expected
    assert upload['if'] == 'always()'
