"""Timeout/progress diagnostics on authored output, not native Ghidriff acceptance."""
import json
import threading
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from test_jobs import fake_runtime  # noqa: F401 - shared authored-runtime fixture

from patchtrace import backend, backend_progress
from patchtrace.jobs import ProcessProgress, ProcessResult


def snapshot(text='', *, elapsed=1.0, last_output=None, stderr='', stdout_total=None, stderr_total=None):
    return ProcessProgress(
        elapsed_seconds=elapsed, log_tail=text, stderr_tail=stderr,
        stdout_total=len(text.encode()) if stdout_total is None else stdout_total,
        stderr_total=len(stderr.encode()) if stderr_total is None else stderr_total,
        last_output_elapsed_seconds=last_output)


@pytest.mark.parametrize(('text', 'expected'), [
    ('INFO Starting Ghidra...', 'starting Ghidra'),
    ('INFO Importing C:\\private\\target.bin as secret', 'importing binaries'),
    ('Starting analysis for 2 binaries\nAnalyzing: private.bin', 'analyzing binaries'),
    ('Running correlator: StructuralGraphHash', 'matching functions'),
    ('Generating matches json...\nDeduping symbols and functions...', 'preparing match data'),
    ('Starting esym lookups for 72 symbols\nSorting functions...', 'checking candidate function pairs'),
    ('Sorting functions...\nStarting esym lookups for 72 symbols\nCompleted 72 at 100%',
     'enhancing function/symbol details'),
])
def test_latest_recognized_marker_is_a_fixed_stage(text, expected):
    assert backend_progress.stage_from_tail(text) == expected


def test_real_ghidra_analysis_sequence_does_not_revert_to_startup():
    # The reported run emits these adjacent messages for each input (target name anonymized).
    text = ('2026-11-05 20:48:55,834 ghidriff INFO     Analyzing: older.bin - .ProgramDB\n'
            '2026-11-05 20:48:56,704 ghidriff INFO     Starting Ghidra analysis of older.bin - .ProgramDB...')
    assert backend_progress.stage_from_tail(text, previous='importing binaries') == 'analyzing binaries'


def test_stage_observer_handles_split_output_quiet_periods_and_unknown_lines():
    state = backend_progress.BackendProgress(7200)
    state.observe(snapshot('INFO Sorting funct', elapsed=2, last_output=2))
    assert state.stage == 'stage not yet observed'
    state.observe(snapshot('INFO Sorting functions...', elapsed=3, last_output=3))
    assert state.stage == 'checking candidate function pairs'
    state.observe(snapshot('unrecognized secret ' * 2000, elapsed=1800, last_output=3))
    assert state.stage == 'checking candidate function pairs'
    assert state.output_age_seconds == 1797
    summary = state.summary()
    assert '1800' in summary and '7200' in summary and '1797' in summary
    assert 'secret' not in summary and '%' not in summary


def test_unknown_or_untrusted_output_cannot_supply_a_stage_or_success():
    state = backend_progress.BackendProgress(14400)
    state.observe(snapshot('token=private-token\nCompleted 72 at 100%\nSUCCESS: run complete', elapsed=4))
    assert state.stage == 'stage not yet observed'
    assert 'no output yet' in state.summary()
    assert all(value not in state.summary() for value in ('private-token', '100%', 'SUCCESS', 'complete'))
    assert backend_progress.stage_from_tail('x' * 20000, previous='private-stage') == 'stage not yet observed'


def test_old_markers_beyond_the_bounded_tail_do_not_replace_last_stage():
    text = 'Starting Ghidra\n' + 'x' * (32 * 1024)
    assert backend_progress.stage_from_tail(text, previous='matching functions') == 'matching functions'


def read_receipt(directory):
    raw = (directory / 'backend-execution.json').read_bytes()
    assert len(raw) <= 8192
    return json.loads(raw)


def write_result(argv, *, valid=True):
    directory = Path(argv[argv.index('--output-path') + 1]) / 'json'
    directory.mkdir()
    (directory / 'result.ghidriff.json').write_text(
        json.dumps({'functions': {'added': [], 'deleted': [], 'modified': []}}) if valid else '{}',
        encoding='utf-8')


@pytest.mark.parametrize('text', ['', 'Runtime wrapper output with no recognized marker'],
                         ids=['silent', 'unrecognized-output'])
def test_unobserved_stage_is_explicit_in_summary_timeout_and_receipt(fake_runtime, monkeypatch, text):  # noqa: F811
    root, _package, project, config = fake_runtime
    events = []

    def runner(argv, **kwargs):
        quarantine = Path(argv[argv.index('--output-path') + 1]).parent
        assert read_receipt(quarantine)['last_observed_stage'] == 'stage not yet observed'
        kwargs['on_progress'](snapshot(text, elapsed=5, last_output=1 if text else None))
        return ProcessResult(-9, text, 'timeout', elapsed_seconds=3600,
                             last_output_elapsed_seconds=1 if text else None)

    monkeypatch.setattr(backend, 'run_process', runner)
    path, run = backend.run_comparison(config, project, root, threading.Event(), events.append)
    assert run.status == 'failed' and 'last observed stage: stage not yet observed' in run.error
    assert read_receipt(path)['last_observed_stage'] == 'stage not yet observed'
    live = [event for event in events if event.stage == 'analysis-progress']
    assert live and all('stage not yet observed' in event.message for event in live)
    assert all('starting Ghidra' not in event.message for event in live)
    assert not any(event.stage == 'analysis-stage' for event in events)


def test_unsafe_output_stop_reason_survives_real_supervision(fake_runtime, monkeypatch):  # noqa: F811
    root, package, project, config = fake_runtime
    config = replace(config, timeout_seconds=3)
    (package / '__main__.py').write_text('import time\ntime.sleep(30)\n', encoding='utf-8')
    monkeypatch.setattr(backend, '_output_error', lambda _raw: 'unsafe-output-path')
    path, run = backend.run_comparison(config, project, root, threading.Event(), lambda _event: None)
    assert run.status == 'failed' and 'unsafe or oversized JSON' in run.error
    receipt = read_receipt(path)
    assert receipt['process_state'] == 'stopped' and receipt['stop_reason'] == 'unsafe-output-path'


@pytest.mark.parametrize('outcome', ['valid', 'invalid', 'timeout', 'exception'])
def test_stopped_event_precedes_receipt_cleanup_and_output_validation(fake_runtime, monkeypatch, outcome):  # noqa: F811
    root, _package, project, config = fake_runtime
    order, events = [], []
    write_receipt, remove_scratch, check_output = (backend._write_execution_receipt, backend._remove_scratch,
                                                  backend._output_error)

    def record(directory, document):
        order.append('receipt:' + document['process_state'])
        write_receipt(directory, document)

    def cleanup(path):
        order.append('cleanup')
        return remove_scratch(path)

    def validate(path):
        order.append('validation')
        return check_output(path)

    def runner(argv, **kwargs):
        kwargs['on_progress'](snapshot('Sorting functions...', elapsed=1, last_output=1))
        order.append('supervision-ended')
        if outcome == 'exception':
            raise OSError('supervisor failed')
        if outcome == 'timeout':
            return ProcessResult(-9, '', 'timeout', elapsed_seconds=config.timeout_seconds)
        write_result(argv, valid=outcome == 'valid')
        return ProcessResult(0, '', elapsed_seconds=2, last_output_elapsed_seconds=1)

    def observe(event):
        events.append(event)
        if event.stage == 'analysis-stopped':
            order.append('analysis-stopped')

    monkeypatch.setattr(backend, '_write_execution_receipt', record)
    monkeypatch.setattr(backend, '_remove_scratch', cleanup)
    monkeypatch.setattr(backend, '_output_error', validate)
    monkeypatch.setattr(backend, 'run_process', runner)
    _, run = backend.run_comparison(config, project, root, threading.Event(), observe)
    assert run.status == ('completed' if outcome == 'valid' else 'failed')
    last_state = 'unverified' if outcome == 'exception' else 'stopped'
    assert order[:4] == ['receipt:launch-pending', 'supervision-ended', 'analysis-stopped',
                         'receipt:' + last_state]
    assert order.count('analysis-stopped') == 1 and order.index('analysis-stopped') < order.index('cleanup')
    assert all(index > order.index('analysis-stopped') for index, item in enumerate(order) if item == 'validation')
    stopped = next(event for event in events if event.stage == 'analysis-stopped')
    assert stopped.message == 'Ghidriff process supervision ended.' and stopped.progress is None


def test_timeout_reports_effective_budget_stage_and_retains_process_receipt(fake_runtime, monkeypatch):  # noqa: F811
    root, _package, project, config = fake_runtime
    config = replace(config, timeout_seconds=7200)
    original = project.model_dump_json()
    prior = root / 'runs' / 'previous' / 'analysis.log'
    prior.parent.mkdir(parents=True)
    prior.write_text('previous completed evidence', encoding='utf-8')
    events, scratch = [], []
    monkeypatch.setattr(backend, '_java_version', lambda *_: pytest.fail('diagnostics must not add a JVM probe'))

    def runner(argv, **kwargs):
        assert kwargs['timeout_seconds'] == 7200 and '--no-threaded' in argv
        scratch.append(kwargs['cwd'])
        quarantine = Path(argv[argv.index('--output-path') + 1]).parent
        initial = read_receipt(quarantine)
        assert initial['process_state'] == 'launch-pending' and initial['stopped_at'] is None
        assert initial['runtime_versions']['jvm'] == 'unverified'
        datetime.fromisoformat(initial['started_at'].replace('Z', '+00:00'))
        text = 'Authorization: Bearer private-secret\nSorting functions...\nC:\\private\\target.bin'
        kwargs['on_progress'](snapshot(text, elapsed=7000, last_output=3600))
        return ProcessResult(-9, text, 'timeout', elapsed_seconds=7201.5,
                             last_output_elapsed_seconds=3600)

    monkeypatch.setattr(backend, 'run_process', runner)
    path, run = backend.run_comparison(config, project, root, threading.Event(), events.append)
    assert run.status == 'failed' and run.error.startswith('PT-BACKEND: analysis timed out')
    assert '7200' in run.error and '7201.5' in run.error and 'checking candidate function pairs' in run.error
    assert 'Analysis > Setup > Backend and desktop > Comparison timeout (seconds) > Save setup' in run.error
    assert f'runs/quarantine-{run.id}' in run.error and str(root) not in run.error
    receipt = read_receipt(path)
    assert receipt['contract'] == 'patchtrace-backend-execution/1' and receipt['run_id'] == run.id
    assert receipt['process_state'] == 'stopped' and receipt['stop_reason'] == 'timeout'
    assert receipt['returncode'] == -9 and receipt['timeout_seconds'] == 7200
    assert receipt['elapsed_seconds'] == 7201.5 and receipt['last_output_age_seconds'] == 3601.5
    assert receipt['last_observed_stage'] == 'checking candidate function pairs'
    assert receipt['runtime_versions']['python'] == '3.12.0'
    assert receipt['runtime_versions']['ghidra'] == '12.0.4'
    assert receipt['runtime_versions']['jvm'] == 'unverified'
    assert datetime.fromisoformat(receipt['stopped_at'].replace('Z', '+00:00'))
    live = [e for e in events if e.stage in {'analysis-stage', 'analysis-progress'}]
    assert any(e.stage == 'analysis-progress' for e in live)
    assert any(e.stage == 'analysis-stage' for e in live)
    assert all(e.progress is None for e in live)
    for secret in ('private-secret', 'C:\\private', 'target.bin', 'Authorization'):
        assert all(secret not in e.message for e in live)
        assert secret not in json.dumps(receipt)
    assert 'private-secret' not in (path / 'analysis.log').read_text(encoding='utf-8')
    assert prior.read_text(encoding='utf-8') == 'previous completed evidence'
    assert project.model_dump_json() == original
    assert scratch and all(not p.exists() for p in scratch)


@pytest.mark.parametrize('valid', [True, False], ids=['valid-output', 'unpublishable-output'])
def test_exited_receipt_is_not_a_normalized_comparison_success(fake_runtime, monkeypatch, valid):  # noqa: F811
    root, _package, project, config = fake_runtime

    def runner(argv, **kwargs):
        write_result(argv, valid=valid)
        kwargs['on_progress'](snapshot('Starting esym lookups\nCompleted 72 at 100%', elapsed=1,
                                       last_output=0.75))
        return ProcessResult(0, '', elapsed_seconds=1.5, last_output_elapsed_seconds=0.75)

    monkeypatch.setattr(backend, 'run_process', runner)
    events = []
    path, run = backend.run_comparison(config, project, root, threading.Event(), events.append)
    assert run.status == ('completed' if valid else 'failed')
    directory = root / 'runs' / run.id if valid else path
    receipt = read_receipt(directory)
    assert receipt['process_state'] == 'stopped' and receipt['stop_reason'] == 'exited'
    assert receipt['returncode'] == 0 and receipt['elapsed_seconds'] == 1.5
    assert receipt['last_observed_stage'] == 'enhancing function/symbol details'
    assert 'completed' not in json.dumps(receipt)
    assert 'elapsed_seconds' not in run.settings and 'last_observed_stage' not in run.settings
    assert all(e.progress is None for e in events)
    assert all('100%' not in e.message for e in events if e.stage.startswith('analysis-'))


def test_cancelled_process_receipt_does_not_become_timeout(fake_runtime, monkeypatch):  # noqa: F811
    root, _package, project, config = fake_runtime
    cancel = threading.Event()

    def runner(argv, **kwargs):
        kwargs['on_progress'](snapshot('Running correlator: private-symbol', elapsed=2, last_output=1))
        cancel.set()
        return ProcessResult(-9, '', 'cancelled', elapsed_seconds=2, last_output_elapsed_seconds=1)

    monkeypatch.setattr(backend, 'run_process', runner)
    path, run = backend.run_comparison(config, project, root, cancel, lambda _e: None)
    assert run.status == 'cancelled' and run.error.startswith('PT-CANCEL:')
    assert read_receipt(path)['stop_reason'] == 'cancelled'


def test_cancellation_at_launch_does_not_invent_a_child_exit(fake_runtime, monkeypatch):  # noqa: F811
    root, _package, project, config = fake_runtime
    cancel = threading.Event()
    real_write = backend._write_execution_receipt

    def cancel_after_receipt(directory, document):
        real_write(directory, document)
        if document['process_state'] == 'launch-pending':
            cancel.set()

    monkeypatch.setattr(backend, '_write_execution_receipt', cancel_after_receipt)
    path, run = backend.run_comparison(config, project, root, cancel, lambda _e: None)
    assert run.status == 'cancelled'
    receipt = read_receipt(path)
    assert receipt['process_state'] == 'not-started' and receipt['stop_reason'] == 'cancelled'
    assert receipt['returncode'] is None and receipt['elapsed_seconds'] == 0


@pytest.mark.parametrize('failed_writes', [{1}, {2}, {1, 2}], ids=['start', 'stop', 'both'])
@pytest.mark.parametrize('failure_point', ['replace', 'fsync'])
def test_receipt_failure_preserves_existing_record_and_analysis_status(fake_runtime, monkeypatch,  # noqa: F811
                                                                      failed_writes, failure_point):
    root, _package, project, config = fake_runtime
    real_write, calls = getattr(backend.os, failure_point), []

    def fail_write(*args):
        if failure_point == 'fsync':
            assert backend.os.fstat(args[0]).st_size > 0, 'receipt must leave Python buffers before syncing'
        calls.append(args)
        if len(calls) in failed_writes:
            raise OSError('Authorization: Bearer private-receipt-error')
        return real_write(*args)

    def runner(argv, **kwargs):
        write_result(argv)
        return ProcessResult(0, '', elapsed_seconds=1)

    monkeypatch.setattr(backend.os, failure_point, fail_write)
    monkeypatch.setattr(backend, 'run_process', runner)
    events = []
    _, run = backend.run_comparison(config, project, root, threading.Event(), events.append)
    assert run.status == 'completed'
    directory = root / 'runs' / run.id
    if failed_writes == {1, 2}:
        assert not (directory / 'backend-execution.json').exists()
    else:
        receipt = read_receipt(directory)
        if failed_writes == {2}:
            assert receipt['process_state'] == 'launch-pending' and receipt['stopped_at'] is None
        else:
            assert receipt['process_state'] == 'stopped' and receipt['stopped_at'] is not None
    assert list(directory.glob('backend-execution-*.tmp')) == []
    warnings = [e.message for e in events if e.stage == 'warning']
    assert warnings == ['Backend execution receipt could not be saved; analysis status is unchanged.'] * len(failed_writes)
    assert all('private-receipt-error' not in e.message for e in events)


def test_observer_event_failure_cannot_fail_a_completed_process(fake_runtime, monkeypatch):  # noqa: F811
    root, _package, project, config = fake_runtime

    def runner(argv, **kwargs):
        kwargs['on_progress'](snapshot('Sorting functions...', elapsed=1, last_output=1))
        write_result(argv)
        return ProcessResult(0, '', elapsed_seconds=2, last_output_elapsed_seconds=1)

    def broken_listener(_event):
        raise RuntimeError('listener unavailable')

    monkeypatch.setattr(backend, 'run_process', runner)
    _, run = backend.run_comparison(config, project, root, threading.Event(), broken_listener)
    assert run.status == 'completed'
    assert read_receipt(root / 'runs' / run.id)['returncode'] == 0


def test_real_authored_child_requires_safe_progress_before_it_finishes(fake_runtime):  # noqa: F811
    """Exercise the production callback wiring; the child cannot produce a result until observed."""
    root, package, project, config = fake_runtime
    config = replace(config, timeout_seconds=8)
    (package / '__main__.py').write_text(
        'import json, pathlib, sys, time\n'
        'out = pathlib.Path(sys.argv[sys.argv.index("--output-path") + 1])\n'
        'print("Sorting functions... Authorization: Bearer private-live-token", flush=True)\n'
        'deadline = time.monotonic() + 10\n'
        'while not (out / "progress-observed").exists():\n'
        '    if time.monotonic() >= deadline: sys.exit(7)\n'
        '    time.sleep(.01)\n'
        '(out / "json").mkdir()\n'
        '(out / "json" / "result.ghidriff.json").write_text(json.dumps('
        '{"functions": {"added": [], "deleted": [], "modified": []}}))\n',
        encoding='utf-8')
    events, before_result = [], []

    def observe(event):
        events.append(event)
        if (event.stage == 'analysis-progress' and 'checking candidate function pairs' in event.message
                and not before_result):
            raw = root / 'runs' / f'quarantine-{event.run_id}' / 'raw'
            before_result.append(not (raw / 'json' / 'result.ghidriff.json').exists())
            (raw / 'progress-observed').touch()

    _, run = backend.run_comparison(config, project, root, threading.Event(), observe)
    assert run.status == 'completed', run.error
    assert before_result == [True]
    assert any(e.stage == 'analysis-progress' and 'checking candidate function pairs' in e.message for e in events)
    assert all('private-live-token' not in e.message for e in events)
    receipt = read_receipt(root / 'runs' / run.id)
    assert receipt['last_observed_stage'] == 'checking candidate function pairs'
    assert 0 < receipt['elapsed_seconds'] < 8 and receipt['stop_reason'] == 'exited'


def test_supervisor_exception_records_unknown_process_outcome(fake_runtime, monkeypatch):  # noqa: F811
    root, _package, project, config = fake_runtime

    def runner(_argv, **_kwargs):
        raise OSError('process launch failed token=private-error')

    monkeypatch.setattr(backend, 'run_process', runner)
    path, run = backend.run_comparison(config, project, root, threading.Event(), lambda _e: None)
    assert run.status == 'failed'
    receipt = read_receipt(path)
    assert receipt['process_state'] == 'unverified' and receipt['stop_reason'] == 'supervision-error'
    assert receipt['returncode'] is None and receipt['elapsed_seconds'] is None
    assert receipt['stopped_at'] is None and 'private-error' not in json.dumps(receipt)


@pytest.mark.parametrize('kind', ['cancelled-before-run', 'identical', 'cache'])
def test_skipped_engine_never_creates_an_execution_receipt(fake_runtime, monkeypatch, kind):  # noqa: F811
    root, _package, project, config = fake_runtime
    cancel = threading.Event()
    if kind == 'cancelled-before-run':
        cancel.set()
    elif kind == 'identical':
        old = project.artifacts[0]
        (root / 'newer.bin').write_bytes((root / 'older.bin').read_bytes())
        project.artifacts[1] = project.artifacts[1].model_copy(update={'sha256': old.sha256, 'size': old.size})
    else:
        config = replace(config, cache_dir=str(root / 'cache'))
        monkeypatch.setattr(backend, '_open_raw_cache', lambda *_: (object(), object()))
        payload = json.dumps({'functions': {'added': [], 'deleted': [], 'modified': []}}).encode()
        monkeypatch.setattr(backend, '_read_raw_cache', lambda *_: (payload, {'key': 'fixture'}))
    monkeypatch.setattr(backend, 'run_process', lambda *_a, **_k: pytest.fail('engine must not run'))
    _, run = backend.run_comparison(config, project, root, cancel, lambda _e: None)
    assert run.status == {'cancelled-before-run': 'cancelled', 'identical': 'identical', 'cache': 'completed'}[kind]
    assert list((root / 'runs').rglob('backend-execution.json')) == []


@pytest.mark.parametrize('value', [None, 'unknown', 'unverified', 'C:\\private\\java',
                                  '25\nAuthorization: Bearer secret', '1.0+' + 'x' * 1000,
                                  'release-description', 'sk-tiny'])
def test_runtime_version_receipts_refuse_paths_secrets_and_unbounded_metadata(value):
    assert backend_progress.safe_version(value) == 'unverified'


@pytest.mark.parametrize('secret', ['ghp_' + 'A' * 36, 'sk-test-secret', '1.0+sk-test-secret'])
def test_receipt_never_copies_credential_versions(secret):
    state = backend_progress.BackendProgress(7200)
    receipt = state.receipt('11111111-1111-1111-1111-111111111111', '2026-11-06T12:00:00+00:00',
                            {'ghidriff': secret, 'python': '3.12.0', 'jvm': '25.0.1+8'})
    assert secret not in json.dumps(receipt)
    assert receipt['runtime_versions']['ghidriff'] == 'unverified'
    assert receipt['runtime_versions']['python'] == '3.12.0'
    assert receipt['runtime_versions']['jvm'] == '25.0.1+8'


@pytest.mark.parametrize('value', ['3.12.0', '25.0.1+8', 'v0.8.0',
                                  '4f5d895fcbb1eacd65efd81145922c15bb7e741d',
                                  'abcdef0123456789abcdef0123456789abcdef01'])
def test_legitimate_versions_and_revisions_remain_identifiable(value):
    assert backend_progress.safe_version(value) == value
