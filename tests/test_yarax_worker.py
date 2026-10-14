"""Rule worker and runner against a fake child process: timeout, cancel, panic, out-of-memory, bad results."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from patchtrace.yarax import runner, worker
from patchtrace.yarax.contracts import RuleText, WorkerRequest, WorkerResult, WorkerTarget
from patchtrace.yarax.errors import RulesError
from patchtrace.yarax.limits import RuleLimits

RULE = RuleText(name='PT_0123456789ab_older', text='rule PT_0123456789ab_older { condition: true }')
SHA = '0' * 64
TARGET = WorkerTarget(target_id='t1', path='/nonexistent/a.dll', sha256=None, size=1)
ENGINE = {'engine': 'yara-x', 'version': '1.21.0', 'version_source': 'metadata', 'decoder': 'none',
          'decoder_version': 'none', 'grammar': 'yrx-gen/1', 'worker': 'rules-worker/1'}
OK_CELL = {'rule_name': RULE.name, 'target_id': 't1', 'state': 'no-hit'}


def fake(body: str):
    """argv factory for a child that runs `body` with `req` (the parsed request) in scope."""
    code = f'import json, sys, time\nreq = json.load(open(sys.argv[1], encoding="utf-8"))\n{body}\n'
    return lambda request: [sys.executable, '-c', code, str(request)]


def writes(doc: dict, exit_code: int = 0) -> str:
    return f'open(req["result"], "w", encoding="utf-8").write(json.dumps({doc!r}))\nsys.exit({exit_code})'


def call(argv_for, tmp_path, op='probe', event=None, **kwargs):
    kwargs.setdefault('timeout_seconds', 20)
    return runner.run_worker(op, cancel=event or threading.Event(), private_dir=tmp_path, argv_for=argv_for,
                             rules=kwargs.pop('rules', (RULE,) if op != 'probe' else ()),
                             targets=kwargs.pop('targets', (TARGET,) if op == 'scan' else ()), **kwargs)


def code_of(excinfo) -> str:
    return excinfo.value.code


def test_ok_document_round_trips_and_work_dir_is_removed(tmp_path):
    doc = call(fake(writes({'kind': 'ok', 'engine': ENGINE})), tmp_path)
    assert doc.engine.version == '1.21.0'
    assert list(tmp_path.iterdir()) == []


def test_scan_cells_must_cover_exactly_rules_times_targets(tmp_path):
    good = call(fake(writes({'kind': 'ok', 'engine': ENGINE, 'cells': [OK_CELL]})), tmp_path, op='scan')
    assert [c.state for c in good.cells] == ['no-hit']
    for cells in ([], [OK_CELL, OK_CELL], [{**OK_CELL, 'target_id': 'other'}]):
        with pytest.raises(RulesError) as caught:
            call(fake(writes({'kind': 'ok', 'engine': ENGINE, 'cells': cells})), tmp_path, op='scan')
        assert code_of(caught) == 'PT-RULE-ENGINE'


def test_timeout_kills_the_child(tmp_path):
    with pytest.raises(RulesError) as caught:
        call(fake('time.sleep(60)'), tmp_path, timeout_seconds=0.5)
    assert code_of(caught) == 'PT-RULE-TIMEOUT'
    assert list(tmp_path.iterdir()) == []


def test_cancel_event_stops_the_child_cooperatively(tmp_path):
    event = threading.Event()
    timer = threading.Timer(0.5, event.set)
    timer.start()
    try:
        with pytest.raises(RulesError) as caught:
            call(fake('time.sleep(60)'), tmp_path, event=event)
    finally:
        timer.cancel()
    assert code_of(caught) == 'PT-RULE-CANCEL'


def test_cancel_before_start_spawns_nothing(tmp_path):
    event = threading.Event()
    event.set()
    with pytest.raises(RulesError) as caught:
        call(lambda request: pytest.fail('spawned'), tmp_path, event=event)
    assert code_of(caught) == 'PT-RULE-CANCEL'


@pytest.mark.parametrize('body, text', [
    ('sys.exit(23)', 'internally'),
    ('sys.exit(22)', 'out of memory'),
    ('sys.stderr.write("memory allocation of 99 bytes failed"); sys.exit(134)', 'out of memory'),
    ('sys.exit(1)', 'failed (exit 1)'),
    ('sys.exit(0)', 'failed (exit 0)'),
], ids=['panic', 'memory-exit', 'memory-text', 'crash', 'no-result'])
def test_failures_are_typed_and_message_is_user_safe(tmp_path, body, text):
    with pytest.raises(RulesError) as caught:
        call(fake(body), tmp_path)
    assert code_of(caught) == 'PT-RULE-ENGINE'
    assert text in caught.value.message
    assert str(tmp_path) not in caught.value.message


def test_stderr_goes_to_sanitised_diagnostics_only(tmp_path):
    body = 'sys.stderr.write("boom \\u202e\\x00 " + "x" * 30000); sys.exit(1)'
    with pytest.raises(RulesError) as caught:
        call(fake(body), tmp_path)
    assert len(caught.value.diagnostics) <= RuleLimits().stderr_tail_bytes
    assert '\u202e' not in caught.value.diagnostics and '\x00' not in caught.value.diagnostics
    assert 'boom' not in caught.value.message


@pytest.mark.parametrize('body', [
    'open(req["result"], "w").write("{not json")',
    'open(req["result"], "w").write("[]")',
    'open(req["result"], "w").write(\'{"kind": "ok", "kind": "ok"}\')',
    'open(req["result"], "w").write(json.dumps({"kind": "ok"}))',
], ids=['syntax', 'not-object', 'duplicate-key', 'ok-without-engine'])
def test_invalid_result_documents_are_refused(tmp_path, body):
    with pytest.raises(RulesError) as caught:
        call(fake(body), tmp_path)
    assert code_of(caught) == 'PT-RULE-ENGINE'
    assert 'invalid result' in caught.value.message


def test_ok_document_with_nonzero_exit_is_not_trusted(tmp_path):
    with pytest.raises(RulesError) as caught:
        call(fake(writes({'kind': 'ok', 'engine': ENGINE}, exit_code=1)), tmp_path)
    assert code_of(caught) == 'PT-RULE-ENGINE'


@pytest.mark.parametrize('error_code', ['PT-RULE-COMPILE', 'PT-RULE-UNAVAILABLE', 'PT-RULE-ENGINE'])
def test_error_document_becomes_the_same_typed_error(tmp_path, error_code):
    doc = {'kind': 'error', 'error_code': error_code, 'message': 'reported'}
    with pytest.raises(RulesError) as caught:
        call(fake(writes(doc, 20)), tmp_path)
    assert (code_of(caught), caught.value.message) == (error_code, 'reported')


def test_endless_stdout_is_cut_off(tmp_path):
    body = 'while True:\n    sys.stdout.write("x" * 65536); sys.stdout.flush()'
    with pytest.raises(RulesError) as caught:
        call(fake(body), tmp_path)
    assert code_of(caught) == 'PT-RULE-ENGINE'


def test_oversized_runs_are_refused_before_spawning(tmp_path):
    small = RuleLimits(run_bytes=10)
    big = WorkerTarget(target_id='t1', path='/x', sha256=None, size=11)
    with pytest.raises(RulesError) as caught:
        call(lambda request: pytest.fail('spawned'), tmp_path, op='scan', targets=(big,), limits=small)
    assert code_of(caught) == 'PT-RULE-LIMIT'


def test_probe_without_the_wheel_is_the_unavailable_state(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, 'engine_installed', lambda: False)
    with pytest.raises(RulesError) as caught:
        runner.probe(cancel=threading.Event(), private_dir=tmp_path)
    assert code_of(caught) == 'PT-RULE-UNAVAILABLE'


def test_worker_env_is_allow_listed():
    env = runner.worker_env({'PATH': '/bin', 'HOME': '/h', 'AWS_SECRET_ACCESS_KEY': 'x', 'HTTPS_PROXY': 'p',
                             'PYTHONPATH': '/evil', 'SystemRoot': 'C:\\Windows'})
    assert set(env) == {'PATH', 'HOME', 'SystemRoot', 'PYTHONUTF8', 'PYTHONIOENCODING', 'PYTHONPATH'}
    assert env['PYTHONPATH'] != '/evil'


def test_worker_argv_is_frozen_aware(monkeypatch, tmp_path):
    request = tmp_path / 'req.json'
    plain = runner.worker_argv(request)
    assert plain[1:5] == ['-P', '-m', 'patchtrace.yarax.worker', '--request']
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    assert runner.worker_argv(request) == [sys.executable, 'rules', '_worker', '--request', str(request)]
    assert 'PYTHONPATH' not in runner.worker_env({'PATH': '/bin'})


def test_worker_limits_respect_the_hard_memory_maximum():
    limits = RuleLimits(worker_memory_bytes=4 * 1024**3)
    assert runner.worker_limits(limits)['worker_memory_bytes'] == limits.worker_memory_hard_max_bytes


def test_parent_never_imports_the_engine():
    code = ('import sys; import patchtrace.yarax.runner as r; '
            'bad = [m for m in sys.modules if m in ("yara_x", "patchtrace.yarax.engine")]; '
            'print(bad); sys.exit(1 if bad else 0)')
    src = str(Path(__file__).resolve().parents[1] / 'src')
    done = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env={'PYTHONPATH': src},
                          check=False)
    assert done.returncode == 0, done.stdout + done.stderr


# --- the worker entry itself (in-process, engine stubbed) -------------------------------------------------------

class Panic(BaseException):
    """Stands in for pyo3's PanicException, which is a BaseException."""


def request_file(tmp_path, op='probe', result='out.json') -> Path:
    request = WorkerRequest(op=op, rules=() if op == 'probe' else (RULE,), limits=runner.worker_limits(),
                            result=str(tmp_path / result) if result != '-' else '-')
    path = tmp_path / 'req.json'
    path.write_text(request.model_dump_json(), encoding='utf-8')
    return path


@pytest.mark.parametrize('raised, exit_code', [
    (Panic(), worker.EXIT_PANIC), (KeyboardInterrupt(), worker.EXIT_PANIC), (MemoryError(), worker.EXIT_MEMORY),
    (RuntimeError('x'), worker.EXIT_INTERNAL), (RulesError('PT-RULE-COMPILE', 'bad'), worker.EXIT_ERROR_DOC),
], ids=['panic', 'interrupt', 'memory', 'internal', 'rules-error'])
def test_worker_maps_every_exception_class_to_an_exit_code(tmp_path, monkeypatch, capsys, raised, exit_code):
    def boom(_request):
        raise raised
    monkeypatch.setattr(worker, '_execute', boom)
    assert worker.run(request_file(tmp_path)) == exit_code
    wrote = (tmp_path / 'out.json').exists()
    assert wrote == (exit_code == worker.EXIT_ERROR_DOC)
    if wrote:
        doc = WorkerResult.model_validate_json((tmp_path / 'out.json').read_bytes())
        assert (doc.kind, doc.error_code) == ('error', 'PT-RULE-COMPILE')
    assert 'Traceback' not in capsys.readouterr().err or exit_code == worker.EXIT_INTERNAL


def test_worker_refuses_unusable_requests(tmp_path, capsys):
    path = tmp_path / 'req.json'
    for raw in (b'{bad', b'{"op": "probe", "limits": {}, "result": "x", "extra": 1}',
                json.dumps({'op': 'probe', 'limits': {}, 'result': 'x'}).encode()):
        path.write_bytes(raw)
        assert worker.run(path) == worker.EXIT_USAGE
    assert worker.run(tmp_path / 'missing.json') == worker.EXIT_USAGE
    assert worker.main([]) == worker.EXIT_USAGE
    assert 'unusable request' in capsys.readouterr().err


def test_worker_never_overwrites_a_result_file(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, '_execute', lambda _r: WorkerResult(kind='ok', engine=_stamp()))
    (tmp_path / 'out.json').write_text('keep', encoding='utf-8')
    with pytest.raises(FileExistsError):
        worker.run(request_file(tmp_path))
    assert (tmp_path / 'out.json').read_text(encoding='utf-8') == 'keep'


def test_worker_can_write_its_document_to_stdout(tmp_path, monkeypatch, capsysbinary):
    monkeypatch.setattr(worker, '_execute', lambda _r: WorkerResult(kind='ok', engine=_stamp()))
    assert worker.run(request_file(tmp_path, result='-')) == worker.EXIT_OK
    assert json.loads(capsysbinary.readouterr().out)['kind'] == 'ok'


def _stamp():
    from patchtrace.yarax.contracts import EngineStamp
    return EngineStamp.model_validate(ENGINE)
