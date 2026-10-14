"""R2 process boundary: the hidden worker and its parent-side runner (docs/specs/program-e/YRX-integration-plan.md s6, s9).

The child is never trusted: fake children (`python -c`) emit every kind of wrong result, crash, hang and flood, and the
runner must map each to a typed `PT-RULE-*` error and leave no scratch directory behind. The worker's own exit codes
(0, 20, 21, 22, 23, 2) are tested in-process with a fake engine, including a `BaseException` that `except Exception`
would miss. A few tests run the real worker (they need the `rules` extra; see test_rules_engine.py for the engine itself).
What a Windows child sees at the Job Object memory limit is a measured unknown (U7): the OOM tests name both outcomes there.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

import patchtrace.rules as rules_package
from patchtrace.rules import contracts as c
from patchtrace.rules import runner, worker
from patchtrace.rules.errors import RuleError
from patchtrace.rules.limits import DEFAULT_LIMITS, MIB, RuleLimits

PY = str(Path(sys.executable).resolve())
SRC = str(Path(rules_package.__file__).resolve().parents[2])
ROOT = Path(__file__).resolve().parents[1]
RULE = c.WorkerRule(name='r1', text='import "pe"\nrule PT_0123456789ab_older: patchtrace {\n  condition:\n    true\n}\n')
ABSENT = str(Path(tempfile.gettempdir()).resolve() / 'patchtrace-rules-test-absent.bin')  # absolute on every OS
TARGET = c.WorkerTarget(target_id='t1', path=ABSENT, size=1)
SHORT = RuleLimits(run_wall_s=1, target_timeout_min_s=1, target_timeout_s=1)  # 1 s wall clock for the fake children


def example_rule_text() -> str:
    """A rule the engine accepts (the R0 schema example); the placeholder RULE above only suits fake children."""
    spec = importlib.util.spec_from_file_location('generate_rules_schemas', ROOT / 'tools' / 'generate_rules_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.example_rule_text()


needs_engine = pytest.mark.skipif(not runner.engine_installed(), reason='YARA-X (the rules extra) is not installed')


@pytest.fixture
def scratch(tmp_path):
    directory = tmp_path / 'private'
    directory.mkdir()
    return directory


@pytest.fixture(autouse=True)
def quick_grace(monkeypatch):
    monkeypatch.setattr(runner, 'TIMEOUT_GRACE', 0.5)


PRELUDE = '''
import json, os, subprocess, sys, time
req = json.load(open(sys.argv[-1], encoding="utf-8"))
ENGINE = {"engine": "yara-x", "version": "1.21.0", "version_source": "pin", "decoder": "none", "decoder_version": None,
          "grammar": "yrx-gen/1", "worker": "rules-worker/1"}
CELL = {"state": "no-hit", "hits": 0, "offsets": [], "rvas": [], "reason": None, "elapsed_ms": 1, "verdict": "unscored"}
ERROR = {"code": "PT-RULE-LIMIT", "message": "The result is larger than the limit", "reason": "result-size"}

def lint_of(name):
    return {"name": name, "ok": True, "errors": [], "warnings": [], "identifiers": [], "imports": ["pe"],
            "patterns": 0, "formatter_stable": False}

def doc(**over):
    op, names = req["op"], [r["name"] for r in req["rules"]]
    out = {"contract": "rules-worker/1", "op": op, "kind": "ok", "engine": ENGINE,
           "modules": ["pe"] if op == "probe" else [], "lint": [lint_of(n) for n in names] if op != "probe" else [],
           "cells": [CELL] * (len(req["targets"]) * len(names)) if op == "scan" else [], "error": None}
    out.update(over)
    return out

def error_doc(**over):
    return {"contract": "rules-worker/1", "op": req["op"], "kind": "error", "engine": None, "modules": [], "lint": [],
            "cells": [], "error": ERROR | over}

def emit(document, code=0, raw=None):
    open(req["result"], "w", encoding="utf-8").write(raw if raw is not None else json.dumps(document))
    sys.exit(code)
'''


def fake_worker(monkeypatch, body: str):
    """Replace the worker with `python -c` running `body`; `req` is the parsed request, `doc()` an honest result."""
    monkeypatch.setattr(runner, 'worker_argv', lambda: [PY, '-c', PRELUDE + body])


def scan(scratch, limits=DEFAULT_LIMITS, **kw):
    return runner.scan([RULE], [TARGET], limits=limits, scratch_dir=scratch, **kw)


def failure(call, *args, **kw) -> RuleError:
    with pytest.raises(RuleError) as info:
        call(*args, **kw)
    return info.value


# --- an honest child ------------------------------------------------------------------------------------------------

def test_an_honest_fake_child_is_accepted_for_every_op(monkeypatch, scratch):
    fake_worker(monkeypatch, 'emit(doc())')
    outcome = scan(scratch)
    assert [x.state for x in outcome.cells] == ['no-hit'] and [r.name for r in outcome.lint] == ['r1']
    assert outcome.engine.version == '1.21.0'
    assert [r.name for r in runner.lint([RULE], scratch_dir=scratch)] == ['r1']
    assert runner.probe(scratch_dir=scratch).modules == ('pe',)
    assert list(scratch.iterdir()) == []


def test_the_child_gets_a_valid_request_in_a_private_directory_and_a_minimal_environment(monkeypatch, scratch):
    fake_worker(monkeypatch, '''
seen = {"cwd": os.getcwd(), "env": sorted(os.environ), "req": req, "argv": sys.argv[1:],
        "mode": os.stat(os.getcwd()).st_mode & 0o777}
open(os.path.join(os.getcwd(), "seen.json"), "w").write(json.dumps(seen))
emit(doc())
''')
    original, captured = runner._remove, {}

    def keep(work):
        captured['seen'] = json.loads((work / 'seen.json').read_text(encoding='utf-8'))
        original(work)
    monkeypatch.setattr(runner, '_remove', keep)
    monkeypatch.setenv('GITHUB_TOKEN', 'must-not-leak')
    scan(scratch)
    seen = captured['seen']
    work = Path(seen['cwd'])
    assert work.parent.resolve() == scratch.resolve() and work.name.startswith('patchtrace-rules-')
    assert seen['argv'][-2] == '--request' and 'GITHUB_TOKEN' not in seen['env']
    assert seen['req']['contract'] == 'rules-worker/1' and seen['req']['op'] == 'scan'
    assert Path(seen['req']['result']).parent.resolve() == work.resolve()
    assert seen['req']['limits']['memory_bytes'] == DEFAULT_LIMITS.worker_memory_bytes
    request = c.WorkerRequest.model_validate_json(json.dumps(seen['req']))
    assert request.rules == (RULE,) and request.targets == (TARGET,)
    if os.name != 'nt':
        assert seen['mode'] == 0o700  # only the owner can read the rule texts and the result


# --- a hostile or broken child -------------------------------------------------------------------------------------------

BAD = ('PT-RULE-ENGINE', 'worker-bad-result')
CASES = {
    'not-json': ('emit(None, 0, raw="not json")', *BAD),
    'nan': ('emit(None, 0, raw=\'{"kind": NaN}\')', *BAD),
    'duplicate-key': ('emit(None, 0, raw=\'{"kind": "ok", "kind": "error"}\')', *BAD),
    'float': ('emit(None, 0, raw=json.dumps(doc()).replace(\'"elapsed_ms": 1\', \'"elapsed_ms": 1.5\'))', *BAD),
    'extra-field': ('emit(doc(surprise=1))', *BAD),
    'wrong-contract': ('emit(doc(contract="rules-worker/2"))', *BAD),
    'unknown-error-code': ('emit(error_doc(code="PT-RULE-NOPE"), 20)', *BAD),
    'foreign-error-code': ('emit(error_doc(code="PT-SECONDARY-RUN"), 20)', *BAD),
    'ok-document-with-exit-20': ('emit(doc(), 20)', *BAD),
    'error-document-with-exit-0': ('emit(error_doc(), 0)', *BAD),
    'other-op': ('emit(doc(op="lint", cells=[]))', *BAD),
    'other-rule-names': ('emit(doc(lint=[lint_of("someone-else")]))', *BAD),
    'missing-cell': ('emit(doc(cells=doc()["cells"][:-1]))', *BAD),
    'extra-cell': ('emit(doc(cells=doc()["cells"] * 2))', *BAD),
    'scored-cell': ('emit(doc(cells=[CELL | {"verdict": "as-expected"}]))', *BAD),
    'no-result-after-exit-0': ('sys.exit(0)', 'PT-RULE-ENGINE', 'worker-crash'),
    'exit-21': ('sys.exit(21)', 'PT-RULE-ENGINE', 'worker-crash'),
    'abort': ('os.abort()', 'PT-RULE-ENGINE', 'worker-crash'),
    'exit-22-memory': ('sys.exit(22)', 'PT-RULE-LIMIT', 'worker-oom'),
    'rust-oom-text': ('sys.stderr.write("memory allocation of 656 bytes failed\\n"); os.abort()', 'PT-RULE-LIMIT',
                      'worker-oom'),
    'enomem-panic': ('sys.stderr.write("Cannot allocate memory (os error 12)\\n"); sys.exit(23)', 'PT-RULE-LIMIT',
                     'worker-oom'),
    'panic-exit-23': ('sys.exit(23)', 'PT-RULE-ENGINE', 'worker-panic'),
    'usage-exit-2': ('sys.exit(2)', 'PT-RULE-ENGINE', 'worker-usage'),
    'stdout-flood': ('while True:\n    sys.stdout.write("x" * 65536)\n    sys.stdout.flush()', 'PT-RULE-ENGINE',
                     'worker-output'),
}


@pytest.mark.parametrize('name', list(CASES), ids=list(CASES))
def test_every_wrong_result_maps_to_a_typed_error_and_leaves_no_scratch(monkeypatch, scratch, name):
    body, code, reason = CASES[name]
    fake_worker(monkeypatch, body)
    error = failure(scan, scratch)
    assert (error.code, error.reason) == (code, reason), error
    assert list(scratch.iterdir()) == [] and error.exit_code == (2 if code == 'PT-RULE-INPUT' else 3)


def test_an_oversize_result_is_refused_before_it_is_parsed(monkeypatch, scratch):
    fake_worker(monkeypatch, 'emit(None, 0, raw="x" * 400)')
    error = failure(scan, scratch, RuleLimits(result_bytes=300))
    assert (error.code, error.reason) == BAD and list(scratch.iterdir()) == []


def test_an_error_document_passes_through_with_its_own_code_message_and_reason(monkeypatch, scratch):
    fake_worker(monkeypatch, 'emit(error_doc(), 20)')
    error = failure(scan, scratch)
    assert (error.code, error.reason, error.message) == ('PT-RULE-LIMIT', 'result-size',
                                                          'The result is larger than the limit')
    fake_worker(monkeypatch, 'emit(error_doc(code="PT-RULE-INPUT", reason=None), 20)')
    assert failure(runner.lint, [RULE], scratch_dir=scratch).code == 'PT-RULE-INPUT'


def test_stderr_is_diagnostics_only_never_the_message(monkeypatch, scratch):
    """The child's runtimes can echo input-derived text, so stderr is sanitized and kept apart from the message."""
    fake_worker(monkeypatch, 'sys.stderr.write("SECRET-NAME \\u202e evil\\x01 \\n" + "z" * 20000); sys.exit(21)')
    error = failure(scan, scratch)
    assert error.reason == 'worker-crash' and 'SECRET' not in error.message and 'SECRET' not in str(error)
    assert error.diagnostics and '\u202e' not in error.diagnostics and '\x01' not in error.diagnostics
    assert len(error.diagnostics) <= DEFAULT_LIMITS.stderr_tail_bytes


@pytest.mark.parametrize('name', ['exit-21', 'abort', 'exit-22-memory', 'panic-exit-23', 'not-json', 'usage-exit-2',
                                  'ok-document-with-exit-20', 'stdout-flood'])
def test_probe_turns_any_worker_failure_into_unavailable_with_the_reason_kept(monkeypatch, scratch, name):
    body, _, reason = CASES[name]
    fake_worker(monkeypatch, body)
    error = failure(runner.probe, scratch_dir=scratch)
    assert (error.code, error.reason) == ('PT-RULE-UNAVAILABLE', reason) and error.exit_code == 2
    assert list(scratch.iterdir()) == []


def test_probe_passes_an_unavailable_document_and_maps_other_codes(monkeypatch, scratch):
    fake_worker(monkeypatch, 'emit(error_doc(code="PT-RULE-UNAVAILABLE", reason="engine-missing"), 20)')
    error = failure(runner.probe, scratch_dir=scratch)
    assert (error.code, error.reason) == ('PT-RULE-UNAVAILABLE', 'engine-missing')
    fake_worker(monkeypatch, 'emit(error_doc(), 20)')  # a LIMIT document from a probe is still "engine unusable"
    assert failure(runner.probe, scratch_dir=scratch).code == 'PT-RULE-UNAVAILABLE'


# --- time, cancel and process trees ---------------------------------------------------------------------------------------

def test_a_sleeping_worker_times_out_without_leftovers(monkeypatch, scratch):
    fake_worker(monkeypatch, 'time.sleep(60)')
    started = time.monotonic()
    error = failure(scan, scratch, SHORT)
    assert (error.code, error.reason) == ('PT-RULE-TIMEOUT', 'worker-timeout') and error.exit_code == 3
    assert time.monotonic() - started < 20 and list(scratch.iterdir()) == []


def test_worker_timeout_kills_child_tree(monkeypatch, scratch, tmp_path):
    """A grandchild that outlives the worker would keep running (and holding files): the whole tree is killed."""
    marker = tmp_path / 'grandchild-survived'
    fake_worker(monkeypatch, 'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2.5); '
                             f'open({str(marker)!r}, \'w\').write(\'x\')"])\ntime.sleep(60)')
    assert failure(scan, scratch, SHORT).code == 'PT-RULE-TIMEOUT'
    time.sleep(3.5)
    assert not marker.exists()


def test_cancel_mid_run_kills_the_worker_and_removes_the_scratch(monkeypatch, scratch, tmp_path):
    marker = tmp_path / 'still-running'
    fake_worker(monkeypatch, f'time.sleep(1.5)\nopen({str(marker)!r}, "w").write("x")\ntime.sleep(60)')
    cancel = threading.Event()
    threading.Timer(0.3, cancel.set).start()
    error = failure(scan, scratch, cancel=cancel)
    assert (error.code, error.reason) == ('PT-RULE-CANCEL', 'cancelled') and error.exit_code == 5
    time.sleep(2)
    assert not marker.exists() and list(scratch.iterdir()) == []


def test_a_cancel_that_is_already_set_never_starts_a_child(monkeypatch, scratch):
    fake_worker(monkeypatch, 'raise SystemExit("must not run")')
    cancel = threading.Event()
    cancel.set()
    for call in (lambda: scan(scratch, cancel=cancel), lambda: runner.probe(cancel=cancel, scratch_dir=scratch),
                 lambda: runner.lint([RULE], cancel=cancel, scratch_dir=scratch)):
        assert failure(call).code == 'PT-RULE-CANCEL'
    assert list(scratch.iterdir()) == []


def test_a_worker_that_cannot_be_started_is_a_typed_error(monkeypatch, scratch):
    monkeypatch.setattr(runner, 'worker_argv', lambda: [str(scratch / 'no-such-python')])
    error = failure(scan, scratch)
    assert (error.code, error.reason) == ('PT-RULE-ENGINE', 'spawn-failed') and list(scratch.iterdir()) == []


# --- requests the parent refuses before spawning --------------------------------------------------------------------------

FEW = RuleLimits(rules_per_run=1, series_targets=1, extra_targets=1, clean_targets=1, cells=3)
BIG_TARGET = c.WorkerTarget(target_id='t', path=ABSENT, size=2 * 1024 ** 3)
RELATIVE = c.WorkerTarget(target_id='t', path='relative/file.bin', size=1)


@pytest.mark.parametrize('call, code, reason', [
    (lambda s: runner.scan([], [TARGET], scratch_dir=s), 'PT-RULE-INPUT', 'empty-request'),
    (lambda s: runner.scan([RULE], [], scratch_dir=s), 'PT-RULE-INPUT', 'empty-request'),
    (lambda s: runner.lint([], scratch_dir=s), 'PT-RULE-INPUT', 'empty-request'),
    (lambda s: runner.scan([RULE], [RELATIVE], scratch_dir=s), 'PT-RULE-INPUT', 'relative-path'),
    (lambda s: runner.scan([RULE], [TARGET], timeout_s=4, scratch_dir=s), 'PT-RULE-INPUT', 'timeout-range'),
    (lambda s: runner.scan([RULE], [TARGET], timeout_s=301, scratch_dir=s), 'PT-RULE-INPUT', 'timeout-range'),
    (lambda s: runner.scan([RULE, RULE], [TARGET], scratch_dir=s), 'PT-RULE-INPUT', 'request-invalid'),
    (lambda s: runner.scan([RULE], [TARGET, TARGET], scratch_dir=s), 'PT-RULE-INPUT', 'request-invalid'),
    (lambda s: runner.scan([RULE] * 2, [TARGET], limits=FEW, scratch_dir=s), 'PT-RULE-LIMIT', 'rules'),
    (lambda s: runner.lint([RULE] * 2, limits=FEW, scratch_dir=s), 'PT-RULE-LIMIT', 'rules'),
    (lambda s: runner.scan([RULE], [TARGET] * 4, limits=FEW, scratch_dir=s), 'PT-RULE-LIMIT', 'targets'),
    (lambda s: runner.scan([RULE], [BIG_TARGET], limits=RuleLimits(run_bytes=MIB, file_bytes=MIB), scratch_dir=s),
     'PT-RULE-LIMIT', 'run-bytes'),
    (lambda s: runner.scan([RULE], [TARGET], limits=RuleLimits(worker_memory_bytes=2 * 1024 ** 3 + 1,
                                                               worker_memory_max_bytes=3 * 1024 ** 3), scratch_dir=s),
     'PT-RULE-INPUT', 'limits-invalid'),
], ids=['no-rules', 'no-targets', 'lint-no-rules', 'relative-path', 'timeout-low', 'timeout-high', 'duplicate-rule-names',
        'duplicate-targets', 'too-many-rules', 'lint-too-many-rules', 'too-many-targets', 'too-many-bytes',
        'memory-over-the-contract'])
def test_the_parent_refuses_bad_requests_before_it_spawns(monkeypatch, scratch, call, code, reason):
    fake_worker(monkeypatch, 'raise SystemExit("must not run")')
    error = failure(call, scratch)
    assert (error.code, error.reason) == (code, reason) and list(scratch.iterdir()) == []


def test_a_scratch_folder_that_cannot_be_made_or_is_too_deep_is_a_typed_error(monkeypatch, tmp_path):
    fake_worker(monkeypatch, 'raise SystemExit("must not run")')
    error = failure(scan, tmp_path / 'absent')
    assert (error.code, error.reason) == ('PT-RULE-ENGINE', 'scratch-failed')
    base = tmp_path / 'deep'
    probe_length = len(str(base / 'x' / 'patchtrace-rules-12345678' / 'out.json'))
    deep = base / ('x' * (runner.MAX_SCRATCH_PATH + 16 - probe_length))  # the worker's paths land 15 over the limit
    deep.mkdir(parents=True)
    error = failure(scan, deep)
    assert (error.code, error.reason) == ('PT-RULE-INPUT', 'scratch-path') and list(deep.iterdir()) == []
    assert failure(runner.probe, scratch_dir=deep).code == 'PT-RULE-INPUT'  # not an "engine unavailable"


# --- argv and environment ----------------------------------------------------------------------------------------------------

def test_worker_env_is_an_allow_list_and_argv_is_frozen_aware(monkeypatch):
    env = runner.worker_env({'PATH': '/bin', 'GITHUB_TOKEN': 'x', 'PYTHONPATH': '/elsewhere', 'PYTHONHOME': '/h',
                             'SystemRoot': 'C:\\Windows', 'HOME': '/home/u'})
    assert set(env) == {'PATH', 'SystemRoot', 'HOME', 'PYTHONUTF8', 'PYTHONIOENCODING', 'PYTHONPATH'}
    assert env['PYTHONPATH'] == SRC and Path(SRC, 'patchtrace', 'rules', 'runner.py').is_file()
    assert runner.worker_argv() == [sys.executable, '-P', '-m', 'patchtrace.rules.worker']
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    assert runner.worker_argv() == [sys.executable, 'rules', '_rules-worker'] and 'PYTHONPATH' not in runner.worker_env({})


# --- the worker's own exit codes (in-process, fake engine) -----------------------------------------------------------------------

class Panic(BaseException):  # what pyo3 raises for a Rust panic: it derives from BaseException, not Exception
    pass


class FakeEngine:
    def __init__(self, failure=None, modules=('pe',)):
        self.failure, self.modules = failure, modules

    def probe(self):
        if self.failure is not None:
            raise self.failure
        return c.EngineStamp(version='1.21.0', version_source='pin'), self.modules


def request_file(tmp_path, op='probe', **kw) -> Path:
    request = c.WorkerRequest(op=op, result=str(tmp_path / 'out.json'), **kw)
    path = tmp_path / 'req.json'
    path.write_text(request.model_dump_json(), encoding='utf-8')
    return path


def test_worker_baseexception_exit_23(monkeypatch, tmp_path, capsys):
    """`except Exception` misses a Rust panic: the worker must still end as exit 23 with no result and no traceback."""
    monkeypatch.setattr(worker, '_engine', lambda: FakeEngine(Panic('internal error: entered unreachable code')))
    assert worker.run(request_file(tmp_path)) == worker.EXIT_PANIC == 23
    assert not (tmp_path / 'out.json').exists()
    err = capsys.readouterr().err
    assert 'Panic' in err and 'Traceback' not in err and 'unreachable' not in err


@pytest.mark.parametrize('failure_, code', [(Panic('x'), 23), (KeyboardInterrupt(), 23), (SystemExit(3), 23),
                                            (MemoryError(), 22), (RuntimeError('x'), 21), (ValueError('x'), 21)],
                         ids=['panic', 'keyboard-interrupt', 'system-exit', 'memory', 'runtime', 'value'])
def test_worker_exit_codes_for_unexpected_failures(monkeypatch, tmp_path, capsys, failure_, code):
    monkeypatch.setattr(worker, '_engine', lambda: FakeEngine(failure_))
    assert worker.run(request_file(tmp_path)) == code
    assert not (tmp_path / 'out.json').exists()
    assert ('Traceback' in capsys.readouterr().err) == (code == 21)


def test_worker_error_document_for_a_typed_failure(monkeypatch, tmp_path):
    error = RuleError('PT-RULE-LIMIT', 'The result is\nlarger\x00 than the limit', reason='result-size')
    monkeypatch.setattr(worker, '_engine', lambda: FakeEngine(error))
    assert worker.run(request_file(tmp_path)) == worker.EXIT_ERROR_DOC == 20
    doc = c.WorkerResult.model_validate_json((tmp_path / 'out.json').read_bytes())
    assert (doc.kind, doc.error.code, doc.error.reason) == ('error', 'PT-RULE-LIMIT', 'result-size')
    assert '\n' not in doc.error.message and '\x00' not in doc.error.message


def test_worker_ok_document_and_it_never_overwrites_a_result(monkeypatch, tmp_path):
    monkeypatch.setattr(worker, '_engine', lambda: FakeEngine())
    path = request_file(tmp_path)
    assert worker.run(path) == worker.EXIT_OK
    doc = c.WorkerResult.model_validate_json((tmp_path / 'out.json').read_bytes())
    assert (doc.op, doc.kind, doc.modules) == ('probe', 'ok', ('pe',))
    before = (tmp_path / 'out.json').read_bytes()
    assert worker.run(path) == worker.EXIT_INTERNAL  # exclusive create: the directory is private to one run
    assert (tmp_path / 'out.json').read_bytes() == before


def test_worker_refuses_a_result_larger_than_the_limit(monkeypatch, tmp_path):
    many = tuple(f'module{i}' for i in range(64))  # an ok document of about 1 KiB; the error document is far smaller
    monkeypatch.setattr(worker, '_engine', lambda: FakeEngine(modules=many))
    monkeypatch.setattr(worker, 'DEFAULT_LIMITS', RuleLimits(result_bytes=500))
    assert worker.run(request_file(tmp_path)) == worker.EXIT_ERROR_DOC
    doc = c.WorkerResult.model_validate_json((tmp_path / 'out.json').read_bytes())
    assert (doc.error.code, doc.error.reason) == ('PT-RULE-LIMIT', 'result-size')


def test_a_missing_engine_is_an_unavailable_document_not_a_crash(monkeypatch, tmp_path):
    monkeypatch.delattr(rules_package, 'engine', raising=False)
    monkeypatch.setitem(sys.modules, 'patchtrace.rules.engine', None)  # makes `from . import engine` raise ImportError
    assert worker.run(request_file(tmp_path)) == worker.EXIT_ERROR_DOC
    doc = c.WorkerResult.model_validate_json((tmp_path / 'out.json').read_bytes())
    assert (doc.error.code, doc.error.reason) == ('PT-RULE-UNAVAILABLE', 'engine-missing')


@pytest.mark.parametrize('content', [b'{"contract": "rules-worker/1", "op": "probe", "result": "/x", "extra": 1}',
                                     b'{"op": "probe", "op": "scan"}', b'not json', b'', b'\xff\xfe',
                                     b'{"contract": "rules-worker/2", "op": "probe", "result": "/x"}',
                                     b'{"contract": "rules-worker/1", "op": "scan", "result": "/x"}',
                                     b'x' * (DEFAULT_LIMITS.request_bytes + 1)],
                         ids=['extra-field', 'duplicate-key', 'not-json', 'empty', 'not-utf8', 'future-contract',
                              'scan-without-rules', 'too-large'])
def test_worker_refuses_an_unusable_request_with_exit_2(tmp_path, capsys, content):
    path = tmp_path / 'req.json'
    path.write_bytes(content)
    assert worker.run(path) == worker.EXIT_USAGE == 2
    assert 'unusable request' in capsys.readouterr().err
    assert worker.run(tmp_path / 'absent.json') == 2
    assert [p.name for p in tmp_path.iterdir()] == ['req.json']


def test_worker_main_wants_exactly_request_and_a_file(capsys):
    assert worker.main([]) == worker.main(['--request']) == worker.main(['--other', 'x']) == 2
    assert worker.main(['--request', 'a', 'b']) == 2
    assert 'usage' in capsys.readouterr().err


def test_worker_module_runs_as_a_script_and_reports_usage_without_loading_the_engine():
    result = subprocess.run([*runner.worker_argv()], capture_output=True, text=True, timeout=120,
                            env=runner.worker_env(dict(os.environ)))
    assert result.returncode == 2 and 'usage' in result.stderr and result.stdout == ''


# --- target files: the child reads untrusted paths ---------------------------------------------------------------------------------

def test_targets_are_read_as_exact_regular_files_within_the_limits(tmp_path):
    limits = c.WorkerLimits(file_bytes=64)
    good = tmp_path / 'good.bin'
    good.write_bytes(b'abcd')
    digest = hashlib.sha256(b'abcd').hexdigest()

    def read(path, size=4, sha=digest):
        return worker._read_target(c.WorkerTarget(target_id='t', path=str(path), sha256=sha, size=size), limits)
    assert read(good) == b'abcd' and read(good, sha=None) == b'abcd'
    assert read(good, size=5) == read(good, sha='0' * 64) == 'file-changed'
    assert read(tmp_path / 'absent') == read(tmp_path) == 'unreadable'  # missing, and a directory
    big = tmp_path / 'big.bin'
    big.write_bytes(bytes(65))
    assert read(big, size=65, sha=None) == 'too-large'
    if os.name != 'nt':
        fifo = tmp_path / 'fifo'
        os.mkfifo(fifo)
        started = time.monotonic()
        assert read(fifo, size=0, sha=None) == 'unreadable'  # a pipe is never read (it would block forever)
        assert time.monotonic() - started < 5
        link = tmp_path / 'link.bin'
        link.symlink_to(good)
        assert read(link) == b'abcd'  # a link to a regular file is read through the checked descriptor


# --- real children ---------------------------------------------------------------------------------------------------------------------

def test_engine_extra_is_installed_in_the_qa_matrix():
    if runner.engine_installed():
        return
    if os.environ.get('CI'):
        pytest.fail('the `rules` extra (yara-x==1.21.0) must be installed in the QA matrix')
    pytest.skip('yara-x is not installed locally: pip install --only-binary=:all: "patchtrace[rules]"')


def test_parent_never_imports_yara_x():
    """Importing the parent-side modules, and using the engine through a real worker, never loads the extension."""
    code = ('import sys\n'
            'import patchtrace.rules.runner, patchtrace.rules.contracts, patchtrace.rules.ports\n'
            'import patchtrace.rules.limits, patchtrace.rules.errors, patchtrace.rules.worker\n'
            'def loaded():\n'
            '    return [m for m in ("yara_x", "iced_x86", "patchtrace.rules.engine", "patchtrace.optional_deps")\n'
            '            if m in sys.modules]\n'
            'before = loaded()\n'
            'if patchtrace.rules.runner.engine_installed():\n'
            '    patchtrace.rules.runner.probe()\n'
            'print(before, loaded())\n'
            'raise SystemExit(1 if before or loaded() else 0)\n')
    env = dict(os.environ, PYTHONPATH=SRC)
    result = subprocess.run([PY, '-P', '-c', code], capture_output=True, text=True, env=env, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    control = subprocess.run([PY, '-P', '-c', 'import sys, patchtrace.rules.engine\nraise SystemExit(0 if "yara_x" in '
                                                'sys.modules else 1)'], capture_output=True, env=env, timeout=120)
    assert control.returncode == 0 or not runner.engine_installed()  # the check can fail: importing the engine loads it


@needs_engine
def test_a_missing_engine_in_a_real_child_is_unavailable(monkeypatch, tmp_path, scratch):
    blocker = tmp_path / 'blocker'
    blocker.mkdir()
    (blocker / 'yara_x.py').write_text('raise ImportError("blocked for the test")\n', encoding='utf-8')
    real = runner.worker_env
    monkeypatch.setattr(runner, 'worker_env', lambda environ=None: real(environ) | {'PYTHONPATH': f'{blocker}{os.pathsep}{SRC}'})
    error = failure(runner.probe, scratch_dir=scratch)
    assert (error.code, error.reason) == ('PT-RULE-UNAVAILABLE', 'engine-missing')
    error = failure(runner.lint, [RULE], scratch_dir=scratch)
    assert (error.code, error.reason) == ('PT-RULE-UNAVAILABLE', 'engine-missing')
    assert list(scratch.iterdir()) == []


@needs_engine
@pytest.mark.parametrize('cap_mib', [64, 128, 192], ids=['cap-64', 'cap-128', 'cap-192'])
def test_real_worker_out_of_memory_is_classified_as_a_limit_not_a_crash(tmp_path, scratch, cap_mib):
    """Linux measured: RLIMIT_AS below the engine's footprint ends as a Rust allocation abort (64), an ENOMEM panic caught
    as BaseException (128) or a MemoryError (192, exit 22); all three are `worker-oom`. Windows (U7): the job limit counts
    commit, so crash vs oom is recorded, not assumed."""
    from pe_builder import PeSpec, build_pe_ex
    data, _ = build_pe_ex(PeSpec(overlay=bytes(32 * MIB)))
    path = tmp_path / 'big.bin'
    path.write_bytes(data)
    target = c.WorkerTarget(target_id='t1', path=str(path), size=len(data))
    limits = RuleLimits(worker_memory_bytes=cap_mib * MIB)
    valid = c.WorkerRule(name='r1', text=example_rule_text())  # a rule that compiles, so the scan really runs
    error = failure(runner.scan, [valid], [target], limits=limits, scratch_dir=scratch)
    assert error.reason == 'worker-oom' or (os.name == 'nt' and error.reason == 'worker-crash'), error
    assert error.code in ('PT-RULE-LIMIT', 'PT-RULE-ENGINE') and list(scratch.iterdir()) == []
    if cap_mib < 192:  # too small to even start: the probe says the engine is unavailable
        assert failure(runner.probe, limits=limits, scratch_dir=scratch).code == 'PT-RULE-UNAVAILABLE'
