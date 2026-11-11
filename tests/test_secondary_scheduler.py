"""SPEC-28 §5/§10: scheduler semantics. Fake engines are `sys.executable -c` argv (portable, no shebangs)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest
from liveness_support import heartbeat_stopped, wait_for

from patchtrace.jobs import ProcessResult
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.registry import (
    BinDiffAdapter,
    GhidriffBaselineAdapter,
    RzDiffAdapter,
    build_registry,
)
from patchtrace.secondary.scheduler import ProjectRef, run_engines

OLD_BYTES, NEW_BYTES = b'old-artifact', b'new-artifact'
# Two distinct newer functions: a result with at most one is refused (SPEC-11 section 9).
GOOD = json.dumps([{'similarity': 0.5, 'type': 'PARTIAL', 'original': {'addr': 1, 'name': 'f', 'size': 1},
                    'modified': {'addr': 2, 'name': 'g', 'size': 1}},
                   {'similarity': 1.0, 'type': 'COMPLETE', 'original': {'addr': 3, 'name': 'h', 'size': 1},
                    'modified': {'addr': 4, 'name': 'h', 'size': 1}}])


class PyEngine(RzDiffAdapter):
    """rz-diff parsing, but the 'executable' is this Python running a snippet."""

    def __init__(self, code: str, engine_id='rz-diff'):
        super().__init__()
        self.code, self.id = code, engine_id

    def probe(self, job_env, cancel):
        return Capability(engine='rz-diff', supported=True, version='0.9.1', path=sys.executable,
                          supports_json=True)

    def argv(self, cap, job):
        return (sys.executable, '-c', self.code)


def interrupt_main_when(event: threading.Event) -> tuple[threading.Event, threading.Thread]:
    """Interrupt the main thread (a Ctrl+C) once `event` is set; `stop` cancels the watcher without interrupting."""
    import _thread
    stop = threading.Event()

    def watch() -> None:
        while not stop.is_set():
            if event.wait(0.05):
                _thread.interrupt_main()
                return

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    return stop, thread


class Boom(PyEngine):
    def run(self, cap, job):
        raise RuntimeError('secret-token-should-not-leak')


def _alive(pid: int) -> bool:
    """Alive and not a zombie (containers without a reaping init leave killed orphans as zombies)."""
    try:
        state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
    except OSError:
        return False
    return state not in ('Z', 'X')


def project(tmp_path):
    (tmp_path / 'old').write_bytes(OLD_BYTES)
    (tmp_path / 'new').write_bytes(NEW_BYTES)
    return ProjectRef(tmp_path / 'old', tmp_path / 'new', hashlib.sha256(OLD_BYTES).hexdigest(),
                      hashlib.sha256(NEW_BYTES).hexdigest())


def go(tmp_path, registry, engines, **kw):
    kw.setdefault('cancel', threading.Event())
    return run_engines(project(tmp_path), engines, env=dict(os.environ), registry=registry, **kw)


def ok_code(marker_dir: Path, name: str, sleep: float = 0.0) -> str:
    return (f"import time,pathlib\nd=pathlib.Path({str(marker_dir)!r})\n(d/'{name}.start').write_text(str(time.time()))\n"
            f"time.sleep({sleep})\n(d/'{name}.end').write_text(str(time.time()))\nprint({GOOD!r})")


def span(d: Path, name: str):
    return float((d / f'{name}.start').read_text()), float((d / f'{name}.end').read_text())


def test_sequential_default_runs_one_at_a_time(tmp_path):
    reg = {'rz-diff': PyEngine(ok_code(tmp_path, 'a', 0.4)), 'bindiff': PyEngine(ok_code(tmp_path, 'b', 0.1), 'bindiff')}
    out = go(tmp_path, reg, ['rz-diff', 'bindiff'])
    assert [o.run.status for o in out] == ['ok', 'ok']
    (a0, a1), (b0, b1) = span(tmp_path, 'a'), span(tmp_path, 'b')
    assert a1 <= b0 or b1 <= a0


def test_parallel_two_overlaps_and_order_is_deterministic(tmp_path):
    reg = {'rz-diff': PyEngine(ok_code(tmp_path, 'a', 1.0)), 'bindiff': PyEngine(ok_code(tmp_path, 'b', 0.1), 'bindiff')}
    out = go(tmp_path, reg, ['rz-diff', 'bindiff'], max_parallel=2)
    assert [o.run.engine for o in out] == ['rz-diff', 'bindiff']
    (a0, a1), (b0, b1) = span(tmp_path, 'a'), span(tmp_path, 'b')
    assert a0 < b1 and b0 < a1


@pytest.mark.parametrize('bad', [0, 3, True])
def test_max_parallel_out_of_range_rejected(tmp_path, bad):
    with pytest.raises(ValueError):
        go(tmp_path, build_registry(), ['rz-diff'], max_parallel=bad)


def test_failure_isolation_and_stderr_not_in_error(tmp_path):
    crash = "import sys\nsys.stderr.write('noisy \\x1b[31m token=SECRET\\n')\nsys.exit(1)"
    reg = {'rz-diff': PyEngine(crash), 'bindiff': PyEngine(ok_code(tmp_path, 'b'), 'bindiff')}
    bad, good = go(tmp_path, reg, ['rz-diff', 'bindiff'], max_parallel=2)
    assert (bad.run.status, bad.run.error_code, bad.run.returncode) == ('failed', 'PT-SECONDARY-RUN', 1)
    assert 'SECRET' in bad.run.stderr_tail and '\x1b' not in bad.run.stderr_tail
    assert bad.error is not None and 'SECRET' not in str(bad.error) and bad.match_set is None
    assert good.run.status == 'ok' and good.match_set is not None
    assert good.match_set.contract == 'secondary/2' and good.match_set.run_id == good.run.run_id


def test_stderr_noise_does_not_corrupt_json(tmp_path):
    code = f"import sys\nsys.stderr.write('warning: noise\\n')\nprint({GOOD!r})"
    [out] = go(tmp_path, {'rz-diff': PyEngine(code)}, ['rz-diff'])
    assert out.run.status == 'ok' and 'noise' in out.run.stderr_tail


def test_timeout_maps_to_timeout_status_and_kills_tree(tmp_path):
    """Portable tree-kill proof: the grandchild's heartbeat file stops growing once run_engines returns."""
    pidfile, beat = tmp_path / 'child.pid', tmp_path / 'child.beat'
    grandchild = ("import sys,time\nf=open(sys.argv[1],'ab',buffering=0)\n"
                  "while True:\n    f.write(b'x')\n    time.sleep(0.05)")
    code = ("import subprocess,sys,time\n"
            f"c=subprocess.Popen([sys.executable,'-c',{grandchild!r},{str(beat)!r}])\n"
            f"open({str(pidfile)!r},'w').write(str(c.pid))\ntime.sleep(60)")
    [out] = go(tmp_path, {'rz-diff': PyEngine(code)}, ['rz-diff'], per_engine_timeout={'rz-diff': 3.0})
    assert (out.run.status, out.run.error_code) == ('timeout', 'PT-SECONDARY-TIMEOUT')
    assert pidfile.exists() and beat.exists(), 'grandchild never started within the deadline'
    assert heartbeat_stopped(beat)  # run_process returns only after the whole tree (Job Object / killpg) is terminated
    if os.name != 'nt':
        assert wait_for(lambda: not _alive(int(pidfile.read_text())), timeout=5)


def test_cancel_fan_out_stops_running_and_marks_unstarted_cancelled(tmp_path):
    cancel = threading.Event()
    sleeper = "import time\ntime.sleep(60)"
    reg = {'rz-diff': PyEngine(sleeper), 'bindiff': PyEngine(sleeper, 'bindiff')}
    threading.Timer(1.0, cancel.set).start()
    started = time.monotonic()
    first, second = go(tmp_path, reg, ['rz-diff', 'bindiff'], cancel=cancel)
    assert time.monotonic() - started < 20
    assert (first.run.status, second.run.status) == ('cancelled', 'cancelled')
    assert second.run.returncode is None  # never started


def test_huge_stdout_is_bounded_and_rejected_as_limit(tmp_path):
    code = "print('x' * 5000)"
    [out] = go(tmp_path, {'rz-diff': PyEngine(code)}, ['rz-diff'], stdout_limit=1000)
    assert (out.run.status, out.run.error_code) == ('failed', 'PT-SECONDARY-LIMIT')


def test_unsupported_engine_is_outcome_not_exception(tmp_path):
    out = go(tmp_path, build_registry(), ['bindiff', 'ghidriff-baseline'])
    assert [o.run.status for o in out] == ['unsupported', 'unsupported']
    assert out[0].run.error_code == 'PT-SECONDARY-UNSUPPORTED' and 'not configured' in str(out[0].error)
    assert out[0].run.provenance == {'failure_kind': 'not-configured'}


def test_missing_rz_diff_is_unsupported(tmp_path):
    reg = build_registry(rz_diff='definitely-not-installed-rz-diff')
    [out] = go(tmp_path, reg, ['rz-diff'])
    assert out.run.status == 'unsupported'


def test_unexpected_exception_becomes_failed_run_without_message_echo(tmp_path):
    [out] = go(tmp_path, {'rz-diff': Boom('pass')}, ['rz-diff'])
    assert out.run.status == 'failed' and str(out.error) == 'PT-SECONDARY-RUN: RuntimeError'


def test_duplicate_engines_run_once_and_unknown_rejected(tmp_path):
    out = go(tmp_path, {'rz-diff': PyEngine(f'print({GOOD!r})')}, ['rz-diff', 'rz-diff'])
    assert len(out) == 1
    with pytest.raises(ValueError):
        go(tmp_path, {}, ['rz-diff'])


def test_cache_hit_skips_run_and_is_recorded_as_cached(tmp_path):
    [first] = go(tmp_path, {'rz-diff': PyEngine(f'print({GOOD!r})')}, ['rz-diff'])

    class Hit:
        def find(self, key):
            return first.match_set

    [second] = go(tmp_path, {'rz-diff': Boom(f'print({GOOD!r})')}, ['rz-diff'], cache=Hit())
    assert second.run.status == 'cached' and second.match_set == first.match_set
    assert second.run.cache_key == first.run.cache_key


def test_ghidriff_baseline_is_provenance_only(tmp_path):
    reg = {'ghidriff-baseline': GhidriffBaselineAdapter('c' * 64)}
    [out] = go(tmp_path, reg, ['ghidriff-baseline'])
    assert out.run.status == 'ok' and out.match_set is None and out.run.match_set_id is None


def test_bindiff_adapter_refuses_to_execute(tmp_path):
    job = None
    with pytest.raises(SecondaryError):
        BinDiffAdapter().run(BinDiffAdapter().probe({}, threading.Event()), job)  # type: ignore[arg-type]


def test_on_outcome_delivers_each_finished_outcome_and_survives_interrupt(tmp_path):
    """Ctrl+C while a later engine runs must not lose the outcome that already finished (SPEC-28 section 7)."""
    seen = []
    reg = {'rz-diff': PyEngine(f'print({GOOD!r})'), 'bindiff': PyEngine('import time\ntime.sleep(60)', 'bindiff')}
    first_done = threading.Event()

    def on_outcome(outcome):
        seen.append(outcome)
        if outcome.run.engine == 'rz-diff':
            first_done.set()

    stop, watcher = interrupt_main_when(first_done)  # deterministic: not a fixed delay (slow runners start children late)
    started = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt):
            go(tmp_path, reg, ['rz-diff', 'bindiff'], on_outcome=on_outcome)
    finally:
        stop.set()
        watcher.join(5)
    assert time.monotonic() - started < 30
    assert [o.run.engine for o in seen if o.run.status == 'ok'] == ['rz-diff']
    assert all(o.run.engine != 'bindiff' or o.run.status == 'cancelled' for o in seen)


def test_on_outcome_runs_on_caller_thread_in_completion_order(tmp_path):
    threads = []
    reg = {'rz-diff': PyEngine(ok_code(tmp_path, 'a', 0.1)), 'bindiff': PyEngine(ok_code(tmp_path, 'b', 0.0), 'bindiff')}
    out = go(tmp_path, reg, ['rz-diff', 'bindiff'], on_outcome=lambda o: threads.append(threading.current_thread()))
    assert [o.run.engine for o in out] == ['rz-diff', 'bindiff']  # return order stays plan order
    assert threads == [threading.current_thread()] * 2


def test_workdir_cleanup_failure_does_not_discard_a_finished_run(tmp_path):
    """Windows can refuse to delete a just-written file (scanner, lingering handle): the finished run stands."""
    leftovers = []

    class Sabotaged(PyEngine):
        def run(self, cap, job):
            raw = super().run(cap, job)
            shutil.rmtree(job.workdir)
            job.workdir.write_text('x')  # TemporaryDirectory cleanup now fails (NotADirectoryError)
            leftovers.append(job.workdir)
            return raw

    events = []
    try:
        [out] = go(tmp_path, {'rz-diff': Sabotaged(f'print({GOOD!r})')}, ['rz-diff'], on_event=events.append)
    finally:
        for path in leftovers:
            path.unlink(missing_ok=True)
    assert (out.run.status, out.run.error_code) == ('ok', None) and out.match_set is not None
    assert [e.phase for e in events] == ['started', 'finished']


SHAPES = {s['id']: s for s in json.loads(
    (Path(__file__).parent / 'fixtures' / 'secondary' / 'rzdiff-singleton-shapes.json').read_text(
        encoding='utf-8'))['shapes']}


def emit(stdout: str) -> str:
    """Child source that writes exactly `stdout` (binary, so Windows adds no carriage returns)."""
    return f"import sys\nsys.stdout.buffer.write({stdout.encode('utf-8')!r})"


@pytest.mark.parametrize('shape_id', ['stock-elf-1-1', 'stock-elf-1-2', 'stock-elf-2-1'])
def test_singleton_shape_fails_the_run_and_produces_no_set(tmp_path, shape_id):
    """SPEC-11 section 9 on retained native stdout: refused, so there is nothing to publish, cache or reconcile."""
    delivered = []
    [out] = go(tmp_path, {'rz-diff': PyEngine(emit(SHAPES[shape_id]['stdout']))}, ['rz-diff'],
               on_outcome=delivered.append)
    assert (out.run.status, out.run.error_code, out.run.returncode) == ('failed', 'PT-SECONDARY-ORIENTATION', 0)
    assert out.error is not None and out.error.kind == 'rzdiff-singleton-ownership'
    assert out.match_set is None and out.run.match_set_id is None and out.run.output_sha256 is None
    assert delivered == [out]


def test_two_newer_functions_still_run_ok(tmp_path):
    shape = SHAPES['stock-elf-2-2']
    [out] = go(tmp_path, {'rz-diff': PyEngine(emit(shape['stdout']))}, ['rz-diff'])
    assert out.run.status == 'ok' and len(out.match_set.matches) == 2
    assert out.run.output_sha256 == shape['stdout_sha256'] == out.match_set.file_sha256


def test_cli_singleton_run_stores_no_set_and_keeps_the_earlier_one(tmp_path, capsys):
    """End to end through `secondary run` and the project store (fake rz-diff printing retained stdout)."""
    from fake_exe import make_fake_exe

    from patchtrace import cli
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.service import ProjectService

    def fake_rz(name: str, shape_id: str) -> str:
        source = ("import sys\nif sys.argv[1:] == ['-v']:\n    print('rz-diff 0.9.1')\n    sys.exit(0)\n"
                  f"sys.stdout.buffer.write({SHAPES[shape_id]['stdout'].encode('utf-8')!r})\n")
        return str(make_fake_exe(tmp_path / name, 'rz-diff', source))

    def run(root, exe):
        code = cli.main(['secondary', 'run', str(root), '--json', '--rz-diff', exe, '--engine', 'rz-diff',
                         '--no-cache'])
        return code, json.loads(capsys.readouterr().out)

    def stored_sets(root) -> list[str]:
        service = ProjectService.open(root)
        try:
            return [e.body['file_sha256'] for e in EnrichmentStore(service.store).entries('secondary-matches')]
        finally:
            service.close()

    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    service.close()
    code, doc = run(root, fake_rz('swapped', 'stock-elf-1-2'))
    [row] = doc['result']['runs']
    assert (code, doc['status']) == (2, 'failed')  # SPEC-28 section 7 maps PT-SECONDARY-ORIENTATION to exit 2
    assert (row['status'], row['error_code'], row['matches']) == ('failed', 'PT-SECONDARY-ORIENTATION', 0)
    assert doc['result']['reconciliation']['reports'] == [] and stored_sets(root) == []
    assert any('not stored' in w and 'use another engine' in w for w in doc['warnings'])

    assert run(root, fake_rz('ordinary', 'stock-elf-2-2'))[0] == 0
    kept = stored_sets(root)
    assert kept == [SHAPES['stock-elf-2-2']['stdout_sha256']]
    assert run(root, fake_rz('again', 'stock-elf-2-1'))[1]['result']['runs'][0]['error_code'] == \
        'PT-SECONDARY-ORIENTATION'
    assert stored_sets(root) == kept  # the earlier current set is untouched


# ---- SPEC-11 section 10: byte-exact stdout, no-functions and rz-diff provenance -------------------------

def write_bytes(data: bytes) -> str:
    return f"import sys\nsys.stdout.buffer.write({data!r})"


class Versioned(PyEngine):
    def __init__(self, code: str, version: str, path: str = sys.executable):
        super().__init__(code)
        self.version, self.path = version, path

    def probe(self, job_env, cancel):
        return Capability(engine='rz-diff', supported=True, version=self.version, path=self.path,
                          supports_json=True)


def python_sha256() -> str:
    return hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()


def test_output_sha256_is_of_the_bytes_the_engine_wrote(tmp_path):
    data = GOOD.replace('"f"', '"caf\u00e9_\ufffd"').encode('utf-8') + b'\r\n'
    assert b'\xef\xbf\xbd' in data
    [out] = go(tmp_path, {'rz-diff': PyEngine(write_bytes(data))}, ['rz-diff'])
    assert (out.run.status, out.run.error_code) == ('ok', None)
    assert out.match_set.matches[0].older_name == 'caf\u00e9_\ufffd'
    assert out.run.output_sha256 == out.match_set.file_sha256 == hashlib.sha256(data).hexdigest()


def test_invalid_utf8_stdout_fails_the_run_instead_of_being_replaced(tmp_path):
    data = GOOD.encode('ascii').replace(b'"f"', b'"\xff"')
    [out] = go(tmp_path, {'rz-diff': PyEngine(write_bytes(data))}, ['rz-diff'])
    assert (out.run.status, out.run.error_code) == ('failed', 'PT-SECONDARY-INPUT')
    assert out.error.message == f'rz-diff output is not valid UTF-8 at byte offset {data.index(bytes([255]))}'
    assert out.match_set is None and out.run.output_sha256 is None


def test_no_functions_run_fails_with_its_own_kind(tmp_path):
    marker = 'ERROR: rz-diff: No functions found in file0.\n'  # the retained native stderr line
    [out] = go(tmp_path, {'rz-diff': PyEngine(f"import sys\nsys.stderr.write({marker!r})")}, ['rz-diff'])
    assert (out.run.status, out.run.error_code, out.run.returncode) == ('failed', 'PT-SECONDARY-INPUT', 0)
    assert out.error.kind == 'no-functions' and 'older file' in out.error.message
    assert out.run.provenance == {'executable_sha256': python_sha256(), 'failure_kind': 'no-functions'}
    assert 'No functions found in file0' in out.run.stderr_tail


@pytest.mark.parametrize('version, extra', [('0.9.1', {}), ('0.9.0', {}), ('0.10.0', {'untested_version': 'true'}),
                                            ('1.0.0', {'untested_version': 'true'})],
                         ids=['0.9.1', '0.9.0', '0.10.0', '1.0.0'])
def test_rzdiff_provenance_names_the_executable_and_an_untested_version(tmp_path, version, extra):
    [out] = go(tmp_path, {'rz-diff': Versioned(f'print({GOOD!r})', version)}, ['rz-diff'])
    assert out.run.status == 'ok'
    assert out.run.provenance == {'executable_sha256': python_sha256(), **extra}
    assert json.loads(out.run.model_dump_json())['provenance'] == out.run.provenance


def test_singleton_refusal_is_recorded_as_failure_kind(tmp_path):
    [out] = go(tmp_path, {'rz-diff': PyEngine(emit(SHAPES['stock-elf-1-2']['stdout']))}, ['rz-diff'])
    assert out.run.provenance == {'executable_sha256': python_sha256(),
                                  'failure_kind': 'rzdiff-singleton-ownership'}


def test_rows_that_record_nothing_new_have_no_provenance_member(tmp_path):
    """Append-only: unsupported, cached and unreadable-executable rows serialise exactly as before."""
    [missing] = go(tmp_path, build_registry(rz_diff='definitely-not-installed-rz-diff'), ['rz-diff'])
    [first] = go(tmp_path, {'rz-diff': PyEngine(f'print({GOOD!r})')}, ['rz-diff'])

    class Hit:
        def find(self, key):
            return first.match_set

    [cached] = go(tmp_path, {'rz-diff': Boom('pass')}, ['rz-diff'], cache=Hit())

    class Gone(Versioned):  # launches a path with no file behind it, so there is nothing to hash
        def argv(self, cap, job):
            return (cap.path, '-c', self.code)

    def runner(argv, **kwargs):
        return ProcessResult(0, GOOD, None, log_bytes=GOOD.encode('ascii'))

    [unreadable] = go(tmp_path, {'rz-diff': Gone('pass', '0.9.1', str(tmp_path / 'gone' / 'rz-diff'))},
                      ['rz-diff'], runner=runner)
    assert [o.run.status for o in (missing, cached, unreadable)] == ['unsupported', 'cached', 'ok']
    for out in (missing, cached, unreadable):
        assert out.run.provenance == {} and 'provenance' not in json.loads(out.run.model_dump_json())


def test_provenance_of_one_attempt_does_not_leak_into_the_next(tmp_path):
    """One shared adapter (as in the module registry): a cache hit after a real run records nothing."""
    adapter = Versioned(f'print({GOOD!r})', '0.10.0')
    [first] = go(tmp_path, {'rz-diff': adapter}, ['rz-diff'])

    class Hit:
        def find(self, key):
            return first.match_set

    [second] = go(tmp_path, {'rz-diff': adapter}, ['rz-diff'], cache=Hit())
    assert first.run.provenance['untested_version'] == 'true'
    assert (second.run.status, second.run.provenance) == ('cached', {})


def test_adapter_notes_belong_to_one_attempt_on_one_thread(tmp_path):
    """The module registry shares one adapter: its notes are per worker thread and cleared by the next probe."""
    from patchtrace.secondary.registry import EngineJob

    adapter = RzDiffAdapter('definitely-not-installed-rz-diff')
    cap = Capability(engine='rz-diff', supported=True, version='0.10.0', path=sys.executable, supports_json=True)
    job = EngineJob(tmp_path / 'old', tmp_path / 'new', 'a' * 64, 'b' * 64, {}, tmp_path, threading.Event(), 60.0,
                    lambda argv, **kw: ProcessResult(0, GOOD, None, log_bytes=GOOD.encode('ascii')))
    seen = []
    worker = threading.Thread(target=lambda: (adapter.run(cap, job), seen.append(adapter.provenance())))
    worker.start()
    worker.join(30)
    assert seen == [{'executable_sha256': python_sha256(), 'untested_version': 'true'}]
    assert adapter.provenance() == {}  # another thread's attempt is invisible here
    adapter.run(cap, job)
    assert adapter.provenance() == seen[0]
    assert not adapter.probe({}, threading.Event()).supported and adapter.provenance() == {}


def test_attempt_that_never_launches_records_only_the_scheduler_kind(tmp_path):
    cancel = threading.Event()
    cancel.set()
    [out] = go(tmp_path, {'rz-diff': PyEngine(f'print({GOOD!r})')}, ['rz-diff'], cancel=cancel)
    assert (out.run.status, out.run.provenance) == ('cancelled', {'failure_kind': 'cancelled'})


# ---- SPEC-11 section 3 and 9: failed attempts commit no evidence and keep the earlier set -----------------

def emit_then(stdout: str, tail: str) -> str:
    """Child source that writes exactly `stdout` (binary), flushes, then runs `tail`."""
    return f"import sys,time\nsys.stdout.buffer.write({stdout.encode('utf-8')!r})\nsys.stdout.flush()\n{tail}"


@pytest.mark.parametrize('stdout', [
    GOOD[:30],                                   # truncated mid-document
    GOOD + ' trailing',                          # bytes after the array
    '{"matches": ' + GOOD + '}',                 # an object, not an array
    GOOD.replace('0.5', 'NaN', 1),               # non-finite number
], ids=['truncated', 'trailing-bytes', 'not-an-array', 'non-finite'])
def test_malformed_backend_json_is_rejected_and_not_committed(tmp_path, stdout):
    [out] = go(tmp_path, {'rz-diff': PyEngine(emit(stdout))}, ['rz-diff'])
    assert (out.run.status, out.run.error_code, out.run.returncode) == ('failed', 'PT-SECONDARY-INPUT', 0)
    assert out.match_set is None and out.run.match_set_id is None and out.run.output_sha256 is None


def test_timeout_after_a_complete_document_commits_nothing(tmp_path):
    [out] = go(tmp_path, {'rz-diff': PyEngine(emit_then(GOOD, 'time.sleep(60)'))}, ['rz-diff'],
               per_engine_timeout={'rz-diff': 3.0})
    assert (out.run.status, out.run.error_code) == ('timeout', 'PT-SECONDARY-TIMEOUT')
    assert out.match_set is None and out.run.match_set_id is None and out.run.output_sha256 is None


def test_cancel_after_a_complete_document_commits_nothing(tmp_path):
    cancel = threading.Event()
    threading.Timer(2.0, cancel.set).start()
    [out] = go(tmp_path, {'rz-diff': PyEngine(emit_then(GOOD, 'time.sleep(60)'))}, ['rz-diff'], cancel=cancel)
    assert (out.run.status, out.run.error_code) == ('cancelled', 'PT-SECONDARY-CANCEL')
    assert out.match_set is None and out.run.match_set_id is None and out.run.output_sha256 is None


def test_nonzero_exit_after_a_partial_document_commits_nothing(tmp_path):
    [out] = go(tmp_path, {'rz-diff': PyEngine(emit_then(GOOD[:30], 'sys.exit(3)'))}, ['rz-diff'])
    assert (out.run.status, out.run.error_code, out.run.returncode) == ('failed', 'PT-SECONDARY-RUN', 3)
    assert out.match_set is None and out.run.match_set_id is None and out.run.output_sha256 is None


@pytest.mark.parametrize('kind, body, error_code', [
    ('truncated', f"sys.stdout.buffer.write({GOOD[:30].encode('utf-8')!r})", 'PT-SECONDARY-INPUT'),
    ('exit-after-partial', f"sys.stdout.buffer.write({GOOD[:30].encode('utf-8')!r})\nsys.exit(4)",
     'PT-SECONDARY-RUN'),
    ('no-functions', "sys.stderr.write('ERROR: rz-diff: No functions found in file0.\\n')", 'PT-SECONDARY-INPUT'),
    ('singleton', f"sys.stdout.buffer.write({SHAPES['stock-elf-1-2']['stdout'].encode('utf-8')!r})",
     'PT-SECONDARY-ORIENTATION'),
], ids=['truncated', 'exit-after-partial', 'no-functions', 'singleton'])
def test_failed_cli_run_keeps_the_earlier_current_set(tmp_path, capsys, kind, body, error_code):
    """`secondary run` with a good result stored first: a later failing run stores nothing and changes nothing."""
    from fake_exe import make_fake_exe

    from patchtrace import cli
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.service import ProjectService

    def fake_rz(name: str, output: str) -> str:
        source = ("import sys\nif sys.argv[1:] == ['-v']:\n    print('rz-diff 0.9.1')\n    sys.exit(0)\n"
                  f"{output}\n")
        return str(make_fake_exe(tmp_path / name, 'rz-diff', source))

    def run(root, exe):
        code = cli.main(['secondary', 'run', str(root), '--json', '--rz-diff', exe, '--engine', 'rz-diff',
                         '--no-cache'])
        return code, json.loads(capsys.readouterr().out)

    def stored_sets(root) -> list[str]:
        service = ProjectService.open(root)
        try:
            return [e.body['file_sha256'] for e in EnrichmentStore(service.store).entries('secondary-matches')]
        finally:
            service.close()

    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    service.close()
    code, doc = run(root, fake_rz('good', f"sys.stdout.buffer.write({GOOD.encode('utf-8')!r})"))
    assert code == 0 and doc['result']['runs'][0]['status'] == 'ok'
    kept = stored_sets(root)
    assert len(kept) == 1
    code, doc = run(root, fake_rz(kind, body))
    [row] = doc['result']['runs']
    assert code != 0 and (row['status'], row['error_code']) == ('failed', error_code)
    assert stored_sets(root) == kept


def test_adapter_refuses_a_stopped_run_even_when_it_exited_zero(tmp_path):
    """SPEC-11 section 3: a timed-out or cancelled run is no evidence, whatever its exit code says."""
    from patchtrace.secondary.registry import EngineJob, RawResult

    adapter = RzDiffAdapter('definitely-not-installed-rz-diff')
    cap = Capability(engine='rz-diff', supported=True, version='0.9.1', path=sys.executable, supports_json=True)
    job = EngineJob(tmp_path / 'old', tmp_path / 'new', 'a' * 64, 'b' * 64, {}, tmp_path, threading.Event(), 60.0)
    for reason in ('timeout', 'cancelled', 'output-limit'):
        raw = RawResult(0, GOOD.encode('ascii'), '', None, reason, False)
        with pytest.raises(SecondaryError):
            adapter.parse(raw, cap, job)
