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

from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.registry import (
    BinDiffAdapter,
    GhidriffBaselineAdapter,
    RzDiffAdapter,
    build_registry,
)
from patchtrace.secondary.scheduler import ProjectRef, run_engines

OLD_BYTES, NEW_BYTES = b'old-artifact', b'new-artifact'
GOOD = json.dumps([{'similarity': 0.5, 'type': 'PARTIAL', 'original': {'addr': 1, 'name': 'f', 'size': 1},
                    'modified': {'addr': 2, 'name': 'g', 'size': 1}}])


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
    size = beat.stat().st_size
    time.sleep(0.5)  # run_process returns only after the whole tree (Job Object / killpg) is terminated
    assert beat.stat().st_size == size
    if os.name != 'nt':
        time.sleep(0.3)
        assert not _alive(int(pidfile.read_text()))


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
