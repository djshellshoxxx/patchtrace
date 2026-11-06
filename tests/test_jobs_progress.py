"""Real interpreter children verify observation without claiming Ghidriff compatibility."""
import os
import sys
import threading
import time
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from liveness_support import heartbeat_code, heartbeat_stopped, wait_for

from patchtrace import jobs
from patchtrace.jobs import ProcessResult, run_process


def execute(tmp_path, code, *, cancel=None, timeout=5, **kwargs):
    return run_process([str(Path(sys.executable).resolve()), '-c', code], cwd=tmp_path,
                       env=os.environ.copy(), cancel=cancel or threading.Event(),
                       timeout_seconds=timeout, **kwargs)


def test_live_progress_is_supervisor_owned_throttled_immutable_and_final(tmp_path):
    acknowledgement = tmp_path / 'observed'
    snapshots = []
    thread_ids = []
    supervisor_id = threading.get_ident()

    def observe(snapshot):
        snapshots.append(snapshot)
        thread_ids.append(threading.get_ident())
        if 'ready' in snapshot.log_tail and not acknowledgement.exists():
            acknowledgement.write_text('observed before exit')

    code = (
        'import pathlib, time\n'
        f'ack=pathlib.Path({str(acknowledgement)!r})\n'
        'print("ready", flush=True)\n'
        'deadline=time.monotonic()+4\n'
        'while not ack.exists() and time.monotonic()<deadline: time.sleep(.01)\n'
        'assert ack.exists(), "no live observer"\n'
        'time.sleep(1.15)\n'
        'print("finished", flush=True)\n'
    )
    result = execute(tmp_path, code, timeout=8, on_progress=observe)

    assert result.returncode == 0 and result.reason is None
    assert len(snapshots) >= 3
    assert set(thread_ids) == {supervisor_id}
    assert any('ready' in item.log_tail and 'finished' not in item.log_tail for item in snapshots[:-1])
    assert all(b.elapsed_seconds - a.elapsed_seconds >= 1
               for a, b in zip(snapshots[:-2], snapshots[1:-1], strict=True))
    assert snapshots[-1].log_tail == result.log_tail == 'ready\nfinished\n'
    assert snapshots[-1].stdout_total == result.stdout_total == len(result.log_bytes)
    assert snapshots[-1].elapsed_seconds == result.elapsed_seconds
    assert snapshots[-1].last_output_elapsed_seconds == result.last_output_elapsed_seconds
    assert all(item.last_output_elapsed_seconds is None or item.last_output_elapsed_seconds >= 0
               for item in snapshots)
    assert isinstance(snapshots[-1], jobs.ProcessProgress)
    with pytest.raises(FrozenInstanceError):
        snapshots[-1].log_tail = 'changed'


def test_quiet_child_has_periodic_progress_and_no_output_timestamp(tmp_path):
    start_quiet = tmp_path / 'start-quiet'
    snapshots = []

    def observe(snapshot):
        snapshots.append(snapshot)
        if not start_quiet.exists():
            start_quiet.write_text('supervisor clock started')

    # Reader startup may be delayed; begin the quiet interval only after a live supervisor observation.
    code = ('import pathlib,time\n'
            f'start_quiet=pathlib.Path({str(start_quiet)!r})\n'
            'deadline=time.monotonic()+4\n'
            'while not start_quiet.exists() and time.monotonic()<deadline: time.sleep(.01)\n'
            'assert start_quiet.exists(), "no live observer"\n'
            'time.sleep(1.15)\n')
    result = execute(tmp_path, code, on_progress=observe)
    assert result.returncode == 0 and result.reason is None
    assert result.elapsed_seconds >= 1.1
    assert len(snapshots) >= 2
    assert all(item.log_tail == item.stderr_tail == '' for item in snapshots)
    assert all(item.stdout_total == item.stderr_total == 0 for item in snapshots)
    assert all(item.last_output_elapsed_seconds is None for item in snapshots)
    assert snapshots[-1].elapsed_seconds == result.elapsed_seconds


@pytest.mark.parametrize('buffer_limit', [65536, 257])
def test_final_progress_preserves_stream_totals_and_bounded_utf8_tails(tmp_path, buffer_limit):
    # The 16 KiB tail starts inside a UTF-8 character; observation must use replacement decoding.
    output = b'A' * 20000 + b'\xe2\x82\xac' + b'O' * 16382
    error = b'E' * 40000 + b'final-error'
    snapshots = []
    code = ('import os\nos.write(1,b"A"*20000+b"\\xe2\\x82\\xac"+b"O"*16382)\n'
            'os.write(2,b"E"*40000+b"final-error")\n')
    result = execute(tmp_path, code, on_progress=snapshots.append, separate_streams=True,
                     log_limit=buffer_limit, stderr_limit=buffer_limit)
    final = snapshots[-1]
    bound = min(buffer_limit, 16 * 1024)
    assert result.returncode == 0
    assert final.log_tail == output[-bound:].decode('utf-8', errors='replace')
    assert final.stderr_tail == error[-bound:].decode('utf-8', errors='replace')
    assert result.log_bytes == output[-buffer_limit:]
    assert result.stderr_bytes == error[-buffer_limit:]
    assert final.stdout_total == result.stdout_total == len(output)
    assert final.stderr_total == result.stderr_total == len(error)
    assert final.last_output_elapsed_seconds is not None
    assert all(len(item.log_tail) <= bound and len(item.stderr_tail) <= bound for item in snapshots)


def test_continuous_output_and_observer_errors_do_not_renew_deadline(tmp_path):
    snapshots = []

    def observe(snapshot):
        snapshots.append(snapshot)
        raise RuntimeError('observer is unavailable')

    before = time.monotonic()
    result = execute(tmp_path,
        'import time\nwhile True:\n    print("activity", flush=True)\n    time.sleep(.03)\n',
        timeout=1.3, on_progress=observe)
    assert result.reason == 'timeout'
    assert 1.3 <= result.elapsed_seconds < 3
    assert time.monotonic() - before < 5
    assert result.stdout_total > 0
    assert 0 <= result.last_output_elapsed_seconds <= result.elapsed_seconds
    assert result.elapsed_seconds - result.last_output_elapsed_seconds < .3
    assert snapshots[-1].elapsed_seconds == result.elapsed_seconds


def test_final_observer_error_preserves_child_exit_code(tmp_path):
    calls = []

    def observe(snapshot):
        calls.append(snapshot)
        raise ValueError('bad observer')

    result = execute(tmp_path, 'import sys;print("exit evidence", flush=True);sys.exit(7)',
                     on_progress=observe)
    assert result.returncode == 7 and result.reason is None
    assert result.log_tail == 'exit evidence\n'
    assert calls[-1].log_tail == result.log_tail


def test_cancellation_from_observer_still_terminates_descendants(tmp_path):
    beat = tmp_path / 'descendant-beat'
    cancel = threading.Event()
    calls = []

    def observe(snapshot):
        calls.append(snapshot)
        if beat.exists() and beat.stat().st_size > 0:
            cancel.set()
        raise RuntimeError('observer failed after cancellation request')

    code = ('import subprocess,sys,time\n'
            f'subprocess.Popen([sys.executable,"-c",{heartbeat_code(beat)!r}])\n'
            'print("spawned",flush=True)\ntime.sleep(15)\n')
    result = execute(tmp_path, code, cancel=cancel, timeout=6, on_progress=observe)
    assert result.reason == 'cancelled'
    assert result.elapsed_seconds < 4
    assert calls[-1].elapsed_seconds == result.elapsed_seconds
    assert heartbeat_stopped(beat), 'the descendant never ran, or survived cancellation'


def test_output_limit_precedes_observer_and_keeps_final_tail_bounded(tmp_path):
    snapshots = []

    def observe(snapshot):
        snapshots.append(snapshot)
        raise RuntimeError('observer must not change output-limit termination')

    result = execute(tmp_path,
        'import os,time\nwhile True:\n    os.write(1,b"x"*8192)\n    time.sleep(.005)\n',
        on_progress=observe, max_output_bytes=32768, log_limit=257)
    assert result.reason == 'output-limit'
    assert result.stdout_total > 32768 and len(result.log_bytes) == 257
    assert snapshots[-1].stdout_total == result.stdout_total
    assert len(snapshots[-1].log_tail) == 257


def test_precancel_has_zero_timing_and_does_not_invoke_observer(tmp_path):
    marker = tmp_path / 'must-not-start'
    cancel = threading.Event()
    cancel.set()
    snapshots = []
    result = execute(tmp_path, f'import pathlib;pathlib.Path({str(marker)!r}).write_text("started")',
                     cancel=cancel, on_progress=snapshots.append)
    assert result.reason == 'cancelled' and not marker.exists()
    assert result.elapsed_seconds == 0 and result.last_output_elapsed_seconds is None
    assert snapshots == []


def test_existing_positional_result_and_no_observer_remain_compatible(tmp_path):
    old = ProcessResult(9, 'old', 'timeout', 'err', 123, b'old', b'err', 3, 3)
    assert old.elapsed_seconds == 0 and old.last_output_elapsed_seconds is None
    result = execute(tmp_path, 'import time;print("evidence",flush=True);time.sleep(.08)')
    assert result.returncode == 0 and result.reason is None
    assert result.log_bytes == b'evidence\n' and result.stdout_total == 9
    assert result.stderr_tail == '' and result.stderr_total == 0
    # The child may finish before reader startup returns; only timing order is contractual.
    assert 0 <= result.last_output_elapsed_seconds <= result.elapsed_seconds


def test_execution_duration_excludes_cleanup_waits(tmp_path, monkeypatch):
    original_join = threading.Thread.join

    def slow_join(thread, *args, **kwargs):
        if thread.name == 'patchtrace-log':
            time.sleep(.4)
        return original_join(thread, *args, **kwargs)

    monkeypatch.setattr(threading.Thread, 'join', slow_join)
    snapshots = []
    before = time.monotonic()
    result = execute(tmp_path, 'print("finished",flush=True)', on_progress=snapshots.append)
    assert result.returncode == 0
    assert time.monotonic() - before - result.elapsed_seconds >= .4
    assert snapshots[-1].elapsed_seconds == result.elapsed_seconds


def test_observer_interrupt_still_cleans_up_running_child(tmp_path):
    beat = tmp_path / 'interrupted-beat'

    def interrupt(_snapshot):
        if beat.exists() and beat.stat().st_size > 0:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        execute(tmp_path, heartbeat_code(beat), timeout=5, on_progress=interrupt)
    assert heartbeat_stopped(beat), 'the child never ran, or survived an observer interrupt'


def test_observer_runs_without_blocking_pipe_reader_lock(tmp_path):
    """A deliberately waiting probe exposes lock inversion if a reader cannot drain during observation."""
    release = tmp_path / 'release-output'
    drained = tmp_path / 'output-drained'
    observations = []

    def probe(_snapshot):
        if not release.exists():
            release.write_text('write now')
            observations.append(wait_for(drained.exists, timeout=2))

    code = ('import os,pathlib,time\n'
            f'release=pathlib.Path({str(release)!r})\n'
            'deadline=time.monotonic()+3\n'
            'while not release.exists() and time.monotonic()<deadline: time.sleep(.01)\n'
            'assert release.exists()\n'
            'os.write(1,b"p"*(1024*1024))\n'
            f'pathlib.Path({str(drained)!r}).write_text("all output written")\n')
    result = execute(tmp_path, code, timeout=6, on_progress=probe, log_limit=1024)
    assert result.returncode == 0 and result.reason is None
    assert observations == [True], 'the callback held the output lock while the child filled its pipe'
    assert result.stdout_total == 1024 * 1024
