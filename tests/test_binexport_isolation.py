"""SPEC-10b §6.1, §7, §10.2 isolation (C3-5): worker subprocess, parent mapping, jobs.run_process memory cap.

Runs on Linux and Windows. What a Windows child sees at the Job Object memory limit is a measured unknown (U7);
where platforms legitimately differ the assertion names both outcomes and the qa row records which one occurred.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from binexport_builder import SHA, raw, valid

from patchtrace.jobs import run_process
from patchtrace.secondary import binexport_run as run
from patchtrace.secondary.binexport_limits import MIB, BinExportLimits
from patchtrace.secondary.contracts import SecondaryError

PY = str(Path(sys.executable).resolve())


def accept(path, private, *, cancel=None, **kw):
    return run.accept_binexport(path, artifact_sha256=kw.pop('sha', SHA), role=kw.pop('role', 'older'),
                                private_dir=private, cancel=cancel or threading.Event(), **kw)


def failure(*a, **kw) -> SecondaryError:
    with pytest.raises(SecondaryError) as info:
        accept(*a, **kw)
    return info.value


@pytest.fixture
def private(tmp_path):
    d = tmp_path / 'private'
    d.mkdir()
    return d


@pytest.fixture
def export(tmp_path):
    p = tmp_path / 'user.BinExport'
    p.write_bytes(raw(valid()))
    return p


def fake_worker(monkeypatch, body: str):
    """Replace the worker with `python -c` running `body`; `req` holds the parsed request."""
    code = 'import json, sys, os, time\nreq = json.load(open(sys.argv[-1], encoding="utf-8"))\n' + body
    monkeypatch.setattr(run, 'worker_argv', lambda: [PY, '-c', code])


# --- real worker ---

def test_real_worker_accepts_and_leaves_only_readonly_snapshot(export, private):
    before = export.read_bytes()
    accepted = accept(export, private)
    assert accepted.summary.function_addresses == (0x140001000, 0x140001100)
    assert accepted.snapshot_path.read_bytes() == before and export.read_bytes() == before
    assert [p.name for p in accepted.snapshot_path.parent.iterdir()] == ['in.BinExport']
    assert accepted.snapshot_path.stat().st_mode & 0o222 == 0  # read-only (Windows: read-only attribute)
    assert accepted.snapshot_path.parent.parent == private


def test_real_worker_reports_input_reasons_and_cleans_up(tmp_path, private):
    m = valid()
    m.expression[0].parent_index = 1
    bad = tmp_path / 'cycle.BinExport'
    bad.write_bytes(raw(m))
    error = failure(bad, private)
    assert (error.code, error.reason) == ('PT-SECONDARY-INPUT', 'expression_cycle')
    assert list(private.iterdir()) == [] and bad.exists()
    error = failure(bad, private, sha='b' * 64)
    assert error.reason == 'expression_cycle'  # structure is checked before identity
    good = tmp_path / 'good.BinExport'
    good.write_bytes(raw(valid()))
    assert failure(good, private, sha='b' * 64).reason == 'executable_id_mismatch'
    assert failure(tmp_path / 'absent.BinExport', private).reason == 'unreadable'


def test_real_worker_unbound_override_and_layout(tmp_path, private):
    from patchtrace.secondary.binexport_identity import PeLayout
    m = valid()
    m.meta_information.executable_id = ''
    p = tmp_path / 'ida.BinExport'
    p.write_bytes(raw(m))
    assert failure(p, private).reason == 'executable_id_empty'
    s = accept(p, private, accept_unbound=True, pe_layout=PeLayout(0x140000000, 0x10000, 'IMAGE_FILE_MACHINE_ARM64'),
               role='newer').summary
    assert (s.id_binding, s.address_basis, s.role, s.warnings) == ('empty', 'va', 'newer', ('architecture_mismatch',))


def test_real_worker_out_of_memory_is_classified(tmp_path, private):
    """Linux measured: a 13 MiB / 2 M-record file peaks at ~137 MiB; a 100 MiB cap must give worker_oom, never
    an INPUT verdict. Windows (U7): the job limit counts commit; crash vs oom is recorded, not assumed."""
    p = tmp_path / 'big.BinExport'
    p.write_bytes(raw(valid()) + b'\x4a\x05hello' * 2_000_000)
    error = failure(p, private, limits=BinExportLimits(memory_bytes=100 * MIB))
    assert error.code == 'PT-SECONDARY-RUN'
    assert error.reason == 'worker_oom' or (os.name == 'nt' and error.reason == 'worker_crash'), error
    assert list(private.iterdir()) == []
    assert accept(p, private, limits=BinExportLimits(memory_bytes=512 * MIB)).summary.counts['string_table'] == \
        2_000_002


def test_parent_prechecks_before_spawn(tmp_path, private, export, monkeypatch):
    with pytest.raises(ValueError):
        accept(export, private, sha='A' * 64)
    with pytest.raises(ValueError):
        accept(export, private, role='both')
    cancel = threading.Event()
    cancel.set()
    assert failure(export, private, cancel=cancel).reason == 'cancelled'
    assert failure(export, private, limits=BinExportLimits(max_file_bytes=10)).reason == 'too_large'
    assert failure(export, private, limits=BinExportLimits(memory_bytes=7 * 1024 * MIB)).reason == 'memory_cap'
    from patchtrace.secondary.binexport_proto import ProtoUnavailable

    def missing():
        raise ProtoUnavailable('protobuf_missing')
    monkeypatch.setattr(run, 'load_binexport2_class', missing)
    error = failure(export, private)
    assert (error.code, error.reason) == ('PT-SECONDARY-UNSUPPORTED', 'protobuf_missing')
    assert list(private.iterdir()) == []


# --- fake workers: the parent never trusts the child ---

@pytest.mark.parametrize('body, reason', [
    ('open(req["result"], "w").write("not json"); sys.exit(0)', 'worker_bad_result'),
    ('open(req["result"], "w").write(\'{"kind": NaN}\'); sys.exit(0)', 'worker_bad_result'),
    ('open(req["result"], "w").write(\'{"kind": "ok", "kind": "error"}\'); sys.exit(0)', 'worker_bad_result'),
    ('open(req["result"], "w").write(json.dumps({"kind": "error", "error": {"code": "PT-OTHER-X", '
     '"message": "m", "reason": "r"}})); sys.exit(20)', 'worker_bad_result'),
    ('open(req["result"], "w").write(json.dumps({"kind": "error", "error": {"code": "PT-SECONDARY-BOGUS", '
     '"message": "m", "reason": "r"}})); sys.exit(20)', 'worker_bad_result'),
    ('open(req["result"], "w").write("x" * 200); sys.exit(0)', 'worker_bad_result'),
    ('sys.exit(0)', 'worker_crash'),
    ('sys.exit(21)', 'worker_crash'),
    ('sys.exit(22)', 'worker_oom'),
    ('sys.stderr.write("memory allocation of 656 bytes failed\\n"); os.abort()', 'worker_oom'),
    ('os.abort()', 'worker_crash'),
])
def test_fake_worker_results_mapped(monkeypatch, export, private, body, reason):
    fake_worker(monkeypatch, body)
    error = failure(export, private, limits=BinExportLimits(max_summary_bytes=150))
    assert (error.code, error.reason) == ('PT-SECONDARY-RUN', reason)
    assert list(private.iterdir()) == []


def test_fake_worker_error_document_passes_through(monkeypatch, export, private):
    fake_worker(monkeypatch, 'open(req["result"], "w").write(json.dumps({"kind": "error", "error": {"code": '
                             '"PT-SECONDARY-INPUT", "message": "bad", "reason": "parse_failed"}})); sys.exit(20)')
    error = failure(export, private)
    assert (error.code, error.reason, error.message) == ('PT-SECONDARY-INPUT', 'parse_failed', 'bad')


def test_lying_worker_is_caught_by_parent_rehash(monkeypatch, export, private, tmp_path):
    """Worker claims success with a summary that does not describe the snapshot it left behind."""
    from patchtrace.secondary.binexport_pipeline import inspect_binexport
    from patchtrace.secondary.binexport_limits import Budget
    summary = inspect_binexport(export, tmp_path / 'ref', artifact_sha256=SHA, role='older',
                                limits=BinExportLimits(), budget=Budget())
    doc = {'kind': 'ok', 'summary': json.loads(summary.model_dump_json())}
    for tamper in ('snapshot', 'role'):
        body = (f'doc = {json.dumps(doc)!r}\n'
                'open(req["snapshot"], "wb").write(b"other bytes" if TAMPER == "snapshot" else open(req["src"], "rb").read())\n'
                'd = json.loads(doc)\n'
                'd["summary"]["role"] = "newer" if TAMPER == "role" else d["summary"]["role"]\n'
                'open(req["result"], "w").write(json.dumps(d)); sys.exit(0)').replace('TAMPER', repr(tamper))
        fake_worker(monkeypatch, body)
        assert failure(export, private).reason == 'worker_bad_result', tamper
        assert list(private.iterdir()) == []


def test_sleeping_worker_times_out_without_leftovers(monkeypatch, export, private):
    monkeypatch.setattr(run, 'TIMEOUT_GRACE', 0.5)
    fake_worker(monkeypatch, 'time.sleep(60)')
    started = time.monotonic()
    error = failure(export, private, limits=BinExportLimits(wall_seconds=1))
    assert (error.code, error.reason) == ('PT-SECONDARY-RUN', 'worker_timeout')
    assert time.monotonic() - started < 15 and list(private.iterdir()) == []


def test_cancel_mid_run_kills_worker_and_removes_private_dir(monkeypatch, export, private, tmp_path):
    marker = tmp_path / 'still-running'
    fake_worker(monkeypatch, f'time.sleep(1.5); open({str(marker)!r}, "w").write("x"); time.sleep(60)')
    cancel = threading.Event()
    threading.Timer(0.3, cancel.set).start()
    error = failure(export, private, cancel=cancel)
    assert (error.code, error.reason) == ('PT-SECONDARY-CANCEL', 'cancelled')
    time.sleep(2)
    assert not marker.exists() and list(private.iterdir()) == []


def test_worker_env_and_argv(monkeypatch):
    env = run.worker_env({'PATH': '/bin', 'GITHUB_TOKEN': 'x', 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION': 'python',
                          'TEMPORARILY_DISABLE_PROTOBUF_VERSION_CHECK': '1', 'SystemRoot': 'C:\\Windows'})
    assert env['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] == 'upb' and 'GITHUB_TOKEN' not in env
    assert 'TEMPORARILY_DISABLE_PROTOBUF_VERSION_CHECK' not in env and env['SystemRoot'] == 'C:\\Windows'
    assert Path(env['PYTHONPATH'], 'patchtrace', 'secondary', 'binexport_run.py').is_file()
    assert run.worker_argv()[1:] == ['-P', '-m', 'patchtrace']
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    assert run.worker_argv() == [sys.executable] and 'PYTHONPATH' not in run.worker_env({})


def test_pure_python_runtime_is_refused_in_a_fresh_interpreter():
    """S2 tripwire: the env var cannot make the fallback safe; only the Type() assertion refuses it."""
    code = ('from patchtrace.secondary.binexport_proto import load_binexport2_class, ProtoUnavailable\n'
            'try:\n    load_binexport2_class(); print("loaded")\n'
            'except ProtoUnavailable as e:\n    print(e.reason)\n')
    env = dict(os.environ, PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION='python',
               PYTHONPATH=str(Path(run.__file__).resolve().parents[2]))
    out = subprocess.run([PY, '-c', code], capture_output=True, text=True, env=env, timeout=60)
    assert out.stdout.strip() == 'protobuf_not_upb', out.stderr[-500:]


def test_worker_subcommand_usage_errors(tmp_path):
    from patchtrace.secondary import binexport_worker
    assert binexport_worker.main([]) == 2
    bad = tmp_path / 'req.json'
    bad.write_text('{"contract": "binexport-worker-request/1", "x": 1}', encoding='utf-8')
    assert binexport_worker.main(['--request', str(bad)]) == 2
    bad.write_text('{"a": 1, "a": 2}', encoding='utf-8')
    assert binexport_worker.main(['--request', str(bad)]) == 2


# --- jobs.run_process memory cap and concurrency (additive; default unchanged) ---

ALLOC = ('import sys\nheld = []\ntry:\n    for _ in range(int(sys.argv[1])):\n        held.append(bytearray(64 << 20))\n'
         '    print("allocated", flush=True)\nexcept MemoryError:\n    print("MemoryError", flush=True)\n    sys.exit(22)\n')


def _alloc(tmp_path, steps, cap):
    return run_process([PY, '-c', ALLOC, str(steps)], cwd=tmp_path, env=dict(os.environ), cancel=threading.Event(),
                       timeout_seconds=60, memory_limit_bytes=cap, separate_streams=True)


def test_run_process_memory_cap_is_enforced(tmp_path):
    uncapped = _alloc(tmp_path, 6, None)  # 384 MiB
    assert uncapped.returncode == 0 and 'allocated' in uncapped.log_tail
    capped = _alloc(tmp_path, 6, 256 * MIB)
    assert 'allocated' not in capped.log_tail and capped.returncode != 0, capped
    if os.name == 'nt':  # U7: the job reports the peak commit; record it, do not assume the failure mode
        assert capped.peak_memory_bytes is not None and capped.peak_memory_bytes <= 256 * MIB
    else:
        assert capped.returncode == 22 and capped.peak_memory_bytes is None


def test_run_process_memory_cap_validation(tmp_path):
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            run_process([PY, '-c', 'pass'], cwd=tmp_path, env=dict(os.environ), cancel=threading.Event(),
                        timeout_seconds=5, memory_limit_bytes=bad)


def test_concurrent_run_process_calls_do_not_cross_pipes_or_leak_threads(tmp_path):
    """Windows regression (inheritable pipe ends during concurrent CreateProcessW): every reader must see EOF
    when its own child exits. Meaningful on POSIX too: output isolation, timing and no leaked reader threads."""
    baseline = threading.active_count()
    results: dict[int, object] = {}

    def one(i):
        code = f'import sys, time\ntime.sleep({0.05 * (i % 4)})\nprint("out{i}")\nprint("err{i}", file=sys.stderr)'
        results[i] = run_process([PY, '-c', code], cwd=tmp_path, env=dict(os.environ), cancel=threading.Event(),
                                 timeout_seconds=30, separate_streams=True)

    long_child = threading.Thread(target=lambda: results.setdefault(-1, run_process(
        [PY, '-c', 'import time; time.sleep(8)'], cwd=tmp_path, env=dict(os.environ), cancel=threading.Event(),
        timeout_seconds=30, separate_streams=True)))
    long_child.start()
    started = time.monotonic()
    threads = [threading.Thread(target=one, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    short_elapsed = time.monotonic() - started
    long_child.join(30)
    assert short_elapsed < 7, f'short runs waited for the long child ({short_elapsed:.1f}s)'
    for i in range(8):
        r = results[i]
        assert r.returncode == 0 and r.log_tail.strip() == f'out{i}' and r.stderr_tail.strip() == f'err{i}'
    deadline = time.monotonic() + 5
    while threading.active_count() > baseline and time.monotonic() < deadline:
        time.sleep(0.05)
    assert threading.active_count() <= baseline
