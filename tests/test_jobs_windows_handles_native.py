"""Real authored Win32 handle/process controls. No package, decoder or target execution."""
from __future__ import annotations

import ctypes as c
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes as w
from pathlib import Path

import pytest

from patchtrace import jobs

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='BLOCKED: native Windows handle inheritance/Job qualification')
PYTHON = str(Path(sys.executable).resolve())


@pytest.fixture
def kernel():
    native = c.WinDLL('kernel32', use_last_error=True)
    for name, args, result in [
        ('CreateEventW', [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR], w.HANDLE),
        ('SetEvent', [w.HANDLE], w.BOOL),
        ('ResetEvent', [w.HANDLE], w.BOOL),
        ('WaitForSingleObject', [w.HANDLE, w.DWORD], w.DWORD),
        ('SetHandleInformation', [w.HANDLE, w.DWORD, w.DWORD], w.BOOL),
        ('GetHandleInformation', [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
        ('CloseHandle', [w.HANDLE], w.BOOL),
    ]:
        fn = getattr(native, name)
        fn.argtypes, fn.restype = args, result
    return native


@pytest.fixture
def events(kernel):
    owned = []

    def create(*, inherit=False):
        handle = kernel.CreateEventW(None, True, False, None)
        assert handle
        owned.append(handle)
        assert kernel.SetHandleInformation(handle, 1, int(inherit))
        return handle
    yield create
    for handle in owned:
        assert kernel.CloseHandle(handle)


def flags(kernel, handle):
    result = w.DWORD()
    assert kernel.GetHandleInformation(handle, c.byref(result))
    return result.value


def execute(tmp_path, code, bindings=None, *, extra=None, cancel=None, on_progress=None):
    return jobs.run_process([PYTHON, '-c', code], cwd=tmp_path,
                            env={**os.environ, **(extra or {})}, cancel=cancel or threading.Event(),
                            timeout_seconds=30, log_limit=4096, max_output_bytes=4096,
                            memory_limit_bytes=256 * 1024 * 1024,
                            windows_borrowed_handles=bindings, on_progress=on_progress)


EVENT_CODE = '''import ctypes as c, os
from ctypes import wintypes as w
k = c.WinDLL('kernel32', use_last_error=True)
k.SetEvent.argtypes, k.SetEvent.restype = [w.HANDLE], w.BOOL
k.WaitForSingleObject.argtypes, k.WaitForSingleObject.restype = [w.HANDLE, w.DWORD], w.DWORD
'''


@pytest.mark.parametrize('borrow', [False, True])
def test_child_cannot_signal_an_unapproved_inheritable_parent_event(tmp_path, kernel, events, borrow):
    unrelated, approved = events(inherit=True), events()
    code = EVENT_CODE + '''
k.SetEvent(int(os.environ['UNAPPROVED_HINT']))
if 'PATCHTRACE_FDI_EVENT' in os.environ:
    assert k.SetEvent(int(os.environ['PATCHTRACE_FDI_EVENT']))
print('done', flush=True)
'''
    result = execute(tmp_path, code, {'PATCHTRACE_FDI_EVENT': approved} if borrow else None,
                     extra={'UNAPPROVED_HINT': str(unrelated)})
    assert (result.returncode, result.reason, result.log_tail.strip()) == (0, None, 'done')
    # A child-local numeric handle could be reused; observe the original object, not only API success there.
    assert kernel.WaitForSingleObject(unrelated, 0) == 258
    assert kernel.WaitForSingleObject(approved, 0) == (0 if borrow else 258)
    assert flags(kernel, unrelated) == 1 and flags(kernel, approved) == 0


def test_child_reads_and_writes_only_duplicates_and_parent_files_remain_open(tmp_path, kernel):
    import msvcrt

    source, sink = tmp_path / 'source.txt', tmp_path / 'sink.txt'
    source.write_bytes(b'authored source bytes')
    source_fd = os.open(source, os.O_RDONLY | os.O_BINARY)
    sink_fd = os.open(sink, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_BINARY, 0o600)
    try:
        source_handle, sink_handle = msvcrt.get_osfhandle(source_fd), msvcrt.get_osfhandle(sink_fd)
        before = flags(kernel, source_handle), flags(kernel, sink_handle)
        code = '''import ctypes as c, os
from ctypes import wintypes as w
k = c.WinDLL('kernel32', use_last_error=True)
for name in ('ReadFile', 'WriteFile'):
    fn = getattr(k, name)
    fn.argtypes, fn.restype = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p], w.BOOL
buf, count = c.create_string_buffer(64), w.DWORD()
source, sink = int(os.environ['PATCHTRACE_FDI_SOURCE']), int(os.environ['PATCHTRACE_FDI_SINK'])
assert k.ReadFile(source, buf, 64, c.byref(count), None)
size = count.value
assert k.WriteFile(sink, buf, size, c.byref(count), None) and count.value == size
assert not k.WriteFile(source, buf, size, c.byref(count), None)
print('copied', flush=True)
'''
        result = execute(tmp_path, code, {'PATCHTRACE_FDI_SOURCE': source_handle, 'PATCHTRACE_FDI_SINK': sink_handle})
        assert (result.returncode, result.reason, result.log_tail.strip()) == (0, None, 'copied')
        assert (flags(kernel, source_handle), flags(kernel, sink_handle)) == before
        os.lseek(source_fd, 0, os.SEEK_SET)
        os.lseek(sink_fd, 0, os.SEEK_SET)
        assert os.read(source_fd, 64) == os.read(sink_fd, 64) == b'authored source bytes'
    finally:
        os.close(source_fd)
        os.close(sink_fd)


@pytest.mark.parametrize('failure', ['AssignProcessToJobObject', 'ResumeThread'])
def test_containment_failure_keeps_original_and_never_executes_child(tmp_path, monkeypatch, kernel, events, failure):
    original = events(inherit=True)
    marker = tmp_path / 'must-not-run.txt'

    def refuse(*_args):
        c.set_last_error(5)
        return 0xffffffff if failure == 'ResumeThread' else 0

    class RefusedKernel:
        def __getattr__(self, name):
            return refuse if name == failure else getattr(kernel, name)
    with monkeypatch.context() as patch:
        patch.setattr(c, 'WinDLL', lambda *_args, **_kwargs: RefusedKernel())
        with pytest.raises(OSError):
            execute(tmp_path, f'import pathlib;pathlib.Path({str(marker)!r}).write_text("ran")',
                    {'PATCHTRACE_FDI_EVENT': original})
    assert not marker.exists()
    assert flags(kernel, original) == 1 and kernel.SetEvent(original)


def test_cancellation_kills_worker_but_preserves_original_handle(tmp_path, kernel, events):
    original, cancel = events(inherit=True), threading.Event()
    code = EVENT_CODE + '''
assert k.SetEvent(int(os.environ['PATCHTRACE_FDI_EVENT']))
print('ready', flush=True)
import time
time.sleep(60)
'''

    def observed(progress):
        if 'ready' in progress.log_tail:
            cancel.set()
    result = execute(tmp_path, code, {'PATCHTRACE_FDI_EVENT': original}, cancel=cancel, on_progress=observed)
    assert result.reason == 'cancelled' and kernel.WaitForSingleObject(original, 0) == 0
    assert flags(kernel, original) == 1 and kernel.ResetEvent(original)


def test_concurrent_jobs_do_not_share_borrowed_objects_or_keep_other_stdout_alive(tmp_path, kernel, events):
    ready = [events(), events()]
    gates = [events(), events()]
    canaries = [events(inherit=True), events(inherit=True)]
    cancel = threading.Event()
    code = EVENT_CODE + '''
k.SetEvent(int(os.environ['FOREIGN_CANARY_HINT']))
assert k.SetEvent(int(os.environ['PATCHTRACE_FDI_READY']))
assert k.WaitForSingleObject(int(os.environ['PATCHTRACE_FDI_GATE']), 20000) == 0
print('independent', flush=True)
'''
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(execute, tmp_path, code,
                               {'PATCHTRACE_FDI_READY': ready[i], 'PATCHTRACE_FDI_GATE': gates[i],
                                'PATCHTRACE_FDI_CANARY': canaries[i]},
                               extra={'FOREIGN_CANARY_HINT': str(canaries[1 - i])}, cancel=cancel)
                   for i in range(2)]
        try:
            assert all(kernel.WaitForSingleObject(handle, 10000) == 0 for handle in ready)
            assert all(kernel.WaitForSingleObject(handle, 0) == 258 for handle in canaries)
            assert kernel.SetEvent(gates[0])
            first = futures[0].result(timeout=10)
            assert (first.returncode, first.reason, first.log_tail.strip()) == (0, None, 'independent')
            assert not futures[1].done()
            assert kernel.SetEvent(gates[1])
            second = futures[1].result(timeout=10)
            assert (second.returncode, second.reason, second.log_tail.strip()) == (0, None, 'independent')
        finally:
            cancel.set()
            for handle in gates:
                kernel.SetEvent(handle)
    assert all(flags(kernel, handle) == 1 for handle in canaries)
