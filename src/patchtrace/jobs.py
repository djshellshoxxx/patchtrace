"""Bounded child-process execution. Targets are never executed by this module."""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

LOG_LIMIT = 2 * 1024 * 1024


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    log_tail: str
    reason: str | None = None


def _windows_process(argv: Sequence[str], cwd: Path, env: Mapping[str, str]):
    """Start suspended, contain the child before it can run, then resume it.

    Popen discards the primary thread handle, so use CreateProcessW directly.
    A containment failure terminates the suspended child and fails closed.
    """
    import ctypes as c
    import msvcrt
    from ctypes import wintypes as w

    class Security(c.Structure):
        _fields_ = [('length', w.DWORD), ('descriptor', c.c_void_p), ('inherit', w.BOOL)]

    class Startup(c.Structure):
        _fields_ = [('cb', w.DWORD), ('reserved', w.LPWSTR), ('desktop', w.LPWSTR),
                    ('title', w.LPWSTR), ('x', w.DWORD), ('y', w.DWORD),
                    ('xsize', w.DWORD), ('ysize', w.DWORD), ('xcount', w.DWORD),
                    ('ycount', w.DWORD), ('fill', w.DWORD), ('flags', w.DWORD),
                    ('show', w.WORD), ('reserved_size', w.WORD), ('reserved2', c.c_void_p),
                    ('stdin', w.HANDLE), ('stdout', w.HANDLE), ('stderr', w.HANDLE)]

    class ProcessInfo(c.Structure):
        _fields_ = [('process', w.HANDLE), ('thread', w.HANDLE), ('pid', w.DWORD), ('tid', w.DWORD)]

    class BasicLimits(c.Structure):
        _fields_ = [('process_time', c.c_longlong), ('job_time', c.c_longlong),
                    ('flags', w.DWORD), ('min_ws', c.c_size_t), ('max_ws', c.c_size_t),
                    ('active', w.DWORD), ('affinity', c.c_size_t),
                    ('priority', w.DWORD), ('scheduling', w.DWORD)]

    class IoCounters(c.Structure):
        _fields_ = [(name, c.c_ulonglong) for name in
                    ['read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes']]

    class ExtendedLimits(c.Structure):
        _fields_ = [('basic', BasicLimits), ('io', IoCounters), ('process_memory', c.c_size_t),
                    ('job_memory', c.c_size_t), ('peak_process', c.c_size_t), ('peak_job', c.c_size_t)]

    kernel = c.WinDLL('kernel32', use_last_error=True)
    signatures = {
        'CreatePipe': ([c.POINTER(w.HANDLE), c.POINTER(w.HANDLE), c.POINTER(Security), w.DWORD], w.BOOL),
        'SetHandleInformation': ([w.HANDLE, w.DWORD, w.DWORD], w.BOOL),
        'CreateFileW': ([w.LPCWSTR, w.DWORD, w.DWORD, c.POINTER(Security), w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
        'CreateProcessW': ([w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL,
                            w.DWORD, c.c_void_p, w.LPCWSTR, c.POINTER(Startup), c.POINTER(ProcessInfo)], w.BOOL),
        'CreateJobObjectW': ([c.c_void_p, w.LPCWSTR], w.HANDLE),
        'SetInformationJobObject': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
        'AssignProcessToJobObject': ([w.HANDLE, w.HANDLE], w.BOOL),
        'ResumeThread': ([w.HANDLE], w.DWORD),
        'GetExitCodeProcess': ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
        'WaitForSingleObject': ([w.HANDLE, w.DWORD], w.DWORD),
        'TerminateProcess': ([w.HANDLE, w.UINT], w.BOOL),
        'TerminateJobObject': ([w.HANDLE, w.UINT], w.BOOL),
        'CloseHandle': ([w.HANDLE], w.BOOL),
    }
    for name, (args, result) in signatures.items():
        fn = getattr(kernel, name)
        fn.argtypes, fn.restype = args, result

    def check(value):
        if not value:
            raise c.WinError(c.get_last_error())
        return value

    read, write = w.HANDLE(), w.HANDLE()
    security = Security(c.sizeof(Security), None, True)
    info = ProcessInfo()
    job = null = None
    stdout = None
    try:
        check(kernel.CreatePipe(c.byref(read), c.byref(write), c.byref(security), 0))
        check(kernel.SetHandleInformation(read, 1, 0))
        null = kernel.CreateFileW('NUL', 0x80000000, 3, c.byref(security), 3, 0, None)
        if null == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
        startup = Startup()
        startup.cb, startup.flags = c.sizeof(Startup), 0x100
        startup.stdin, startup.stdout, startup.stderr = null, write, write
        command = c.create_unicode_buffer(subprocess.list2cmdline(list(argv)))
        environment = c.create_unicode_buffer('\0'.join(f'{k}={v}' for k, v in sorted(env.items())) + '\0\0')
        check(kernel.CreateProcessW(str(argv[0]), command, None, None, True,
                                    0x4 | 0x400 | 0x08000000, environment, str(cwd),
                                    c.byref(startup), c.byref(info)))
        job = check(kernel.CreateJobObjectW(None, None))
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        check(kernel.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)))
        check(kernel.AssignProcessToJobObject(job, info.process))
        if kernel.ResumeThread(info.thread) == 0xffffffff:
            raise c.WinError(c.get_last_error())
        stdout = os.fdopen(msvcrt.open_osfhandle(read.value, os.O_RDONLY | os.O_BINARY), 'rb', buffering=0)
        read = w.HANDLE()  # Python now owns this handle.
    except BaseException:
        if info.process:
            kernel.TerminateProcess(info.process, 1)
            kernel.WaitForSingleObject(info.process, 5000)
            kernel.CloseHandle(info.process)
        if job:
            kernel.CloseHandle(job)
        if stdout:
            stdout.close()
        raise
    finally:
        for handle in [write, read, null, info.thread]:
            if handle:
                kernel.CloseHandle(handle)

    class WindowsChild:
        pid = info.pid

        def __init__(self):
            self.stdout = stdout

        def poll(self):
            # Exit code 259 is legal: wait status distinguishes it from STILL_ACTIVE.
            if kernel.WaitForSingleObject(info.process, 0) == 258:
                return None
            code = w.DWORD()
            check(kernel.GetExitCodeProcess(info.process, c.byref(code)))
            return code.value

        def kill_tree(self):
            check(kernel.TerminateJobObject(job, 1))

        def close(self):
            kernel.CloseHandle(job)
            kernel.CloseHandle(info.process)

    return WindowsChild()


def run_process(argv: Sequence[str], *, cwd: Path, env: Mapping[str, str],
                cancel: threading.Event, timeout_seconds: float,
                check_output: Callable[[], str | None] | None = None,
                log_limit: int = LOG_LIMIT) -> ProcessResult:
    """Run an argv with a bounded merged log and terminate descendants on every exit."""
    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError('PT-BACKEND: configure an absolute executable path')
    if timeout_seconds <= 0 or log_limit < 1:
        raise ValueError('PT-BACKEND: timeout and log limit must be positive')
    if cancel.is_set():
        return ProcessResult(-1, '', 'cancelled')
    if os.name == 'nt':
        child = _windows_process(argv, cwd, env)
    else:
        child = subprocess.Popen(list(argv), cwd=cwd, env=dict(env), shell=False,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, start_new_session=True, bufsize=0)
    tail = bytearray()
    lock = threading.Lock()

    def collect():
        try:
            while chunk := child.stdout.read(8192):
                with lock:
                    tail.extend(chunk)
                    if len(tail) > log_limit:
                        del tail[:-log_limit]
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=collect, name='patchtrace-log', daemon=True)
    reader.start()
    started, reason = time.monotonic(), None

    def terminate():
        if os.name == 'nt':
            child.kill_tree()
        else:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    try:
        while child.poll() is None:
            if cancel.is_set():
                reason = 'cancelled'
            elif time.monotonic() - started >= timeout_seconds:
                reason = 'timeout'
            elif check_output:
                reason = check_output()
            if reason:
                terminate()
                break
            cancel.wait(0.05)
        # A successful parent may leave a descendant holding the output pipe.
        terminate()
        if os.name != 'nt':
            try:
                returncode = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise RuntimeError('PT-BACKEND: terminated child did not exit') from None
        else:
            deadline = time.monotonic() + 5
            while child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            returncode = child.poll()
            if returncode is None:
                raise RuntimeError('PT-BACKEND: contained child did not exit')
        reader.join(timeout=5)
        with lock:
            log = bytes(tail).decode('utf-8', errors='replace')
        return ProcessResult(returncode, log, reason)
    finally:
        terminate()
        if os.name != 'nt':
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass  # Already reported above; do not mask the primary error.
        if os.name == 'nt':
            child.close()
        if not reader.is_alive():
            child.stdout.close()
