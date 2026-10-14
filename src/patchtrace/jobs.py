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
# Windows: inheritable pipe/NUL handles exist from CreatePipe until the parent closes the child ends after
# CreateProcessW(bInheritHandles=True). Serialising that window stops a concurrent run_process child from
# inheriting another run's pipe write end (which would keep that reader from ever seeing EOF).
_WINDOWS_SPAWN_LOCK = threading.Lock()


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    log_tail: str
    reason: str | None = None
    # Populated only when run_process(separate_streams=True); log_tail is then stdout alone.
    stderr_tail: str = ''
    # Windows only: the Job Object's PeakProcessMemoryUsed (committed bytes); None elsewhere or if unavailable.
    peak_memory_bytes: int | None = None


def _windows_process(argv: Sequence[str], cwd: Path, env: Mapping[str, str], separate_streams: bool = False,
                     memory_limit_bytes: int | None = None):
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
        'QueryInformationJobObject': ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
    }
    for name, (args, result) in signatures.items():
        fn = getattr(kernel, name)
        fn.argtypes, fn.restype = args, result

    def check(value):
        if not value:
            raise c.WinError(c.get_last_error())
        return value

    read, write = w.HANDLE(), w.HANDLE()
    err_read, err_write = w.HANDLE(), w.HANDLE()
    security = Security(c.sizeof(Security), None, True)
    info = ProcessInfo()
    job = null = None
    stdout = stderr = None
    _WINDOWS_SPAWN_LOCK.acquire()
    try:
        check(kernel.CreatePipe(c.byref(read), c.byref(write), c.byref(security), 0))
        check(kernel.SetHandleInformation(read, 1, 0))
        if separate_streams:
            check(kernel.CreatePipe(c.byref(err_read), c.byref(err_write), c.byref(security), 0))
            check(kernel.SetHandleInformation(err_read, 1, 0))
        null = kernel.CreateFileW('NUL', 0x80000000, 3, c.byref(security), 3, 0, None)
        if null == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
        startup = Startup()
        startup.cb, startup.flags = c.sizeof(Startup), 0x100
        startup.stdin, startup.stdout = null, write
        startup.stderr = err_write if separate_streams else write
        command = c.create_unicode_buffer(subprocess.list2cmdline(list(argv)))
        environment = c.create_unicode_buffer('\0'.join(f'{k}={v}' for k, v in sorted(env.items())) + '\0\0')
        check(kernel.CreateProcessW(str(argv[0]), command, None, None, True,
                                    0x4 | 0x400 | 0x08000000, environment, str(cwd),
                                    c.byref(startup), c.byref(info)))
        job = check(kernel.CreateJobObjectW(None, None))
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if memory_limit_bytes is not None:
            # JOB_OBJECT_LIMIT_PROCESS_MEMORY: committed-memory cap per process, set before the child resumes.
            # Over-limit behaviour (allocation failure vs termination, exit code) is a measured unknown (U7).
            limits.basic.flags |= 0x100
            limits.process_memory = memory_limit_bytes
        check(kernel.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)))
        check(kernel.AssignProcessToJobObject(job, info.process))
        if kernel.ResumeThread(info.thread) == 0xffffffff:
            raise c.WinError(c.get_last_error())
        stdout = os.fdopen(msvcrt.open_osfhandle(read.value, os.O_RDONLY | os.O_BINARY), 'rb', buffering=0)
        read = w.HANDLE()  # Python now owns this handle.
        if separate_streams:
            stderr = os.fdopen(msvcrt.open_osfhandle(err_read.value, os.O_RDONLY | os.O_BINARY), 'rb', buffering=0)
            err_read = w.HANDLE()
    except BaseException:
        if info.process:
            kernel.TerminateProcess(info.process, 1)
            kernel.WaitForSingleObject(info.process, 5000)
            kernel.CloseHandle(info.process)
        if job:
            kernel.CloseHandle(job)
        if stdout:
            stdout.close()
        if stderr:
            stderr.close()
        raise
    finally:
        try:
            for handle in [write, read, err_write, err_read, null, info.thread]:
                if handle:
                    kernel.CloseHandle(handle)
        finally:
            _WINDOWS_SPAWN_LOCK.release()

    class WindowsChild:
        pid = info.pid

        def __init__(self):
            self.stdout = stdout
            self.stderr = stderr

        def poll(self):
            # Exit code 259 is legal: wait status distinguishes it from STILL_ACTIVE.
            if kernel.WaitForSingleObject(info.process, 0) == 258:
                return None
            code = w.DWORD()
            check(kernel.GetExitCodeProcess(info.process, c.byref(code)))
            return code.value

        def peak_memory(self):
            info_out = ExtendedLimits()
            if not kernel.QueryInformationJobObject(job, 9, c.byref(info_out), c.sizeof(info_out), None):
                return None
            return int(info_out.peak_process)

        def kill_tree(self):
            check(kernel.TerminateJobObject(job, 1))

        def close(self):
            kernel.CloseHandle(job)
            kernel.CloseHandle(info.process)

    return WindowsChild()


def _posix_preexec(memory_limit_bytes: int | None):
    if memory_limit_bytes is None or hasattr(__import__('resource'), 'prlimit'):
        return None
    import resource

    def apply():  # only on POSIX systems without prlimit (not Linux)
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
    return apply


def _posix_prlimit(child, memory_limit_bytes: int) -> None:
    import resource
    if not hasattr(resource, 'prlimit'):
        return  # applied by preexec_fn
    try:
        _, hard = resource.prlimit(child.pid, resource.RLIMIT_AS)
        # Never raise an inherited lower hard limit (needs privilege); lowering is always allowed.
        cap = memory_limit_bytes if hard == resource.RLIM_INFINITY else min(hard, memory_limit_bytes)
        resource.prlimit(child.pid, resource.RLIMIT_AS, (cap, cap))
    except ProcessLookupError:
        pass  # exited before the cap applied: nothing left to cap
    except OSError:
        try:  # fail closed: never run uncapped when a cap was requested
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        raise


def run_process(argv: Sequence[str], *, cwd: Path, env: Mapping[str, str],
                cancel: threading.Event, timeout_seconds: float,
                check_output: Callable[[], str | None] | None = None,
                log_limit: int = LOG_LIMIT, separate_streams: bool = False,
                stderr_limit: int = LOG_LIMIT, memory_limit_bytes: int | None = None) -> ProcessResult:
    """Run an argv with a bounded log and terminate descendants on every exit.

    By default stdout and stderr are merged into `log_tail`. With `separate_streams`,
    `log_tail` holds stdout only (bounded by `log_limit`) and `stderr_tail` holds stderr
    (bounded by `stderr_limit`), each drained by its own thread so neither can block the other.

    `memory_limit_bytes` (default None = unlimited, unchanged behaviour) caps the child: a Windows Job Object
    per-process memory limit applied before the suspended child resumes; on Linux RLIMIT_AS set with
    prlimit() right after spawn (no preexec_fn in a threaded GUI; a self-limiting child closes the startup
    window); on other POSIX systems RLIMIT_AS through preexec_fn. RLIMIT_AS counts virtual memory, so size
    the cap with headroom over the expected RSS.
    """
    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError('PT-BACKEND: configure an absolute executable path')
    if timeout_seconds <= 0 or log_limit < 1 or stderr_limit < 1:
        raise ValueError('PT-BACKEND: timeout and log limit must be positive')
    if memory_limit_bytes is not None and (isinstance(memory_limit_bytes, bool)
                                           or not isinstance(memory_limit_bytes, int) or memory_limit_bytes < 1):
        raise ValueError('PT-BACKEND: memory limit must be a positive integer')
    if cancel.is_set():
        return ProcessResult(-1, '', 'cancelled')
    if os.name == 'nt':
        child = _windows_process(argv, cwd, env, separate_streams, memory_limit_bytes)
    else:
        child = subprocess.Popen(list(argv), cwd=cwd, env=dict(env), shell=False,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE if separate_streams else subprocess.STDOUT,
                                 start_new_session=True, bufsize=0,
                                 preexec_fn=_posix_preexec(memory_limit_bytes))
        if memory_limit_bytes is not None:
            _posix_prlimit(child, memory_limit_bytes)
    tail, err_tail = bytearray(), bytearray()
    lock = threading.Lock()

    def collect(stream, buffer: bytearray, limit: int):
        try:
            while chunk := stream.read(8192):
                with lock:
                    buffer.extend(chunk)
                    if len(buffer) > limit:
                        del buffer[:-limit]
        except (OSError, ValueError):
            pass

    readers = [threading.Thread(target=collect, args=(child.stdout, tail, log_limit),
                                name='patchtrace-log', daemon=True)]
    if separate_streams:
        readers.append(threading.Thread(target=collect, args=(child.stderr, err_tail, stderr_limit),
                                        name='patchtrace-err', daemon=True))
    for reader in readers:
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
        for reader in readers:
            reader.join(timeout=5)
        with lock:
            log = bytes(tail).decode('utf-8', errors='replace')
            err = bytes(err_tail).decode('utf-8', errors='replace')
        peak = None
        if os.name == 'nt':
            try:
                peak = child.peak_memory()
            except OSError:
                peak = None
        return ProcessResult(returncode, log, reason, err, peak)
    finally:
        terminate()
        if os.name != 'nt':
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass  # Already reported above; do not mask the primary error.
        if os.name == 'nt':
            child.close()
        streams = [child.stdout, child.stderr][:len(readers)]
        for reader, stream in zip(readers, streams, strict=True):
            if not reader.is_alive():
                stream.close()
