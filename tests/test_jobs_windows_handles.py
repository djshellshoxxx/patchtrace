"""Authored process-ownership controls; fake Win32 calls are not native qualification."""
from __future__ import annotations

import ctypes as c
import io
import os
import struct
import sys
import threading
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from patchtrace import jobs

PYTHON = str(Path(sys.executable).resolve())
POINTER_LIMIT = 1 << (8 * struct.calcsize('P'))
SOURCE = (1 << 40) + 72 if struct.calcsize('P') == 8 else 472
SINK = SOURCE + 4


def run(tmp_path, handles, *, env=None, cancel=None):
    return jobs.run_process([PYTHON, '-c', 'pass'], cwd=tmp_path, env=env or {},
                            cancel=cancel or threading.Event(), timeout_seconds=5,
                            windows_borrowed_handles=handles)


@pytest.mark.parametrize('handles', [
    [], True, {'': SOURCE}, {'lower': SOURCE}, {'1BAD': SOURCE}, {'A-B': SOURCE},
    {'A' * 65: SOURCE}, {'A\0B': SOURCE}, {'SOURCE': True}, {'SOURCE': '72'},
    {'SOURCE': 0}, {'SOURCE': -1}, {'SOURCE': POINTER_LIMIT},
    *({'SOURCE': POINTER_LIMIT - n} for n in (1, 2, 4, 5, 6)),
    {'SOURCE': SOURCE, 'SINK': SOURCE}, {f'HANDLE_{i}': 100 + i for i in range(17)},
], ids=lambda value: type(value).__name__)
def test_invalid_binding_never_reaches_a_launcher(tmp_path, monkeypatch, handles):
    def forbidden(*_args, **_kwargs):
        raise AssertionError('invalid input spawned a child')
    monkeypatch.setattr(jobs.subprocess, 'Popen', forbidden)
    monkeypatch.setattr(jobs, '_windows_process', forbidden)
    monkeypatch.setattr(jobs, 'os', SimpleNamespace(**{**vars(os), 'name': 'nt'}))
    with pytest.raises(ValueError, match='PT-BACKEND') as refused:
        run(tmp_path, handles)
    assert str(SOURCE) not in str(refused.value)


@pytest.mark.parametrize('name', ['PATCHTRACE_FDI_SOURCE', 'patchtrace_fdi_source'])
def test_environment_collision_refuses_before_spawn(tmp_path, monkeypatch, name):
    monkeypatch.setattr(jobs, 'os', SimpleNamespace(**{**vars(os), 'name': 'nt'}))
    with pytest.raises(ValueError, match='PT-BACKEND'):
        run(tmp_path, {'PATCHTRACE_FDI_SOURCE': SOURCE}, env={name: 'already present'})


def test_mapping_is_captured_and_pre_cancelled_request_never_duplicates(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, 'os', SimpleNamespace(**{**vars(os), 'name': 'nt'}))
    handles = {'PATCHTRACE_FDI_SOURCE': SOURCE}
    observed = []

    def stop(*_args, **kwargs):
        handles['PATCHTRACE_FDI_SOURCE'] = SINK
        observed.append(kwargs['windows_borrowed_handles'])
        raise OSError('authored stop before native launch')
    monkeypatch.setattr(jobs, '_windows_process', stop)
    with pytest.raises(OSError, match='authored stop'):
        run(tmp_path, handles)
    assert observed == [(('PATCHTRACE_FDI_SOURCE', SOURCE),)]
    cancelled = threading.Event()
    cancelled.set()
    assert run(tmp_path, handles, cancel=cancelled).reason == 'cancelled'
    assert len(observed) == 1


def test_binding_iteration_is_bounded_even_when_mapping_length_is_wrong(tmp_path, monkeypatch):
    class MoreThanReported(Mapping):
        def __len__(self):
            return 1

        def __getitem__(self, name):
            return 100 + int(name[1:])

        def __iter__(self):
            for i in range(18):
                assert i < 17, 'capture iterated past the handle ceiling'
                yield f'H{i}'
    monkeypatch.setattr(jobs, 'os', SimpleNamespace(**{**vars(os), 'name': 'nt'}))
    with pytest.raises(ValueError, match='too many'):
        run(tmp_path, MoreThanReported())


def test_exact_sixteen_binding_boundary_reaches_windows_launcher(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, 'os', SimpleNamespace(**{**vars(os), 'name': 'nt'}))

    def stop(*_args, **kwargs):
        assert len(kwargs['windows_borrowed_handles']) == 16
        raise OSError('authored complete boundary')
    monkeypatch.setattr(jobs, '_windows_process', stop)
    with pytest.raises(OSError, match='authored complete boundary'):
        run(tmp_path, {f'H{i}': 100 + i for i in range(16)})


@pytest.mark.skipif(os.name == 'nt', reason='explicit non-Windows refusal')
def test_other_platform_refuses_nonempty_bindings_but_empty_is_ordinary(tmp_path):
    with pytest.raises(ValueError, match='Windows'):
        run(tmp_path, {'PATCHTRACE_FDI_SOURCE': SOURCE})
    result = run(tmp_path, {})
    assert (result.returncode, result.reason) == (0, None)


class Function:
    def __init__(self, kernel, name):
        self.kernel, self.name = kernel, name

    def __call__(self, *args):
        kernel = self.kernel
        kernel.calls.append(self.name)
        kernel.count[self.name] += 1
        if self.name in {'CreatePipe', 'CreateFileW', 'GetHandleInformation', 'DuplicateHandle',
                         'InitializeProcThreadAttributeList', 'UpdateProcThreadAttribute', 'CreateProcessW',
                         'AssignProcessToJobObject', 'ResumeThread'}:
            assert jobs._WINDOWS_SPAWN_LOCK.locked()
        if kernel.fail in (self.name, f'{self.name}:{kernel.count[self.name]}'):
            kernel.error = 5
            if self.name == 'CreateFileW':
                return c.c_void_p(-1).value
            if self.name == 'ResumeThread':
                return 0xffffffff
            return 0
        method = getattr(kernel, 'call_' + self.name, None)
        return method(*args) if method else 1


class Kernel:
    """Small handle table with exact ownership, environment and startup observations."""
    def __init__(self, fail=None):
        self.fail, self.error = fail, 0
        self.calls, self.closed, self.created, self.duplicates, self.records = [], [], [], [], []
        self.count, self.functions, self.attributes = Counter(), {}, {}
        self.flags, self.next_handle, self.query_size = {SOURCE: 0, SINK: 1}, 100, 128

    def __getattr__(self, name):
        if name.startswith('call_'):
            raise AttributeError(name)
        return self.functions.setdefault(name, Function(self, name))

    @staticmethod
    def number(handle):
        return handle.value if hasattr(handle, 'value') else handle

    def new(self, inherit=False, high=False):
        self.next_handle += 1
        handle = self.next_handle + ((1 << 40) if high and struct.calcsize('P') == 8 else 0)
        self.created.append(handle)
        self.flags[handle] = int(inherit)
        return handle

    def call_CreatePipe(self, read, write, security, _size):
        read._obj.value, write._obj.value = self.new(True), self.new(True)
        return 1

    def call_SetHandleInformation(self, handle, mask, flags):
        handle = self.number(handle)
        assert handle not in (SOURCE, SINK), 'caller inheritance flags changed'
        self.flags[handle] = (self.flags[handle] & ~mask) | flags
        return 1

    def call_CreateFileW(self, *_args):
        return self.new(True)

    def call_GetCurrentProcess(self):
        return c.c_void_p(-1).value

    def call_GetHandleInformation(self, handle, out):
        handle = self.number(handle)
        if handle not in self.flags:
            self.error = 6
            return 0
        out._obj.value = self.flags[handle]
        return 1

    def call_DuplicateHandle(self, source_process, source, target_process, out, desired, inherit, options):
        assert source_process == target_process == c.c_void_p(-1).value
        assert (desired, inherit, options) == (0, True, 2)
        source = self.number(source)
        assert source in (SOURCE, SINK)
        out._obj.value = self.new(True, high=True)
        self.duplicates.append((source, out._obj.value))
        return 1

    def call_InitializeProcThreadAttributeList(self, buffer, count, flags, size):
        assert (count, flags) == (1, 0)
        if buffer is None:
            size._obj.value, self.error = self.query_size, 122
            return 0
        assert size._obj.value == 128
        return 1

    def call_UpdateProcThreadAttribute(self, buffer, flags, attribute, value, size, previous, returned):
        assert (flags, attribute, previous, returned) == (0, 0x20002, None, None)
        values = c.cast(value, c.POINTER(c.c_void_p))
        self.attributes[c.cast(buffer, c.c_void_p).value] = tuple(values[i] for i in range(size // c.sizeof(c.c_void_p)))
        return 1

    def call_CreateProcessW(self, _exe, _command, _ps, _ts, inherit, flags, env, _cwd, startup, info):
        value = startup._obj
        basic = getattr(value, 'startup', value)
        pointer = getattr(value, 'attributes', None)
        environment = dict(item.split('=', 1) for item in ''.join(env).rstrip('\0').split('\0') if item)
        self.records.append({'inherit': inherit, 'flags': flags, 'cb': basic.cb, 'size': c.sizeof(value),
                             'stdio': (basic.stdin, basic.stdout, basic.stderr),
                             'handles': self.attributes.get(pointer), 'env': environment})
        info._obj.process, info._obj.thread, info._obj.pid = self.new(), self.new(), 42
        return 1

    def call_CreateJobObjectW(self, *_args):
        return self.new()

    def call_CloseHandle(self, handle):
        handle = self.number(handle)
        assert handle in self.created and handle not in self.closed, 'foreign or double close'
        self.closed.append(handle)
        del self.flags[handle]
        return 1


def fake_native(monkeypatch, fail=None):
    kernel = Kernel(fail)
    monkeypatch.setattr(c, 'WinDLL', lambda *_args, **_kwargs: kernel, raising=False)
    monkeypatch.setattr(c, 'WinError', lambda value: OSError(value, 'authored Win32 failure'), raising=False)
    monkeypatch.setattr(c, 'get_last_error', lambda: kernel.error, raising=False)
    def open_osfhandle(handle, _flags):
        kernel.count['open_osfhandle'] += 1
        if fail == f'open_osfhandle:{kernel.count["open_osfhandle"]}':
            raise OSError('authored CRT ownership transfer failure')
        return handle
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(open_osfhandle=open_osfhandle))

    class Stream(io.BytesIO):
        def __init__(self, handle):
            super().__init__()
            self.handle = handle

        def close(self):
            if not self.closed:
                kernel.CloseHandle(self.handle)
            super().close()
    monkeypatch.setattr(jobs, 'os', SimpleNamespace(**{**vars(os), 'O_BINARY': 0,
                                                     'fdopen': lambda handle, *_args, **_kw: Stream(handle)}))
    return kernel


@pytest.mark.parametrize('separate', [False, True])
def test_ordinary_windows_launch_restricts_inheritance_to_exact_stdio(tmp_path, monkeypatch, separate):
    kernel = fake_native(monkeypatch)
    child = jobs._windows_process([PYTHON], tmp_path, {}, separate)
    record = kernel.records[0]
    assert record['handles'] == tuple(dict.fromkeys(record['stdio']))
    assert record['inherit'] is True and record['flags'] & 0x80000
    assert record['flags'] & 0x4 and record['cb'] == record['size']
    assert kernel.calls.index('AssignProcessToJobObject') < kernel.calls.index('ResumeThread')
    child.stdout.close()
    if child.stderr:
        child.stderr.close()
    child.close()
    assert set(kernel.closed) == set(kernel.created)


def test_borrowed_values_use_only_owned_duplicates_and_transient_child_environment(tmp_path, monkeypatch):
    kernel = fake_native(monkeypatch)
    env = {'KEPT': 'same'}
    bindings = (('PATCHTRACE_FDI_SOURCE', SOURCE), ('PATCHTRACE_FDI_SINK', SINK))
    child = jobs._windows_process([PYTHON], tmp_path, env, True, 123456,
                                  windows_borrowed_handles=bindings)
    record = kernel.records[0]
    duplicates = tuple(duplicate for _original, duplicate in kernel.duplicates)
    if struct.calcsize('P') == 8:
        assert min(duplicates) > 0xffffffff  # Authored pointer marshalling; not a native issued-handle claim.
    assert record['handles'] == (*dict.fromkeys(record['stdio']), *duplicates)
    assert all(original not in record['handles'] for original in (SOURCE, SINK))
    assert record['env'] == {**env, **{name: str(duplicate) for (name, _), duplicate in zip(bindings, duplicates, strict=True)}}
    assert env == {'KEPT': 'same'} and kernel.flags[SOURCE] == 0 and kernel.flags[SINK] == 1
    assert set(duplicates) <= set(kernel.closed)
    assert kernel.calls.index('DeleteProcThreadAttributeList') < kernel.calls.index('CloseHandle')
    child.stdout.close()
    child.stderr.close()
    child.close()
    assert set(kernel.closed) == set(kernel.created)


@pytest.mark.parametrize('failure', [
    'CreatePipe', 'SetHandleInformation', 'CreateFileW', 'GetHandleInformation', 'DuplicateHandle:2',
    'InitializeProcThreadAttributeList:1', 'InitializeProcThreadAttributeList:2',
    'UpdateProcThreadAttribute', 'CreateProcessW',
    'CreateJobObjectW', 'SetInformationJobObject', 'AssignProcessToJobObject', 'ResumeThread',
    'open_osfhandle:1', 'open_osfhandle:2',
])
def test_launch_failure_closes_only_owned_handles_and_keeps_originals(tmp_path, monkeypatch, failure):
    kernel = fake_native(monkeypatch, failure)
    with pytest.raises(OSError):
        jobs._windows_process([PYTHON], tmp_path, {}, True,
                              windows_borrowed_handles=(('SOURCE', SOURCE), ('SINK', SINK)))
    assert kernel.flags == {SOURCE: 0, SINK: 1}
    assert set(kernel.closed) == set(kernel.created)
    assert not jobs._WINDOWS_SPAWN_LOCK.locked()
    if failure == 'AssignProcessToJobObject':
        assert 'ResumeThread' not in kernel.calls
    if kernel.records:
        assert 'TerminateProcess' in kernel.calls
    if 'UpdateProcThreadAttribute' in kernel.calls:
        assert kernel.count['DeleteProcThreadAttributeList'] == 1


@pytest.mark.parametrize('size', [0, 65537, (1 << 63) - 1])
def test_attribute_size_is_bounded_before_allocation_or_process_creation(tmp_path, monkeypatch, size):
    kernel = fake_native(monkeypatch)
    kernel.query_size = size
    with pytest.raises(OSError, match='attribute size'):
        jobs._windows_process([PYTHON], tmp_path, {},
                              windows_borrowed_handles=(('SOURCE', SOURCE),))
    assert kernel.count['InitializeProcThreadAttributeList'] == 1
    assert not kernel.records and not kernel.count['DeleteProcThreadAttributeList']
    assert kernel.flags == {SOURCE: 0, SINK: 1}
