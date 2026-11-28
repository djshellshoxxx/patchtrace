"""Portable ABI regression controls; the installed Windows SDK probe is a separate gate."""
from __future__ import annotations

import ctypes as c
import importlib
import json
import sys
from types import SimpleNamespace

import pytest

from patchtrace.acquisition.contracts import AcquisitionError


def abi():
    return importlib.import_module('patchtrace.acquisition.package_fdi_abi')


def test_fixed_windows_widths_and_natural_amd64_layout():
    module = abi()
    assert c.sizeof(module.LONG) == c.sizeof(module.BOOL) == c.sizeof(module.ULONG) == 4
    assert c.sizeof(module.USHORT) == 2 and c.sizeof(module.INT_PTR) == 8
    module.verify_amd64_layout()
    assert module.layout_snapshot()['FDINOTIFICATION.hf'] == 40
    assert module.layout_snapshot()['FDINOTIFICATION.fdie'] == 60
    assert module.layout_snapshot()['FDISPILLFILE.cbFile'] == 4


def test_callback_round_trip_keeps_pointer_sized_handles_and_signed_seek():
    module = abi()
    handle = 0x1_2345_6789
    name = c.create_string_buffer(b'opaque-token')
    seen = []

    @module.PFNOPEN
    def opened(pointer, flags, mode):
        seen.append((pointer, flags, mode))
        return handle

    @module.PFNSEEK
    def seek(value, distance, origin):
        seen.append((value, distance, origin))
        return -1

    assert opened(c.addressof(name), 0, 0) == handle
    assert seen[0] == (c.addressof(name), 0, 0)
    assert seek(handle, -1234567, 2) == -1
    assert seen[1] == (handle, -1234567, 2)


def test_read_callback_receives_raw_output_pointer_and_reports_exact_count():
    module = abi()
    buffer = c.create_string_buffer(4)
    seen = []

    @module.PFNREAD
    def read(handle, pointer, count):
        seen.append((handle, pointer, count))
        c.memmove(pointer, b'CAB!', count)
        return count

    assert read(0x1_0000_0001, c.addressof(buffer), 4) == 4
    assert buffer.raw == b'CAB!'
    assert seen == [(0x1_0000_0001, c.addressof(buffer), 4)]


def test_notification_round_trip_does_not_truncate_handles_or_read_name_pointers():
    module = abi()
    record = module.FDINOTIFICATION()
    record.cb, record.hf, record.psz1 = 17, 0x1_ffff_ffff, 1
    seen = []

    @module.PFNFDINOTIFY
    def notify(kind, pointer):
        value = pointer.contents
        seen.append((kind, value.cb, value.hf, value.psz1))
        return value.hf

    assert notify(2, c.byref(record)) == record.hf
    assert seen == [(2, 17, 0x1_ffff_ffff, 1)]


def test_valid_native_layout_receipt_is_exact_and_bounded():
    module = abi()
    raw = json.dumps(module.layout_snapshot(), sort_keys=True).encode()
    assert module.verify_native_layout(raw) == module.layout_snapshot()
    with pytest.raises(AcquisitionError):
        module.verify_native_layout(b' ' * 4097 + raw)


@pytest.mark.parametrize('damage', ['field-offset', 'missing', 'extra', 'duplicate', 'boolean', 'float',
                                    'string', 'list', 'invalid-utf8', 'nonfinite'])
def test_invalid_native_receipt_cannot_be_credited(damage):
    module = abi()
    value = module.layout_snapshot()
    if damage == 'field-offset':
        value['FDINOTIFICATION.hf'] = 36
    elif damage == 'missing':
        value.pop('FDINOTIFICATION.cb')
    elif damage == 'extra':
        value['claimed_success'] = 1
    elif damage in ('boolean', 'float', 'string'):
        value['ERF.erfOper'] = {'boolean': False, 'float': 0.0, 'string': '0'}[damage]
    raw = json.dumps(value).encode()
    if damage == 'duplicate':
        raw = b'{"pointer_bits":32,' + raw[1:]
    elif damage == 'list':
        raw = b'[]'
    elif damage == 'invalid-utf8':
        raw = b'\xff'
    elif damage == 'nonfinite':
        raw = b'{"pointer_bits":NaN}'
    with pytest.raises(AcquisitionError):
        module.verify_native_layout(raw)


def test_binding_checks_platform_before_touching_library(monkeypatch):
    module = abi()

    def refused():
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'authored unsupported platform')

    monkeypatch.setattr(module, 'require_supported_platform', refused)

    class NoTouch:
        def __getattr__(self, _name):
            pytest.fail('unsupported platform touched native library')

    with pytest.raises(AcquisitionError, match='unsupported'):
        module.bind_functions(NoTouch())


def test_complete_entry_points_receive_required_signatures(monkeypatch):
    module = abi()
    monkeypatch.setattr(module, 'require_supported_platform', lambda: 'windows-amd64')
    library = SimpleNamespace(**{name: SimpleNamespace() for name in
                                 ('FDICreate', 'FDIIsCabinet', 'FDICopy', 'FDIDestroy')})
    assert module.bind_functions(library) is library
    assert library.FDICreate.restype is c.c_void_p
    assert library.FDICopy.argtypes[1:3] == [c.c_void_p, c.c_void_p]
    assert library.FDIIsCabinet.argtypes[1] is module.INT_PTR
    assert library.FDIDestroy.restype is module.BOOL


@pytest.mark.skipif(sys.platform == 'win32', reason='explicit unsupported-host control')
def test_native_check_command_refuses_before_compiler_or_process_access(monkeypatch, capsys):
    module = importlib.import_module('tools.check_package_fdi_abi')
    monkeypatch.setattr(module.shutil, 'which', lambda *_: pytest.fail('compiler lookup before platform boundary'))
    monkeypatch.setattr(module, 'run_process', lambda *_a, **_k: pytest.fail('process before platform boundary'))
    assert module.main([]) == 3
    assert 'PT-ACQ-UNSUPPORTED' in capsys.readouterr().err


@pytest.mark.parametrize('failure', ['lost-prefix', 'compiler-stderr'])
def test_checker_rejects_incomplete_stdout_or_excess_compiler_diagnostics(monkeypatch, tmp_path, failure):
    checker = importlib.import_module('tools.check_package_fdi_abi')
    monkeypatch.setattr(checker, 'require_supported_platform', lambda: 'windows-amd64')
    raw = json.dumps(abi().layout_snapshot()).encode()
    calls = []

    def reported(_argv, **_options):
        calls.append(1)
        if len(calls) == 1:
            return SimpleNamespace(returncode=0, reason=None, stdout_total=0,
                                   stderr_total=65537 if failure == 'compiler-stderr' else 0, log_bytes=b'')
        return SimpleNamespace(returncode=0, reason=None, stderr_total=0,
                               stdout_total=len(raw) + 1, log_bytes=raw)

    monkeypatch.setattr(checker, 'run_process', reported)
    with pytest.raises(AcquisitionError):
        checker.check(str(tmp_path / 'authored-compiler.exe'))
    assert len(calls) == (1 if failure == 'compiler-stderr' else 2)
