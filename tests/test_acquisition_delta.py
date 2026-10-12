"""SPEC-08 §4.6 delta reconstruction: explicit `unsupported` off Windows; real msdelta on Windows."""
from __future__ import annotations

import hashlib
import struct
import sys
import zlib

import pytest

from patchtrace.acquisition import delta
from patchtrace.acquisition.contracts import AcquisitionError

windows_only = pytest.mark.skipif(sys.platform != 'win32', reason='msdelta.dll is Windows-only')


def test_strip_header_verifies_crc():
    payload = b'PA30' + b'\x07' * 20
    framed = struct.pack('<I', zlib.crc32(payload)) + payload
    assert delta.strip_header(framed) == ('pa30', payload)
    assert delta.strip_header(payload) == ('pa30', payload)
    with pytest.raises(AcquisitionError, match='CRC32'):
        delta.strip_header(framed[:-1] + b'\x08')
    with pytest.raises(AcquisitionError):
        delta.strip_header(b'PA19xxxx')


def test_pa31_requires_user_selected_dll():
    payload = b'PA31' + b'\0' * 8
    with pytest.raises(AcquisitionError) as err:
        delta.apply_raw(b'', struct.pack('<I', zlib.crc32(payload)) + payload)
    assert err.value.code == 'PT-ACQ-UNSUPPORTED'


@pytest.mark.skipif(sys.platform == 'win32', reason='non-Windows behaviour')
def test_non_windows_reports_unsupported():
    assert delta.capability() == 'unsupported'
    with pytest.raises(AcquisitionError) as err:
        delta.reconstruct(b'base', [b'PA30rest'], '0' * 64)
    assert err.value.code == 'PT-ACQ-UNSUPPORTED'


@windows_only
def test_apply_synthetic_delta_created_with_createdeltab():
    import ctypes
    assert delta.capability() == 'available'
    DeltaInput, DeltaOutput = delta._structs()
    dll = delta._load(None)
    create = dll.CreateDeltaB
    create.argtypes = [ctypes.c_int64, ctypes.c_uint64, ctypes.c_uint64, DeltaInput, DeltaInput, DeltaInput,
                       DeltaInput, DeltaInput, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(DeltaOutput)]
    create.restype = ctypes.c_int
    keep: list = []
    base = bytes(range(256)) * 64
    target = base[:5000] + b'PatchTrace synthetic change' + base[5000:]
    out = DeltaOutput()
    empty = DeltaInput(None, 0, 0)
    ok = create(delta.DELTA_FILE_TYPE_RAW, 0, 0, delta._input(DeltaInput, base, keep),
                delta._input(DeltaInput, target, keep), empty, empty, empty, None, 0x8003, ctypes.byref(out))
    assert ok, ctypes.GetLastError()
    try:
        raw = ctypes.string_at(out.lpStart, out.uSize)
    finally:
        dll.DeltaFree.argtypes = [ctypes.c_void_p]
        dll.DeltaFree(out.lpStart)
    assert raw[:4] == b'PA30'
    expected = hashlib.sha256(target).hexdigest()
    assert delta.reconstruct(base, [raw], expected) == target
    framed = struct.pack('<I', zlib.crc32(raw)) + raw
    assert delta.reconstruct(base, [framed], expected) == target
    with pytest.raises(AcquisitionError):
        delta.reconstruct(base, [raw], '0' * 64)
    with pytest.raises(AcquisitionError):
        delta.reconstruct(base[1:], [raw], expected)
