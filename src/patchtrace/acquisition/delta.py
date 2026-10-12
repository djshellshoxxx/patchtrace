"""Optional Windows-only PA30/PA31 reconstruction via the system msdelta.dll (SPEC-08 §4.6).

No pure-Python applier is used: none found is both complete and licensed. Microsoft DLLs
are never bundled; PA30 uses the system msdelta.dll loaded by absolute System32 path (so a
DLL planted in the working directory cannot be picked up), PA31 a user-selected
UpdateCompression.dll. Off Windows the capability reports `unsupported` explicitly.
"""
from __future__ import annotations

import ctypes
import hashlib
import struct
import sys
import zlib
from collections.abc import Iterable
from pathlib import Path

from .contracts import AcquisitionError

DELTA_FILE_TYPE_RAW = 1


def capability() -> str:
    if sys.platform != 'win32':
        return 'unsupported'
    try:
        _load(None)
    except AcquisitionError:
        return 'unavailable'
    return 'available'


def strip_header(delta: bytes) -> tuple[str, bytes]:
    """Return (format, raw msdelta bytes). The 4-byte CRC32 prefix of update payloads is verified."""
    if len(delta) >= 8 and delta[4:8] in (b'PA30', b'PA31'):
        if zlib.crc32(delta[4:]) != struct.unpack_from('<I', delta, 0)[0]:
            raise AcquisitionError('PT-ACQ-VERIFY', 'delta CRC32 does not match')
        return delta[4:8].decode('ascii').lower(), delta[4:]
    if delta[:4] == b'PA30':
        return 'pa30', delta
    raise AcquisitionError('PT-ACQ-INPUT', 'not a PA30/PA31 delta')


def _structs():
    class DeltaInput(ctypes.Structure):
        _fields_ = [('lpStart', ctypes.c_void_p), ('uSize', ctypes.c_size_t), ('Editable', ctypes.c_int)]

    class DeltaOutput(ctypes.Structure):
        _fields_ = [('lpStart', ctypes.c_void_p), ('uSize', ctypes.c_size_t)]
    return DeltaInput, DeltaOutput


def _system_msdelta() -> Path:
    buffer = ctypes.create_unicode_buffer(260)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer, 260):
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'system directory unavailable')
    return Path(buffer.value) / 'msdelta.dll'


def _load(dll_path: Path | None):
    if sys.platform != 'win32':
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'delta reconstruction requires Windows msdelta.dll')
    path = _system_msdelta() if dll_path is None else Path(dll_path)
    if not path.is_absolute() or not path.is_file():
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', f'{path.name} not found')
    try:
        return ctypes.WinDLL(str(path))
    except OSError:
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', f'cannot load {path.name}') from None


def _input(cls, data: bytes, keep: list):
    buffer = ctypes.create_string_buffer(data, len(data)) if data else None
    keep.append(buffer)
    return cls(ctypes.cast(buffer, ctypes.c_void_p) if buffer is not None else None, len(data), 0)


def apply_raw(base: bytes, delta: bytes, *, update_compression: Path | None = None) -> bytes:
    """Apply one delta (PA30 via msdelta.dll; PA31 only with a user-selected UpdateCompression.dll)."""
    fmt, raw = strip_header(delta)
    if fmt == 'pa31' and update_compression is None:
        raise AcquisitionError('PT-ACQ-UNSUPPORTED', 'PA31 needs a user-selected UpdateCompression.dll')
    dll = _load(update_compression if fmt == 'pa31' else None)
    DeltaInput, DeltaOutput = _structs()
    apply = dll.ApplyDeltaB
    apply.argtypes = [ctypes.c_uint64, DeltaInput, DeltaInput, ctypes.POINTER(DeltaOutput)]
    apply.restype = ctypes.c_int
    free = dll.DeltaFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_int
    keep: list = []
    output = DeltaOutput()
    ok = apply(0, _input(DeltaInput, base, keep), _input(DeltaInput, raw, keep), ctypes.byref(output))
    try:
        if not ok:
            # A wrong base fails here: the delta embeds the target hash.
            raise AcquisitionError('PT-ACQ-VERIFY', f'ApplyDeltaB failed (error {ctypes.GetLastError()})')
        return ctypes.string_at(output.lpStart, output.uSize) if output.uSize else b''
    finally:
        if output.lpStart:
            free(output.lpStart)


def reconstruct(base: bytes, deltas: Iterable[bytes], expected_sha256: str, *,
                update_compression: Path | None = None) -> bytes:
    """Apply deltas in order (reverse `r` first, then forward `f`) and verify the target hash."""
    deltas = tuple(deltas)
    if not deltas:
        raise AcquisitionError('PT-ACQ-INPUT', 'no deltas supplied')
    data = base
    for delta in deltas:
        data = apply_raw(data, delta, update_compression=update_compression)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise AcquisitionError('PT-ACQ-VERIFY', 'reconstructed file does not match the expected SHA-256')
    return data
