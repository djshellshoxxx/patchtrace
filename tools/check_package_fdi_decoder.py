"""Check the Windows FDI ctypes binding with one authored, in-memory MSZIP cabinet."""
from __future__ import annotations

import ctypes as ct
import hashlib
import json
import os
import struct
import sys
import tempfile
import zlib
from pathlib import Path
from threading import Event

from patchtrace.acquisition import package_fdi_abi as abi
from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.acquisition.package_platform import require_supported_platform
from patchtrace.jobs import run_process

_TEXT = b'PatchTrace cabinet integration check.\r\n'
_MEMBER = b'readme.txt'
_CAB = b'fixture.cab'
_OUTPUT = 9000


def cabinet_fixture() -> bytes:
    compressor = zlib.compressobj(wbits=-15)
    compressed = b'CK' + compressor.compress(_TEXT) + compressor.flush()
    data = struct.pack('<IHH', 0, len(compressed), len(_TEXT)) + compressed
    member = struct.pack('<IIHHHH', len(_TEXT), 0, 0, 0x21, 0, 0x20) + _MEMBER + b'\0'
    files_at = 36 + 8
    data_at = files_at + len(member)
    header = struct.pack('<4sIIIIIBBHHHHH', b'MSCF', 0, data_at + len(data), 0, files_at, 0,
                         3, 1, 1, 1, 0, 23, 0)
    return header + struct.pack('<IHH', data_at, 1, 1) + member + data


def _system_fdi():
    require_supported_platform()
    from ctypes import wintypes as wt

    kernel = ct.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [wt.LPWSTR, wt.UINT]
    kernel.GetSystemDirectoryW.restype = wt.UINT
    directory = ct.create_unicode_buffer(32768)
    if not 0 < kernel.GetSystemDirectoryW(directory, len(directory)) < len(directory):
        raise ValueError('Windows system directory unavailable')
    expected = Path(directory.value) / 'cabinet.dll'
    dll = ct.CDLL(str(expected), winmode=0x0800)  # LOAD_LIBRARY_SEARCH_SYSTEM32
    kernel.GetModuleFileNameW.argtypes = [wt.HMODULE, wt.LPWSTR, wt.DWORD]
    kernel.GetModuleFileNameW.restype = wt.DWORD
    actual = ct.create_unicode_buffer(32768)
    if (not 0 < kernel.GetModuleFileNameW(dll._handle, actual, len(actual)) < len(actual)
            or Path(actual.value) != expected):
        raise ValueError('loaded module differs from the selected Windows cabinet library')
    return abi.bind_functions(dll)


def _matches(pointer, expected: bytes) -> bool:
    if not pointer:
        return False
    return all(ct.c_ubyte.from_address(pointer + i).value == byte for i, byte in enumerate(expected + b'\0'))


class _FixtureIO:
    def __init__(self, data: bytes):
        self.data = data
        self.cursors = {}
        self.allocations = {}
        self.output = bytearray()
        self.closed_output = False
        self.output_open = False
        self.failed = False
        self.calls = 0
        self.next_handle = 1

    def callback(self, signature, method, failure):
        def guarded(*args):
            try:
                self.calls += 1
                if self.calls > 4096:
                    raise ValueError('callback limit exceeded')
                return method(*args)
            except BaseException:
                self.failed = True
                return failure
        return signature(guarded)

    def allocate(self, size):
        if size > 4 * 2**20 or len(self.allocations) >= 64:
            raise ValueError('unexpected allocation')
        buffer = ct.create_string_buffer(max(1, size))
        address = ct.addressof(buffer)
        self.allocations[address] = buffer
        return address

    def free(self, address):
        if address:
            del self.allocations[address]

    def cursor(self):
        handle = self.next_handle
        self.next_handle += 1
        self.cursors[handle] = 0
        return handle

    def open(self, name, flags, _mode):
        if flags & 3 or not _matches(name, _CAB):
            raise ValueError('unexpected fixture open')
        return self.cursor()

    def read(self, handle, destination, count):
        offset = self.cursors[handle]
        raw = self.data[offset:offset + count]
        if raw:
            ct.memmove(destination, raw, len(raw))
        self.cursors[handle] += len(raw)
        return len(raw)

    def seek(self, handle, distance, origin):
        if origin not in (0, 1, 2):
            raise ValueError('unexpected seek origin')
        position = (0, self.cursors[handle], len(self.data))[origin] + distance
        if not 0 <= position <= len(self.data):
            raise ValueError('seek outside fixture')
        self.cursors[handle] = position
        return position

    def close(self, handle):
        del self.cursors[handle]
        return 0

    def write(self, handle, source, count):
        if handle != _OUTPUT or not self.output_open or count > len(_TEXT) - len(self.output):
            raise ValueError('unexpected fixture output')
        self.output.extend(ct.string_at(source, count))
        return count

    def notify(self, kind, pointer):
        item = pointer.contents
        if kind in (0, 5):  # CABINET_INFO, ENUMERATE
            return 0
        if kind == 2 and not self.output_open and not self.closed_output:  # COPY_FILE
            if item.cb != len(_TEXT) or not _matches(item.psz1, _MEMBER):
                raise ValueError('unexpected fixture member')
            self.output_open = True
            return _OUTPUT
        if kind == 3 and item.hf == _OUTPUT and self.output_open and item.cb == 0:  # CLOSE_FILE_INFO
            self.output_open = False
            self.closed_output = True
            return 1
        raise ValueError('unexpected cabinet notification')


def _exercise(dll, data: bytes, *, malformed: bool):
    io = _FixtureIO(data)
    callbacks = [io.callback(signature, method, failure) for signature, method, failure in (
        (abi.PFNALLOC, io.allocate, None), (abi.PFNFREE, io.free, None), (abi.PFNOPEN, io.open, -1),
        (abi.PFNREAD, io.read, 0xffffffff), (abi.PFNWRITE, io.write, 0xffffffff),
        (abi.PFNCLOSE, io.close, -1), (abi.PFNSEEK, io.seek, -1))]
    error = abi.ERF()
    context = dll.FDICreate(*callbacks, -1, ct.byref(error))
    if not context:
        raise ValueError('could not create FDI context')
    try:
        handle = io.cursor()
        header = abi.FDICABINETINFO()
        accepted = bool(dll.FDIIsCabinet(context, handle, ct.byref(header)))
        io.close(handle)
        if malformed:
            if accepted:
                raise ValueError('invalid fixture header was accepted')
        else:
            if not accepted or (header.cbCabinet, header.cFolders, header.cFiles) != (len(data), 1, 1):
                raise ValueError('authored cabinet header mismatch')
            notify = io.callback(abi.PFNFDINOTIFY, io.notify, -1)
            name, directory = ct.create_string_buffer(_CAB), ct.create_string_buffer(b'')
            if not dll.FDICopy(context, name, directory, 0, notify, None, None):
                raise ValueError('FDI could not decode the authored cabinet')
            if io.output != _TEXT or not io.closed_output or io.output_open:
                raise ValueError('decoded text or close notification mismatch')
    finally:
        destroyed = dll.FDIDestroy(context)
    if not destroyed or io.failed or io.allocations or io.cursors:
        raise ValueError('FDI fixture callbacks or cleanup failed')


def _expected(data: bytes) -> dict:
    return {'system_dll': 'cabinet.dll', 'platform': 'windows-amd64', 'files': 1, 'folders': 1,
            'cabinet_sha256': hashlib.sha256(data).hexdigest(), 'text_sha256': hashlib.sha256(_TEXT).hexdigest(),
            'malformed_header_rejected': True}


def check() -> dict:
    require_supported_platform()
    script = Path(__file__).resolve()
    env = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
    env['PYTHONPATH'] = str(script.parents[1] / 'src')
    with tempfile.TemporaryDirectory(prefix='pt-cabinet-check-') as temp:
        result = run_process([sys.executable, '-P', str(script), '--worker'], cwd=Path(temp), env=env,
                             cancel=Event(), timeout_seconds=45, memory_limit_bytes=512 * 2**20,
                             max_output_bytes=4096, log_limit=4096, stderr_limit=2048, separate_streams=True)
    expected = _expected(cabinet_fixture())
    # Require the complete, canonical known answer, with no diagnostic output.
    wire = (json.dumps(expected, sort_keys=True) + '\n').encode()
    if (result.returncode != 0 or result.reason is not None or result.stderr_total or result.log_bytes is None
            or result.stdout_total != len(result.log_bytes) or result.log_bytes.replace(b'\r\n', b'\n') != wire):
        raise ValueError(f'supervised FDI known-answer check failed (exit {result.returncode}, '
                         f'reason {result.reason}, stdout {result.stdout_total}, stderr {result.stderr_total})')
    return expected


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if args == ['--worker']:
            dll = _system_fdi()
            data = cabinet_fixture()
            _exercise(dll, data, malformed=False)
            _exercise(dll, b'NOT!' + data[4:], malformed=True)
            receipt = _expected(data)
        elif not args:
            receipt = check()
        else:
            return 2
    except (AcquisitionError, OSError, ValueError) as exc:
        print(f'package-fdi: {exc}', file=sys.stderr)
        return 3
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
