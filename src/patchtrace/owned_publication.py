"""Owned, no-replace file publication for immutable local evidence.

Linux holds an anonymous staging descriptor and an anchored destination directory.
Windows holds rooted native directory/source handles that deny delete sharing.
Existing-file reuse is opt-in, bounded, and validated while its handle is held.
No failure path unlinks a pathname; unsupported ownership primitives fail closed.
"""
from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
import sys
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STREAM_CHUNK = 1024 * 1024
SNAPSHOT_BLOCK = 64 * 1024
MAX_SNAPSHOT_READ = 16 * 1024 * 1024


class OwnedPublicationError(RuntimeError):
    """The requested operation cannot preserve file identity and ownership."""


class _MissingEvidence(FileNotFoundError):
    """Only the initial rooted leaf open was absent, not a later validation step."""


@dataclass(frozen=True)
class DirectoryAnchor:
    """Expected identity of an already selected root, checked on its held handle."""

    path: Path
    identity: tuple[int, ...]


def _anchor_scope(path: Path, anchor: DirectoryAnchor | None) -> None:
    if anchor is not None and not path.is_relative_to(anchor.path):
        raise OwnedPublicationError('object publication is outside its selected root')


def _anchor_identity(path: Path, identity: tuple[int, ...], anchor: DirectoryAnchor | None) -> None:
    if anchor is not None and path == anchor.path and identity != anchor.identity:
        raise OwnedPublicationError('the selected workspace root identity changed')


def file_identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def verify_stage(fd: int, data: bytes, identity: tuple[int, int]) -> os.stat_result:
    """Verify the held source with reads bounded by the expected length plus one."""
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or file_identity(before) != identity or
            before.st_size != len(data)):
        raise OwnedPublicationError('safe publication staging identity or bytes changed')
    digest = hashlib.sha256()
    with os.fdopen(fd, 'rb', buffering=0, closefd=False) as handle:
        handle.seek(0)
        remaining = len(data)
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                raise OwnedPublicationError('safe publication staging identity or bytes changed')
            digest.update(chunk)
            remaining -= len(chunk)
        if handle.read(1):
            raise OwnedPublicationError('safe publication staging identity or bytes changed')
    after = os.fstat(fd)
    if (_observation(before) != _observation(after) or digest.digest() != hashlib.sha256(data).digest()):
        raise OwnedPublicationError('safe publication staging identity or bytes changed')
    return after


def write_stage(fd: int, data: bytes) -> tuple[int, int]:
    """Keep the exact source open; verify the flushed bytes through that descriptor."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise OwnedPublicationError('safe publication requires an ordinary staging file')
    with os.fdopen(fd, 'w+b', closefd=False) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(fd)
    identity = file_identity(before)
    verify_stage(fd, data, identity)
    return identity


def linux_directory(path: Path, *, create: bool, anchor: DirectoryAnchor | None = None) -> int:
    """Open root to leaf without following any parent link, creating only anchored children."""
    _anchor_scope(path, anchor)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open(path.anchor, flags)
    try:
        observed_path = Path(path.anchor)
        _anchor_identity(observed_path, file_identity(os.fstat(current)), anchor)
        for component in path.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
            observed_path /= component
            _anchor_identity(observed_path, file_identity(os.fstat(current)), anchor)
        return current
    except BaseException as exc:
        os.close(current)
        if isinstance(exc, OSError) and exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise OwnedPublicationError('safe publication parent is a link or not a directory') from exc
        raise


def check_linux_parent(path: Path, owned: int, *, anchor: DirectoryAnchor | None = None) -> None:
    try:
        observed = linux_directory(path, create=False, anchor=anchor)
    except OSError:
        raise OwnedPublicationError('safe publication parent changed or became a link') from None
    try:
        if file_identity(os.fstat(observed)) != file_identity(os.fstat(owned)):
            raise OwnedPublicationError('safe publication parent changed')
    finally:
        os.close(observed)


class WindowsPublication:
    """Rooted NT opens and information calls; never reopen a stage for cleanup.

    Sharing locks alone do not protect reparse attributes. Every child operation
    therefore uses RootDirectory and rejects reparse processing as well.
    """

    blocked_error = OwnedPublicationError

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes as wt

        self.ct = ctypes
        self.wt = wt
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.nt = ctypes.WinDLL('ntdll')

        class UnicodeString(ctypes.Structure):
            _fields_ = [('Length', wt.USHORT), ('MaximumLength', wt.USHORT), ('Buffer', wt.LPWSTR)]

        class ObjectAttributes(ctypes.Structure):
            _fields_ = [('Length', wt.ULONG), ('RootDirectory', wt.HANDLE),
                        ('ObjectName', ctypes.POINTER(UnicodeString)), ('Attributes', wt.ULONG),
                        ('SecurityDescriptor', wt.LPVOID), ('SecurityQualityOfService', wt.LPVOID)]

        class IoStatus(ctypes.Structure):
            _fields_ = [('StatusOrPointer', wt.LPVOID), ('Information', ctypes.c_size_t)]

        class FileInfo(ctypes.Structure):
            _fields_ = [('Attributes', wt.DWORD), ('Creation', wt.FILETIME), ('Access', wt.FILETIME),
                        ('Write', wt.FILETIME), ('Volume', wt.DWORD), ('SizeHigh', wt.DWORD),
                        ('SizeLow', wt.DWORD), ('Links', wt.DWORD), ('IndexHigh', wt.DWORD),
                        ('IndexLow', wt.DWORD)]

        class RenameInfo(ctypes.Structure):
            _fields_ = [('ReplaceIfExists', wt.BOOLEAN), ('RootDirectory', wt.HANDLE),
                        ('FileNameLength', wt.DWORD), ('FileName', wt.WCHAR * 1)]

        self.UnicodeString, self.ObjectAttributes, self.IoStatus = UnicodeString, ObjectAttributes, IoStatus
        self.FileInfo, self.RenameInfo = FileInfo, RenameInfo
        self.kernel.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID,
                                            wt.DWORD, wt.DWORD, wt.HANDLE]
        self.kernel.CreateFileW.restype = wt.HANDLE
        self.kernel.CloseHandle.argtypes = [wt.HANDLE]
        self.kernel.CloseHandle.restype = wt.BOOL
        self.kernel.GetFileInformationByHandle.argtypes = [wt.HANDLE, ctypes.POINTER(FileInfo)]
        self.kernel.GetFileInformationByHandle.restype = wt.BOOL
        self.nt.NtCreateFile.argtypes = [ctypes.POINTER(wt.HANDLE), wt.DWORD,
                                         ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IoStatus),
                                         wt.LPVOID, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
                                         wt.LPVOID, wt.DWORD]
        self.nt.NtCreateFile.restype = wt.LONG
        self.nt.NtSetInformationFile.argtypes = [wt.HANDLE, ctypes.POINTER(IoStatus), wt.LPVOID,
                                                wt.ULONG, ctypes.c_int]
        self.nt.NtSetInformationFile.restype = wt.LONG
        self.nt.RtlNtStatusToDosError.argtypes = [wt.LONG]
        self.nt.RtlNtStatusToDosError.restype = wt.ULONG

    def error(self, code: int | None = None) -> None:
        code = self.ct.get_last_error() if code is None else code
        if code in (80, 183):  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
            raise FileExistsError('destination already exists; prior evidence is preserved')
        raise self.ct.WinError(code)

    def identity(self, handle: int, *, directory: bool = False) -> tuple[int, int, int]:
        info = self.FileInfo()
        if not self.kernel.GetFileInformationByHandle(handle, self.ct.byref(info)):
            self.error()
        if info.Attributes & 0x400 or (directory and not info.Attributes & 0x10):
            raise self.blocked_error('safe publication requires ordinary, non-reparse directories/files')
        if not (info.IndexHigh or info.IndexLow):
            raise self.blocked_error('safe publication file identity is unavailable')
        return info.Volume, info.IndexHigh, info.IndexLow

    def open_child(self, parent: int, name: str, *, directory: bool, create: bool) -> int:
        encoded = name.encode('utf-16-le')
        if len(encoded) > 65532:
            raise self.blocked_error('safe publication component is too long')
        buffer = self.ct.create_unicode_buffer(name)
        text = self.UnicodeString(len(encoded), len(encoded) + 2, self.ct.cast(buffer, self.wt.LPWSTR))
        attrs = self.ObjectAttributes(self.ct.sizeof(self.ObjectAttributes), parent, self.ct.pointer(text),
                                      0x1040, None, None)  # OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
        result, status = self.wt.HANDLE(), self.IoStatus()
        access = 0x1000A0 if directory else (0xC0110000 if create else 0x100081)
        # Directories: traverse/attributes/sync. Stages: R/W, DELETE, sync.
        # Existing files: read-data/attributes/sync, without write or delete access.
        # Native rename opens the target directory for FILE_WRITE_DATA. Deny
        # delete sharing on guards, but do not block that internal write open.
        # The staged byte source must continue to deny both write and delete.
        sharing = 3 if directory else 1  # READ | WRITE for directories; READ for the source
        disposition = (3 if create else 1) if directory else (2 if create else 1)  # OPEN_IF / OPEN; CREATE / OPEN
        options = 0x200020 | (1 if directory else 0x40)  # no reparse, sync; directory / ordinary file
        code = self.nt.NtCreateFile(self.ct.byref(result), access, self.ct.byref(attrs),
                                    self.ct.byref(status), None, 0x80, sharing, disposition, options, None, 0)
        if code & 0xFFFFFFFF in (0xC000050B, 0xC0000103, 0xC00000BA):
            # REPARSE_POINT_ENCOUNTERED, NOT_A_DIRECTORY, FILE_IS_A_DIRECTORY.
            raise self.blocked_error('safe publication requires ordinary, non-reparse directories/files')
        if code < 0:
            self.error(self.nt.RtlNtStatusToDosError(code))
        return result.value

    def directory(self, path: Path, stack: ExitStack, *, create: bool,
                  anchor: DirectoryAnchor | None = None) -> int:
        # Only the volume/share root is opened by path. Every descendant is rooted
        # in its already held parent, including creation of missing directories.
        _anchor_scope(path, anchor)
        parent = self.kernel.CreateFileW(str(path.anchor), 0x1000A0, 3, None, 3, 0x2200000, None)
        if parent == self.ct.c_void_p(-1).value:
            self.error()
        stack.callback(self.kernel.CloseHandle, parent)
        observed_path = path.__class__(path.anchor)
        _anchor_identity(observed_path, self.identity(parent, directory=True), anchor)
        for component in path.parts[1:]:
            parent = self.open_child(parent, component, directory=True, create=create)
            stack.callback(self.kernel.CloseHandle, parent)
            observed_path /= component
            _anchor_identity(observed_path, self.identity(parent, directory=True), anchor)
        return parent

    def check_parent(self, path: Path, owned: int, *, anchor: DirectoryAnchor | None = None) -> None:
        try:
            with ExitStack() as stack:
                observed = self.directory(path, stack, create=False, anchor=anchor)
                if self.identity(observed, directory=True) != self.identity(owned, directory=True):
                    raise self.blocked_error('safe publication parent changed')
        except OSError:
            raise self.blocked_error('safe publication parent changed or became unavailable') from None

    def _set_information(self, source: int, buffer: Any, size: int, information_class: int) -> None:
        status = self.IoStatus()
        code = self.nt.NtSetInformationFile(source, self.ct.byref(status), buffer, size, information_class)
        if code < 0:
            self.error(self.nt.RtlNtStatusToDosError(code))
        if code != 0:
            # The owned source was opened synchronously and nonalertably. Never
            # credit STATUS_PENDING or an unexpected informational return as done.
            raise self.blocked_error('safe publication information call did not complete synchronously')

    def rename(self, source: int, parent: int, name: str, *, replace: bool = False) -> None:
        encoded = name.encode('utf-16-le')
        buffer = self.ct.create_string_buffer(self.ct.sizeof(self.RenameInfo) + len(encoded))
        info = self.RenameInfo.from_buffer(buffer)
        info.ReplaceIfExists, info.RootDirectory, info.FileNameLength = replace, parent, len(encoded)
        self.ct.memmove(self.ct.addressof(buffer) + self.RenameInfo.FileName.offset, encoded, len(encoded))
        self._set_information(source, buffer, len(buffer), 10)  # FileRenameInformation

    def discard(self, source: int) -> None:
        delete = self.wt.BOOLEAN(True)  # FILE_DISPOSITION_INFORMATION, exact held source
        self._set_information(source, self.ct.byref(delete), self.ct.sizeof(delete), 13)


def _read_descriptor(fd: int, maximum: int) -> bytes:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= maximum:
        raise OwnedPublicationError('existing evidence is not an ordinary file within its byte budget')
    with os.fdopen(fd, 'rb', closefd=False) as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise OwnedPublicationError('existing evidence exceeds its byte budget')
    return data


def _observation(info: os.stat_result) -> tuple:
    return file_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _descriptor_chunk(fd: int, offset: int, size: int, check: Callable[[], None]) -> bytes:
    """Unbuffered short-read loop; no physical read can exceed STREAM_CHUNK."""
    os.lseek(fd, offset, os.SEEK_SET)
    data = bytearray()
    while len(data) < size:
        check()
        part = os.read(fd, min(STREAM_CHUNK, size - len(data)))
        if not part:
            break
        data.extend(part)
    return bytes(data)


class FileSnapshot:
    """Verified ranges of a borrowed descriptor, valid only inside its context.

    This single-threaded reader never owns or closes ``fd``. It keeps a SHA-256
    per 64 KiB block so parsers and publication can reject changed bytes before
    using them, without retaining the complete file in memory.
    """

    def __init__(self, fd: int, *, maximum: int, expected_size: int | None = None,
                 expected_sha256: str | None = None, check: Callable[[], None] = lambda: None):
        _options(maximum, False, None)
        if (expected_size is not None and (type(expected_size) is not int or not 0 <= expected_size <= maximum)):
            raise ValueError('snapshot size must be within its integer byte budget')
        if (expected_sha256 is not None and (not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or
                any(char not in '0123456789abcdef' for char in expected_sha256))):
            raise ValueError('snapshot digest must be a lowercase SHA-256')
        self._fd, self._guard, self._closed = fd, check, False
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise OwnedPublicationError('snapshot requires an ordinary file within its byte budget')
        if expected_size is not None and before.st_size != expected_size:
            raise OwnedPublicationError('snapshot size differs from its expected identity')
        self._baseline, self._size = _observation(before), before.st_size
        digest, blocks = hashlib.sha256(), bytearray()
        for offset in range(0, self.size, STREAM_CHUNK):
            size = min(STREAM_CHUNK, self.size - offset)
            data = _descriptor_chunk(fd, offset, size, self._check)
            if len(data) != size:
                raise OwnedPublicationError('snapshot ended during verification')
            digest.update(data)
            view = memoryview(data)
            for start in range(0, size, SNAPSHOT_BLOCK):
                blocks.extend(hashlib.sha256(view[start:start + SNAPSHOT_BLOCK]).digest())
        if _descriptor_chunk(fd, self.size, 1, self._check):
            raise OwnedPublicationError('snapshot grew during verification')
        self._check()
        self._sha256, self._blocks = digest.hexdigest(), bytes(blocks)
        if expected_sha256 is not None and self.sha256 != expected_sha256:
            raise OwnedPublicationError('snapshot bytes differ from the expected SHA-256')

    @property
    def size(self) -> int:
        return self._size

    @property
    def sha256(self) -> str:
        return self._sha256

    def _check(self) -> None:
        if self._closed:
            raise OwnedPublicationError('snapshot descriptor is no longer borrowed')
        self._guard()
        if _observation(os.fstat(self._fd)) != self._baseline:
            raise OwnedPublicationError('snapshot identity or bytes changed')

    def read(self, offset: int, length: int, *, clip: bool = True) -> bytes:
        if (type(offset) is not int or type(length) is not int or not 0 <= offset <= self.size or
                not 0 <= length <= MAX_SNAPSHOT_READ):
            raise OwnedPublicationError('snapshot range exceeds its read budget')
        if not clip and length > self.size - offset:
            raise OwnedPublicationError('snapshot range ends beyond its verified bytes')
        end, data = min(self.size, offset + length), bytearray()
        self._check()
        if end > offset:
            for block in range(offset // SNAPSHOT_BLOCK, (end - 1) // SNAPSHOT_BLOCK + 1):
                start = block * SNAPSHOT_BLOCK
                size = min(SNAPSHOT_BLOCK, self.size - start)
                part = _descriptor_chunk(self._fd, start, size, self._check)
                expected = self._blocks[block * 32:(block + 1) * 32]
                if len(part) != size or hashlib.sha256(part).digest() != expected:
                    raise OwnedPublicationError('snapshot block differs from its verified bytes')
                data.extend(part[max(0, offset - start):min(size, end - start)])
        self._check()
        return bytes(data)

    def verify(self) -> None:
        digest = hashlib.sha256()
        for offset in range(0, self.size, STREAM_CHUNK):
            digest.update(self.read(offset, min(STREAM_CHUNK, self.size - offset)))
        if _descriptor_chunk(self._fd, self.size, 1, self._check) or digest.hexdigest() != self.sha256:
            raise OwnedPublicationError('snapshot content changed')
        self._check()

    def __enter__(self) -> FileSnapshot:
        self._check()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        try:
            if exc_type is None:
                self.verify()
        finally:
            self._closed, self._blocks = True, b''


def _close_preserving(close: Callable[[], Any], primary: BaseException | None) -> None:
    try:
        close()
    except BaseException as exc:
        if primary is None:
            raise
        primary.add_note(f'Owned stream cleanup also failed: {type(exc).__name__}')


class _StreamStack(ExitStack):
    """Attempt every owned close without replacing an active operation failure."""
    def __init__(self):
        super().__init__()
        self.failures: list[BaseException] = []

    def callback(self, callback, /, *args, **kwargs):
        def guarded():
            try:
                result = callback(*args, **kwargs)
                if result is not None and result == 0:
                    raise OwnedPublicationError('native stream directory handle did not close')
            except BaseException as exc:
                self.failures.append(exc)
        super().callback(guarded)
        return callback

    def __exit__(self, exc_type, primary, traceback):
        super().__exit__(exc_type, primary, traceback)
        if self.failures:
            error = primary if primary is not None else self.failures[0]
            for failure in self.failures:
                if failure is not error:
                    error.add_note(f'Owned stream cleanup also failed: {type(failure).__name__}')
            self.failures.clear()
            if primary is None:
                raise error
        return False


def _inspect_linux(target: Path, parent: int, maximum: int, inspect: Callable[[FileSnapshot], Any],
                   anchor: DirectoryAnchor | None, *, check: Callable[[], None] = lambda: None) -> Any:
    try:
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    except FileNotFoundError as exc:
        raise _MissingEvidence(*exc.args) from exc
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise OwnedPublicationError('existing evidence is a link or not a regular local file') from exc
        raise
    primary = None
    try:
        with FileSnapshot(fd, maximum=maximum, check=check) as snapshot:
            result = inspect(snapshot)
        before = os.fstat(fd)
        named = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
        if snapshot._baseline != _observation(before) or _observation(before) != _observation(named):
            raise OwnedPublicationError('existing evidence identity changed during verification')
        check_linux_parent(target.parent, parent, anchor=anchor)
        return result
    except BaseException as exc:
        primary = exc
        raise
    finally:
        _close_preserving(lambda: os.close(fd), primary)


def _inspect_windows(target: Path, parent: int, win: WindowsPublication, maximum: int,
                     inspect: Callable[[FileSnapshot], Any], anchor: DirectoryAnchor | None, *,
                     check: Callable[[], None] = lambda: None) -> Any:
    import msvcrt

    try:
        source = win.open_child(parent, target.name, directory=False, create=False)
    except FileNotFoundError as exc:
        raise _MissingEvidence(*exc.args) from exc
    fd, primary = None, None
    try:
        identity = win.identity(source)
        fd = msvcrt.open_osfhandle(source, os.O_RDONLY | os.O_BINARY)
        with FileSnapshot(fd, maximum=maximum, check=check) as snapshot:
            result = inspect(snapshot)
        if win.identity(source) != identity or snapshot._baseline != _observation(os.fstat(fd)):
            raise OwnedPublicationError('existing evidence identity changed during verification')
        win.check_parent(target.parent, parent, anchor=anchor)
        return result
    except BaseException as exc:
        primary = exc
        raise
    finally:
        def close() -> None:
            if fd is None:
                if not win.kernel.CloseHandle(source):
                    win.error()
            else:
                os.close(fd)
        _close_preserving(close, primary)


def inspect_file(target: Path, *, maximum: int, inspect: Callable[[FileSnapshot], Any],
                 anchor: DirectoryAnchor | None = None, check: Callable[[], None] = lambda: None) -> Any:
    """Run a callback against bounded verified ranges while the ordinary parent/leaf stay held."""
    _options(maximum, False, inspect)
    target = Path(os.path.abspath(target))
    stack, primary = _StreamStack(), None
    try:
        if sys.platform.startswith('linux'):
            parent = linux_directory(target.parent, create=False, anchor=anchor)
            stack.callback(os.close, parent)
            return _inspect_linux(target, parent, maximum, inspect, anchor, check=check)
        if os.name == 'nt':
            win = WindowsPublication()
            parent = win.directory(target.parent, stack, create=False, anchor=anchor)
            return _inspect_windows(target, parent, win, maximum, inspect, anchor, check=check)
        raise OwnedPublicationError('safe publication is unsupported on this platform')
    except BaseException as exc:
        primary = exc
        raise
    finally:
        _close_preserving(stack.close, primary)


def _verify_stream_stage(fd: int, source: FileSnapshot, identity: tuple[int, int]) -> None:
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or file_identity(before) != identity or before.st_size != source.size):
        raise OwnedPublicationError('safe publication streaming stage identity or size changed')
    digest = hashlib.sha256()
    for offset in range(0, source.size, STREAM_CHUNK):
        size = min(STREAM_CHUNK, source.size - offset)
        data = _descriptor_chunk(fd, offset, size, source._check)
        if len(data) != size:
            raise OwnedPublicationError('safe publication streaming stage ended during verification')
        digest.update(data)
    if (_descriptor_chunk(fd, source.size, 1, source._check) or digest.hexdigest() != source.sha256 or
            _observation(before) != _observation(os.fstat(fd))):
        raise OwnedPublicationError('safe publication streaming stage bytes changed')


def _write_stream_stage(fd: int, source: FileSnapshot) -> tuple[int, int]:
    identity = file_identity(os.fstat(fd))
    os.lseek(fd, 0, os.SEEK_SET)
    for offset in range(0, source.size, STREAM_CHUNK):
        chunk = memoryview(source.read(offset, min(STREAM_CHUNK, source.size - offset)))
        while chunk:
            source._check()
            count = os.write(fd, chunk)
            if count <= 0:
                raise OwnedPublicationError('short streaming publication write')
            chunk = chunk[count:]
    os.fsync(fd)
    _verify_stream_stage(fd, source, identity)
    return identity


def _read_linux(target: Path, parent: int, maximum: int, validate: Callable[[bytes], None],
                anchor: DirectoryAnchor | None) -> bytes:
    try:
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    except FileNotFoundError as exc:
        raise _MissingEvidence(*exc.args) from exc
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise OwnedPublicationError('existing evidence is a link or not a regular local file') from exc
        raise
    try:
        before = os.fstat(fd)
        data = _read_descriptor(fd, maximum)
        validate(data)
        after = os.fstat(fd)
        named = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
        if _observation(before) != _observation(after) or _observation(after) != _observation(named):
            raise OwnedPublicationError('existing evidence identity or bytes changed during verification')
        check_linux_parent(target.parent, parent, anchor=anchor)
        return data
    finally:
        os.close(fd)


def _read_windows(target: Path, parent: int, win: WindowsPublication, maximum: int,
                  validate: Callable[[bytes], None], anchor: DirectoryAnchor | None) -> bytes:
    import msvcrt

    try:
        source = win.open_child(parent, target.name, directory=False, create=False)
    except FileNotFoundError as exc:
        raise _MissingEvidence(*exc.args) from exc
    fd = None
    try:
        identity = win.identity(source)
        fd = msvcrt.open_osfhandle(source, os.O_RDONLY | os.O_BINARY)
        before = os.fstat(fd)
        data = _read_descriptor(fd, maximum)
        validate(data)
        if win.identity(source) != identity or _observation(before) != _observation(os.fstat(fd)):
            raise OwnedPublicationError('existing evidence identity or bytes changed during verification')
        win.check_parent(target.parent, parent, anchor=anchor)
        return data
    finally:
        if fd is None:
            if not win.kernel.CloseHandle(source):
                win.error()
        else:
            os.close(fd)


def _reuse(reader: Callable[[], bytes], require_existing: bool) -> bool:
    try:
        reader()
        return True
    except _MissingEvidence:
        if require_existing:
            raise
        return False


def publish_linux(target: Path, data: bytes, *, validate_existing: Callable[[bytes], None] | None = None,
                  maximum: int = 0, require_existing: bool = False,
                  stage_writer: Callable[[int, bytes], Any] | None = None,
                  stage_verifier: Callable[[int, Any, tuple[int, int]], Any] | None = None,
                  existing_reader: Callable | None = None,
                  stack_factory: Callable[[], ExitStack] = ExitStack,
                  anchor: DirectoryAnchor | None = None) -> bool:
    with stack_factory() as stack:
        parent = linux_directory(target.parent, create=not require_existing, anchor=anchor)
        stack.callback(os.close, parent)
        def read_existing() -> bytes:
            return (existing_reader or _read_linux)(target, parent, maximum, validate_existing, anchor)

        if validate_existing is not None and _reuse(read_existing, require_existing):
            return False
        if not hasattr(os, 'O_TMPFILE'):
            raise OwnedPublicationError('safe publication requires Linux anonymous staging support')
        # There is no staging pathname to replace or to unlink on failure.
        fd = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=parent)
        stack.callback(os.close, fd)
        identity = (stage_writer or write_stage)(fd, data)
        check_linux_parent(target.parent, parent, anchor=anchor)
        try:
            # procfs names this process's owned descriptor, not a directory entry
            # another writer can substitute. dst_dir_fd holds the original parent.
            os.link(f'/proc/self/fd/{fd}', target.name, dst_dir_fd=parent, follow_symlinks=True)
        except FileExistsError:
            if validate_existing is None:
                raise
            _reuse(read_existing, require_existing=True)
            return False
        (stage_verifier or verify_stage)(fd, data, identity)
        if file_identity(os.stat(target.name, dir_fd=parent, follow_symlinks=False)) != identity:
            raise OwnedPublicationError('safe publication destination identity changed')
        check_linux_parent(target.parent, parent, anchor=anchor)
        return True


def publish_windows(target: Path, data: bytes, *, validate_existing: Callable[[bytes], None] | None = None,
                    maximum: int = 0, require_existing: bool = False,
                    windows_factory: Callable[[], WindowsPublication] = WindowsPublication,
                    stage_writer: Callable[[int, bytes], Any] | None = None,
                    stage_verifier: Callable[[int, Any, tuple[int, int]], Any] | None = None,
                    existing_reader: Callable | None = None,
                    stack_factory: Callable[[], ExitStack] = ExitStack,
                    os_api: Any = os, prefix: str = '.owned-', anchor: DirectoryAnchor | None = None,
                    replace: bool = False) -> bool:
    import msvcrt

    if replace and (validate_existing is not None or require_existing):
        raise ValueError('forced publication cannot reuse existing evidence')
    win = windows_factory()
    anchor_options = {'anchor': anchor} if anchor is not None else {}
    with stack_factory() as stack:
        parent = win.directory(target.parent, stack, create=not require_existing, **anchor_options)
        def read_existing() -> bytes:
            return (existing_reader or _read_windows)(target, parent, win, maximum, validate_existing, anchor)

        if validate_existing is not None and _reuse(read_existing, require_existing):
            return False
        source = win.open_child(parent, f'{prefix}{secrets.token_hex(16)}.tmp', directory=False, create=True)
        fd, published = None, False
        primary: BaseException | None = None
        try:
            identity = win.identity(source)
            fd = msvcrt.open_osfhandle(source, os_api.O_RDWR | os_api.O_BINARY)
            stage_identity = (stage_writer or write_stage)(fd, data)
            win.check_parent(target.parent, parent, **anchor_options)
            if win.identity(source) != identity:
                raise win.blocked_error('safe publication staging identity changed')
            try:
                if replace:
                    win.rename(source, parent, target.name, replace=True)
                else:
                    win.rename(source, parent, target.name)
            except FileExistsError:
                if validate_existing is None:
                    raise
                _reuse(read_existing, require_existing=True)
                return False
            published = True
            if stage_verifier is not None:
                stage_verifier(fd, data, stage_identity)
            win.check_parent(target.parent, parent, **anchor_options)
            if win.identity(source) != identity:
                raise win.blocked_error('safe publication destination identity changed')
            return True
        except BaseException as exc:
            primary = exc
            raise
        finally:
            failures: list[tuple[str, BaseException]] = []
            try:
                if not published:
                    win.discard(source)
            except BaseException as exc:
                failures.append(('discard', exc))
            try:
                if fd is None:
                    if not win.kernel.CloseHandle(source):
                        win.error()
                else:
                    os_api.close(fd)  # owns the native handle after open_osfhandle succeeds
            except BaseException as exc:
                failures.append(('close', exc))
            if failures:
                error = primary if primary is not None else failures[0][1]
                for operation, failure in failures:
                    if failure is not error:
                        error.add_note(f'Windows {operation} cleanup also failed: {type(failure).__name__}'[:160])
                if primary is None:
                    raise error


def _options(maximum: int, require_existing: bool, validate_existing: Callable[[bytes], None] | None) -> None:
    if type(maximum) is not int or maximum < 0:
        raise ValueError('existing evidence requires a non-negative integer byte budget')
    if require_existing and validate_existing is None:
        raise ValueError('existing evidence requires a content validator')


def publish_bytes(target: Path, data: bytes, *, validate_existing: Callable[[bytes], None] | None = None,
                  maximum: int = 0, require_existing: bool = False, anchor: DirectoryAnchor | None = None) -> bool:
    """Return True for a new object or False for validated reuse; never replace.

    The caller bounds and validates supplied bytes. A reuse validator must raise
    if existing compressed/content bytes are unacceptable. Missing referenced
    evidence is an error when require_existing is True, including a concurrent loss.
    """
    _options(maximum, require_existing, validate_existing)
    target = Path(os.path.abspath(target))
    options = dict(validate_existing=validate_existing, maximum=maximum,
                   require_existing=require_existing, anchor=anchor)
    if sys.platform.startswith('linux'):
        return publish_linux(target, data, **options)
    if os.name == 'nt':
        return publish_windows(target, data, **options)
    raise OwnedPublicationError('safe publication is unsupported on this platform')


def publish_stream(target: Path, source: FileSnapshot, *,
                   validate_existing: Callable[[FileSnapshot], None] | None = None,
                   maximum: int = 0, require_existing: bool = False,
                   anchor: DirectoryAnchor | None = None) -> bool:
    """Exclusively publish a held verified snapshot in fixed chunks; never replace or close its source."""
    _options(maximum, require_existing, validate_existing)
    if not isinstance(source, FileSnapshot):
        raise TypeError('stream publication requires a held FileSnapshot')
    source._check()
    target = Path(os.path.abspath(target))
    options = dict(validate_existing=validate_existing, maximum=maximum, require_existing=require_existing,
                   anchor=anchor, stage_writer=_write_stream_stage, stage_verifier=_verify_stream_stage,
                   stack_factory=_StreamStack)
    if sys.platform.startswith('linux'):
        return publish_linux(target, source, existing_reader=lambda *args: _inspect_linux(*args, check=source._check),
                             **options)
    if os.name == 'nt':
        return publish_windows(target, source, existing_reader=lambda *args: _inspect_windows(*args, check=source._check),
                               **options)
    raise OwnedPublicationError('safe publication is unsupported on this platform')


def read_bytes(target: Path, *, maximum: int, validate: Callable[[bytes], None] = lambda data: None,
               anchor: DirectoryAnchor | None = None) -> bytes:
    """Read one ordinary file through a held parent/leaf; reject links and changes."""
    _options(maximum, False, validate)
    target = Path(os.path.abspath(target))
    with ExitStack() as stack:
        if sys.platform.startswith('linux'):
            parent = linux_directory(target.parent, create=False, anchor=anchor)
            stack.callback(os.close, parent)
            return _read_linux(target, parent, maximum, validate, anchor)
        if os.name == 'nt':
            win = WindowsPublication()
            parent = win.directory(target.parent, stack, create=False, anchor=anchor)
            return _read_windows(target, parent, win, maximum, validate, anchor)
        raise OwnedPublicationError('safe publication is unsupported on this platform')


def directory_anchor(path: Path) -> DirectoryAnchor:
    """Capture one ordinary selected root, without following descendants or links."""
    path = Path(os.path.abspath(path))
    with ExitStack() as stack:
        if sys.platform.startswith('linux'):
            parent = linux_directory(path, create=False)
            stack.callback(os.close, parent)
            identity = file_identity(os.fstat(parent))
        elif os.name == 'nt':
            win = WindowsPublication()
            parent = win.directory(path, stack, create=False)
            identity = win.identity(parent, directory=True)
        else:
            raise OwnedPublicationError('safe publication is unsupported on this platform')
        return DirectoryAnchor(path, identity)


def verify_anchor(anchor: DirectoryAnchor) -> None:
    if directory_anchor(anchor.path) != anchor:
        raise OwnedPublicationError('the selected workspace root identity changed')
