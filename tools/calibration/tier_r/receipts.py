"""Publish a new development receipt without following replaced parent paths.

The caller owns outside-repository/work-root policy and retains completed work on
publication errors. These helpers own filesystem anchoring, not engine evidence.
"""
from __future__ import annotations

import os
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path

_HAS_DIR_FD = (all(fn in os.supports_dir_fd for fn in (os.open, os.mkdir, os.stat))
               and os.stat in os.supports_follow_symlinks)


def validate_spelling(path: Path) -> None:
    """Reject aliases before work, including Win32 special-file spellings."""
    if not path.is_absolute() or '..' in path.parts or path.suffix != '.json':
        raise ValueError('receipt must be an absolute .json path without traversal')
    if os.name == 'nt':
        if str(path).startswith(('\\\\.\\', '\\\\?\\')):
            raise ValueError('receipt device namespaces are not allowed')
        for part in path.parts[1:]:
            if ':' in part or part.endswith((' ', '.')) or Path(part).is_reserved():
                raise ValueError('receipt path contains a device, stream, or aliased component')
        for candidate in (path, *path.parents):
            try:
                attributes = candidate.lstat().st_file_attributes
            except FileNotFoundError:
                continue
            if attributes & 0x400:
                raise ValueError('receipt paths cannot contain reparse points')


def _identity(info) -> tuple[int, int]:
    return info.st_dev, info.st_ino


@contextmanager
def _posix_parent(path: Path, *, create: bool):
    # Refuse hosts lacking the primitives. A preceding is_symlink() check is not
    # an alternative to kernel no-follow or directory-relative operations.
    if (not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY')
            or not _HAS_DIR_FD):
        raise OSError('safe directory-relative receipt publication is unsupported')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    with ExitStack() as stack:
        current = os.open(path.anchor, flags)
        stack.callback(os.close, current)
        links = []
        for part in path.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass  # The no-follow directory open below decides the race.
                child = os.open(part, flags, dir_fd=current)
            stack.callback(os.close, child)
            links.append((current, part, _identity(os.fstat(child))))
            current = child
        yield current
        # A moved original directory is safe from redirect, but its old pathname
        # is no longer a truthful publication result. Preserve it and fail.
        for parent, name, identity in links:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or _identity(info) != identity:
                raise OSError('receipt parent changed during publication; completed data retained on stdout')


@contextmanager
def _windows_parent(path: Path, *, create: bool):
    """Pin every ancestor without write/delete sharing, refusing all reparse points.

    Retaining every handle is essential: locking only the leaf directory still
    lets an ancestor be moved and replaced. OPEN_REPARSE_POINT applies to the
    final component of each successive open; earlier components are already held.
    """
    import ctypes
    from ctypes import wintypes as w

    class AttributeTagInfo(ctypes.Structure):
        _fields_ = [('attributes', w.DWORD), ('tag', w.DWORD)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p,
                                  w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    kernel.GetFileInformationByHandleEx.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    invalid = ctypes.c_void_p(-1).value
    with ExitStack() as stack:
        current = Path(path.anchor)
        for index, part in enumerate((path.anchor, *path.parts[1:])):
            if index:
                current /= part
            # LIST_DIRECTORY|READ_ATTRIBUTES; SHARE_READ only; OPEN_EXISTING;
            # BACKUP_SEMANTICS|OPEN_REPARSE_POINT. Attribute-only access does not
            # participate in share checks: LIST_DIRECTORY (READ_DATA's bit) is
            # required. Denying WRITE also blocks in-place junction mutation.
            handle = kernel.CreateFileW(str(current), 0x81, 0x1, None, 3, 0x02200000, None)
            if handle == invalid:
                error = ctypes.get_last_error()
                if not create or error not in (2, 3) or not index:
                    raise ctypes.WinError(error)
                try:
                    current.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                handle = kernel.CreateFileW(str(current), 0x81, 0x1, None, 3, 0x02200000, None)
                if handle == invalid:
                    raise ctypes.WinError(ctypes.get_last_error())
            stack.callback(kernel.CloseHandle, handle)
            info = AttributeTagInfo()
            if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.attributes & 0x400 or not info.attributes & 0x10:
                raise OSError('receipt parents must be plain directories, not reparse points')
        yield


def write_new_receipt(path: Path, data: bytes, *, create_parents: bool = False) -> None:
    """Exclusively create a receipt in its anchored parent; never retry by path.

    Keep the original absolute spelling: resolving it before opening the parent
    could itself turn a raced symlink into an apparently safe destination.
    A failed write may leave new partial evidence, which is never removed by an
    untrusted pathname. The CLI reports error and keeps the full receipt object.
    """
    path = Path(path)
    validate_spelling(path)
    if os.name == 'nt':
        with _windows_parent(path.parent, create=create_parents), path.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    elif os.name == 'posix':
        with _posix_parent(path.parent, create=create_parents) as parent:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
            fd = os.open(path.name, flags, mode=0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
    else:
        raise OSError('safe receipt publication is unsupported on this platform')
