"""Read-only, rooted source capture for local CAB and CAB-form MSU inputs."""
from __future__ import annotations

import ctypes
import hashlib
import os
import re
from contextlib import ExitStack, contextmanager
from pathlib import Path, PureWindowsPath
from threading import Event

from patchtrace.owned_publication import OwnedPublicationError, WindowsPublication

from .contracts import AcquisitionError
from .package_budget import PackageBudget
from .package_contracts import PackageFileIdentity, PackageLimits, PackageSource
from .package_paths import decode_member_name
from .package_platform import require_supported_platform

_CHUNK = 256 * 1024


class _FileIdInfo(ctypes.Structure):
    _fields_ = [('volume', ctypes.c_uint64), ('identifier', ctypes.c_ubyte * 16)]


def _local_path(path: PureWindowsPath) -> None:
    if not path.name or bool(path.drive) != bool(path.root) or (
        path.drive and re.fullmatch(r'[A-Za-z]:', path.drive) is None
    ):
        raise AcquisitionError('PT-ACQ-INPUT', 'select a file on a local drive')
    for component in path.parts[1 if path.anchor else 0:]:
        decode_member_name(component.encode('utf-8'), utf8=True)


def _identity(win, handle: int, maximum: int) -> PackageFileIdentity:
    kernel = win.kernel
    wt = win.wt
    kernel.GetFileType.argtypes = [wt.HANDLE]
    kernel.GetFileType.restype = wt.DWORD
    if kernel.GetFileType(handle) != 1:  # FILE_TYPE_DISK
        raise AcquisitionError('PT-ACQ-INPUT', 'package source must be an ordinary disk file')
    info = win.FileInfo()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
        win.error()
    if info.Attributes & (0x400 | 0x10 | 0x40):  # reparse point, directory, or device
        raise AcquisitionError('PT-ACQ-INPUT', 'package source must be an ordinary disk file')
    size = (info.SizeHigh << 32) | info.SizeLow
    if size < 36:
        raise AcquisitionError('PT-ACQ-INPUT', 'package source is shorter than a cabinet header')
    if size > maximum:
        raise AcquisitionError('PT-ACQ-LIMIT', 'package source exceeds the input size limit')
    query = kernel.GetFileInformationByHandleEx
    query.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
    query.restype = wt.BOOL
    native = _FileIdInfo()
    if not query(handle, 18, ctypes.byref(native), ctypes.sizeof(native)):  # FileIdInfo
        win.error()
    return PackageFileIdentity(volume_serial=native.volume, file_id=bytes(native.identifier).hex(),
                               size=size, last_write_ticks=(info.Write.dwHighDateTime << 32) | info.Write.dwLowDateTime)


def _hash_cabinet(fd: int, size: int, budget: PackageBudget) -> str:
    digest = hashlib.sha256()
    prefix = bytearray()
    remaining = size
    while remaining:
        budget.check()
        piece = os.read(fd, min(_CHUNK, remaining))
        if not piece:
            raise AcquisitionError('PT-ACQ-VERIFY', 'package source ended before its captured size')
        budget.charge_hash(len(piece))
        if len(prefix) < 4:
            prefix.extend(piece[:4 - len(prefix)])
            if len(prefix) == 4 and prefix != b'MSCF':
                raise AcquisitionError('PT-ACQ-INPUT', 'package source lacks the cabinet signature')
        digest.update(piece)
        remaining -= len(piece)
    budget.check()
    if os.read(fd, 1):
        budget.charge_hash(1)
        raise AcquisitionError('PT-ACQ-VERIFY', 'package source exceeds its captured size')
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


@contextmanager
def open_package_source(path: Path, budget: PackageBudget):
    """Yield (source record, borrowed read-only HANDLE) while retaining the original and its parents."""
    require_supported_platform()
    import msvcrt

    budget.callback()
    with ExitStack() as stack:
        try:
            # Validate the spelling before making a relative path absolute. Do not resolve links.
            _local_path(PureWindowsPath(path))
            target = path.absolute()
            _local_path(PureWindowsPath(target))
            win = WindowsPublication()
            win.kernel.GetDriveTypeW.argtypes = [win.wt.LPCWSTR]
            win.kernel.GetDriveTypeW.restype = win.wt.UINT
            if win.kernel.GetDriveTypeW(target.anchor) not in (2, 3, 5, 6):  # removable, fixed, CD, RAM
                raise AcquisitionError('PT-ACQ-INPUT', 'package source requires a local drive')
            parent = win.directory(target.parent, stack, create=False)
            handle = win.open_child(parent, target.name, directory=False, create=False)
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                win.kernel.CloseHandle(handle)
                raise
            stack.callback(os.close, fd)  # The CRT owns the same handle after successful transfer.
            maximum = budget.limits.max_source_bytes
            before = _identity(win, handle, maximum)
            digest = _hash_cabinet(fd, before.size, budget)
            if _identity(win, handle, maximum) != before:
                raise AcquisitionError('PT-ACQ-VERIFY', 'package source changed during hashing')
            source = PackageSource(sha256=digest, size=before.size, file_identity=before, display_name=target.name)
        except AcquisitionError as exc:
            budget.fail_source(exc)
        except (OSError, ValueError, OwnedPublicationError):
            budget.fail_source(AcquisitionError('PT-ACQ-VERIFY', 'could not capture an ordinary local package source'))
        budget.check()
        yield source, handle
        try:
            win.check_parent(target.parent, parent)
            named = win.open_child(parent, target.name, directory=False, create=False)
            stack.callback(win.kernel.CloseHandle, named)
            if _identity(win, handle, maximum) != before or _identity(win, named, maximum) != before:
                raise AcquisitionError('PT-ACQ-VERIFY', 'package source identity changed')
        except AcquisitionError as exc:
            budget.fail_source(exc)
        except (OSError, ValueError, OwnedPublicationError):
            budget.fail_source(AcquisitionError('PT-ACQ-VERIFY', 'could not recheck the selected package source'))
        budget.check()


def inspect_source(path: Path, *, cancel: Event | None = None) -> PackageSource:
    """Return a record only after rechecking the original and releasing its handles."""
    with open_package_source(path, PackageBudget(PackageLimits(), cancel=cancel)) as (source, _handle):
        return source
