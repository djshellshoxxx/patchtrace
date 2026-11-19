"""Publish a complete private directory without replacing a destination entry.

The caller owns the stable parent and private stage throughout publication and
cleanup. This boundary supplies an atomic no-replacement move, not protection
against a hostile process replacing those parent/source paths.
"""
from __future__ import annotations

import errno
import os
import stat
import sys
from pathlib import Path


def _native_move(stage: Path, destination: Path) -> None:
    if sys.platform == 'win32':
        # Python's Windows rename refuses any existing destination entry.
        os.rename(stage, destination)
        return
    if sys.platform != 'linux':
        raise OSError(errno.ENOTSUP, 'exclusive directory publication is unavailable')
    import ctypes

    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        raise OSError(errno.ENOTSUP, 'exclusive directory publication is unavailable') from None
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    # AT_FDCWD, RENAME_NOREPLACE; never downgrade on an unsupported filesystem.
    if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno() or errno.EIO
        raise OSError(code, os.strerror(code), os.fspath(stage), None, os.fspath(destination))


def publish_directory_no_replace(stage: Path, destination: Path) -> None:
    """Move an ordinary private stage to its absent sibling in one native call."""
    stage, destination = Path(stage), Path(destination)
    if '\0' in os.fspath(stage) or '\0' in os.fspath(destination):
        raise ValueError('directory publication paths contain an embedded NUL')
    if (not stage.is_absolute() or not destination.is_absolute()
            or stage == destination or stage.parent != destination.parent):
        raise ValueError('directory publication requires distinct absolute sibling paths')
    info = stage.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise NotADirectoryError(errno.ENOTDIR, 'publication stage must be an ordinary directory', os.fspath(stage))
    _native_move(stage, destination)
