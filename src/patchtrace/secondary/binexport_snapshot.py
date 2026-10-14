"""TOCTOU-safe bounded snapshot of an untrusted `.BinExport` (SPEC-10b §6.3). Stdlib only.

The source is opened once (no symlink following where the OS supports it), checked as a regular file on the
open handle, and copied into a fresh private directory while hashing. What was validated is the snapshot, and
the snapshot is what BinDiff later reads.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .binexport_limits import BinExportLimits, Budget, err

CHUNK = 4 * 1024 * 1024
TICK_UNITS = 8192  # one budget check per chunk


@dataclass(frozen=True, slots=True)
class Snapshot:
    path: Path
    sha256: str
    size: int


def take_snapshot(src: Path | str, dst: Path | str, limits: BinExportLimits, budget: Budget | None = None) -> Snapshot:
    budget = budget or Budget()
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    if hasattr(os, 'O_NONBLOCK'):
        flags |= os.O_NONBLOCK  # a FIFO must not block the open; it is rejected by the S_ISREG check below
    try:
        fd = os.open(src, flags)
    except OSError as exc:
        if os.path.isdir(src):  # Windows cannot open a directory at all; classify it like POSIX does
            raise err('PT-SECONDARY-INPUT', 'not_regular_file', 'BinExport path is not a regular file') from None
        raise err('PT-SECONDARY-INPUT', 'unreadable', f'cannot open BinExport file: {exc.strerror}') from None
    st = os.fstat(fd)  # fstat the OPEN handle, never the path
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise err('PT-SECONDARY-INPUT', 'not_regular_file', 'BinExport path is not a regular file')
    with os.fdopen(fd, 'rb', buffering=0) as handle:
        if st.st_size == 0:
            raise err('PT-SECONDARY-INPUT', 'empty_file', 'BinExport file is empty')
        if st.st_size > limits.max_file_bytes:
            raise err('PT-SECONDARY-LIMIT', 'too_large', f'BinExport file exceeds {limits.max_file_bytes} bytes')
        digest = hashlib.sha256()
        total = 0
        try:
            out = open(dst, 'xb')  # noqa: SIM115 - 'x': never overwrite; dst lives in a fresh 0700 directory
        except OSError as exc:
            raise err('PT-SECONDARY-RUN', 'worker_crash', f'cannot create snapshot: {exc.strerror}') from None
        try:
            with out:
                while chunk := handle.read(CHUNK):
                    total += len(chunk)
                    if total > limits.max_file_bytes:  # the file grew while being read
                        raise err('PT-SECONDARY-LIMIT', 'too_large',
                                  f'BinExport file exceeds {limits.max_file_bytes} bytes')
                    digest.update(chunk)
                    out.write(chunk)
                    budget.tick(TICK_UNITS)
            if total != st.st_size:
                raise err('PT-SECONDARY-INPUT', 'file_changed_during_read',
                          'BinExport file changed while being read')
        except BaseException:
            Path(dst).unlink(missing_ok=True)  # no partial snapshot survives a failure
            raise
    return Snapshot(Path(dst), digest.hexdigest(), total)
