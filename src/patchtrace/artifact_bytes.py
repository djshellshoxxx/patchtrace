"""Verified, bounded, read-only access to immutable artifact bytes (SPEC-26 shared seam).

Responsibility: give PE inspection and raw byte representations one audited way
to read the exact bytes of a project-owned artifact (or an explicit local file
before a project exists). The reader hashes the file through the same open
handle it later reads from, rejects changes detected after verification, clips
or rejects out-of-range requests, and caps every single read.

Error contract: every failure raises :class:`ArtifactBytesError` with a stable
``code``. Callers must surface the code and never substitute guessed bytes.

Codes: ``path_invalid``, ``unreadable``, ``hash_mismatch``, ``size_mismatch``,
``artifact_changed``, ``range_invalid``, ``read_too_large``, ``closed``,
``cancelled``.

No Qt imports, no execution, no network.
"""
from __future__ import annotations

import hashlib
import os
import stat
import threading
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from .ingestion import safe_path
from .models import Artifact

MAX_READ_BYTES = 16 * 1024 * 1024
HASH_CHUNK = 1024 * 1024


class ArtifactBytesError(Exception):
    """Stable, user-presentable failure reading verified artifact bytes."""

    def __init__(self, code: str, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code


def _stat_key(stream: BinaryIO) -> tuple[int, int, int]:
    """Identity of the open file's current state.

    ``st_mtime_ns`` alone can be restored with ``utime`` after an in-place edit. On POSIX
    ``st_ctime_ns`` is the inode change time and cannot be set by user code, so it detects
    that. On Windows ``st_ctime_ns`` is the creation time and adds nothing; there an
    in-place edit that preserves size and mtime is a documented residual risk (artifacts
    are project-owned read-only copies).
    """
    info = os.fstat(stream.fileno())
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns


class VerifiedArtifactReader:
    """Read-only bytes of one file whose SHA-256 was verified on this handle.

    Thread-safety: ``read`` serializes seeks with a lock so one reader may be
    shared by a single worker thread and inspected from another; Qt code should
    still perform reads off the GUI thread.
    """

    def __init__(self, stream: BinaryIO, size: int, sha256: str, label: str, stat: tuple[int, int, int]):
        self._stream: BinaryIO | None = stream
        self._size = size
        self._sha256 = sha256
        self._label = label
        self._stat = stat
        self._lock = threading.Lock()

    # -- construction -----------------------------------------------------
    @classmethod
    def open_path(cls, path: Path, expected_sha256: str | None = None,
                  expected_size: int | None = None,
                  cancel: Callable[[], bool] | None = None) -> VerifiedArtifactReader:
        """Open ``path`` read-only, hash it on the same handle and verify identity."""
        try:
            # O_NONBLOCK so a FIFO cannot hang the open; the regular-file check follows.
            descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0))
            stream = os.fdopen(descriptor, 'rb')
        except OSError as exc:
            raise ArtifactBytesError('unreadable', f'cannot open input: {exc.strerror or exc}') from exc
        try:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ArtifactBytesError('unreadable', 'input is not a regular file')
            baseline = _stat_key(stream)  # taken before hashing so a change during verification is caught
            size = baseline[0]
            if expected_size is not None and size != expected_size:
                raise ArtifactBytesError('size_mismatch', f'expected {expected_size} bytes, found {size}')
            digest = hashlib.sha256()
            while True:
                if cancel is not None and cancel():
                    raise ArtifactBytesError('cancelled', 'verification cancelled')
                chunk = stream.read(HASH_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
            actual = digest.hexdigest()
            if expected_sha256 is not None and actual != expected_sha256.lower():
                raise ArtifactBytesError('hash_mismatch', 'file content differs from the recorded SHA-256')
            if _stat_key(stream) != baseline:
                raise ArtifactBytesError('artifact_changed', 'file changed during verification')
            return cls(stream, size, actual, Path(path).name, baseline)
        except BaseException:
            stream.close()
            raise

    @classmethod
    def open_artifact(cls, artifact: Artifact, root: Path,
                      cancel: Callable[[], bool] | None = None) -> VerifiedArtifactReader:
        """Open a project-owned immutable artifact copy and verify its recorded identity."""
        try:
            path = safe_path(Path(root), artifact.relative_path)
        except ValueError as exc:
            raise ArtifactBytesError('path_invalid', str(exc)) from exc
        return cls.open_path(path, artifact.sha256, artifact.size, cancel)

    # -- properties ---------------------------------------------------------
    @property
    def size(self) -> int:
        return self._size

    @property
    def sha256(self) -> str:
        return self._sha256

    @property
    def label(self) -> str:
        return self._label

    # -- reading ------------------------------------------------------------
    def read(self, offset: int, length: int, *, clip: bool = True) -> bytes:
        """Return bytes ``[offset, offset+length)``.

        ``clip=True`` truncates a range running past end of file; ``clip=False``
        raises ``range_invalid`` instead. Offsets past EOF always raise.
        """
        if isinstance(offset, bool) or isinstance(length, bool) or not isinstance(offset, int) \
                or not isinstance(length, int):
            raise ArtifactBytesError('range_invalid', 'offset and length must be integers')
        if offset < 0 or length < 0 or offset > self._size:
            raise ArtifactBytesError('range_invalid', f'offset {offset} length {length} outside 0..{self._size}')
        if length > MAX_READ_BYTES:
            raise ArtifactBytesError('read_too_large', f'single read capped at {MAX_READ_BYTES} bytes')
        end = offset + length
        if end > self._size:
            if not clip:
                raise ArtifactBytesError('range_invalid', f'range ends at {end}, beyond {self._size}')
            end = self._size
        with self._lock:
            stream = self._stream
            if stream is None:
                raise ArtifactBytesError('closed', 'reader is closed')
            if _stat_key(stream) != self._stat:
                raise ArtifactBytesError('artifact_changed', 'file changed after verification')
            try:
                stream.seek(offset)
                data = stream.read(end - offset)
            except OSError as exc:
                raise ArtifactBytesError('unreadable', f'read failed: {exc.strerror or exc}') from exc
        if len(data) != end - offset:
            raise ArtifactBytesError('artifact_changed', 'short read; file changed after verification')
        return data

    def close(self) -> None:
        with self._lock:
            if self._stream is not None:
                self._stream.close()
                self._stream = None

    def __enter__(self) -> VerifiedArtifactReader:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
