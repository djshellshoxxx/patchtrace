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


def _stat_key(stream: BinaryIO) -> tuple[int, int]:
    info = os.fstat(stream.fileno())
    return info.st_size, info.st_mtime_ns


class VerifiedArtifactReader:
    """Read-only bytes of one file whose SHA-256 was verified on this handle.

    Thread-safety: ``read`` serializes seeks with a lock so one reader may be
    shared by a single worker thread and inspected from another; Qt code should
    still perform reads off the GUI thread.
    """

    def __init__(self, stream: BinaryIO, size: int, sha256: str, label: str):
        self._stream: BinaryIO | None = stream
        self._size = size
        self._sha256 = sha256
        self._label = label
        self._stat = _stat_key(stream)
        self._lock = threading.Lock()

    # -- construction -----------------------------------------------------
    @classmethod
    def open_path(cls, path: Path, expected_sha256: str | None = None,
                  expected_size: int | None = None,
                  cancel: Callable[[], bool] | None = None) -> VerifiedArtifactReader:
        """Open ``path`` read-only, hash it on the same handle and verify identity."""
        try:
            stream = Path(path).open('rb')
        except OSError as exc:
            raise ArtifactBytesError('unreadable', f'cannot open input: {exc.strerror or exc}') from exc
        try:
            size, _ = _stat_key(stream)
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
            reader = cls(stream, size, actual, Path(path).name)
            if reader._stat[0] != size:
                raise ArtifactBytesError('artifact_changed', 'file size changed during verification')
            return reader
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
