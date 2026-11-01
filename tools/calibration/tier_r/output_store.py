"""Retain normalized Tier R evidence with atomic, non-replacing publication.

Selectively adapts the intent of PR #78 (repository MIT license), not its
check-then-replace writer. There is no fallback when atomic hard links are absent.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tempfile
from pathlib import Path

from . import contracts as C
from . import report_schemas as RS

MAX_ENGINE_OUTPUT_BYTES = 64 * 1024 * 1024
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z')
_ENGINES = frozenset(('rz-diff', 'bindiff', 'ghidriff', 'attention'))


class OutputError(ValueError):
    """Evidence could not be retained; it must not receive successful-run credit."""


def output_file_name(pair_id: str, engine: str) -> str:
    if not isinstance(pair_id, str) or not _NAME.fullmatch(pair_id):
        raise OutputError('invalid pair identifier for output filename')
    if engine not in _ENGINES:
        raise OutputError('engine has no normalized output storage contract')
    return f'{pair_id}.{engine}.json'


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def canonical_output_bytes(document: dict) -> bytes:
    """The existing canonical JSON format, with an incremental total-byte cap."""
    stream = io.BytesIO()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    try:
        for chunk in encoder.iterencode(document):
            encoded = chunk.encode('utf-8')
            if stream.tell() + len(encoded) > MAX_ENGINE_OUTPUT_BYTES:
                raise OutputError(f'normalized output exceeds {MAX_ENGINE_OUTPUT_BYTES} bytes')
            stream.write(encoded)
    except (TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, OutputError):
            raise
        raise OutputError(f'normalized output is not canonical JSON: {type(exc).__name__}') from None
    return stream.getvalue()


def publish_bytes(path: Path, raw: bytes) -> str:
    """Publish complete bytes without replacing any existing file, link or device.

    A flushed/fsynced private stage is hard-linked into place atomically. Verify
    the linked inode and its actual bytes before success. A failed final artifact
    is retained without credit; only the owned temporary name is cleaned up.
    """
    path = Path(path)
    expected = hashlib.sha256(raw).hexdigest()
    pending = None
    owned = None
    descriptor = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix='.pending-', suffix='.tmp', dir=path.parent)
        pending = Path(name)
        with os.fdopen(descriptor, 'w+b') as handle:
            descriptor = None
            owned = _identity(os.fstat(handle.fileno()))
            if handle.write(raw) != len(raw):
                raise OutputError('short evidence write')
            handle.flush()
            os.fsync(handle.fileno())
            stage = pending.lstat()
            if _linked(stage) or not stat.S_ISREG(stage.st_mode) or _identity(stage) != owned:
                raise OutputError('evidence stage identity changed')
            os.link(pending, path, follow_symlinks=False)
            published = path.lstat()
            if _linked(published) or _identity(published) != owned:
                raise OutputError('published evidence identity changed')
            before = os.fstat(handle.fileno())
            handle.seek(0)
            actual = hashlib.sha256()
            count = 0
            while chunk := handle.read(min(1024 * 1024, len(raw) + 1 - count)):
                count += len(chunk)
                actual.update(chunk)
                if count > len(raw):
                    break
            after = os.fstat(handle.fileno())
            if (count != len(raw) or actual.hexdigest() != expected or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
                raise OutputError('published evidence bytes changed')
            if _identity(path.lstat()) != owned:
                raise OutputError('published evidence identity changed')
        return expected
    except (OSError, NotImplementedError) as exc:
        raise OutputError(f'evidence publication failed: {type(exc).__name__}') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if pending is not None:
            try:
                if owned is None or _identity(pending.lstat()) == owned:
                    pending.unlink()
            except OSError:
                # A leftover .tmp is not a successful normalized JSON artifact.
                # Never remove the published path or another completed output.
                pass


class OutputStore:
    """One exclusively created run directory; never adopt an existing empty one."""

    def __init__(self, folder: Path):
        self.folder = Path(folder)
        try:
            self.folder.mkdir(parents=True, mode=0o700, exist_ok=False)
            info = self.folder.lstat()
            if _linked(info) or not stat.S_ISDIR(info.st_mode):
                raise OutputError('output directory is linked or not a directory')
            self._owner = _identity(info)
        except OSError as exc:
            raise OutputError(f'a fresh output directory is required: {type(exc).__name__}') from None

    def _check_owner(self) -> None:
        try:
            info = self.folder.lstat()
        except OSError as exc:
            raise OutputError(f'output directory unavailable: {type(exc).__name__}') from None
        if _linked(info) or not stat.S_ISDIR(info.st_mode) or _identity(info) != self._owner:
            raise OutputError('output directory ownership changed')

    def write(self, pair_id: str, engine: str, document: dict) -> str:
        filename = output_file_name(pair_id, engine)
        self._check_owner()
        raw = canonical_output_bytes(document)
        try:
            parsed = RS.load_engine_output(raw)
        except C.ContractError as exc:
            raise OutputError(f'normalized output contract invalid: {str(exc)[:250]}') from None
        if parsed.engine != engine:
            raise OutputError('normalized output engine differs from its provider owner')
        digest = publish_bytes(self.folder / filename, raw)
        self._check_owner()
        return digest
