"""Static PE validation and immutable, content-addressed input copies."""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import tempfile
from pathlib import Path

from .models import Artifact

MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


def safe_path(root: Path, relative: str) -> Path:
    """Resolve a persisted relative path without allowing traversal or symlinks."""
    base = Path(root).resolve()
    rel = Path(relative)
    if not relative or rel.is_absolute() or '..' in rel.parts or '\\' in relative or ':' in relative:
        raise ValueError('PT-STORAGE: project path must be relative and contained')
    candidate = base / rel
    for part in (candidate, *candidate.parents):
        if part == base:
            break
        if part.is_symlink():
            raise ValueError('PT-STORAGE: project files cannot be symlinks')
    if not candidate.resolve().is_relative_to(base):
        raise ValueError('PT-STORAGE: project path escapes project root')
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate_pe(path: Path) -> None:
    """Validate bounded DOS/PE headers; never load or execute the input."""
    with Path(path).open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        if size < 64 or size > MAX_ARTIFACT_BYTES:
            raise ValueError('PT-INPUT: PE input size is invalid (maximum 1 GiB)')
        header = stream.read(64)
        if header[:2] != b'MZ':
            raise ValueError('PT-INPUT: missing DOS MZ header')
        offset = struct.unpack_from('<I', header, 0x3C)[0]
        if offset < 64 or offset > size - 26:
            raise ValueError('PT-INPUT: PE header offset is out of bounds')
        stream.seek(offset)
        pe = stream.read(26)
        if pe[:4] != b'PE\0\0':
            raise ValueError('PT-INPUT: missing PE signature')
        if struct.unpack_from('<H', pe, 4)[0] != 0x8664:
            raise ValueError('PT-INPUT: only PE AMD64 inputs are supported')
        optional_size = struct.unpack_from('<H', pe, 20)[0]
        if optional_size < 2 or offset + 24 + optional_size > size:
            raise ValueError('PT-INPUT: truncated PE optional header')
        if struct.unpack_from('<H', pe, 24)[0] != 0x20B:
            raise ValueError('PT-INPUT: PE32+ optional header required')


def inspect_artifact(path: Path, side: str, root: Path) -> Artifact:
    if side not in {'older', 'newer'}:
        raise ValueError('PT-INPUT: explicit older/newer side required')
    source = Path(path)
    root = Path(root).resolve()
    stage: Path | None = None
    try:
        before = source.stat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('PT-INPUT: input must be a regular file')
        if not 1 <= before.st_size <= MAX_ARTIFACT_BYTES:
            raise ValueError('PT-INPUT: input exceeds 1 GiB or is empty')
        destdir = safe_path(root, 'artifacts')
        destdir.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.input-', dir=destdir)
        stage = Path(temporary)
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(fd, 'wb') as target, source.open('rb') as original:
            opened = os.fstat(original.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
            ):
                raise ValueError('PT-INPUT: source changed before copying')
            for chunk in iter(lambda: original.read(CHUNK_SIZE), b''):
                copied += len(chunk)
                if copied > MAX_ARTIFACT_BYTES:
                    raise ValueError('PT-INPUT: source grew beyond 1 GiB while copying')
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
            after_open = os.fstat(original.fileno())
        after = source.stat()
        def fingerprint(s):
            return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
        if fingerprint(before) != fingerprint(after) or fingerprint(before) != fingerprint(after_open):
            raise ValueError('PT-INPUT: source changed while copying; try again')
        if copied != before.st_size:
            raise ValueError('PT-INPUT: incomplete input copy')
        validate_pe(stage)
        sha = digest.hexdigest()
        relative = f'artifacts/{sha}.bin'
        destination = safe_path(root, relative)
        if destination.exists():
            if destination.stat().st_size != copied or sha256_file(destination) != sha:
                raise ValueError('PT-STORAGE: existing immutable artifact has changed')
            stage.unlink()
        else:
            os.replace(stage, destination)
            destination.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        stage = None
        return Artifact(side=side, name=source.name, sha256=sha, size=copied, relative_path=relative)
    except OSError as exc:
        raise ValueError(f'PT-INPUT: cannot read or preserve input: {exc.strerror or exc}') from exc
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)


def verify_artifact(artifact: Artifact, root: Path) -> None:
    path = safe_path(root, artifact.relative_path)
    if artifact.relative_path != f'artifacts/{artifact.sha256}.bin':
        raise ValueError('PT-STORAGE: artifact path does not match its content hash')
    try:
        if not path.is_file() or path.stat().st_size != artifact.size or sha256_file(path) != artifact.sha256:
            raise ValueError('PT-STORAGE: immutable input is missing or has changed')
        validate_pe(path)
    except OSError as exc:
        raise ValueError('PT-STORAGE: immutable input is not readable') from exc
