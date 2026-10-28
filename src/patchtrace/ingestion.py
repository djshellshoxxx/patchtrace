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
    # Checked here, not left to the OS: Windows accepts lone surrogates in names that POSIX file systems refuse.
    try:
        too_long = any(len(part.encode('utf-8')) > 255 for part in rel.parts)
    except UnicodeEncodeError:
        too_long = True
    if '\x00' in relative or too_long:
        raise ValueError('PT-STORAGE: project path has an invalid or over-long component')
    candidate = base / rel
    try:
        for part in (candidate, *candidate.parents):
            if part == base:
                break
            if part.is_symlink():
                raise ValueError('PT-STORAGE: project files cannot be symlinks')
        contained = candidate.resolve().is_relative_to(base)
    except (OSError, UnicodeError):
        raise ValueError('PT-STORAGE: project path cannot be checked on this file system') from None
    if not contained:
        raise ValueError('PT-STORAGE: project path escapes project root')
    return candidate


def display_text(text: str) -> str:
    """Keep code units UTF-8 cannot encode (invalid file-name bytes, lone surrogates) visible and storable."""
    return text.encode('utf-8', 'backslashreplace').decode('utf-8')


def file_fingerprint(path: Path) -> tuple:
    if os.name == 'nt':
        # Python 3.12 Windows st_ctime is creation time, not metadata/content change time.
        # Use NTFS FILE_BASIC_INFO.ChangeTime so restoring mtime cannot bypass verification.
        import ctypes
        import msvcrt
        from ctypes import wintypes
        class FileBasicInfo(ctypes.Structure):
            _fields_ = [('creation', ctypes.c_int64), ('access', ctypes.c_int64),
                        ('write', ctypes.c_int64), ('change', ctypes.c_int64),
                        ('attributes', wintypes.DWORD)]
        info = FileBasicInfo()
        get_info = ctypes.WinDLL('kernel32', use_last_error=True).GetFileInformationByHandleEx
        get_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        get_info.restype = wintypes.BOOL
        with path.open('rb') as stream:
            stat = os.fstat(stream.fileno())
            if not get_info(msvcrt.get_osfhandle(stream.fileno()), 0, ctypes.byref(info), ctypes.sizeof(info)):
                raise OSError(ctypes.get_last_error(), 'Cannot query immutable file change time')
        return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, info.change
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


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
        if optional_size < 112 or offset + 24 + optional_size > size:
            raise ValueError('PT-INPUT: truncated PE optional header')
        if struct.unpack_from('<H', pe, 24)[0] != 0x20B:
            raise ValueError('PT-INPUT: PE32+ optional header required')
        section_count = struct.unpack_from('<H', pe, 6)[0]
        section_offset = offset + 24 + optional_size
        if section_count < 1 or section_offset + section_count * 40 > size:
            raise ValueError('PT-INPUT: PE section table is truncated or empty')
        stream.seek(offset + 24 + 108)
        directories = struct.unpack('<I', stream.read(4))[0]
        if directories > (optional_size - 112) // 8:
            raise ValueError('PT-INPUT: PE data directory count exceeds optional header')
        stream.seek(section_offset)
        for _ in range(section_count):
            section = stream.read(40)
            raw_size, raw_offset = struct.unpack_from('<II', section, 16)
            if raw_size and (raw_offset > size or raw_size > size - raw_offset):
                raise ValueError('PT-INPUT: PE section raw data is out of bounds')


def inspect_artifact(path: Path, side: str, root: Path) -> Artifact:
    if side not in {'older', 'newer'}:
        raise ValueError('PT-INPUT: explicit older/newer side required')
    source = Path(path)
    root = Path(root).resolve()
    stage: Path | None = None
    try:
        before = source.stat()
        before_fingerprint = file_fingerprint(source)
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
        if (fingerprint(before) != fingerprint(after) or fingerprint(opened) != fingerprint(after_open)
                or before_fingerprint != file_fingerprint(source)):
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
        return Artifact(side=side, name=display_text(source.name), sha256=sha, size=copied, relative_path=relative)
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
