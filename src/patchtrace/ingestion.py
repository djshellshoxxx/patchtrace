"""Static PE validation and immutable, content-addressed input copies."""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import sys
import tempfile
from contextlib import contextmanager
from itertools import chain
from pathlib import Path

from .hostile_text import is_hostile
from .input_readers import HeldInput, InputReadError, ReadCheckpoint
from .models import Artifact
from .offline_bundle import windows_unsafe_component

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
    # TB-12: also on POSIX, because the project is opened on Windows later, where `runs/x/CON` is the console
    # device and `raw.json.` names another file than the one written.
    if '\x00' in relative or too_long or any(windows_unsafe_component(part) for part in rel.parts):
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
    """Keep code units UTF-8 cannot encode (invalid file-name bytes, lone surrogates) visible and storable;
    control, bidirectional and other format characters become `?` (the file is addressed by path and hash)."""
    escaped = text.encode('utf-8', 'backslashreplace').decode('utf-8')
    return ''.join('?' if is_hostile(char) else char for char in escaped)


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


def _read(stream, size: int, checkpoint: ReadCheckpoint | None = None) -> bytes:
    if checkpoint is not None:
        checkpoint(0)
    data = stream.read(size)
    if type(data) is not bytes or len(data) > size:
        raise InputReadError('invalid')
    if checkpoint is not None:
        checkpoint(len(data))
    return data


def _exact_read(stream, size: int, checkpoint: ReadCheckpoint | None) -> bytes:
    data = _read(stream, size, checkpoint)
    if len(data) != size:
        raise ValueError('PT-INPUT: PE header or section data is truncated')
    return data


def sha256_file(path: Path, *, checkpoint: ReadCheckpoint | None = None) -> str:
    digest = hashlib.sha256()
    if checkpoint is not None:
        checkpoint(0)
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: _read(stream, CHUNK_SIZE, checkpoint), b''):
            digest.update(chunk)
    if checkpoint is not None:
        checkpoint(0)
    return digest.hexdigest()


def validate_pe(path: Path, *, reader: HeldInput | None = None,
                checkpoint: ReadCheckpoint | None = None) -> None:
    """Validate bounded DOS/PE headers; never load or execute the input."""
    path = Path(path)
    if checkpoint is not None:
        checkpoint(0)
    if reader is not None:
        reader.check(path)
    with (path.open('rb') if reader is None else reader.open_reader(path)) as stream:
        before = os.fstat(stream.fileno())
        if reader is not None and not stat.S_ISREG(before.st_mode):
            raise ValueError('PT-INPUT: input must be a regular file')
        size = before.st_size
        if size < 64 or size > MAX_ARTIFACT_BYTES:
            raise ValueError('PT-INPUT: PE input size is invalid (maximum 1 GiB)')
        # The provider already accounts held reads. Only ordinary path reads charge here.
        charge = checkpoint if reader is None else None
        header = _exact_read(stream, 64, charge)
        if header[:2] != b'MZ':
            raise ValueError('PT-INPUT: missing DOS MZ header')
        offset = struct.unpack_from('<I', header, 0x3C)[0]
        if offset < 64 or offset > size - 26:
            raise ValueError('PT-INPUT: PE header offset is out of bounds')
        stream.seek(offset)
        pe = _exact_read(stream, 26, charge)
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
        directories = struct.unpack('<I', _exact_read(stream, 4, charge))[0]
        if directories > (optional_size - 112) // 8:
            raise ValueError('PT-INPUT: PE data directory count exceeds optional header')
        stream.seek(section_offset)
        for _ in range(section_count):
            section = _exact_read(stream, 40, charge)
            raw_size, raw_offset = struct.unpack_from('<II', section, 16)
            if raw_size and (raw_offset > size or raw_size > size - raw_offset):
                raise ValueError('PT-INPUT: PE section raw data is out of bounds')
        if reader is not None and _file_state(before) != _file_state(os.fstat(stream.fileno())):
            raise InputReadError('changed')
    if reader is not None:
        reader.check(path)
    if checkpoint is not None:
        checkpoint(0)


def _validate_pe_prefix(header: bytes, size: int) -> None:
    """Reject invalid headers in the first 64 KiB before writing the input copy."""
    if size < 64 or len(header) < 64:
        raise ValueError('PT-INPUT: PE input size is invalid (maximum 1 GiB)')
    if header[:2] != b'MZ':
        raise ValueError('PT-INPUT: missing DOS MZ header')
    offset = struct.unpack_from('<I', header, 0x3C)[0]
    if offset < 64 or offset > size - 26:
        raise ValueError('PT-INPUT: PE header offset is out of bounds')
    if offset + 26 > len(header):
        return  # A later header is checked by validate_pe on the completed copy.
    pe = header[offset:offset + 26]
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
    if section_count < 1 or offset + 24 + optional_size + section_count * 40 > size:
        raise ValueError('PT-INPUT: PE section table is truncated or empty')


def _file_state(info) -> tuple:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def _source_stream(source: Path, reader: HeldInput | None, checkpoint: ReadCheckpoint | None):
    if checkpoint is not None:
        checkpoint(0)
    before = before_fingerprint = None
    if reader is None:
        before = source.stat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('PT-INPUT: input must be a regular file')
        before_fingerprint = file_fingerprint(source)
        if not 1 <= before.st_size <= MAX_ARTIFACT_BYTES:
            raise ValueError('PT-INPUT: input exceeds 1 GiB or is empty')
    else:
        reader.check(source)
    with (source.open('rb') if reader is None else reader.open_reader(source)) as original:
        opened = os.fstat(original.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError('PT-INPUT: input must be a regular file')
        if not 1 <= opened.st_size <= MAX_ARTIFACT_BYTES:
            raise ValueError('PT-INPUT: input exceeds 1 GiB or is empty')
        if before is not None and _file_state(opened)[:4] != _file_state(before)[:4]:
            raise ValueError('PT-INPUT: source changed before copying')
        yield original, opened.st_size
        after_open = os.fstat(original.fileno())
    if _file_state(opened) != _file_state(after_open):
        raise ValueError('PT-INPUT: source changed while copying; try again')
    if reader is None:
        if (_file_state(before) != _file_state(source.stat())
                or before_fingerprint != file_fingerprint(source)):
            raise ValueError('PT-INPUT: source changed while copying; try again')
    else:
        reader.check(source)
    if checkpoint is not None:
        checkpoint(0)


def inspect_artifact(path: Path, side: str, root: Path, *,
                     created: list[tuple[Path, os.stat_result]] | None = None,
                     reader: HeldInput | None = None, checkpoint: ReadCheckpoint | None = None) -> Artifact:
    if side not in {'older', 'newer'}:
        raise ValueError('PT-INPUT: explicit older/newer side required')
    source = Path(path)
    root = Path(root).resolve()
    stage: Path | None = None
    try:
        with _source_stream(source, reader, checkpoint) as (original, size):
            destdir = safe_path(root, 'artifacts')
            destdir.parent.mkdir(parents=True, exist_ok=True)
            try:
                destdir.mkdir()
            except FileExistsError:
                pass
            else:
                if created is not None:
                    created.append((destdir, destdir.stat()))
            fd, temporary = tempfile.mkstemp(prefix='.input-', dir=destdir)
            stage = Path(temporary)
            digest = hashlib.sha256()
            copied = 0
            charge = checkpoint if reader is None else None
            with os.fdopen(fd, 'wb') as target:
                header = _read(original, 65536, charge)
                _validate_pe_prefix(header, size)
                for chunk in chain((header,), iter(lambda: _read(original, CHUNK_SIZE, charge), b'')):
                    copied += len(chunk)
                    if copied > MAX_ARTIFACT_BYTES:
                        raise ValueError('PT-INPUT: source grew beyond 1 GiB while copying')
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                if checkpoint is not None:
                    checkpoint(0)
                os.fsync(target.fileno())
        if copied != size:
            raise ValueError('PT-INPUT: incomplete input copy')
        validate_pe(stage, **({'checkpoint': checkpoint} if checkpoint is not None else {}))
        sha = digest.hexdigest()
        relative = f'artifacts/{sha}.bin'
        destination = safe_path(root, relative)
        published = stage.stat()
        if checkpoint is not None:
            checkpoint(0)
        try:
            os.link(stage, destination)  # exclusive publication; never replace a concurrent file
        except FileExistsError:
            destination = safe_path(root, relative)
            if destination.stat().st_size != copied or sha256_file(
                    destination, **({'checkpoint': checkpoint} if checkpoint is not None else {})) != sha:
                raise ValueError('PT-STORAGE: existing immutable artifact has changed') from None
            stage.unlink()
        else:
            if created is not None:
                created.append((destination, published))
            stage.unlink()
            stage = None
            destination.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        stage = None
        return Artifact(side=side, name=display_text(source.name), sha256=sha, size=copied, relative_path=relative)
    except OSError as exc:
        raise ValueError(f'PT-INPUT: cannot read or preserve input: {exc.strerror or exc}') from exc
    finally:
        if stage is not None:
            primary = sys.exception()
            try:
                stage.unlink(missing_ok=True)
            except OSError:
                if primary is None:
                    raise
                primary.add_note('PT-STORAGE: input staging cleanup failed; temporary bytes may remain')


def verify_artifact(artifact: Artifact, root: Path, *, checkpoint: ReadCheckpoint | None = None) -> None:
    if checkpoint is not None:
        checkpoint(0)
    path = safe_path(root, artifact.relative_path)
    if artifact.relative_path != f'artifacts/{artifact.sha256}.bin':
        raise ValueError('PT-STORAGE: artifact path does not match its content hash')
    try:
        options = {'checkpoint': checkpoint} if checkpoint is not None else {}
        if not path.is_file() or path.stat().st_size != artifact.size or sha256_file(path, **options) != artifact.sha256:
            raise ValueError('PT-STORAGE: immutable input is missing or has changed')
        validate_pe(path, **options)
    except OSError as exc:
        raise ValueError('PT-STORAGE: immutable input is not readable') from exc
