"""Verified, explicit offline runtime import; no downloads, shell or subprocesses.

A self-hashed manifest detects corruption, NOT publisher authenticity. Users
should verify an out-of-band trusted archive SHA-256 before trusting a bundle.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import unicodedata
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

FORMAT = 'patchtrace-offline-runtime'
MAX_MANIFEST = 4 * 1024 * 1024
MAX_MEMBERS = 60_000
MAX_FILE = 2 * 1024**3
MAX_TOTAL = 8 * 1024**3
CHUNK = 1024 * 1024
HEX = re.compile(r'^[0-9a-f]{64}$')
ID = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$')
VERSION = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,95}$')
WINDOWS_RESERVED = {'CON', 'PRN', 'AUX', 'NUL'} | {
    f'{kind}{index}' for kind in ('COM', 'LPT') for index in range(1, 10)
}
MANIFEST_KEYS = {'format', 'schema_version', 'runtime_id', 'platform', 'architecture',
                 'python', 'ghidra', 'java', 'versions', 'files'}
VERSION_KEYS = {'python', 'ghidra', 'jdk', 'ghidriff_revision'}
REQUIRED_FILES = ('python/python.exe', 'ghidra/Ghidra/application.properties',
                  'jdk/bin/java.exe', 'LICENSES/NOTICE.txt')


class OfflineBundleError(ValueError):
    """A predictable, actionable PT-OFFLINE failure."""


@dataclass(frozen=True)
class BundleFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class OfflineBundlePlan:
    archive: Path
    sha256: str
    runtime_id: str
    files: tuple[BundleFile, ...]
    manifest_bytes: bytes

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.files)


@dataclass(frozen=True)
class InstalledRuntime:
    root: Path
    python_executable: Path
    ghidra_dir: Path
    java_home: Path
    manifest: Path
    archive_sha256: str


def _fail(message: str) -> None:
    raise OfflineBundleError('PT-OFFLINE: ' + message)


def _cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        _fail('installation cancelled; existing runtimes were preserved')


def _sha256_file(path: Path, cancel: threading.Event | None) -> str:
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(CHUNK):
            _cancel(cancel)
            hasher.update(chunk)
    _cancel(cancel)
    return hasher.hexdigest()


def _json_no_duplicates(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail('duplicate JSON manifest field')
            result[key] = value
        return result

    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: _fail('nonfinite manifest number'))
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, OfflineBundleError):
            raise
        _fail('invalid UTF-8 JSON manifest')
    if not isinstance(data, dict):
        _fail('manifest must be a JSON object')
    return data


def _safe_relative(name: str) -> str:
    """Validate literal portable POSIX paths, including Windows filesystem rules."""
    if not isinstance(name, str) or not name or len(name) > 512 or name.startswith('/'):
        _fail('unsafe archive path')
    if '\\' in name or '//' in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        _fail('unsafe archive path')
    parts = name.split('/')
    if any(part in ('', '.', '..') or part.endswith((' ', '.')) or ':' in part
           or any(char in part for char in '<>"|?*')
           or part.split('.')[0].upper() in WINDOWS_RESERVED for part in parts):
        _fail('unsafe archive path')
    return name


def _validated_manifest(data: dict) -> tuple[str, tuple[BundleFile, ...]]:
    if set(data) != MANIFEST_KEYS:
        _fail('unsupported manifest fields')
    if data['format'] != FORMAT or type(data['schema_version']) is not int or data['schema_version'] != 1:
        _fail('unsupported bundle format or schema')
    if data['platform'] != 'windows' or data['architecture'] != 'amd64':
        _fail('this bundle is not a Windows x64 backend')
    runtime_id = data['runtime_id']
    if (not isinstance(runtime_id, str) or not ID.fullmatch(runtime_id)
            or runtime_id.endswith('.') or runtime_id.split('.')[0].upper() in WINDOWS_RESERVED):
        _fail('invalid runtime ID')
    if data['python'] != 'python/python.exe' or data['ghidra'] != 'ghidra' or data['java'] != 'jdk':
        _fail('unsupported portable runtime layout')
    versions = data['versions']
    if not isinstance(versions, dict) or set(versions) != VERSION_KEYS:
        _fail('runtime versions are missing')
    if any(not isinstance(value, str) or not VERSION.fullmatch(value) for value in versions.values()):
        _fail('invalid runtime version')
    records = data['files']
    if not isinstance(records, list) or not 4 <= len(records) <= MAX_MEMBERS:
        _fail('invalid manifest file count')
    files: list[BundleFile] = []
    names = set()
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {'path', 'size', 'sha256'}:
            _fail('malformed file inventory')
        name = _safe_relative(record['path'])
        canonical = unicodedata.normalize('NFC', name).casefold()
        if canonical in names:
            _fail('duplicate or Windows-colliding file inventory path')
        names.add(canonical)
        size, digest = record['size'], record['sha256']
        if type(size) is not int or not 0 <= size <= MAX_FILE:
            _fail('invalid file length')
        if not isinstance(digest, str) or not HEX.fullmatch(digest):
            _fail('invalid SHA-256 in file inventory')
        total += size
        if total > MAX_TOTAL:
            _fail('uncompressed bundle exceeds 8 GiB')
        files.append(BundleFile(name, size, digest))
    if any(required.casefold() not in names for required in REQUIRED_FILES):
        _fail('portable runtime or license notice component is missing')
    return runtime_id, tuple(files)


def _zip_entries(archive: zipfile.ZipFile, files: tuple[BundleFile, ...]) -> None:
    entries = archive.infolist()
    if len(entries) > MAX_MEMBERS + 1:
        _fail('ZIP contains too many entries')
    mapped = {}
    for info in entries:
        name = info.filename
        _safe_relative(name)
        canonical = unicodedata.normalize('NFC', name).casefold()
        if canonical in mapped:
            _fail('duplicate or Windows-colliding ZIP paths')
        mapped[canonical] = info
        if (info.is_dir() or info.flag_bits & 1
                or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
            _fail('unsupported directory, encryption or compression in ZIP')
        mode = stat.S_IFMT(info.external_attr >> 16)
        if mode not in (0, stat.S_IFREG):
            _fail('symlink or special file in ZIP is forbidden')
        if info.file_size > MAX_FILE or (info.file_size > 1024 and info.compress_size * 200 < info.file_size):
            _fail('ZIP member exceeds safe size or compression limits')
    if len(entries) != len(files) + 1:
        _fail('ZIP entries do not match the exact manifest inventory')
    if 'manifest.json' not in mapped:
        _fail('ZIP must contain manifest.json')
    for f in files:
        key = unicodedata.normalize('NFC', 'payload/' + f.path).casefold()
        info = mapped.get(key)
        if info is None or info.filename != 'payload/' + f.path or info.file_size != f.size:
            _fail('ZIP payload does not match manifest')
    if set(mapped) != ({'manifest.json'} | {
            unicodedata.normalize('NFC', 'payload/' + f.path).casefold() for f in files}):
        _fail('ZIP has unexpected files')


def _verify_stream(stream, expected: BundleFile, cancel: threading.Event | None,
                   destination=None) -> None:
    digest = hashlib.sha256()
    length = 0
    while chunk := stream.read(CHUNK):
        _cancel(cancel)
        length += len(chunk)
        if length > expected.size or length > MAX_FILE:
            _fail('decompressed payload exceeded declared size')
        digest.update(chunk)
        if destination is not None:
            destination.write(chunk)
    _cancel(cancel)
    if length != expected.size or digest.hexdigest() != expected.sha256:
        _fail('payload SHA-256 hash or size mismatch')


def inspect_offline_bundle(archive: Path, *, expected_sha256: str | None = None,
                           cancel: threading.Event | None = None) -> OfflineBundlePlan:
    """Read and verify all bytes without extraction, execution or network."""
    _cancel(cancel)
    archive = Path(archive).resolve()
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
                                         or not HEX.fullmatch(expected_sha256)):
        _fail('expected archive SHA-256 must be 64 lowercase hexadecimal characters')
    try:
        if not archive.is_file():
            _fail('select an existing offline ZIP')
        archive_hash = _sha256_file(archive, cancel)
        if expected_sha256 is not None and archive_hash != expected_sha256:
            _fail('archive SHA-256 differs from the trusted expected SHA-256')
        with zipfile.ZipFile(archive, 'r') as zf:
            entries = zf.infolist()
            manifests = [info for info in entries if info.filename == 'manifest.json']
            if len(manifests) != 1 or manifests[0].file_size > MAX_MANIFEST:
                _fail('exactly one bounded manifest.json is required')
            with zf.open(manifests[0]) as stream:
                raw = stream.read(MAX_MANIFEST + 1)
            if len(raw) > MAX_MANIFEST:
                _fail('manifest exceeds size limit')
            runtime_id, files = _validated_manifest(_json_no_duplicates(raw))
            _zip_entries(zf, files)
            for item in files:
                with zf.open('payload/' + item.path) as stream:
                    _verify_stream(stream, item, cancel)
        return OfflineBundlePlan(archive, archive_hash, runtime_id, files, raw)
    except OfflineBundleError:
        raise
    except (OSError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
        _fail(f'cannot read or verify offline ZIP ({type(exc).__name__})')


def _no_symlink_ancestors(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            _fail('symbolic link in installation destination is forbidden')


def install_offline_bundle(plan: OfflineBundlePlan, runtimes_root: Path, *,
                           cancel: threading.Event | None = None,
                           event: Callable[[str], None] | None = None) -> InstalledRuntime:
    """Verify again, extract to private staging, publish atomically, never overwrite."""
    _cancel(cancel)
    destination_root = Path(runtimes_root)
    if not destination_root.is_absolute() or str(destination_root) == destination_root.anchor:
        _fail('installation root must be an absolute dedicated runtimes directory')
    _no_symlink_ancestors(destination_root)
    try:
        verified = inspect_offline_bundle(plan.archive, expected_sha256=plan.sha256, cancel=cancel)
        if (verified.runtime_id != plan.runtime_id or verified.files != plan.files
                or verified.manifest_bytes != plan.manifest_bytes):
            _fail('bundle changed after inspection')
    except OfflineBundleError as exc:
        if 'SHA-256 differs' in str(exc):
            _fail('bundle changed after inspection: archive SHA-256 differs')
        raise
    destination = destination_root / verified.runtime_id
    _no_symlink_ancestors(destination)
    disk_path = destination_root
    while not disk_path.exists():
        disk_path = disk_path.parent
    reserve = min(512 * 1024 * 1024, verified.total_bytes // 10)
    try:
        if shutil.disk_usage(disk_path).free < verified.total_bytes + reserve:
            _fail('insufficient disk space for this offline backend and extraction reserve')
    except OSError:
        _fail('cannot determine available disk space for offline backend')
    if destination.exists():
        _fail('runtime already installed; existing files were not overwritten')
    destination_root.mkdir(parents=True, exist_ok=True)
    lock = destination_root / f'.runtime-{verified.runtime_id}.lock'
    stage = None
    lock_fd = None
    try:
        try:
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            _fail('installation lock exists; a concurrent or interrupted install must be reviewed')
        if destination.exists():
            _fail('runtime already installed; existing files were not overwritten')
        stage = Path(tempfile.mkdtemp(prefix='.install-', dir=destination_root))
        with zipfile.ZipFile(verified.archive, 'r') as zf:
            for index, item in enumerate(verified.files):
                _cancel(cancel)
                target = stage / 'payload' / item.path
                if os.name == 'nt' and len(str(destination / 'payload' / item.path)) >= 248:
                    _fail('Windows destination path too long; use a shorter runtime ID or install root')
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open('payload/' + item.path) as src, target.open('xb') as output:
                    _verify_stream(src, item, cancel, output)
                    output.flush()
                if event is not None:
                    event(f'Verified {index + 1} of {verified.file_count} files')
        (stage / 'manifest.json').write_bytes(verified.manifest_bytes)
        if _sha256_file(verified.archive, cancel) != verified.sha256:
            _fail('bundle changed after inspection during extraction')
        _cancel(cancel)
        if destination.exists():
            _fail('runtime already installed; existing files were not overwritten')
        os.replace(stage, destination)
        stage = None
        return InstalledRuntime(
            root=destination,
            python_executable=destination / 'payload' / 'python' / 'python.exe',
            ghidra_dir=destination / 'payload' / 'ghidra',
            java_home=destination / 'payload' / 'jdk',
            manifest=destination / 'manifest.json',
            archive_sha256=verified.sha256,
        )
    except OfflineBundleError:
        raise
    except (OSError, EOFError, zipfile.BadZipFile, RuntimeError) as exc:
        _fail(f'installation failed; no runtime published ({type(exc).__name__})')
    finally:
        try:
            if stage is not None and stage.exists():
                try:
                    shutil.rmtree(stage)
                except OSError:
                    # Do not touch unknown stages; provide the exact path for manual review.
                    raise OfflineBundleError(f'PT-OFFLINE: staging cleanup failed at {stage}') from None
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
                lock.unlink(missing_ok=True)


def build_offline_bundle(source_payload: Path, runtime_id: str, versions: Mapping[str, str],
                         destination: Path) -> Path:
    """Package a preassembled relocatable runtime; never install/download/execute it.

    Success means package integrity, not runtime compatibility or license approval.
    """
    source = Path(source_payload).resolve()
    destination = Path(destination).resolve()
    if not source.is_dir() or source.is_symlink() or not destination.is_absolute():
        _fail('producer needs an existing payload directory and absolute output path')
    if not isinstance(runtime_id, str) or not ID.fullmatch(runtime_id):
        _fail('invalid runtime ID')
    if set(versions) != VERSION_KEYS:
        _fail('producer needs all four exact dependency version fields')
    if destination.exists() or destination.is_relative_to(source):
        _fail('producer will not replace an archive or write inside the source payload')
    records = []
    for source_file in source.rglob('*'):
        if source_file.is_symlink():
            _fail('producer refuses symbolic links in payload')
        if source_file.is_dir():
            continue
        if not source_file.is_file():
            _fail('producer refuses special files')
        relative = _safe_relative(source_file.relative_to(source).as_posix())
        length = source_file.stat().st_size
        if length > MAX_FILE:
            _fail('payload file exceeds size limit')
        records.append({'path': relative, 'size': length,
                        'sha256': _sha256_file(source_file, None)})
    records.sort(key=lambda entry: entry['path'])
    info = {
        'format': FORMAT, 'schema_version': 1, 'runtime_id': runtime_id,
        'platform': 'windows', 'architecture': 'amd64',
        'python': 'python/python.exe', 'ghidra': 'ghidra', 'java': 'jdk',
        'versions': dict(versions), 'files': records,
    }
    _validated_manifest(info)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.offline-pack-', dir=destination.parent)
    os.close(fd)
    stage = Path(temporary)
    try:
        with zipfile.ZipFile(stage, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6,
                             allowZip64=True) as output:
            def add(name, body):
                header = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                header.compress_type = zipfile.ZIP_DEFLATED
                header.external_attr = 0o100644 << 16
                output.writestr(header, body)
            add('manifest.json', json.dumps(info, sort_keys=True, separators=(',', ':')).encode())
            for record in records:
                relative = record['path']
                path = source / relative
                # Recheck source identity before archiving each member; no binary execution.
                if path.is_symlink() or path.stat().st_size != record['size']:
                    _fail('payload changed during packaging')
                header = zipfile.ZipInfo('payload/' + relative, date_time=(1980, 1, 1, 0, 0, 0))
                header.compress_type = zipfile.ZIP_DEFLATED
                header.external_attr = 0o100644 << 16
                with path.open('rb') as stream, output.open(header, 'w') as member:
                    while chunk := stream.read(CHUNK):
                        member.write(chunk)
                if _sha256_file(path, None) != record['sha256']:
                    _fail('payload changed during packaging')
        inspect_offline_bundle(stage)
        if destination.exists():
            _fail('archive already exists; refused to overwrite')
        os.replace(stage, destination)
        return destination
    finally:
        stage.unlink(missing_ok=True)
