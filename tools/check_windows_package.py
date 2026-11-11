"""Read-only Windows desktop ZIP preflight; never extracts or executes payloads.

Expected digest and source identity must come from the intended build's evidence.
A structural pass is not Windows, native, executable-resource or offline acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import unicodedata
import zipfile
import zlib
from pathlib import Path

from patchtrace.offline_bundle import WINDOWS_RESERVED
from patchtrace.persistence import strict_json

MAX_ARCHIVE = 2 * 1024**3
MAX_DIRECTORY = 16 * 1024**2
MAX_ENTRIES = 50_000
MAX_EXPANDED = 4 * 1024**3
MAX_METADATA = 4 * 1024**2
CHUNK = 1024**2
ROOT = 'PatchTrace/'


def _refuse(message: str):
    raise ValueError(f'PT-REL-PACKAGE: {message}')


def _path(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 1024:
        _refuse('invalid member path')
    if '\\' in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        _refuse('unsafe member path')
    parts = name.split('/')
    try:
        if any(len(part.encode('utf-16-le')) > 510 for part in parts):
            _refuse('Windows path component exceeds 255 UTF-16 code units')
    except UnicodeEncodeError:
        _refuse('unencodable Windows member path')
    if any(not part or part in {'.', '..'} or part.endswith((' ', '.'))
           or any(c in part for c in ':<>"|?*')
           or part.split('.')[0].rstrip(' ').upper() in WINDOWS_RESERVED for part in parts):
        _refuse('unsafe Windows member path')
    return unicodedata.normalize('NFC', name).casefold()


def _directory_bound(stream, size: int) -> int:
    """Bound the central directory before ZipFile allocates its member objects."""
    stream.seek(max(0, size - 65_557))
    tail = stream.read(65_557)
    offset = tail.rfind(b'PK\x05\x06')
    if offset < 0 or len(tail) - offset < 22:
        _refuse('missing ZIP end record')
    _, disk, directory_disk, disk_count, count, length, start, comment = struct.unpack_from(
        '<4s4H2IH', tail, offset)
    if offset + 22 + comment != len(tail):
        _refuse('invalid ZIP end record')
    if disk or directory_disk or disk_count != count:
        _refuse('split ZIP archives unsupported')
    if count == 65_535 or length == 0xffffffff or start == 0xffffffff:
        _refuse('ZIP64 archives unsupported')
    end = size - len(tail) + offset
    if end >= 20:
        stream.seek(end - 20)
        if stream.read(4) == b'PK\x06\x07':
            _refuse('ZIP64 archives unsupported')
    if not 1 <= count <= MAX_ENTRIES or length > MAX_DIRECTORY or start + length != end:
        _refuse('ZIP central directory exceeds bounds or has an unsupported layout')
    return count


def _json(archive: zipfile.ZipFile, info: zipfile.ZipInfo):
    if info.file_size > MAX_METADATA:
        _refuse('metadata exceeds size limit')
    with archive.open(info) as stream:
        raw = stream.read(MAX_METADATA + 1)
    if len(raw) > MAX_METADATA:
        _refuse('metadata exceeds size limit')
    return strict_json(raw.decode('utf-8'))


def _members(archive: zipfile.ZipFile, expected_count: int) -> dict[str, zipfile.ZipInfo]:
    entries = archive.infolist()
    if len(entries) != expected_count or len(entries) > MAX_ENTRIES:
        _refuse('ZIP member count mismatch')
    files, seen, total = {}, set(), 0
    for info in entries:
        if info.orig_filename != info.filename:
            _refuse('ZIP member name was truncated or normalized')
        extra = info.extra
        while len(extra) >= 4:
            kind, length = struct.unpack_from('<HH', extra)
            if kind == 1:
                _refuse('ZIP64 member metadata unsupported')
            extra = extra[4 + length:]
        directory = info.is_dir()
        name = info.filename[:-1] if directory else info.filename
        key = _path(name)
        if name != 'PatchTrace' and not name.startswith(ROOT):
            _refuse('unexpected package root')
        if name == 'PatchTrace' and not directory:
            _refuse('package root must be a directory')
        if key in seen:
            _refuse('duplicate or colliding member path')
        seen.add(key)
        kind = stat.S_IFMT(info.external_attr >> 16)
        if info.flag_bits & 1 or kind not in {0, stat.S_IFDIR if directory else stat.S_IFREG}:
            _refuse('encrypted or nonregular member')
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            _refuse('unsupported ZIP compression')
        total += info.file_size
        if total > MAX_EXPANDED:
            _refuse('declared expanded size exceeds limit')
        if not directory:
            files[name] = info
    file_keys = {_path(name) for name in files}
    for key in seen:
        parts = key.split('/')
        if any('/'.join(parts[:i]) in file_keys for i in range(1, len(parts))):
            _refuse('file conflicts with directory prefix')
    return files


def _layout(files: dict[str, zipfile.ZipInfo]):
    required = ('PatchTrace.exe', 'dependency-versions.json', 'file-inventory.json',
                'licenses/Python-LICENSE.txt',
                'licenses/upstream/qtbase-6.12.0/LICENSES/LGPL-3.0-only.txt',
                'licenses/upstream/pyside-setup-6.12.0/LICENSES/LGPL-3.0-only.txt')
    if any(ROOT + name not in files or files[ROOT + name].file_size == 0 for name in required):
        _refuse('required desktop file or notice missing')
    names = {name.casefold().removeprefix(ROOT.casefold()) for name, info in files.items() if info.file_size}
    if not {'_internal/pyside6/qt6core.dll', '_internal/pyside6/plugins/platforms/qwindows.dll'} <= names or not any(
            re.fullmatch(r'_internal/python3\d+\.dll', name) for name in names):
        _refuse('replaceable Python/Qt runtime files missing')


def inspect_package(path: Path, *, sha256: str, commit: str, label: str) -> dict:
    if not re.fullmatch('[0-9a-f]{64}', sha256) or not re.fullmatch('[0-9a-f]{40}', commit):
        _refuse('invalid expected digest or commit')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,95}', label):
        _refuse('invalid expected label')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            _refuse('archive must be a regular file')
        stream = os.fdopen(descriptor, 'rb')
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 22 <= before.st_size <= MAX_ARCHIVE:
            _refuse('archive must be a regular file within size limit')
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(CHUNK):
            size += len(chunk)
            if size > MAX_ARCHIVE:
                _refuse('archive grew beyond size limit')
            digest.update(chunk)
        if digest.hexdigest() != sha256:
            _refuse('archive digest mismatch')
        count = _directory_bound(stream, size)
        with zipfile.ZipFile(stream) as archive:
            files = _members(archive, count)
            _layout(files)
            versions = _json(archive, files[ROOT + 'dependency-versions.json'])
            if not isinstance(versions, dict) or versions.get('PatchTrace') != label or versions.get(
                    'PatchTrace commit') != commit:
                _refuse('dependency manifest source identity mismatch')
            if any(not isinstance(versions.get(name), str) or not 1 <= len(versions[name]) <= 96
                   for name in ('Python', 'PySide6')):
                _refuse('dependency versions missing or invalid')
            inventory = _json(archive, files[ROOT + 'file-inventory.json'])
            if not isinstance(inventory, list) or len(inventory) > MAX_ENTRIES:
                _refuse('invalid inventory')
            keys = [_path(item) for item in inventory]
            if len(set(keys)) != len(keys):
                _refuse('duplicate inventory path')
            actual = {name.removeprefix(ROOT) for name in files if name != ROOT + 'file-inventory.json'}
            if set(inventory) != actual:
                _refuse('inventory does not match archive files')
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if size != before.st_size or any(getattr(before, field) != getattr(after, field) for field in fields):
            _refuse('archive changed during inspection')
    return {'format': 'patchtrace-windows-package-preflight/1', 'status': 'verified-structure',
            'sha256': sha256, 'bytes': size, 'commit': commit, 'label': label, 'files': len(files),
            'windows_smoke': 'not-run', 'native_acceptance': 'not-run', 'manual_acceptance': 'not-run'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--label', required=True)
    args = parser.parse_args(argv)
    try:
        result = inspect_package(args.archive, sha256=args.sha256, commit=args.commit, label=args.label)
    except (ValueError, OSError, EOFError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error):
        print(json.dumps({'format': 'patchtrace-windows-package-preflight/1', 'status': 'failed',
                          'error': 'PT-REL-PACKAGE: archive or expected identity invalid'}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
