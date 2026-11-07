"""Authored ZIP fixtures prove structural checks, never native Windows acceptance."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import struct
import warnings
import zipfile
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    'check_windows_package', Path(__file__).resolve().parents[1] / 'tools/check_windows_package.py')
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)
COMMIT = 'a' * 40
LABEL = '0.1.0-dev.42'


def _files():
    return {'PatchTrace.exe': b'authored bytes, never executable',
            '_internal/python312.dll': b'python',
            '_internal/PySide6/Qt6Core.dll': b'qt',
            '_internal/PySide6/plugins/platforms/qwindows.dll': b'plugin',
            'licenses/Python-LICENSE.txt': b'authored notice fixture',
            'licenses/upstream/qtbase-6.12.0/LICENSES/LGPL-3.0-only.txt': b'fixture',
            'licenses/upstream/pyside-setup-6.12.0/LICENSES/LGPL-3.0-only.txt': b'fixture',
            'dependency-versions.json': json.dumps({'Python': '3.12', 'PySide6': '6.12.0',
                                                  'PatchTrace': LABEL, 'PatchTrace commit': COMMIT}).encode()}


def _archive(tmp_path, files=None, *, inventory=None, extra=()):
    files = _files() if files is None else files
    path = tmp_path / 'candidate.zip'
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('PatchTrace/', b'')
            for name, data in files.items():
                archive.writestr('PatchTrace/' + name, data)
            archive.writestr('PatchTrace/file-inventory.json',
                             json.dumps(sorted(files)).encode() if inventory is None else inventory)
            for name, data in extra:
                archive.writestr(name, data)
    return path


def _inspect(path, **kwargs):
    args = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'commit': COMMIT, 'label': LABEL}
    args.update(kwargs)
    return check.inspect_package(path, **args)


def test_complete_structural_receipt_is_not_windows_acceptance(tmp_path):
    path = _archive(tmp_path)
    original = path.read_bytes()
    result = _inspect(path)
    assert result['status'] == 'verified-structure'
    assert result['files'] == len(_files()) + 1
    assert result['bytes'] == len(original)
    assert all(result[name] == 'not-run' for name in (
        'windows_smoke', 'native_acceptance', 'manual_acceptance'))
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]  # no extraction, execution or receipt side effect


@pytest.mark.parametrize('kwargs', [{'sha256': 'b' * 64}, {'commit': 'b' * 40}, {'label': 'wrong'},
                                   {'sha256': 'A' * 64}, {'commit': 'bad'}, {'label': 'bad label'}])
def test_expected_identity_must_match(tmp_path, kwargs):
    with pytest.raises(ValueError, match='PT-REL-PACKAGE'):
        _inspect(_archive(tmp_path), **kwargs)


@pytest.mark.parametrize('name', ['PatchTrace.exe', '_internal/python312.dll',
                                 '_internal/PySide6/Qt6Core.dll',
                                 '_internal/PySide6/plugins/platforms/qwindows.dll',
                                 'licenses/Python-LICENSE.txt',
                                 'licenses/upstream/qtbase-6.12.0/LICENSES/LGPL-3.0-only.txt'])
def test_missing_runtime_and_notices_fail(tmp_path, name):
    files = _files()
    del files[name]
    with pytest.raises(ValueError, match='missing'):
        _inspect(_archive(tmp_path, files))


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'dir\\escape', 'NUL.txt', 'CONIN$',
                                 'dir./file', 'dir /file', 'a:b', 'a//b', 'a/<b>', 'a/./b'])
def test_unsafe_inventory_or_member_paths_fail(tmp_path, name):
    files = _files() | {name: b'data'}
    with pytest.raises(ValueError, match='PT-REL-PACKAGE'):
        _inspect(_archive(tmp_path, files))


@pytest.mark.parametrize('extra', [
    [('other/root', b'x')], [('PatchTrace/PatchTrace.exe', b'duplicate')],
    [('PatchTrace/PATCHTRACE.EXE', b'collision')],
    [('PatchTrace/a', b'file'), ('PatchTrace/a/b', b'conflict')],
    [('PatchTrace/caf\u00e9', b'file'), ('PatchTrace/cafe\u0301', b'collision')],
])
def test_root_collisions_and_directory_prefix_conflicts_fail(tmp_path, extra):
    with pytest.raises(ValueError, match='PT-REL-PACKAGE'):
        _inspect(_archive(tmp_path, extra=extra))


@pytest.mark.parametrize('raw', [b'[]', b'{}', b'NaN', b'["PatchTrace.exe", "PatchTrace.exe"]',
                               b'["../x"]', b'[3]', b'["\\ud800"]'])
def test_inventory_is_strict_and_complete(tmp_path, raw):
    with pytest.raises(ValueError):
        _inspect(_archive(tmp_path, inventory=raw))


@pytest.mark.parametrize('raw', [b'[]', b'{"Python":"3", "Python":"4"}', b'{"Python": NaN}',
                               b'{"Python": 1e999}', b'{"PatchTrace":"\\ud800"}'])
def test_dependency_metadata_is_strict(tmp_path, raw):
    files = _files() | {'dependency-versions.json': raw}
    with pytest.raises(ValueError):
        _inspect(_archive(tmp_path, files))


def test_symlink_member_refused_without_following(tmp_path):
    info = zipfile.ZipInfo('PatchTrace/link')
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ValueError, match='nonregular'):
        _inspect(_archive(tmp_path, extra=[(info, b'../outside')]))


def test_nul_truncated_member_name_refused(tmp_path):
    files = _files() | {'noticeXtail': b'notice'}
    inventory = json.dumps(sorted(_files()) + ['notice']).encode()
    path = _archive(tmp_path, files, inventory=inventory)
    raw = path.read_bytes()
    assert raw.count(b'PatchTrace/noticeXtail') == 2
    path.write_bytes(raw.replace(b'PatchTrace/noticeXtail', b'PatchTrace/notice\0tail'))
    with pytest.raises(ValueError, match='truncated'):
        _inspect(path)


@pytest.mark.parametrize('name', ['x' * 256, '\U0001f600' * 128])
def test_windows_component_limit_counts_utf16_code_units(tmp_path, name):
    with pytest.raises(ValueError, match='255 UTF-16'):
        _inspect(_archive(tmp_path, _files() | {name: b'data'}))


def test_runtime_names_in_unusable_locations_do_not_pass(tmp_path):
    files = {('not-a-runtime/' + name.split('/')[-1] if name.endswith('.dll') else name): data
             for name, data in _files().items()}
    with pytest.raises(ValueError, match='runtime files missing'):
        _inspect(_archive(tmp_path, files))


def test_zip64_locator_cannot_override_bounded_ordinary_directory(tmp_path, monkeypatch):
    path = _archive(tmp_path)
    raw = path.read_bytes()
    end = raw.rfind(b'PK\x05\x06')
    fields = struct.unpack_from('<4s4H2IH', raw, end)
    count, length, start = fields[4], fields[5], fields[6]
    record = struct.pack('<4sQ2H2I4Q', b'PK\x06\x06', 44, 45, 45, 0, 0,
                         count, count, length, start)
    locator = struct.pack('<4sIQI', b'PK\x06\x07', 0, end, 1)
    forged = bytearray(raw[:end] + record + locator + raw[end:])
    new_end = end + len(record) + len(locator)
    struct.pack_into('<II', forged, new_end + 12, 1, new_end - 1)
    path.write_bytes(forged)
    monkeypatch.setattr(check, 'MAX_DIRECTORY', length - 1)
    with pytest.raises(ValueError, match='ZIP64'):
        _inspect(path)


def test_corrupt_compressed_metadata_has_failed_cli_receipt(tmp_path, capsys):
    path = _archive(tmp_path)
    with zipfile.ZipFile(path) as archive:
        offset = archive.getinfo('PatchTrace/dependency-versions.json').header_offset
    raw = bytearray(path.read_bytes())
    name, extra = struct.unpack_from('<HH', raw, offset + 26)
    raw[offset + 30 + name + extra] = 0xff  # invalid DEFLATE block
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert check.main([str(path), '--sha256', digest, '--commit', COMMIT, '--label', LABEL]) == 3
    assert json.loads(capsys.readouterr().out)['status'] == 'failed'


@pytest.mark.parametrize('compression', [zipfile.ZIP_LZMA, zipfile.ZIP_BZIP2])
def test_unsupported_compression_refused_before_metadata_open(tmp_path, monkeypatch, compression):
    path = _archive(tmp_path)
    with zipfile.ZipFile(path, 'a', compression=compression) as archive:
        archive.writestr('PatchTrace/extra', b'untrusted compressed member')
    monkeypatch.setattr(check.zipfile.ZipFile, 'open', lambda *a, **k: pytest.fail('decompressor reached'))
    with pytest.raises(ValueError, match='unsupported ZIP compression'):
        _inspect(path)


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='POSIX special-file control')
def test_nonregular_input_refused_before_buffered_io(tmp_path, monkeypatch):
    path = tmp_path / 'fifo'
    os.mkfifo(path)

    def forbidden(*args, **kwargs):
        pytest.fail('nonregular archive reached buffered IO')

    monkeypatch.setattr(check.os, 'fdopen', forbidden)
    with pytest.raises(ValueError, match='regular file'):
        check.inspect_package(path, sha256='0' * 64, commit=COMMIT, label=LABEL)


@pytest.mark.parametrize('limit,value', [('MAX_ARCHIVE', 30), ('MAX_DIRECTORY', 10),
                                      ('MAX_ENTRIES', 2), ('MAX_EXPANDED', 10), ('MAX_METADATA', 2)])
def test_each_resource_bound_fails_closed(tmp_path, monkeypatch, limit, value):
    path = _archive(tmp_path)
    monkeypatch.setattr(check, limit, value)
    with pytest.raises(ValueError, match='PT-REL-PACKAGE'):
        _inspect(path)


@pytest.mark.parametrize('field,value', [(4, 1), (10, 65535), (12, 0xffffffff)])
def test_split_and_zip64_end_records_refused_before_zip_parse(tmp_path, monkeypatch, field, value):
    path = _archive(tmp_path)
    raw = bytearray(path.read_bytes())
    end = raw.rfind(b'PK\x05\x06')
    struct.pack_into('<I' if field == 12 else '<H', raw, end + field, value)
    path.write_bytes(raw)
    monkeypatch.setattr(check.zipfile, 'ZipFile', lambda *a, **k: pytest.fail('ZIP parser reached'))
    with pytest.raises(ValueError, match='PT-REL-PACKAGE'):
        _inspect(path)


def test_cli_emits_one_failed_document_with_exit_three(tmp_path, capsys):
    path = _archive(tmp_path)
    assert check.main([str(path), '--sha256', '0' * 64, '--commit', COMMIT, '--label', LABEL]) == 3
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'failed'
