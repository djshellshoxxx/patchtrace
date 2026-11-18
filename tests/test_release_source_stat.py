"""Real authored files with portable observation seams; separate Windows-native controls."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest
from test_release_qualification import authored_checkout


@pytest.fixture
def gate():
    return importlib.import_module('tools.release_qualification')


class OSView:
    def __init__(self, *, name, fstat):
        self.name, self.fstat = name, fstat

    def __getattr__(self, name):
        return getattr(os, name)


def observations(gate, monkeypatch, path, *, platform='nt', descriptor_delta=None, path_delta=None):
    """Use actual bytes/descriptor identity, changing only the reported stat view."""
    original_lstat, original_fstat = Path.lstat, os.fstat
    counts = {'path': 0, 'descriptor': 0}

    def snapshot(info, view):
        values = {name: getattr(info, name) for name in
                  ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        values.update(st_ctime_ns=10 if view == 'path' else 20,
                      st_birthtime_ns=10, st_file_attributes=0x20)
        # Match CPython's Windows physical read/write mode in both observations;
        # the pathname only adds suffix-derived execute bits.
        values['st_mode'] = stat.S_IFREG | 0o666
        if view == 'path' and path.suffix.lower() in {'.exe', '.cmd', '.bat', '.com'}:
            values['st_mode'] |= 0o111
        counts[view] += 1
        changes = descriptor_delta if view == 'descriptor' else path_delta
        if changes:
            values.update(changes(counts[view], values.copy()))
        return SimpleNamespace(**values)

    def lstat(self, *args, **kwargs):
        info = original_lstat(self, *args, **kwargs)
        return snapshot(info, 'path') if self == path else info

    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(gate, 'os', OSView(name=platform,
        fstat=lambda fd: snapshot(original_fstat(fd), 'descriptor')))
    return counts


def blob_id(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data,
                        usedforsecurity=False).hexdigest().encode()


@pytest.mark.parametrize('suffix', ['.txt', '.cmd', '.exe', '.com', '.bat'])
def test_stable_windows_observations_hash_actual_bytes_despite_api_differences(gate, tmp_path, monkeypatch, suffix):
    data = b'inert authored bytes\r\n'
    path = tmp_path / ('source' + suffix)
    path.write_bytes(data)
    counts = observations(gate, monkeypatch, path)
    actual, _ = gate.source_blob(path, b'100644', len(data))
    assert actual == blob_id(data)
    assert counts['path'] >= 2 and counts['descriptor'] >= 2


@pytest.mark.parametrize('field', ['st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_birthtime_ns',
                                  'st_file_attributes', 'st_mode'])
def test_cross_view_physical_identity_mismatch_still_refuses(gate, tmp_path, monkeypatch, field):
    path = tmp_path / 'source.txt'
    path.write_bytes(b'unchanged')
    def changed(_count, values):
        return {field: values[field] + (0o200 if field == 'st_mode' else 1)}
    observations(gate, monkeypatch, path, descriptor_delta=changed)
    with pytest.raises(gate.QualificationError, match='changed at open'):
        gate.source_blob(path, b'100644', 9)


def test_windows_descriptor_change_time_drift_refuses_during_hash(gate, tmp_path, monkeypatch):
    path = tmp_path / 'source.txt'
    path.write_bytes(b'unchanged')
    observations(gate, monkeypatch, path,
                 descriptor_delta=lambda count, _values: {'st_ctime_ns': 20 if count == 1 else 21})
    with pytest.raises(gate.QualificationError, match='changed during verification'):
        gate.source_blob(path, b'100644', 9)


def test_windows_path_change_time_drift_refuses_after_hash(gate, tmp_path, monkeypatch):
    path = tmp_path / 'source.txt'
    path.write_bytes(b'unchanged')
    observations(gate, monkeypatch, path,
                 path_delta=lambda count, _values: {'st_ctime_ns': 10 if count == 1 else 11})
    with pytest.raises(gate.QualificationError, match='source entry was replaced'):
        gate.source_blob(path, b'100644', 9)


def test_nonwindows_cross_view_change_time_check_stays_strict(gate, tmp_path, monkeypatch):
    path = tmp_path / 'source.txt'
    path.write_bytes(b'unchanged')
    observations(gate, monkeypatch, path, platform='posix')
    with pytest.raises(gate.QualificationError, match='changed at open'):
        gate.source_blob(path, b'100644', 9)


@pytest.mark.parametrize('field', ['st_birthtime_ns', 'st_file_attributes'])
def test_missing_windows_observation_is_a_typed_refusal(gate, tmp_path, monkeypatch, field):
    path = tmp_path / 'source.txt'
    path.write_bytes(b'unchanged')
    observations(gate, monkeypatch, path, descriptor_delta=lambda _count, _values: {field: None})
    with pytest.raises(gate.QualificationError, match='Windows source observation is unavailable'):
        gate.source_blob(path, b'100644', 9)


@pytest.mark.parametrize('changed', [False, True])
def test_canonical_checkout_guard_keeps_actual_byte_check_with_windows_views(gate, tmp_path, monkeypatch, changed):
    root, source = authored_checkout(tmp_path)
    path = root / 'sample.txt'
    if changed:
        path.write_text('modified data\n')  # Same length; actual canonical blob must still refuse.
    observations(gate, monkeypatch, path)
    if changed:
        with pytest.raises(gate.QualificationError, match='source bytes differ from canonical commit'):
            gate.checked_source(root, source)
    else:
        gate.checked_source(root, source)


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows path/descriptor metadata needs Windows')
@pytest.mark.parametrize('suffix', ['.txt', '.cmd', '.exe'])
def test_native_windows_rewritten_inert_source_has_stable_canonical_bytes(gate, tmp_path, suffix, record_property):
    path = tmp_path / ('source' + suffix)
    path.write_bytes(b'before')
    data = b'inert source bytes after rewrite\r\n'
    path.write_bytes(data)
    os.utime(path, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
    by_path = path.lstat()
    with path.open('rb') as stream:
        by_fd = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
              'st_birthtime_ns', 'st_file_attributes')
    record_property('stat_views', json.dumps({view: {name: getattr(info, name, None) for name in fields}
                                            for view, info in [('path', by_path), ('descriptor', by_fd)]}))
    actual, _ = gate.source_blob(path, b'100644', len(data))
    assert actual == blob_id(data)
