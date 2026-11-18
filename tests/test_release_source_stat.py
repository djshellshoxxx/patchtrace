"""Real authored files with portable observation seams; separate Windows-native controls."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_release_qualification import authored_checkout


@pytest.fixture
def gate():
    module = importlib.import_module('tools.release_qualification')
    assert Path(module.__file__).resolve() == Path(__file__).resolve().parents[1] / 'tools/release_qualification.py'
    return module


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


@pytest.mark.parametrize('field', ['st_birthtime_ns', 'st_file_attributes'])
@pytest.mark.parametrize('value', [None, 1.5, 'unavailable', True])
def test_invalid_windows_path_observation_refuses_before_attribute_use(gate, tmp_path, monkeypatch, field, value):
    path = tmp_path / 'source.txt'
    path.write_bytes(b'unchanged')
    observations(gate, monkeypatch, path, path_delta=lambda _count, _values: {field: value})
    with pytest.raises(gate.QualificationError, match='Windows source observation is unavailable'):
        gate.source_blob(path, b'100644', 9)


def change_time_observations(gate, monkeypatch, path):
    """Keep real inode/bytes and changing descriptor ctime; model Windows path ctime."""
    original_lstat, original_fstat = Path.lstat, os.fstat
    birth = original_lstat(path).st_ctime_ns

    def view(info, *, pathname):
        return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_mode=stat.S_IFREG | 0o666,
                               st_size=info.st_size, st_mtime_ns=info.st_mtime_ns,
                               st_ctime_ns=birth if pathname else info.st_ctime_ns,
                               st_birthtime_ns=birth, st_file_attributes=0x20)

    def lstat(candidate, *args, **kwargs):
        info = original_lstat(candidate, *args, **kwargs)
        return view(info, pathname=True) if candidate == path else info

    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(gate, 'os', OSView(name='nt',
        fstat=lambda fd: view(original_fstat(fd), pathname=False)))
    return original_lstat


@pytest.mark.parametrize('consumer', ['publication', 'dependency'])
@pytest.mark.parametrize('change', [False, True])
@pytest.mark.parametrize('platform', ['modeled-windows', 'posix', pytest.param('native-windows',
    marks=pytest.mark.skipif(os.name != 'nt', reason='Actual Windows final source observation needs Windows'))])
def test_final_tree_pass_observes_post_hash_change_time(gate, tmp_path, monkeypatch, consumer, change, platform):
    if platform == 'posix' and os.name == 'nt':
        pytest.skip('Actual POSIX metadata needs a POSIX host')
    root, source = authored_checkout(tmp_path)
    path = root / 'sample.txt'
    raw_lstat = Path.lstat
    before = raw_lstat(path)
    with path.open('rb') as stream:
        descriptor_change_before = os.fstat(stream.fileno()).st_ctime_ns
    if platform == 'modeled-windows':
        change_time_observations(gate, monkeypatch, path)
    original_blob = gate.source_blob
    changes = []

    def after_hash(candidate, mode, size):
        result = original_blob(candidate, mode, size)
        if change:
            assert candidate == path
            path.write_bytes(b'modified data\n')
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = raw_lstat(path)
            assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            with path.open('rb') as stream:
                assert os.fstat(stream.fileno()).st_ctime_ns != descriptor_change_before
            changes.append(True)
        return result

    monkeypatch.setattr(gate, 'source_blob', after_hash)
    check = gate.checked_source
    if consumer == 'dependency':
        dependency = importlib.import_module('tools.dependency_security')
        assert dependency.gate is gate
        check = dependency.checked_tree
    if change:
        with pytest.raises(gate.QualificationError, match='changed'):
            check(root, source)
        assert changes == [True] and path.read_bytes() == b'modified data\n'
    else:
        check(root, source)
        assert not changes and path.read_bytes() == b'authored data\n'


@pytest.mark.parametrize('suffix', ['.stdout', '.cmd'])
@pytest.mark.parametrize('drift', [False, True])
def test_dependency_receipt_reads_use_compatible_views_and_full_descriptor_state(
        gate, tmp_path, monkeypatch, suffix, drift):
    dependency = importlib.import_module('tools.dependency_security')
    assert dependency.gate is gate
    path = tmp_path / ('receipt' + suffix)
    data = b'{"authored": true}\n'
    path.write_bytes(data)
    observations(gate, monkeypatch, path, descriptor_delta=(
        (lambda count, _values: {'st_ctime_ns': 20 if count == 1 else 21}) if drift else None))
    monkeypatch.setattr(dependency, 'os', gate.os)
    if drift:
        with pytest.raises(gate.QualificationError, match='changed during read'):
            dependency.read_json(path)
    else:
        assert dependency.read_json(path) == {'authored': True}
        assert dependency.digest(path) == hashlib.sha256(data).hexdigest()


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows receipt metadata needs Windows')
def test_native_windows_rewritten_inert_dependency_receipt_is_readable(tmp_path):
    dependency = importlib.import_module('tools.dependency_security')
    path = tmp_path / 'profile-inspect.stdout'
    path.write_bytes(b'before')
    data = b'{"authored": true}\n'
    path.write_bytes(data)
    os.utime(path, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
    assert dependency.read_json(path) == {'authored': True}
    assert dependency.digest(path) == hashlib.sha256(data).hexdigest()


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
