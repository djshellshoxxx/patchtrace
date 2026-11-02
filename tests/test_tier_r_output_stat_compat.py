"""Preserve read integrity across CPython's Windows path/fd ctime meanings."""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.calibration.tier_r import output_store as OS


def _view(info, **changes):
    fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
    fields.update(changes)
    return SimpleNamespace(**fields)


def _separate_api_clocks(monkeypatch, path, *, changing_api=None, field=None):
    """Model CPython 3.12.10: lstat ctime=CreationTime, fstat ctime=ChangeTime."""
    original_lstat, original_fstat = Path.lstat, os.fstat
    calls = {'path': 0, 'fd': 0}

    def observe(info, api):
        calls[api] += 1
        changes = {'st_ctime_ns': 100 if api == 'path' else 200}
        if api == changing_api and calls[api] == 2:
            changes[field] = changes.get(field, getattr(info, field)) + 1
        return _view(info, **changes)

    def lstat(self):
        info = original_lstat(self)
        return observe(info, 'path') if self == path else info

    def fstat(fd):
        return observe(original_fstat(fd), 'fd')

    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(os, 'fstat', fstat)
    return calls


def test_unchanged_output_with_distinct_creation_and_change_times_is_read(tmp_path, monkeypatch):
    path = tmp_path / 'ordinary.json'
    raw = b'{"fixture":"unchanged"}'
    path.write_bytes(raw)
    calls = _separate_api_clocks(monkeypatch, path)

    assert OS.read_output_bytes(path) == raw
    assert calls == {'path': 2, 'fd': 2}


@pytest.mark.parametrize('api', ['path', 'fd'])
@pytest.mark.parametrize('field', ['st_ctime_ns', 'st_mtime_ns', 'st_size', 'st_dev', 'st_ino'])
def test_each_metadata_api_still_rejects_observed_changes(tmp_path, monkeypatch, api, field):
    path = tmp_path / 'ordinary.json'
    path.write_bytes(b'{"fixture":"before"}')
    _separate_api_clocks(monkeypatch, path, changing_api=api, field=field)

    with pytest.raises(OS.OutputError, match='changed'):
        OS.read_output_bytes(path)


@pytest.mark.parametrize('field', ['st_size', 'st_mtime_ns'])
def test_path_and_descriptor_content_state_must_agree(tmp_path, monkeypatch, field):
    path = tmp_path / 'ordinary.json'
    path.write_bytes(b'{"fixture":"before"}')
    original = os.fstat

    def fstat(fd):
        info = original(fd)
        return _view(info, **{field: getattr(info, field) + 1})

    monkeypatch.setattr(os, 'fstat', fstat)
    with pytest.raises(OS.OutputError, match='changed'):
        OS.read_output_bytes(path)


def test_same_size_mutation_with_restored_mtime_still_fails(tmp_path, monkeypatch):
    path = tmp_path / 'ordinary.json'
    original_bytes, changed_bytes = b'{"fixture":"before"}', b'{"fixture":"after!"}'
    assert len(original_bytes) == len(changed_bytes)
    path.write_bytes(original_bytes)
    times = path.stat()
    _separate_api_clocks(monkeypatch, path, changing_api='fd', field='st_ctime_ns')
    original_fdopen = os.fdopen

    @contextmanager
    def fdopen(*args, **kwargs):
        with original_fdopen(*args, **kwargs) as stream:
            class MutatingReader:
                def read(self, count):
                    raw = stream.read(count)
                    path.write_bytes(changed_bytes)
                    os.utime(path, ns=(times.st_atime_ns, times.st_mtime_ns))
                    return raw
            yield MutatingReader()

    monkeypatch.setattr(os, 'fdopen', fdopen)
    with pytest.raises(OS.OutputError, match='changed'):
        OS.read_output_bytes(path)
    assert path.read_bytes() == changed_bytes, 'failed evidence must remain inspectable'


def test_actual_rewritten_file_and_managed_marker_are_read_without_metadata_mocks(tmp_path):
    path = tmp_path / 'ordinary.json'
    path.write_bytes(b'before')
    path.write_bytes(b'after!')
    info = path.stat()
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
    assert OS.read_output_bytes(path) == b'after!'
    store = OS.OutputStore(tmp_path / 'run')
    assert OS.read_output_bytes(store.folder / OS.MANAGED_MARKER) == OS._MARKER_BYTES
