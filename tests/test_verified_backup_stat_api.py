"""Windows descriptor/path timestamps differ; retain each API's change checks."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from patchtrace import verified_backup as V
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def _stat_view(info, **changes):
    fields = {name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns',
                                                   'st_ctime_ns', 'st_mode')}
    return SimpleNamespace(**(fields | changes))


def _descriptor_change_time(monkeypatch):
    original = os.fstat
    monkeypatch.setattr(os, 'fstat', lambda fd: _stat_view(original(fd),
                                                        st_ctime_ns=original(fd).st_ctime_ns + 1_000_000))


def test_fingerprint_accepts_stable_distinct_descriptor_and_path_change_times(tmp_path, monkeypatch):
    path = tmp_path / 'backup.sqlite3'
    raw = b'exact unchanged bytes'
    path.write_bytes(raw)
    _descriptor_change_time(monkeypatch)
    version = V._fingerprint(path)
    assert version is not None
    assert version[-1] == hashlib.sha256(raw).hexdigest()


def test_real_sqlite_backup_and_cached_reuse_with_distinct_change_times(tmp_path, monkeypatch):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    with ProjectService.create(older, newer, 'Windows stat seam', tmp_path / 'project') as service:
        _descriptor_change_time(monkeypatch)
        V.forget_all()
        backup = V.write_verified_backup(service.root, service.store.connection, 'history-prune')
        assert V.trusted_backup(service.root, 'history-prune', project_id=service.project.id,
                                require_tables=('history',)) == backup
        assert not list((service.root / 'backups').glob('*.part'))
    V.forget_all()


@pytest.mark.parametrize('channel', ['descriptor', 'path', 'native-change-time'])
def test_change_time_mutation_in_each_observation_channel_refuses_bytes(tmp_path, monkeypatch, channel):
    path = tmp_path / 'backup.sqlite3'
    path.write_bytes(b'unchanged size and mtime')
    calls = 0
    if channel == 'descriptor':
        original = os.fstat

        def changing(fd):
            nonlocal calls
            calls += 1
            info = original(fd)
            return _stat_view(info, st_ctime_ns=info.st_ctime_ns + calls)

        monkeypatch.setattr(os, 'fstat', changing)
    elif channel == 'path':
        original = Path.lstat

        def changing(self):
            nonlocal calls
            info = original(self)
            if self == path:
                calls += 1
                return _stat_view(info, st_ctime_ns=info.st_ctime_ns + calls)
            return info

        monkeypatch.setattr(Path, 'lstat', changing)
    else:
        original = V.file_fingerprint

        def changing(value):
            nonlocal calls
            calls += 1
            result = original(value)
            return (*result[:4], result[4] + calls)

        monkeypatch.setattr(V, 'file_fingerprint', changing)
    assert V._fingerprint(path) is None


@pytest.mark.parametrize('field', ['st_dev', 'st_ino', 'st_size', 'st_mtime_ns'])
def test_incompatible_cross_api_identity_or_content_metadata_is_refused(tmp_path, monkeypatch, field):
    path = tmp_path / 'backup.sqlite3'
    path.write_bytes(b'unchanged file')
    original = Path.lstat

    def changed(self):
        info = original(self)
        return _stat_view(info, **{field: getattr(info, field) + 1}) if self == path else info

    monkeypatch.setattr(Path, 'lstat', changed)
    assert V._fingerprint(path) is None
