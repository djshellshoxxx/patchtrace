"""Project creation keeps pathname and descriptor metadata observations separate."""
from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import pytest

from patchtrace import persistence
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


class OSView:
    def __init__(self, fstat):
        self.fstat = fstat

    def __getattr__(self, name):
        return getattr(os, name)


def snapshot(info, **changes):
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
    return SimpleNamespace(**({field: getattr(info, field) for field in fields} | changes))


def descriptor_view(monkeypatch, database, change=None):
    actual = os.fstat
    observations = []

    def fstat(fd):
        info = actual(fd)
        if database.exists() and os.path.samestat(info, database.lstat()):
            observations.append(info)
            changes = {'st_ctime_ns': info.st_ctime_ns + 17}
            if change:
                changes.update(change(info, len(observations)))
            return snapshot(info, **changes)
        return info

    monkeypatch.setattr(persistence, 'os', OSView(fstat))
    return observations


def pair(tmp_path):
    paths = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for variant, path in enumerate(paths):
        path.write_bytes(synthetic_pe(variant))
    return paths


def test_new_project_accepts_stable_descriptor_and_path_change_time_views(tmp_path, monkeypatch):
    """Windows can report creation time through stat and change time through fstat."""
    root = tmp_path / 'project'
    observed = descriptor_view(monkeypatch, root / 'project.sqlite3')
    with ProjectService.create(*pair(tmp_path), 'independent observations', root) as service:
        identity = service.project.id
        assert service.store.load().id == identity
    with ProjectService.open(root) as reopened:
        assert reopened.project.id == identity
    assert len(observed) >= 2


@pytest.mark.parametrize('field', ['st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode', 'st_nlink'])
def test_descriptor_and_path_physical_disagreement_refuses(tmp_path, monkeypatch, field):
    root = tmp_path / 'project'

    def changed(info, _count):
        return {field: stat.S_IFIFO if field == 'st_mode' else getattr(info, field) + 1}

    descriptor_view(monkeypatch, root / 'project.sqlite3', changed)
    with pytest.raises(ValueError, match='project database changed'):
        ProjectService.create(*pair(tmp_path), 'must refuse', root)
    assert not (root / 'artifacts').exists()


def test_descriptor_change_time_drift_during_admission_refuses(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    descriptor_view(monkeypatch, root / 'project.sqlite3',
                    lambda info, count: {'st_ctime_ns': info.st_ctime_ns + count})
    with pytest.raises(ValueError, match='project database changed'):
        ProjectService.create(*pair(tmp_path), 'must refuse drift', root)
    assert not (root / 'artifacts').exists()


def test_path_change_time_drift_after_admission_refuses(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    descriptor_view(monkeypatch, root / 'project.sqlite3')
    actual = persistence._creation_file
    calls = []

    def pathname(path):
        info = actual(path)
        calls.append(info)
        return snapshot(info, st_ctime_ns=info.st_ctime_ns + len(calls)) if info is not None else None

    monkeypatch.setattr(persistence, '_creation_file', pathname)
    with pytest.raises(ValueError, match='project database changed'):
        ProjectService.create(*pair(tmp_path), 'must refuse drift', root)
    assert not (root / 'artifacts').exists()
