"""Real SQLite creation retains its primary failure through interrupted cleanup."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from patchtrace import persistence
from patchtrace import service as core
from patchtrace.input_readers import InputReadError
from patchtrace.persistence import ProjectLock, ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


@pytest.mark.parametrize('secondary_type', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('phase', ['rollback', 'connection-close', 'store-close', 'artifact-delete'])
def test_real_cancel_keeps_primary_and_attempts_remaining_owned_cleanup(tmp_path, monkeypatch,
                                                                       secondary_type, phase):
    paths = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for path, version in zip(paths, (0, 1), strict=True):
        path.write_bytes(synthetic_pe(version))
    root = tmp_path / 'project'
    root.mkdir()
    foreign = root / 'note.txt'
    foreign.write_bytes(b'keep independent analyst work')
    primary, secondary = InputReadError('cancelled'), secondary_type('secondary cleanup detail')
    attempts, statements, connections = [], [], []
    real_connect, real_store_close, real_remove = sqlite3.connect, ProjectStore.close, core._remove_owned
    stopping = False

    class Connection(sqlite3.Connection):
        def rollback(self):
            if stopping:
                attempts.append('rollback')
                if phase == 'rollback':
                    raise secondary
            return super().rollback()

        def close(self):
            if stopping:
                attempts.append('connection-close')
                if phase == 'connection-close' and attempts.count('connection-close') == 1:
                    raise secondary
            return super().close()

    def connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs, factory=Connection)
        connection.set_trace_callback(statements.append)
        connections.append(connection)
        return connection

    def close(store):
        attempts.append('store-close')
        real_store_close(store)
        if phase == 'store-close':
            raise secondary

    def remove(path, recorded, **kwargs):
        attempts.append(Path(path).name)
        if phase == 'artifact-delete' and Path(path).suffix == '.bin' and not any(
                item == 'interrupted-delete' for item in attempts):
            attempts.append('interrupted-delete')
            raise secondary
        return real_remove(path, recorded, **kwargs)

    def checkpoint(_count):
        nonlocal stopping
        if any(sql.startswith('INSERT INTO current_snapshot') for sql in statements):
            stopping = True
            raise primary

    monkeypatch.setattr(persistence.sqlite3, 'connect', connect)
    monkeypatch.setattr(ProjectStore, 'close', close)
    monkeypatch.setattr(core, '_remove_owned', remove)
    try:
        with pytest.raises(BaseException) as caught:
            ProjectService.create(*paths, 'cancelled', root, checkpoint=checkpoint)
        assert caught.value is primary and 'store-close' in attempts
        assert foreign.read_bytes() == b'keep independent analyst work'
        assert primary.__notes__ and all('secondary cleanup detail' not in note for note in primary.__notes__)
        if phase == 'artifact-delete':
            assert len([item for item in attempts if item.endswith('.bin')]) == 2
            assert len(list(root.rglob('*.bin'))) == 1
            assert not (root / 'project.sqlite3').exists()
        elif phase in {'rollback', 'connection-close'}:
            assert (root / 'project.sqlite3').exists() and len(list(root.rglob('*.bin'))) == 2
        else:
            assert not (root / 'project.sqlite3').exists() and not list(root.rglob('*.bin'))
        lock = ProjectLock(root)
        lock.close()
        for connection in connections:
            with pytest.raises(sqlite3.ProgrammingError, match='closed'):
                connection.execute('SELECT 1')
    finally:
        for connection in connections:
            sqlite3.Connection.close(connection)


@pytest.mark.parametrize('secondary_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_postcommit_primary_and_snapshot_survive_secondary_close(tmp_path, monkeypatch, secondary_type):
    path = tmp_path / 'input.dll'
    path.write_bytes(synthetic_pe(0))
    root = tmp_path / 'project'
    primary = RuntimeError('caller observed a failure after the real COMMIT')
    save, close = ProjectStore.save, ProjectStore.close

    def committed(store, project, **kwargs):
        save(store, project, **kwargs)
        raise primary

    def closed(store):
        close(store)
        raise secondary_type('secondary cleanup detail')

    with monkeypatch.context() as scoped:
        scoped.setattr(ProjectStore, 'save', committed)
        scoped.setattr(ProjectStore, 'close', closed)
        with pytest.raises(BaseException) as caught:
            ProjectService.create(path, path, 'retained after commit', root)
    assert caught.value is primary and primary.__notes__
    with ProjectService.open(root) as reopened:
        assert reopened.project.name == 'retained after commit'
