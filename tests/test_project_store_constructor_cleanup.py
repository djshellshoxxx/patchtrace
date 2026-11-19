"""Real acquired resources remain owned by the constructor until it returns."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import pytest

from patchtrace import persistence
from patchtrace.input_readers import InputReadError
from patchtrace.persistence import ProjectLock, ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def sources(tmp_path):
    pair = [tmp_path / (side + '.dll') for side in ('older', 'newer')]
    for variant, path in enumerate(pair):
        path.write_bytes(synthetic_pe(variant))
    return pair


def existing(tmp_path):
    pair, root = sources(tmp_path), tmp_path / 'project'
    with ProjectService.create(*pair, 'retained project', root):
        pass
    (root / 'analyst.txt').write_bytes(b'Preserve foreign analyst evidence.')
    return pair, root


def retained(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob('*')
            if path.is_file() and path.name != '.patchtrace.lock'}


def failure(kind):
    return {'keyboard': KeyboardInterrupt('authored stop'), 'exit': SystemExit(7),
            'neutral': InputReadError('cancelled'), 'ordinary': PermissionError('authored denial'),
            'sqlite': sqlite3.OperationalError('authored SQLite refusal')}[kind]


def assert_primary(caught, primary):
    if isinstance(primary, sqlite3.Error):
        assert type(caught) is ValueError
        assert str(caught) == 'PT-STORAGE: project database cannot be opened'
        assert caught.__cause__ is primary
    else:
        assert caught is primary


@contextmanager
def initialization_failure(monkeypatch, primary, boundary, *, cleanup='healthy'):
    """Use actual SQLite; inject only the named failure and observe before test cleanup."""
    real_connect, real_init = sqlite3.connect, ProjectStore.__init__
    real_lock_close = ProjectLock.close
    stores, connections = [], []
    secondary = PermissionError('private secondary detail /secret/path')

    class ActualConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            result = super().execute(statement, *args, **kwargs)
            if statement == boundary:
                raise primary
            return result

        def close(self):
            if cleanup != 'connection-before':
                super().close()
            if cleanup.startswith('connection-'):
                raise secondary

    def connect(database, *args, **kwargs):
        if 'mode=rw' not in str(database):
            return real_connect(database, *args, **kwargs)
        if boundary == 'connect':
            raise primary
        connection = real_connect(database, *args, factory=ActualConnection, **kwargs)
        connections.append(connection)
        return connection

    def initialize(store, *args, **kwargs):
        stores.append(store)
        return real_init(store, *args, **kwargs)

    def close_lock(lock):
        if cleanup != 'lock-before':
            real_lock_close(lock)
        if cleanup.startswith('lock-'):
            raise secondary

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, 'connect', connect)
        patch.setattr(ProjectStore, '__init__', initialize)
        patch.setattr(ProjectLock, 'close', close_lock)
        try:
            yield stores, connections
        finally:
            # Restore only the test-owned resources after recording product behavior.
            for connection in connections:
                sqlite3.Connection.close(connection)
            for store in stores:
                store.connection = None
                if store.lock is not None:
                    real_lock_close(store.lock)
                    store.lock = None
                store.closed = True


@pytest.mark.parametrize('kind', ['keyboard', 'exit', 'neutral', 'ordinary', 'sqlite'])
@pytest.mark.parametrize('boundary', ['connect', 'PRAGMA foreign_keys=ON', 'PRAGMA quick_check'])
def test_initialization_failure_closes_acquired_store_without_touching_committed_data(tmp_path, monkeypatch,
                                                                                   kind, boundary):
    _pair, root = existing(tmp_path)
    before = retained(root)
    primary = failure(kind)
    with initialization_failure(monkeypatch, primary, boundary) as (stores, connections):
        with pytest.raises(BaseException) as caught:
            ProjectService.open(root, maintenance=False, recover_interrupted=False)
        assert len(stores) == 1 and len(connections) == int(boundary != 'connect')
        assert retained(root) == before
        assert_primary(caught.value, primary)
        assert not getattr(caught.value, '__notes__', [])
        store = stores[0]
        assert store.closed and store.connection is None and store.lock is None
        lock = ProjectLock(root)
        lock.close()


@pytest.mark.parametrize('kind', ['keyboard', 'exit', 'neutral', 'sqlite'])
@pytest.mark.parametrize('database', ['new', 'zero-byte', 'empty-current'])
def test_initialization_stop_keeps_create_and_retry_ownership(tmp_path, monkeypatch, kind, database):
    pair, root = sources(tmp_path), tmp_path / 'project'
    root.mkdir()
    path = root / 'project.sqlite3'
    if database == 'zero-byte':
        path.write_bytes(b'')
    elif database == 'empty-current':
        ProjectStore(root, create=True).close()
    (root / 'analyst.txt').write_bytes(b'Never delete this unowned file.')
    before = retained(root)
    identity = (path.stat().st_dev, path.stat().st_ino) if path.exists() else None
    boundary = 'BEGIN IMMEDIATE' if database == 'empty-current' else persistence._HISTORY_SQL
    primary = failure(kind)
    with initialization_failure(monkeypatch, primary, boundary) as (stores, connections):
        with pytest.raises(BaseException) as caught:
            ProjectService.create(*pair, 'must not publish', root)
        assert len(stores) == len(connections) == 1
        assert retained(root) == before
        assert_primary(caught.value, primary)
        assert stores[0].closed and stores[0].connection is None and stores[0].lock is None
        if identity is not None:
            assert (path.stat().st_dev, path.stat().st_ino) == identity
    with ProjectService.create(*pair, 'healthy retry', root) as service:
        saved_id = service.project.id
    with ProjectService.open(root, maintenance=False, recover_interrupted=False) as service:
        assert service.project.id == saved_id
    assert (root / 'analyst.txt').read_bytes() == before['analyst.txt']


@pytest.mark.parametrize('kind', ['keyboard', 'neutral', 'sqlite'])
@pytest.mark.parametrize('cleanup', ['connection-before', 'connection-after', 'lock-before', 'lock-after'])
def test_secondary_constructor_cleanup_failure_keeps_primary_and_bounded_note(tmp_path, monkeypatch, kind, cleanup):
    _pair, root = existing(tmp_path)
    before = retained(root)
    primary = failure(kind)
    with initialization_failure(monkeypatch, primary, 'PRAGMA quick_check', cleanup=cleanup) as (stores, _):
        with pytest.raises(BaseException) as caught:
            ProjectService.open(root, maintenance=False, recover_interrupted=False)
        assert retained(root) == before
        assert_primary(caught.value, primary)
        notes = getattr(caught.value, '__notes__', [])
        assert len(notes) == 1 and len(notes[0]) < 160
        assert 'cleanup' in notes[0] and 'remain' in notes[0]
        assert 'private' not in notes[0] and '/secret' not in notes[0]
        assert not stores[0].closed  # The wrapper never completed successful cleanup.


def test_discard_interruption_keeps_owned_file_and_reports_uncertainty(tmp_path, monkeypatch):
    pair, root = sources(tmp_path), tmp_path / 'project'
    primary = InputReadError('limited')

    def refused_discard(path, owned):
        assert path.is_file() and owned is not None
        raise KeyboardInterrupt('private cleanup detail')

    monkeypatch.setattr(persistence, '_discard_created_database', refused_discard)
    with initialization_failure(monkeypatch, primary, persistence._HISTORY_SQL) as (stores, _):
        with pytest.raises(BaseException) as caught:
            ProjectService.create(*pair, 'incomplete owned attempt', root)
        assert caught.value is primary
        assert (root / 'project.sqlite3').is_file()
        assert not (root / 'artifacts').exists()
        assert stores[0].closed and stores[0].connection is None and stores[0].lock is None
        notes = getattr(caught.value, '__notes__', [])
        assert len(notes) == 1 and 'remain' in notes[0] and 'private' not in notes[0]


def test_unknown_database_refusal_preserves_foreign_bytes_and_releases_lock(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    with sqlite3.connect(root / 'project.sqlite3') as connection:
        connection.execute('CREATE TABLE analyst_notes (body TEXT)')
        connection.execute('INSERT INTO analyst_notes VALUES (?)', ('retained',))
    before = retained(root)
    with pytest.raises(ValueError, match='project database already exists'):
        ProjectStore(root, create=True)
    assert retained(root) == before
    lock = ProjectLock(root)
    lock.close()
