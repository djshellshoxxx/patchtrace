"""Actual SQLite ownership after ordinary workspace construction fails."""
from __future__ import annotations

import sqlite3

import pytest

from patchtrace.kbcorrelation import store as module
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore


@pytest.mark.parametrize('statement', [
    'PRAGMA busy_timeout=5000',
    'PRAGMA user_version',
    'CREATE TABLE docs ',
    'PRAGMA journal_mode=WAL',
])
@pytest.mark.parametrize('kind', ['sqlite', 'interrupt', 'exit'])
def test_initialization_failure_closes_real_connection_and_keeps_primary(tmp_path, monkeypatch,
                                                                        statement, kind):
    root = tmp_path / 'workspace'
    connect = sqlite3.connect
    acquired = []
    primary = {'sqlite': sqlite3.OperationalError('authored SQLite failure /private/path'),
               'interrupt': KeyboardInterrupt('authored interrupt'), 'exit': SystemExit(19)}[kind]

    class ObservedConnection(sqlite3.Connection):
        close_calls = 0

        def execute(self, sql, *args, **kwargs):
            result = super().execute(sql, *args, **kwargs)
            if sql.startswith(statement):
                raise primary
            return result

        def close(self):
            self.close_calls += 1
            return super().close()

    def observed(*args, **kwargs):
        db = connect(*args, factory=ObservedConnection, **kwargs)
        acquired.append(db)
        return db

    monkeypatch.setattr(sqlite3, 'connect', observed)
    try:
        with pytest.raises(BaseException) as caught:
            WorkspaceStore(root)
        if kind == 'sqlite':
            assert isinstance(caught.value, KbcStoreError)
            assert caught.value.code == 'PT-KBC-STORAGE'
            assert caught.value.__cause__ is primary
            assert '/private/path' not in str(caught.value)
        else:
            assert caught.value is primary
        assert len(acquired) == 1
        assert acquired[0].close_calls == 1
        with pytest.raises(sqlite3.ProgrammingError):
            acquired[0].execute('SELECT 1')
        assert (root / 'kbc.sqlite3').is_file(), 'construction cleanup must not delete workspace files'
    finally:
        for db in acquired:
            sqlite3.Connection.close(db)


@pytest.mark.parametrize('version', [1, 2])
@pytest.mark.parametrize('close_failure', ['none', 'error', 'interrupt'])
@pytest.mark.parametrize('failure', ['interrupt', 'anchor'])
def test_root_verification_failure_closes_current_connection_preserves_retained_data(
        tmp_path, monkeypatch, version, close_failure, failure):
    root = tmp_path / 'workspace'
    with WorkspaceStore(root) as original:
        original.journal_put('retained', 'intent', {'analyst': 'keep'})
        original.db.execute(f'PRAGMA user_version={version}')
    connect = sqlite3.connect
    acquired = []
    primary = (KeyboardInterrupt('authored root-check interrupt') if failure == 'interrupt'
               else module.OwnedPublicationError('untrusted changed root /private/path'))
    secondary = (RuntimeError('untrusted close failure /private/path') if close_failure == 'error'
                 else SystemExit('untrusted close failure /private/path'))

    class ObservedConnection(sqlite3.Connection):
        close_calls = 0

        def close(self):
            self.close_calls += 1
            super().close()
            # The first writable connection closes normally before a newer-version reopen.
            if close_failure != 'none' and len(acquired) == version:
                raise secondary

    def observed(*args, **kwargs):
        db = connect(*args, factory=ObservedConnection, **kwargs)
        acquired.append(db)
        return db

    def reject_anchor(_anchor):
        raise primary

    monkeypatch.setattr(sqlite3, 'connect', observed)
    monkeypatch.setattr(module, 'verify_anchor', reject_anchor)
    try:
        with pytest.raises(BaseException) as caught:
            WorkspaceStore(root)
        if failure == 'interrupt':
            assert caught.value is primary
        else:
            assert isinstance(caught.value, KbcStoreError)
            assert caught.value.code == 'PT-KBC-STORAGE'
            assert caught.value.__cause__ is primary
            assert '/private/path' not in str(caught.value)
        assert len(acquired) == version
        assert all(db.close_calls == 1 for db in acquired)
        for db in acquired:
            with pytest.raises(sqlite3.ProgrammingError):
                db.execute('SELECT 1')
        notes = getattr(caught.value, '__notes__', [])
        assert notes == ([] if close_failure == 'none'
                         else ['Workspace connection cleanup failed; resources may remain.'])
        assert not any('untrusted' in note or '/private/path' in note for note in notes)
        retained = connect(root / 'kbc.sqlite3')
        try:
            assert retained.execute('SELECT state,body FROM journal WHERE op_id=?', ('retained',)).fetchone() == (
                'intent', '{"analyst":"keep"}')
            assert retained.execute('PRAGMA user_version').fetchone() == (version,)
        finally:
            retained.close()
    finally:
        for db in acquired:
            sqlite3.Connection.close(db)


@pytest.mark.parametrize('version', [1, 2])
def test_success_keeps_only_current_connection_open_until_explicit_close(tmp_path, monkeypatch, version):
    root = tmp_path / 'workspace'
    with WorkspaceStore(root) as original:
        original.journal_put('retained', 'intent', {'analyst': 'keep'})
        original.db.execute(f'PRAGMA user_version={version}')
    connect = sqlite3.connect
    acquired = []

    class ObservedConnection(sqlite3.Connection):
        close_calls = 0

        def close(self):
            self.close_calls += 1
            return super().close()

    def observed(*args, **kwargs):
        db = connect(*args, factory=ObservedConnection, **kwargs)
        acquired.append(db)
        return db

    monkeypatch.setattr(sqlite3, 'connect', observed)
    try:
        with WorkspaceStore(root) as current:
            assert len(acquired) == version
            assert current.db is acquired[-1] and acquired[-1].close_calls == 0
            assert current.journal_get('retained') == ('intent', {'analyst': 'keep'})
            assert current.read_only is (version == 2)
            if version == 2:
                assert acquired[0].close_calls == 1
                with pytest.raises(sqlite3.ProgrammingError):
                    acquired[0].execute('SELECT 1')
        assert all(db.close_calls == 1 for db in acquired)
    finally:
        for db in acquired:
            sqlite3.Connection.close(db)


@pytest.mark.parametrize('state', ['new', 'retained-v0'])
@pytest.mark.parametrize('kind', ['sqlite', 'interrupt', 'exit'])
@pytest.mark.parametrize('rollback_kind', ['error', 'interrupt'])
@pytest.mark.parametrize('rollback_completed', [False, True])
def test_schema_failure_survives_failed_rollback_and_closes_owned_connection(
        tmp_path, monkeypatch, state, kind, rollback_kind, rollback_completed):
    root = tmp_path / 'workspace'
    path = root / 'kbc.sqlite3'
    connect = sqlite3.connect
    if state == 'retained-v0':
        root.mkdir()
        retained = connect(path)
        try:
            retained.execute('CREATE TABLE analyst_notes (body TEXT)')
            retained.execute('INSERT INTO analyst_notes VALUES (?)', ('preserve original notes',))
            retained.commit()
        finally:
            retained.close()
    acquired, rollbacks = [], []
    primary = {'sqlite': sqlite3.OperationalError('authored initialization failure'),
               'interrupt': KeyboardInterrupt('authored initialization interrupt'),
               'exit': SystemExit(29)}[kind]
    secondary = (sqlite3.OperationalError('untrusted rollback failure /private/path')
                 if rollback_kind == 'error' else KeyboardInterrupt('untrusted rollback interrupt /private/path'))

    class ObservedConnection(sqlite3.Connection):
        close_calls = 0

        def execute(self, sql, *args, **kwargs):
            if sql == 'ROLLBACK':
                rollbacks.append(self.in_transaction)
                if rollback_completed:
                    super().execute(sql, *args, **kwargs)
                raise secondary
            result = super().execute(sql, *args, **kwargs)
            if sql.startswith('CREATE TABLE docs '):
                raise primary
            return result

        def close(self):
            self.close_calls += 1
            return super().close()

    def observed(*args, **kwargs):
        db = connect(*args, factory=ObservedConnection, **kwargs)
        acquired.append(db)
        return db

    monkeypatch.setattr(sqlite3, 'connect', observed)
    try:
        with pytest.raises(BaseException) as caught:
            WorkspaceStore(root)
        if kind == 'sqlite':
            assert isinstance(caught.value, KbcStoreError)
            assert caught.value.__cause__ is primary
            assert caught.value.code == 'PT-KBC-STORAGE'
        else:
            assert caught.value is primary
        assert getattr(primary, '__notes__', []) == [
            'Workspace initialization rollback failed; resources may remain.']
        assert '/private/path' not in str(caught.value)
        assert rollbacks == [True] and len(acquired) == 1
        assert acquired[0].close_calls == 1
        with pytest.raises(sqlite3.ProgrammingError):
            acquired[0].execute('SELECT 1')
        assert path.is_file(), 'cleanup must not delete a created or preexisting database'
        retained = connect(path)
        try:
            assert retained.execute('PRAGMA user_version').fetchone() == (0,)
            expected = [('analyst_notes',)] if state == 'retained-v0' else []
            assert retained.execute("SELECT name FROM sqlite_schema WHERE type='table'").fetchall() == expected
            if state == 'retained-v0':
                assert retained.execute('SELECT body FROM analyst_notes').fetchall() == [('preserve original notes',)]
        finally:
            retained.close()
    finally:
        for db in acquired:
            sqlite3.Connection.close(db)
