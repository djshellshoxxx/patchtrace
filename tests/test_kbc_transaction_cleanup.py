"""Real workspace writes preserve primary failures when rollback also fails."""
from __future__ import annotations

import sqlite3

import pytest

from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore


def _primary(kind):
    return {'sqlite': sqlite3.OperationalError('authored write failure'),
            'interrupt': KeyboardInterrupt('authored cancellation'),
            'exit': SystemExit(31),
            'domain': KbcStoreError('PT-KBC-VERIFY', 'authored verification failure')}[kind]


@pytest.mark.parametrize('kind', ['sqlite', 'interrupt', 'exit', 'domain'])
@pytest.mark.parametrize('rollback_kind', ['error', 'interrupt'])
@pytest.mark.parametrize('rollback_completed', [False, True])
def test_write_failure_survives_rollback_failure_and_prior_commits_are_retained(
        tmp_path, monkeypatch, kind, rollback_kind, rollback_completed):
    root = tmp_path / 'workspace'
    connect = sqlite3.connect
    primary = _primary(kind)
    secondary = (sqlite3.OperationalError('untrusted rollback error /private/path')
                 if rollback_kind == 'error' else KeyboardInterrupt('untrusted rollback interrupt /private/path'))
    armed = False
    acquired, rollbacks = [], []

    class ObservedConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if armed and sql == 'ROLLBACK':
                rollbacks.append(self.in_transaction)
                if rollback_completed:
                    super().execute(sql, *args, **kwargs)
                raise secondary
            result = super().execute(sql, *args, **kwargs)
            if armed and sql.startswith('INSERT INTO journal '):
                raise primary
            return result

    def observed(*args, **kwargs):
        db = connect(*args, factory=ObservedConnection, **kwargs)
        acquired.append(db)
        return db

    monkeypatch.setattr(sqlite3, 'connect', observed)
    try:
        with WorkspaceStore(root) as workspace:
            workspace.journal_put('prior', 'done', {'analyst': 'keep'})
            armed = True
            with pytest.raises(BaseException) as caught:
                workspace.journal_put('pending', 'intent', {'attempt': 'must not commit'})
            assert caught.value is primary
            assert getattr(primary, '__notes__', []) == [
                'Workspace transaction rollback failed; close the workspace before reuse.']
            assert '/private/path' not in str(primary)
            assert rollbacks == [True]
            assert workspace.journal_get('prior') == ('done', {'analyst': 'keep'})
            assert workspace.db.in_transaction is not rollback_completed
            if not rollback_completed:
                with pytest.raises(KbcStoreError, match='busy'):
                    workspace.journal_put('later', 'done', {})
                assert workspace.journal_get('later') is None
        with pytest.raises(sqlite3.ProgrammingError):
            acquired[0].execute('SELECT 1')
        armed = False
        with WorkspaceStore(root, open_mode='existing') as reopened:
            assert reopened.journal_get('prior') == ('done', {'analyst': 'keep'})
            assert reopened.journal_get('pending') is None
            assert reopened.journal_get('later') is None
    finally:
        for db in acquired:
            sqlite3.Connection.close(db)


@pytest.mark.parametrize('kind', ['sqlite', 'interrupt'])
def test_failure_observed_after_commit_does_not_erase_committed_write(tmp_path, monkeypatch, kind):
    root = tmp_path / 'workspace'
    connect = sqlite3.connect
    primary = _primary(kind)
    armed = False
    rollbacks = []

    class ObservedConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if armed and sql == 'ROLLBACK':
                rollbacks.append(True)
            result = super().execute(sql, *args, **kwargs)
            if armed and sql == 'COMMIT':
                raise primary
            return result

    monkeypatch.setattr(sqlite3, 'connect', lambda *args, **kwargs: connect(
        *args, factory=ObservedConnection, **kwargs))
    with WorkspaceStore(root) as workspace:
        armed = True
        with pytest.raises(BaseException) as caught:
            workspace.journal_put('committed', 'done', {'analyst': 'keep'})
        assert caught.value is primary
        assert not workspace.db.in_transaction
        assert not rollbacks and not getattr(primary, '__notes__', [])
    armed = False
    with WorkspaceStore(root, open_mode='existing') as reopened:
        assert reopened.journal_get('committed') == ('done', {'analyst': 'keep'})
