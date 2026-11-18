"""Real connection ownership at the final existing-mode attribute assignment."""
from __future__ import annotations

import ast
import inspect
import sqlite3
import sys
from pathlib import Path

import pytest

from patchtrace.kbcorrelation.store import WorkspaceStore


def _workspace(root):
    with WorkspaceStore(root) as store:
        store.journal_put('retained', 'intent', {'analyst': 'keep'})
    return (root / 'kbc.sqlite3').read_bytes()


def _handoff_line():
    function = WorkspaceStore._open_existing
    tree = ast.parse(Path(inspect.getsourcefile(function)).read_text())
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'WorkspaceStore')
    method = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == '_open_existing')
    assignments = [node for node in ast.walk(method) if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
        and target.value.id == 'self' and target.attr == 'db' for target in node.targets)]
    assert len(assignments) == 1
    return function, assignments[0].lineno


@pytest.mark.parametrize('stop', ['interrupt', 'exit'])
@pytest.mark.parametrize('close_failure', ['none', 'error', 'interrupt'])
def test_final_connection_assignment_closes_once_and_preserves_primary(tmp_path, monkeypatch,
                                                                      stop, close_failure):
    root = tmp_path / 'workspace'
    original = _workspace(root)
    connect = sqlite3.connect
    acquired = []
    primary = KeyboardInterrupt('authored primary') if stop == 'interrupt' else SystemExit(23)
    secondary = (RuntimeError('untrusted secondary /private/path') if close_failure == 'error'
                 else KeyboardInterrupt('untrusted secondary interrupt /private/path'))

    class TrackedConnection(sqlite3.Connection):
        close_calls = 0

        def close(self):
            self.close_calls += 1
            super().close()
            if close_failure != 'none':
                raise secondary

    def observed(*args, **kwargs):
        db = connect(*args, factory=TrackedConnection, **kwargs)
        acquired.append(db)
        return db

    monkeypatch.setattr(sqlite3, 'connect', observed)
    function, line = _handoff_line()
    fired = False

    def trace(frame, event, arg):
        nonlocal fired
        if frame.f_code is not function.__code__:
            return None
        if event == 'line' and frame.f_lineno == line and not fired:
            fired = True
            raise primary
        return trace

    previous = sys.gettrace()
    assert previous is None
    try:
        try:
            sys.settrace(trace)
            with pytest.raises(BaseException) as caught:
                WorkspaceStore(root, open_mode='existing')
        finally:
            sys.settrace(previous)
        assert fired and caught.value is primary
        assert len(acquired) == 1
        db = acquired[0]
        assert db.close_calls == 1, 'final handoff must remain inside owned admission cleanup'
        with pytest.raises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')
        notes = getattr(caught.value, '__notes__', [])
        if close_failure == 'none':
            assert notes == []
        else:
            assert notes == ['Workspace connection cleanup failed; resources may remain.']
            assert 'untrusted' not in str(caught.value) and 'private' not in str(caught.value)
        assert (root / 'kbc.sqlite3').read_bytes() == original
    finally:
        sys.settrace(previous)
        for db in acquired:
            sqlite3.Connection.close(db)  # Test cleanup occurs after observing production ownership.


def test_successful_existing_handoff_keeps_connection_live_until_explicit_close(tmp_path, monkeypatch):
    root = tmp_path / 'workspace'
    original = _workspace(root)
    connect = sqlite3.connect
    acquired = []

    class TrackedConnection(sqlite3.Connection):
        close_calls = 0

        def close(self):
            self.close_calls += 1
            return super().close()

    def observed(*args, **kwargs):
        db = connect(*args, factory=TrackedConnection, **kwargs)
        acquired.append(db)
        return db

    monkeypatch.setattr(sqlite3, 'connect', observed)
    try:
        store = WorkspaceStore(root, open_mode='existing')
        assert len(acquired) == 1 and store.db is acquired[0]
        assert store.db.close_calls == 0
        assert store.db.execute('SELECT 1').fetchone() == (1,)
        assert store.journal_get('retained') == ('intent', {'analyst': 'keep'})
        store.close()
        assert store.db.close_calls == 1
        with pytest.raises(sqlite3.ProgrammingError):
            store.db.execute('SELECT 1')
        assert (root / 'kbc.sqlite3').read_bytes() == original
    finally:
        for db in acquired:
            sqlite3.Connection.close(db)
