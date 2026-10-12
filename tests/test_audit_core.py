from __future__ import annotations

import sqlite3

import pytest

from patchtrace import persistence
from patchtrace.persistence import ProjectStore, strict_json


class _FailingHistoryDDL(sqlite3.Connection):
    def execute(self, sql, *args):
        if sql.startswith('CREATE TABLE history'):
            raise sqlite3.OperationalError('injected failure')
        return super().execute(sql, *args)


def test_failed_database_initialization_is_atomic_and_retryable(tmp_path, monkeypatch):
    real_connect = sqlite3.connect
    monkeypatch.setattr(persistence.sqlite3, 'connect',
                        lambda *a, **k: real_connect(*a, factory=_FailingHistoryDDL, **k))
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectStore(tmp_path, create=True)
    path = tmp_path / 'project.sqlite3'
    if path.exists():
        # If anything remains, it must not carry a committed version or partial tables.
        connection = real_connect(path)
        try:
            assert connection.execute('PRAGMA user_version').fetchone()[0] == 0
            assert connection.execute('SELECT count(*) FROM sqlite_master').fetchone()[0] == 0
        finally:
            connection.close()
    monkeypatch.setattr(persistence.sqlite3, 'connect', real_connect)
    store = ProjectStore(tmp_path, create=True)
    try:
        tables = {row[0] for row in store.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {'current_snapshot', 'history'} <= tables
    finally:
        store.close()


def test_failed_initialization_does_not_delete_preexisting_database(tmp_path):
    (tmp_path / 'project.sqlite3').write_bytes(b'existing')
    with pytest.raises(ValueError, match='already exists'):
        ProjectStore(tmp_path, create=True)
    assert (tmp_path / 'project.sqlite3').read_bytes() == b'existing'


@pytest.mark.parametrize('text', ['{"a": 1e999}', '{"a": -1e400}', '[1E+999]'])
def test_strict_json_rejects_overflowing_floats(text):
    with pytest.raises(ValueError, match='PT-SCHEMA: invalid JSON number'):
        strict_json(text)


def test_strict_json_tags_oversized_integers():
    with pytest.raises(ValueError, match='PT-SCHEMA'):
        strict_json('{"a": ' + '9' * 5000 + '}')
    assert strict_json('{"a": 1.5, "b": 7}') == {'a': 1.5, 'b': 7}
