"""Existing-mode admission: actual SQLite connection, no application initialization."""
from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore


@contextmanager
def _database(path, *, connect=None):
    db = (connect or sqlite3.connect)(path)
    try:
        with db:
            yield db
    finally:
        db.close()


def _files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def _workspace(root: Path, *, journal_mode: str = 'delete') -> Path:
    with WorkspaceStore(root) as store:
        store.journal_put('retained', 'intent', {'analyst': 'original'})
        raw = b'authored retained metadata'
        store.write_object(hashlib.sha256(raw).hexdigest(), raw)
    with _database(root / 'kbc.sqlite3') as db:
        if journal_mode == 'delete':
            assert db.execute('PRAGMA journal_mode=DELETE').fetchone() == ('delete',)
        else:
            assert journal_mode == 'wal'
    (root / 'analyst.txt').write_bytes(b'Keep this analyst-owned file.')
    return root / 'kbc.sqlite3'


@pytest.mark.parametrize('journal_mode', ['delete', 'wal'])
def test_existing_reads_healthy_workspace_without_changing_journal_mode(tmp_path, journal_mode):
    root = tmp_path / 'workspace'
    path = _workspace(root, journal_mode=journal_mode)
    before = _files(root)
    with WorkspaceStore(root, open_mode='existing') as store:
        assert not store.read_only
        assert store.journal_get('retained') == ('intent', {'analyst': 'original'})
        assert store.db.execute('PRAGMA user_version').fetchone() == (1,)
        assert store.db.execute('PRAGMA journal_mode').fetchone() == (journal_mode,)
        raw = b'authored retained metadata'
        assert store.read_object(hashlib.sha256(raw).hexdigest()) == raw
    assert _files(root) == before
    assert path.exists()


def test_existing_allows_explicit_later_transaction_and_extra_tables(tmp_path):
    root = tmp_path / 'workspace'
    path = _workspace(root)
    with _database(path) as db:
        db.execute('CREATE TABLE retained_notes (body TEXT)')
        db.execute('INSERT INTO retained_notes VALUES (?)', ('keep',))
    with WorkspaceStore(root, create=False, open_mode='existing') as store:
        store.journal_put('later-approved', 'done', {'after': 'explicit transaction'})
        assert store.db.execute('SELECT body FROM retained_notes').fetchall() == [('keep',)]
    with WorkspaceStore(root, create=False) as store:
        assert store.journal_get('later-approved') == ('done', {'after': 'explicit transaction'})


@pytest.mark.parametrize('state', ['missing-root', 'missing-file', 'zero', 'empty-v0', 'foreign-v0'])
def test_existing_refuses_uninitialized_storage_without_creating_or_changing_it(tmp_path, state):
    root = tmp_path / 'workspace'
    path = root / 'kbc.sqlite3'
    if state != 'missing-root':
        root.mkdir()
        (root / 'analyst.txt').write_bytes(b'Keep unrelated input.')
    if state == 'zero':
        path.write_bytes(b'')
    elif state in {'empty-v0', 'foreign-v0'}:
        with _database(path) as db:
            if state == 'foreign-v0':
                db.execute('CREATE TABLE retained_notes (body TEXT)')
                db.execute('INSERT INTO retained_notes VALUES (?)', ('keep',))
    before = _files(root)
    with pytest.raises(KbcStoreError) as caught:
        WorkspaceStore(root, open_mode='existing')
    assert caught.value.code == 'PT-KBC-STORAGE'
    assert _files(root) == before
    assert root.exists() == (state != 'missing-root')


@pytest.mark.parametrize('mode', [None, 'normal'])
@pytest.mark.parametrize('state', ['zero', 'foreign-v0'])
def test_ordinary_create_false_still_initializes_existing_v0(tmp_path, state, mode):
    root = tmp_path / 'ordinary'
    root.mkdir()
    path = root / 'kbc.sqlite3'
    if state == 'zero':
        path.write_bytes(b'')
    else:
        with _database(path) as db:
            db.execute('CREATE TABLE retained_notes (body TEXT)')
            db.execute('INSERT INTO retained_notes VALUES (?)', ('keep',))
    options = {} if mode is None else {'open_mode': mode}
    with WorkspaceStore(root, create=False, **options) as store:
        assert store.db.execute('PRAGMA user_version').fetchone() == (1,)
        assert store.db.execute('PRAGMA journal_mode').fetchone() == ('wal',)
        if state == 'foreign-v0':
            assert store.db.execute('SELECT body FROM retained_notes').fetchall() == [('keep',)]


@pytest.mark.parametrize('version', [2, 99])
def test_existing_refuses_unknown_version_without_changing_ordinary_read_only_policy(tmp_path, version):
    root = tmp_path / 'workspace'
    path = _workspace(root)
    with _database(path) as db:
        db.execute('PRAGMA user_version=' + str(version))
    before = _files(root)
    with pytest.raises(KbcStoreError) as caught:
        WorkspaceStore(root, open_mode='existing')
    assert caught.value.code == 'PT-KBC-UNSUPPORTED'
    assert not caught.value.recoverable
    assert _files(root) == before
    with WorkspaceStore(root, create=False) as store:
        assert store.read_only
        assert store.journal_get('retained') == ('intent', {'analyst': 'original'})
        with pytest.raises(KbcStoreError) as blocked:
            store.journal_put('blocked', 'done', {})
        assert not blocked.value.recoverable
    assert _files(root) == before


@pytest.mark.parametrize('damage', ['foreign-v1', 'missing', 'view', 'extra', 'type', 'pk', 'notnull',
                                  'rowid', 'strict', 'order', 'virtual', 'stored'])
def test_existing_validates_actual_full_base_layout(tmp_path, damage):
    root = tmp_path / 'workspace'
    path = _workspace(root)
    if damage == 'foreign-v1':
        path.unlink()
        with _database(path) as foreign:
            foreign.execute('CREATE TABLE retained_notes (body TEXT)')
            foreign.execute('PRAGMA user_version=1')
    with _database(path) as db:
        if damage == 'foreign-v1':
            pass
        elif damage == 'missing':
            db.execute('DROP TABLE journal')
        elif damage == 'view':
            db.execute('ALTER TABLE journal RENAME TO retained_journal')
            db.execute('CREATE VIEW journal AS SELECT * FROM retained_journal')
        elif damage == 'extra':
            db.execute('ALTER TABLE journal ADD COLUMN extra TEXT')
        elif damage in {'type', 'pk', 'notnull', 'rowid', 'strict', 'order'}:
            db.execute('ALTER TABLE journal RENAME TO retained_journal')
            statements = {
                'type': 'CREATE TABLE journal (op_id INTEGER PRIMARY KEY, state TEXT NOT NULL, '
                        'body TEXT NOT NULL, updated TEXT NOT NULL)',
                'pk': 'CREATE TABLE journal (op_id TEXT, state TEXT NOT NULL, body TEXT NOT NULL, '
                      'updated TEXT NOT NULL)',
                'notnull': 'CREATE TABLE journal (op_id TEXT PRIMARY KEY, state TEXT, body TEXT NOT NULL, '
                           'updated TEXT NOT NULL)',
                'rowid': 'CREATE TABLE journal (op_id TEXT PRIMARY KEY, state TEXT NOT NULL, body TEXT NOT NULL, '
                         'updated TEXT NOT NULL) WITHOUT ROWID',
                'strict': 'CREATE TABLE journal (op_id TEXT PRIMARY KEY, state TEXT NOT NULL, body TEXT NOT NULL, '
                          'updated TEXT NOT NULL) STRICT',
                'order': 'CREATE TABLE journal (updated TEXT NOT NULL, state TEXT NOT NULL, body TEXT NOT NULL, '
                         'op_id TEXT PRIMARY KEY)',
            }
            db.execute(statements[damage])
        else:
            db.execute('ALTER TABLE journal RENAME TO retained_journal')
            statements = {
                'virtual': 'CREATE TABLE journal (op_id TEXT PRIMARY KEY, state TEXT NOT NULL, '
                           'body TEXT NOT NULL, updated TEXT NOT NULL, '
                           'hidden_note TEXT GENERATED ALWAYS AS (state) VIRTUAL)',
                'stored': 'CREATE TABLE journal (op_id TEXT PRIMARY KEY, state TEXT NOT NULL, '
                          'body TEXT NOT NULL, updated TEXT NOT NULL, '
                          'hidden_note TEXT GENERATED ALWAYS AS (state) STORED)',
            }
            db.execute(statements[damage])
            assert len(db.execute('PRAGMA table_info(journal)').fetchall()) == 4
            assert len(db.execute('PRAGMA table_xinfo(journal)').fetchall()) == 5
    before = _files(root)
    with pytest.raises(KbcStoreError) as caught:
        WorkspaceStore(root, open_mode='existing')
    assert caught.value.code == 'PT-KBC-STORAGE'
    assert not caught.value.recoverable
    assert _files(root) == before


@pytest.mark.parametrize('component', ['hash#value', 'percent%value', 'space é漢',
    pytest.param('question?value#%é', marks=pytest.mark.skipif(os.name == 'nt',
        reason='Question marks are invalid Windows file names; remaining URI cases are portable.'))],
    ids=['hash', 'percent', 'unicode-space', 'question-combined'])
def test_existing_uri_preserves_literal_path_characters(tmp_path, component, monkeypatch):
    root = tmp_path / component
    _workspace(root)
    connect = sqlite3.connect
    calls = []

    def observed(database, *args, **kwargs):
        calls.append((database, kwargs))
        return connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, 'connect', observed)
    with WorkspaceStore(root, open_mode='existing') as store:
        assert store.journal_get('retained') == ('intent', {'analyst': 'original'})
    assert len(calls) == 1
    uri, options = calls[0]
    assert options['uri'] is True
    assert uri == (root.resolve() / 'kbc.sqlite3').as_uri() + '?mode=rw'
    assert parse_qs(urlsplit(uri).query) == {'mode': ['rw']}


@pytest.mark.parametrize('replacement', ['missing', 'zero', 'foreign-v0'])
def test_existing_checks_the_opened_database_after_replacement(tmp_path, monkeypatch, replacement):
    root = tmp_path / 'workspace'
    path = _workspace(root)
    original = path.read_bytes()
    retained = root / 'retained-original.sqlite3'
    connect = sqlite3.connect
    replacement_bytes = None
    calls = 0

    def replaced(database, *args, **kwargs):
        nonlocal replacement_bytes, calls
        calls += 1
        path.rename(retained)
        if replacement == 'zero':
            path.write_bytes(b'')
        elif replacement == 'foreign-v0':
            with _database(path, connect=connect) as foreign:
                foreign.execute('CREATE TABLE retained_notes (body TEXT)')
                foreign.execute('INSERT INTO retained_notes VALUES (?)', ('keep',))
        replacement_bytes = path.read_bytes() if path.exists() else None
        return connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, 'connect', replaced)
    with pytest.raises(KbcStoreError) as caught:
        WorkspaceStore(root, create=False, open_mode='existing')
    assert caught.value.code == 'PT-KBC-STORAGE'
    assert calls == 1
    assert retained.read_bytes() == original
    assert (path.read_bytes() if path.exists() else None) == replacement_bytes


@pytest.mark.parametrize('mode', [None, True, 1, {}, 'other'],
                         ids=['none', 'bool', 'integer', 'mapping', 'unknown'])
def test_invalid_mode_refuses_before_path_or_connect(mode, monkeypatch):
    class ForbiddenPath:
        def __fspath__(self):
            pytest.fail('invalid mode reached path handling')

    def forbidden(*args, **kwargs):
        pytest.fail('invalid mode reached SQLite')

    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    with pytest.raises(KbcStoreError) as caught:
        WorkspaceStore(ForbiddenPath(), open_mode=mode)
    assert caught.value.code == 'PT-KBC-INPUT'
    assert not caught.value.recoverable


@pytest.mark.parametrize('failure_kind', ['typed', 'sqlite', 'interrupt', 'exit'])
@pytest.mark.parametrize('close_fails', [False, True], ids=['close-ok', 'close-fails'])
def test_existing_closes_acquired_connection_without_masking_primary(tmp_path, monkeypatch,
                                                                    failure_kind, close_fails):
    root = tmp_path / 'workspace'
    path = _workspace(root)
    before = _files(root)
    primary = {'typed': KbcStoreError('PT-KBC-STORAGE', 'authored primary', recoverable=False),
               'sqlite': sqlite3.DatabaseError('untrusted-primary-schema-text'),
               'interrupt': KeyboardInterrupt('authored interrupt'),
               'exit': SystemExit(17)}[failure_kind]
    acquired = sqlite3.connect(path)

    class Acquired:
        close_calls = 0

        def execute(self, sql, *args):
            if 'USER_VERSION' in sql.upper():
                raise primary
            return acquired.execute(sql, *args)

        def close(self):
            self.close_calls += 1
            acquired.close()
            if close_fails:
                raise RuntimeError('untrusted-secondary-close-text/path')

    owned = Acquired()
    monkeypatch.setattr(sqlite3, 'connect', lambda *args, **kwargs: owned)
    try:
        with pytest.raises(BaseException) as caught:
            WorkspaceStore(root, open_mode='existing')
        if failure_kind == 'sqlite':
            assert isinstance(caught.value, KbcStoreError)
            assert caught.value.code == 'PT-KBC-STORAGE'
            assert caught.value.__cause__ is primary
            assert 'untrusted-primary-schema-text' not in str(caught.value)
        else:
            assert caught.value is primary
        assert owned.close_calls == 1
        notes = getattr(caught.value, '__notes__', [])
        assert bool(notes) == close_fails
        assert all('untrusted-secondary' not in note and 'path' not in note for note in notes)
        if close_fails:
            assert any('cleanup' in note and 'remain' in note for note in notes)
        assert _files(root) == before
        with pytest.raises(sqlite3.ProgrammingError):
            acquired.execute('SELECT 1')
    finally:
        acquired.close()
