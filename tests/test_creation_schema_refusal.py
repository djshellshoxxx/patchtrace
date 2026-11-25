"""Authored SQLite schemas must not be mistaken for an abandoned current creation."""
from __future__ import annotations

import os
import sqlite3

import pytest

from patchtrace import persistence
from patchtrace.persistence import ProjectLock, ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def pair(tmp_path):
    paths = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for index, path in enumerate(paths):
        path.write_bytes(synthetic_pe(index))
    return paths


def incomplete(tmp_path):
    root = tmp_path / 'incomplete'
    ProjectStore(root, create=True).close()
    return root


def contents(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() if path.is_file() else None
            for path in root.rglob('*') if path.name != '.patchtrace.lock'}


def assert_refused_without_loss(root, pair):
    (root / 'operator-notes.txt').write_bytes(b'Retain unrelated analyst notes.')
    before = contents(root)
    lock = root / '.patchtrace.lock'
    identity = (lock.stat().st_dev, lock.stat().st_ino) if lock.exists() else None
    with pytest.raises(ValueError, match='PT-STORAGE: project database already exists'):
        with ProjectService.create(*pair, 'must preserve the prior database', root):
            pass
    assert contents(root) == before
    acquired = ProjectLock(root)
    acquired.close()
    if identity is not None:
        assert (lock.stat().st_dev, lock.stat().st_ino) == identity


@pytest.mark.parametrize('statements', [
    ('CREATE VIEW operator_notes AS SELECT 1 AS retained_note',),
    ('CREATE TRIGGER operator_note AFTER INSERT ON history BEGIN SELECT 1; END',),
    ('ALTER TABLE history ADD COLUMN operator_note TEXT',),
    ('CREATE INDEX operator_note ON history(created)',),
    ('CREATE TABLE operator_notes (body TEXT)',),
    ('DROP TABLE current_snapshot',
     'CREATE TABLE current_snapshot (singleton INTEGER PRIMARY KEY, payload TEXT NOT NULL, sha256 TEXT NOT NULL)'),
    ("INSERT INTO history(revision,created,payload,sha256) VALUES (1,'then','{}','retained')",
     'DELETE FROM history'),
    ('PRAGMA user_version=0',),
    ('PRAGMA application_id=42',),
], ids=['view', 'trigger', 'column', 'index', 'table', 'changed-constraint', 'sequence-history', 'changed-version',
       'other-application'])
def test_unknown_schema_or_retained_sequence_is_preserved(tmp_path, pair, statements):
    root = incomplete(tmp_path)
    with sqlite3.connect(root / 'project.sqlite3') as db:
        for statement in statements:
            db.execute(statement)
    assert_refused_without_loss(root, pair)


@pytest.mark.parametrize('version,view', [(0, False), (1, False), (0, True), (1, True)])
def test_nonempty_database_without_the_current_schema_is_preserved(tmp_path, pair, version, view):
    root = tmp_path / 'foreign'
    root.mkdir()
    path = root / 'project.sqlite3'
    with sqlite3.connect(path) as db:
        db.execute(f'PRAGMA user_version={version}')
        if view:
            db.execute('CREATE VIEW operator_notes AS SELECT 1 AS retained_note')
    assert path.stat().st_size > 0
    assert_refused_without_loss(root, pair)


@pytest.mark.parametrize('suffix', ['-journal', '-wal', '-shm'])
@pytest.mark.parametrize('empty', [False, True], ids=['current-empty', 'zero-byte'])
def test_unknown_companion_is_preserved_before_retry(tmp_path, pair, suffix, empty):
    root = incomplete(tmp_path)
    path = root / 'project.sqlite3'
    if empty:
        path.write_bytes(b'')
    path.with_name(path.name + suffix).write_bytes(b'Unrecognized retained companion bytes.')
    assert_refused_without_loss(root, pair)


@pytest.mark.parametrize('empty', [False, True], ids=['current-empty', 'zero-byte'])
def test_recognized_incomplete_database_still_creates_and_reopens(tmp_path, pair, empty):
    root = incomplete(tmp_path)
    if empty:
        (root / 'project.sqlite3').write_bytes(b'')
    lock = root / '.patchtrace.lock'
    identity = (lock.stat().st_dev, lock.stat().st_ino)
    with ProjectService.create(*pair, 'healthy retry', root) as service:
        expected_id = service.project.id
        assert len(service.project.artifacts) == 2
    with ProjectService.open(root) as service:
        assert service.project.id == expected_id
        assert service.project.name == 'healthy retry'
    assert (lock.stat().st_dev, lock.stat().st_ino) == identity


def test_oversized_candidate_is_refused_before_sqlite_opens_it(tmp_path, monkeypatch):
    root = incomplete(tmp_path)
    path = root / 'project.sqlite3'
    with path.open('ab') as stream:
        stream.truncate(1024 * 1024 + 1)

    def forbidden(*args, **kwargs):
        pytest.fail('oversized retry candidate reached SQLite')

    monkeypatch.setattr(persistence.sqlite3, 'connect', forbidden)
    assert persistence._abandoned_creation(path) is False


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='named pipes need POSIX')
def test_zero_size_special_file_is_not_a_reusable_database(tmp_path):
    path = tmp_path / 'project.sqlite3'
    os.mkfifo(path)
    assert persistence._abandoned_creation(path) is False


def test_linked_database_is_not_positively_owned_for_retry(tmp_path):
    root = incomplete(tmp_path)
    path = root / 'project.sqlite3'
    alias = tmp_path / 'another-owner.sqlite3'
    try:
        os.link(path, alias)
    except (OSError, NotImplementedError):
        pytest.skip('this filesystem cannot create hardlinks')
    before = alias.read_bytes()
    assert persistence._abandoned_creation(path) is False
    assert alias.read_bytes() == before
