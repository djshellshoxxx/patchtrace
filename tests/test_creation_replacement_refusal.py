"""A prior empty-database admission cannot authorize deleting a later database."""
from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from patchtrace import persistence
from patchtrace import service as service_module
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def case(tmp_path, empty=False):
    root = tmp_path / 'case'
    persistence.ProjectStore(root, create=True).close()
    path = root / 'project.sqlite3'
    if empty:
        path.write_bytes(b'')
    foreign = tmp_path / 'foreign.sqlite3'
    with closing(sqlite3.connect(foreign)) as db, db:
        db.execute('CREATE TABLE notes (value TEXT)')
        db.execute('INSERT INTO notes VALUES (?)', ('retained analyst record',))
    pair = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for number, source in enumerate(pair):
        source.write_bytes(synthetic_pe(number))
    return root, path, foreign, pair


def replacement(path, foreign, suffix):
    expected = {path: foreign.read_bytes()}
    foreign.replace(path)
    if suffix:
        companion = path.with_name(path.name + suffix)
        expected[companion] = b'Preserve unrecognized companion evidence.'
        companion.write_bytes(expected[companion])
    return expected


def assert_refused(root, pair, expected):
    with pytest.raises(ValueError):
        with ProjectService.create(*pair, 'refuse replacement', root):
            pass
    assert expected
    assert {path: path.read_bytes() for path in expected} == expected
    assert not (root / 'artifacts').exists()


@pytest.mark.parametrize('suffix', ['', '-journal', '-wal', '-shm'])
@pytest.mark.parametrize('empty', [False, True], ids=['current-empty', 'zero-byte'])
def test_replacement_after_admission_preserves_database_and_companions(tmp_path, monkeypatch, suffix, empty):
    root, path, foreign, pair = case(tmp_path, empty)
    check = persistence._abandoned_creation
    expected = {}

    def checked(candidate):
        accepted = check(candidate)
        assert accepted
        expected.update(replacement(path, foreign, suffix))
        return accepted

    monkeypatch.setattr(persistence, '_abandoned_creation', checked)
    assert_refused(root, pair, expected)


@pytest.mark.parametrize('suffix', ['', '-journal', '-wal', '-shm'])
def test_replacement_at_connection_open_preserves_database_and_companions(tmp_path, monkeypatch, suffix):
    root, path, foreign, pair = case(tmp_path)
    check, connect = persistence._abandoned_creation, sqlite3.connect
    admitted = False
    expected = {}

    def checked(candidate):
        nonlocal admitted
        admitted = check(candidate)
        assert admitted
        return admitted

    def opening(database, *args, **kwargs):
        if admitted and not expected and (database == path or str(database).startswith(path.as_uri())):
            expected.update(replacement(path, foreign, suffix))
        return connect(database, *args, **kwargs)

    monkeypatch.setattr(persistence, '_abandoned_creation', checked)
    monkeypatch.setattr(persistence.sqlite3, 'connect', opening)
    assert_refused(root, pair, expected)


def test_initialization_failure_cannot_unlink_a_replacement(tmp_path, monkeypatch):
    root, path, foreign, pair = case(tmp_path)
    connect = sqlite3.connect
    expected = {}

    class Replaced(sqlite3.Connection):
        def execute(self, statement, *args):
            if statement == 'BEGIN IMMEDIATE' and not expected:
                self.close()  # Release the authored connection before simulating an external replacement.
                expected.update(replacement(path, foreign, '-journal'))
                raise sqlite3.OperationalError('authored initialization failure')
            return super().execute(statement, *args)

    def opening(*args, **kwargs):
        return connect(*args, factory=Replaced, **kwargs)

    monkeypatch.setattr(persistence.sqlite3, 'connect', opening)
    assert_refused(root, pair, expected)


@pytest.mark.parametrize('empty', [False, True], ids=['current-empty', 'zero-byte'])
@pytest.mark.parametrize('phase', ['first-input', 'second-input', 'before-save', 'after-history'])
def test_failed_retry_preserves_the_preexisting_database_exactly(tmp_path, monkeypatch, empty, phase):
    root, path, _foreign, pair = case(tmp_path, empty)
    before = path.read_bytes()
    identity = path.stat().st_dev, path.stat().st_ino
    inspect, save, connect = service_module.inspect_artifact, persistence.ProjectStore.save, sqlite3.connect

    def reading(source, side, *args, **kwargs):
        if (phase, side) in [('first-input', 'older'), ('second-input', 'newer')]:
            raise ValueError('authored ingestion failure')
        return inspect(source, side, *args, **kwargs)

    def saving(store, project):
        if phase == 'before-save':
            raise ValueError('authored pre-save failure')
        return save(store, project)

    class FailedHistory(sqlite3.Connection):
        def execute(self, statement, *args):
            result = super().execute(statement, *args)
            if phase == 'after-history' and statement.startswith('INSERT INTO history('):
                raise sqlite3.OperationalError('authored error after writing history')
            return result

    monkeypatch.setattr(service_module, 'inspect_artifact', reading)
    monkeypatch.setattr(persistence.ProjectStore, 'save', saving)
    monkeypatch.setattr(persistence.sqlite3, 'connect',
                        lambda *args, **kwargs: connect(*args, factory=FailedHistory, **kwargs))
    with pytest.raises(ValueError):
        ProjectService.create(*pair, 'must roll back in place', root)
    assert path.read_bytes() == before
    assert (path.stat().st_dev, path.stat().st_ino) == identity
    assert not (root / 'artifacts').exists()
    assert sorted(p.name for p in root.iterdir()) == ['.patchtrace.lock', 'project.sqlite3']


@pytest.mark.parametrize('empty', [False, True], ids=['current-empty', 'zero-byte'])
def test_closing_an_unpublished_retry_preserves_the_existing_database(tmp_path, empty):
    root, path, _foreign, _pair = case(tmp_path, empty)
    before = path.read_bytes()
    identity = path.stat().st_dev, path.stat().st_ino
    persistence.ProjectStore(root, create=True).close()
    assert path.read_bytes() == before
    assert (path.stat().st_dev, path.stat().st_ino) == identity


def test_new_creation_cannot_claim_a_replacement_at_connection_open(tmp_path, monkeypatch):
    root, path, foreign, pair = case(tmp_path)
    path.unlink()  # Authored fixture: the next create must reserve a new file.
    connect = sqlite3.connect
    expected = {}

    def opening(database, *args, **kwargs):
        if not expected and (database == path or str(database).startswith(path.as_uri())):
            expected.update(replacement(path, foreign, '-journal'))
        return connect(database, *args, **kwargs)

    monkeypatch.setattr(persistence.sqlite3, 'connect', opening)
    assert_refused(root, pair, expected)
