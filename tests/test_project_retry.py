"""Explicit retry consumes only verified incomplete creation layouts under a held lock."""
from __future__ import annotations

import hashlib
import sqlite3
import threading

import pytest

from patchtrace import project_retry
from patchtrace.ingestion import inspect_artifact
from patchtrace.persistence import ProjectLock, ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def inputs(tmp_path):
    pair = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for path, index in zip(pair, (0, 1), strict=True):
        path.write_bytes(synthetic_pe(index))
    return pair


def partial(tmp_path, *, database=True, artifact=True):
    pair, root = inputs(tmp_path), tmp_path / 'project'
    ProjectStore(root, create=True).close()
    if not database:
        (root / 'project.sqlite3').unlink()
    if artifact:
        inspect_artifact(pair[0], 'older', root)
    return pair, root


def contents(root):
    if not root.exists():
        return None
    return {str(path.relative_to(root)): ('link', str(path.readlink())) if path.is_symlink()
            else ('directory',) if path.is_dir() else ('file', path.read_bytes())
            for path in root.rglob('*')}


def unlocked(root):
    lock = ProjectLock(root, _preserve_existing=True)
    lock.close()


@pytest.mark.parametrize('database', [False, True])
@pytest.mark.parametrize('artifact', [False, True])
def test_actual_partial_retry_reuses_exact_input_and_reopens(tmp_path, database, artifact):
    pair, root = partial(tmp_path, database=database, artifact=artifact)
    lock_bytes = (root / '.patchtrace.lock').read_bytes()
    target = root / 'artifacts' / (hashlib.sha256(pair[0].read_bytes()).hexdigest() + '.bin')
    identity = target.stat().st_ino if artifact else None
    with ProjectService.retry_create(*pair, 'Recovered', root) as service:
        assert service.project.name == 'Recovered'
        assert len(service.project.artifacts) == 2
    assert (root / '.patchtrace.lock').read_bytes() == lock_bytes
    if artifact:
        assert target.stat().st_ino == identity
    with ProjectService.open(root) as reopened:
        assert reopened.project.name == 'Recovered'


@pytest.mark.parametrize('invalid', ['unknown', 'hidden', 'journal', 'foreign-table', 'foreign-view',
                                    'schema', 'snapshot', 'history', 'sequence', 'version', 'zero',
                                    'corrupt', 'oversize', 'artifact-name', 'artifact-bytes', 'artifact-size'])
def test_refused_retry_preserves_every_byte_and_releases_lock(tmp_path, invalid):
    pair, root = partial(tmp_path)
    database = root / 'project.sqlite3'
    if invalid in {'unknown', 'hidden', 'journal'}:
        name = {'unknown': 'user-note.txt', 'hidden': '.other', 'journal': 'project.sqlite3-journal'}[invalid]
        (root / name).write_bytes(b'foreign bytes')
    elif invalid in {'foreign-table', 'foreign-view', 'schema', 'snapshot', 'history', 'sequence', 'version'}:
        with sqlite3.connect(database) as connection:
            sql = {'foreign-table': 'CREATE TABLE user_data(value TEXT)',
                   'foreign-view': 'CREATE VIEW extra AS SELECT 1',
                   'schema': 'ALTER TABLE history ADD COLUMN foreign_data TEXT',
                   'snapshot': "INSERT INTO current_snapshot VALUES(1,'x','x')",
                   'history': "INSERT INTO history(revision,created,payload,sha256) VALUES(0,'x','x','x')",
                   'sequence': "INSERT INTO sqlite_sequence VALUES('history', 1)",
                   'version': 'PRAGMA user_version=99'}[invalid]
            connection.execute(sql)
    elif invalid in {'zero', 'corrupt', 'oversize'}:
        database.write_bytes({'zero': b'', 'corrupt': b'not sqlite',
                              'oversize': b'x' * (project_retry.MAX_RETRY_DATABASE_BYTES + 1)}[invalid])
    else:
        path = next((root / 'artifacts').iterdir())
        path.chmod(0o600)
        if invalid == 'artifact-name':
            path.rename(path.with_name('foreign.bin'))
        elif invalid == 'artifact-bytes':
            path.write_bytes(b'x' * path.stat().st_size)
        else:
            path.write_bytes(b'short')
    before = contents(root)
    with pytest.raises((ValueError, OSError)):
        ProjectService.retry_create(*pair, 'Refused', root)
    assert contents(root) == before
    unlocked(root)
    assert contents(root) == before


def test_different_selected_inputs_do_not_adopt_partial_artifact(tmp_path):
    pair, root = partial(tmp_path)
    pair[0].write_bytes(synthetic_pe(2))
    before = contents(root)
    with pytest.raises(ValueError, match='selected inputs'):
        ProjectService.retry_create(*pair, 'Other inputs', root)
    assert contents(root) == before
    unlocked(root)


@pytest.mark.parametrize('kind', ['absent', 'empty', 'unrelated', 'short-lock'])
def test_retry_never_creates_or_populates_an_unrecognized_root(tmp_path, kind):
    pair, root = inputs(tmp_path), tmp_path / 'project'
    if kind != 'absent':
        root.mkdir()
    if kind == 'unrelated':
        (root / 'note.txt').write_bytes(b'keep')
    if kind == 'short-lock':
        (root / '.patchtrace.lock').write_bytes(b'keep short lock')
    before = contents(root)
    with pytest.raises((ValueError, OSError)):
        ProjectService.retry_create(*pair, 'No mutation', root)
    assert contents(root) == before


@pytest.mark.parametrize('stage', ['before', 'second-input', 'validation'])
def test_cancel_during_preparation_or_validation_preserves_all_destination_bytes(tmp_path, monkeypatch, stage):
    pair, root = partial(tmp_path)
    cancel = threading.Event()
    if stage == 'before':
        cancel.set()
    inspect = project_retry.inspect_artifact
    def inspected(path, side, folder):
        result = inspect(path, side, folder)
        if stage == 'second-input' and side == 'newer':
            cancel.set()
        return result
    validate = project_retry._artifact
    def validated(path, artifact, token):
        validate(path, artifact, token)
        if stage == 'validation':
            cancel.set()
    monkeypatch.setattr(project_retry, 'inspect_artifact', inspected)
    monkeypatch.setattr(project_retry, '_artifact', validated)
    before = contents(root)
    with pytest.raises(project_retry.CreationCancelled):
        ProjectService.retry_create(*pair, 'Cancelled', root, cancel=cancel)
    assert contents(root) == before
    unlocked(root)


def test_validation_and_pre_recycle_recheck_hold_the_same_kernel_lock(tmp_path, monkeypatch):
    pair, root = partial(tmp_path)
    validate, observations = project_retry.validate_retry, []
    def observed(*args):
        with pytest.raises(ValueError, match='locked'):
            ProjectLock(root)
        check = validate(*args)
        def recheck():
            with pytest.raises(ValueError, match='locked'):
                ProjectLock(root)
            observations.append('held')
            check()
        return recheck
    monkeypatch.setattr(project_retry, 'validate_retry', observed)
    with ProjectService.retry_create(*pair, 'Locked retry', root):
        pass
    assert observations == ['held']


def test_changed_layout_after_validation_is_refused_before_database_recycle(tmp_path, monkeypatch):
    pair, root = partial(tmp_path)
    validate = project_retry.validate_retry
    database = (root / 'project.sqlite3').read_bytes()
    lock = (root / '.patchtrace.lock').read_bytes()
    def changed(*args):
        recheck = validate(*args)
        (root / 'foreign.txt').write_bytes(b'preserve')
        return recheck
    monkeypatch.setattr(project_retry, 'validate_retry', changed)
    with pytest.raises(ValueError, match='entries'):
        ProjectService.retry_create(*pair, 'Refused', root)
    assert (root / 'project.sqlite3').read_bytes() == database
    assert (root / '.patchtrace.lock').read_bytes() == lock
    assert (root / 'foreign.txt').read_bytes() == b'preserve'
    unlocked(root)


@pytest.mark.parametrize('kind', ['ancestor-link', 'artifact-link', 'artifact-hardlink'])
def test_retry_refuses_linked_paths_without_mutation(tmp_path, kind):
    pair, root = partial(tmp_path)
    path = next((root / 'artifacts').iterdir())
    requested = root
    try:
        if kind == 'ancestor-link':
            requested = tmp_path / 'linked' / root.name
            (tmp_path / 'linked').symlink_to(tmp_path, target_is_directory=True)
        else:
            target = tmp_path / 'saved.bin'
            path.rename(target)
            if kind == 'artifact-link':
                path.symlink_to(target)
            else:
                path.hardlink_to(target)
    except OSError as exc:
        pytest.skip(f'filesystem link operation blocked: {type(exc).__name__}')
    before = contents(root)
    with pytest.raises((ValueError, OSError)):
        ProjectService.retry_create(*pair, 'Linked retry', requested)
    assert contents(root) == before
    unlocked(root)


@pytest.mark.parametrize('database', [False, True])
def test_retry_database_publication_never_adopts_a_new_foreign_file(tmp_path, monkeypatch, database):
    import os
    from pathlib import Path

    pair, root = partial(tmp_path, database=database)
    target = root / 'project.sqlite3'
    real_open, real_connect = os.open, sqlite3.connect
    injected = False
    def collide():
        nonlocal injected
        if not injected:
            injected = True
            with real_connect(target) as foreign:
                foreign.execute('CREATE TABLE user_data(value TEXT)')
                foreign.execute("INSERT INTO user_data VALUES('preserve foreign database')")
    def collided_open(path, flags, *args, **kwargs):
        if Path(path) == target and flags & os.O_EXCL:
            collide()
        return real_open(path, flags, *args, **kwargs)
    def collided_connect(path, *args, **kwargs):
        if not kwargs.get('uri') and Path(path) == target and not target.exists():
            collide()
        return real_connect(path, *args, **kwargs)
    monkeypatch.setattr(os, 'open', collided_open)
    monkeypatch.setattr(sqlite3, 'connect', collided_connect)
    with pytest.raises((ValueError, OSError)):
        ProjectService.retry_create(*pair, 'Collision', root)
    with real_connect(target) as foreign:
        assert foreign.execute('SELECT value FROM user_data').fetchall() == [('preserve foreign database',)]
        assert foreign.execute("SELECT name FROM sqlite_schema WHERE type='table'").fetchall() == [('user_data',)]
    unlocked(root)


def test_actual_retry_consumer_refuses_a_modeled_reparse_ancestor(tmp_path, monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace

    pair, root = partial(tmp_path)
    before = contents(root)
    original = Path.lstat
    def reparse(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == tmp_path:
            return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino,
                                   st_file_attributes=0x400)
        return info
    monkeypatch.setattr(Path, 'lstat', reparse)
    with pytest.raises(OSError, match='linked'):
        ProjectService.retry_create(*pair, 'Reparse ancestor', root)
    assert contents(root) == before
    unlocked(root)


@pytest.mark.parametrize('kind', ['link', 'reparse'])
def test_retry_refuses_lexical_link_before_dotdot_without_normalizing_it_away(tmp_path, monkeypatch, kind):
    from pathlib import Path
    from types import SimpleNamespace

    pair, root = partial(tmp_path)
    ordinary = tmp_path / 'ordinary'
    ordinary.mkdir()
    component = tmp_path / 'linked'
    if kind == 'link':
        try:
            component.symlink_to(ordinary, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f'filesystem symlink operation blocked: {type(exc).__name__}')
    else:
        component.mkdir()
        original = Path.lstat
        def reparse(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == component:
                return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino,
                                       st_file_attributes=0x400)
            return info
        monkeypatch.setattr(Path, 'lstat', reparse)
    before = contents(root)
    with pytest.raises(OSError, match='linked'):
        ProjectService.retry_create(*pair, 'Linked dotdot', component / '..' / root.name)
    assert contents(root) == before
    unlocked(root)


def test_retry_allows_ordinary_dotdot_only_after_checking_lexical_components(tmp_path):
    pair, root = partial(tmp_path)
    ordinary = tmp_path / 'ordinary'
    ordinary.mkdir()
    with ProjectService.retry_create(*pair, 'Ordinary parent', ordinary / '..' / root.name) as service:
        assert service.root == root
