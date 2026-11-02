"""Explicit, bounded incomplete-creation reuse; validation never repairs a directory."""
from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

from .ingestion import CHUNK_SIZE, file_fingerprint, inspect_artifact, validate_pe
from .persistence import _CURRENT_SNAPSHOT_SQL, _HISTORY_SQL, ProjectStore, _creation_identity
from .project_creation import CreationPublication, staged_project

MAX_RETRY_DATABASE_BYTES = 1024 * 1024


class CreationCancelled(ValueError):
    """Cooperative stop, with no implication that a completed project was removed."""


def _check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise CreationCancelled('Project creation cancelled')


def _state(path, *, directory=False):
    identity = _creation_identity(path, directory=directory)
    if directory:
        return identity
    if path.lstat().st_nlink != 1:
        raise ValueError('PT-RETRY: hard-linked files cannot be reused')
    return identity, file_fingerprint(path)


def _entries(path, limit):
    names = set()
    with os.scandir(path) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names) > limit:
                raise ValueError('PT-RETRY: directory has unexpected entries')
    return names


def _directories(root):
    return {directory: _state(directory, directory=True) for directory in (*reversed(root.parents), root)}


def _database(path, cancel):
    size = path.stat().st_size
    if not 0 < size <= MAX_RETRY_DATABASE_BYTES:
        raise ValueError('PT-RETRY: incomplete database must be within 1 MiB')
    connection = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True, timeout=0)
    steps = 0
    def progress():
        nonlocal steps
        steps += 1000
        return int(steps > 100_000 or (cancel is not None and cancel.is_set()))
    try:
        connection.set_progress_handler(progress, 1000)
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RETRY_DATABASE_BYTES)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4096)
        if connection.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise ValueError('PT-RETRY: database version is not an incomplete current project')
        schema = connection.execute('SELECT type,name,sql FROM sqlite_schema').fetchall()
        expected = {('table', 'current_snapshot', _CURRENT_SNAPSHOT_SQL),
                    ('table', 'history', _HISTORY_SQL),
                    ('table', 'sqlite_sequence', 'CREATE TABLE sqlite_sequence(name,seq)')}
        if len(schema) != len(expected) or set(schema) != expected:
            raise ValueError('PT-RETRY: database schema is not an incomplete project')
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise ValueError('PT-RETRY: database integrity check failed')
        for table in ('current_snapshot', 'history', 'sqlite_sequence'):
            if connection.execute(f'SELECT EXISTS(SELECT 1 FROM {table})').fetchone()[0]:
                raise ValueError('PT-RETRY: database already contains project data')
        _check_cancel(cancel)
    except sqlite3.Error as exc:
        _check_cancel(cancel)
        raise ValueError('PT-RETRY: incomplete database cannot be validated') from exc
    finally:
        connection.close()


def _artifact(path, artifact, cancel):
    if path.stat().st_size != artifact.size:
        raise ValueError('PT-RETRY: artifact size differs from the selected input')
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        if _creation_identity(path) != (info.st_dev, info.st_ino):
            raise ValueError('PT-RETRY: artifact identity changed')
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b''):
            _check_cancel(cancel)
            size += len(chunk)
            if size > artifact.size:
                raise ValueError('PT-RETRY: artifact grew during validation')
            digest.update(chunk)
    if size != artifact.size or digest.hexdigest() != artifact.sha256:
        raise ValueError('PT-RETRY: artifact bytes differ from the selected input')
    validate_pe(path)


def validate_retry(root, project, store, cancel):
    """Return a read-only recheck, called immediately before database recycling."""
    _check_cancel(cancel)
    states = {directory: (True, state) for directory, state in _directories(root).items()}
    if root.resolve() != store.root:
        raise ValueError('PT-RETRY: destination resolves through a different path')
    names = _entries(root, 3)
    if '.patchtrace.lock' not in names or names - {'.patchtrace.lock', 'project.sqlite3', 'artifacts'}:
        raise ValueError('PT-RETRY: destination is not an incomplete creation directory')
    lock_path = root / '.patchtrace.lock'
    states[lock_path] = False, _state(lock_path)
    held = os.fstat(store.lock.stream.fileno())
    if held.st_size != 4096 or _creation_identity(lock_path) != (held.st_dev, held.st_ino):
        raise ValueError('PT-RETRY: destination lock identity changed')
    artifact_names = set()
    if 'artifacts' in names:
        folder = root / 'artifacts'
        states[folder] = True, _state(folder, directory=True)
        artifact_names = _entries(folder, 2)
        expected = {Path(artifact.relative_path).name: artifact for artifact in project.artifacts}
        if artifact_names - expected.keys():
            raise ValueError('PT-RETRY: artifacts do not belong to the selected inputs')
        for name in sorted(artifact_names):
            path = folder / name
            states[path] = False, _state(path)
            _artifact(path, expected[name], cancel)
    if 'project.sqlite3' in names:
        database = root / 'project.sqlite3'
        states[database] = False, _state(database)
        _database(database, cancel)

    def recheck():
        _check_cancel(cancel)
        if _entries(root, 3) != names:
            raise ValueError('PT-RETRY: destination entries changed during validation')
        if 'artifacts' in names and _entries(root / 'artifacts', 2) != artifact_names:
            raise ValueError('PT-RETRY: artifact entries changed during validation')
        for path, (directory, state) in states.items():
            if _state(path, directory=directory) != state:
                raise ValueError('PT-RETRY: destination identity or content changed during validation')
        current = os.fstat(store.lock.stream.fileno())
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            raise ValueError('PT-RETRY: held lock changed during validation')
    recheck()
    return recheck


def retry_project(service_type, older, newer, name, root, *, cancel=None):
    """Stage first, validate under the existing lock, then reuse only verified paths."""
    root = Path(root)
    if not root.is_absolute():
        root = Path.cwd() / root  # Keep link/.. components visible until they are checked.
    store = publication = None
    def inspect(path, side, stage):
        _check_cancel(cancel)
        artifact = inspect_artifact(path, side, stage)
        _check_cancel(cancel)
        return artifact
    try:
        with staged_project(older, newer, name, inspector=inspect) as (stage, project):
            _check_cancel(cancel)
            directories = _directories(root)
            resolved = root.resolve()
            def validate(held):
                if _directories(root) != directories:
                    raise ValueError('PT-RETRY: lexical destination ownership changed')
                return validate_retry(root, project, held, cancel)
            store = ProjectStore(resolved, create=True, _creation_validator=validate)
            publication = CreationPublication(store)
            publication.publish(stage, project)
            _check_cancel(cancel)
            project = store.save(project)
        return service_type(store.root, project, store)
    except BaseException:
        try:
            if publication is not None:
                publication.discard_if_unpublished()
        finally:
            if store is not None:
                store.close()
        raise
