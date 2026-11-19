"""Explicit incomplete-directory reuse through current store and artifact publication."""
from __future__ import annotations

import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .ingestion import MAX_ARTIFACT_BYTES, file_fingerprint, inspect_artifact, verify_artifact
from .input_readers import InputReadError, ReadCheckpoint
from .persistence import ProjectStore

_ROOT_ENTRIES = frozenset({'.patchtrace.lock', 'project.sqlite3', 'artifacts'})


def _read_budget(maximum: int, checkpoint: ReadCheckpoint | None):
    consumed = 0

    def charge(count):
        nonlocal consumed
        if type(count) is not int or count < 0:
            raise InputReadError('invalid')
        consumed += count
        if checkpoint is not None:
            checkpoint(count)
        if consumed > maximum:
            raise InputReadError('limited')

    return charge


def _ordinary(path: Path, *, directory: bool = False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('PT-RETRY: linked paths cannot be reused')
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
        raise ValueError('PT-RETRY: expected ordinary directories and singly linked files')
    return info


def _state(path: Path, *, directory: bool = False):
    info = _ordinary(path, directory=directory)
    identity = info.st_dev, info.st_ino
    if directory:
        return identity
    fingerprint = file_fingerprint(path)
    after = _ordinary(path)
    if identity != fingerprint[:2] or not os.path.samestat(info, after):
        raise ValueError('PT-RETRY: file identity changed during validation')
    return info.st_mode, fingerprint


def _directories(root: Path):
    # Keep lexical link/.. components visible before any resolve/abspath operation.
    return {path: _state(path, directory=True) for path in (*reversed(root.parents), root)}


def _entries(root: Path, allowed):
    names = set()
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.name not in allowed or entry.name in names:
                raise ValueError('PT-RETRY: directory has unexpected entries')
            names.add(entry.name)
    return names


def _layout(root: Path):
    names = _entries(root, _ROOT_ENTRIES)
    if '.patchtrace.lock' not in names or _ordinary(root / '.patchtrace.lock').st_size != 4096:
        raise ValueError('PT-RETRY: destination needs its existing complete project lock')
    if 'artifacts' in names:
        _ordinary(root / 'artifacts', directory=True)
    return names


def validate_retry(root: Path, project, store: ProjectStore, checkpoint: ReadCheckpoint | None):
    """Capture a bounded layout under the held lock; return its pre-mutation recheck."""
    if checkpoint is not None:
        checkpoint(0)
    states = {path: (True, state) for path, state in _directories(root).items()}
    if root.resolve() != store.root:
        raise ValueError('PT-RETRY: destination resolves through a different path')
    names = _layout(root)
    lock = root / '.patchtrace.lock'
    states[lock] = False, _state(lock)
    held = os.fstat(store.lock.stream.fileno())
    if held.st_size != 4096 or not os.path.samestat(held, lock.lstat()):
        raise ValueError('PT-RETRY: held lock identity changed')
    expected = {Path(artifact.relative_path).name: artifact for artifact in project.artifacts}
    artifact_names = set()
    if 'artifacts' in names:
        folder = root / 'artifacts'
        states[folder] = True, _state(folder, directory=True)
        try:
            artifact_names = _entries(folder, expected)
        except ValueError as exc:
            raise ValueError('PT-RETRY: artifact entries do not belong to the selected inputs') from exc
        for name in sorted(artifact_names):
            path = folder / name
            states[path] = False, _state(path)
            artifact = expected[name]
            verify_artifact(artifact, root, checkpoint=_read_budget(2 * artifact.size, checkpoint))
    if 'project.sqlite3' in names:
        states[root / 'project.sqlite3'] = False, _state(root / 'project.sqlite3')

    def recheck():
        if checkpoint is not None:
            checkpoint(0)
        if _layout(root) != names:
            raise ValueError('PT-RETRY: destination entries changed during validation')
        if 'artifacts' in names and _entries(root / 'artifacts', expected) != artifact_names:
            raise ValueError('PT-RETRY: artifact entries changed during validation')
        for path, (directory, state) in states.items():
            if _state(path, directory=directory) != state:
                raise ValueError('PT-RETRY: destination identity or content changed during validation')
        if not os.path.samestat(os.fstat(store.lock.stream.fileno()), held):
            raise ValueError('PT-RETRY: held lock changed during validation')

    return recheck


@contextmanager
def _staged_project(older, newer, name, checkpoint):
    from .service import ProjectService

    temporary = tempfile.TemporaryDirectory(prefix='patchtrace-retry-')
    # Automatic cleanup has only a pathname, not our captured ownership. Detach
    # it before any operation can substitute that path, including on an error.
    temporary._finalizer.detach()
    private_root, ownership = Path(temporary.name), None
    primary = None
    try:
        ownership = _directories(private_root)
        stage = private_root / 'project'
        with ProjectService.create(older, newer, name, stage,
                                   checkpoint=_read_budget(8 * MAX_ARTIFACT_BYTES, checkpoint)) as prepared:
            candidate = prepared.project
        yield stage, candidate
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            try:
                unchanged = ownership is not None and _directories(private_root) == ownership
            except (OSError, ValueError):
                unchanged = False
            if not unchanged:
                raise ValueError('PT-RETRY: private staging ownership changed; directory retained')
            temporary.cleanup()
        except BaseException:
            if primary is None:
                raise
            primary.add_note('PT-RETRY: private staging cleanup failed; temporary files may remain')


def retry_project(service_type, older, newer, name, root, *, checkpoint: ReadCheckpoint | None = None):
    from .service import _rollback_creation

    if checkpoint is not None:
        if not callable(checkpoint):
            raise InputReadError('invalid')
        checkpoint(0)
    root = Path(root)
    if not root.is_absolute():
        root = Path.cwd() / root
    directories = _directories(root)
    _layout(root)
    store, database, created = None, None, []
    try:
        with _staged_project(older, newer, name, checkpoint) as (stage, candidate):
            def validate(held):
                if _directories(root) != directories:
                    raise ValueError('PT-RETRY: lexical destination ownership changed')
                return validate_retry(root, candidate, held, checkpoint)

            store = ProjectStore(root.resolve(), create=True, _creation_validator=validate)
            database = store.created_database
            for artifact in candidate.artifacts:
                copied = inspect_artifact(stage / artifact.relative_path, artifact.side, store.root,
                                          created=created, checkpoint=_read_budget(3 * artifact.size, checkpoint))
                if ((copied.sha256, copied.size, copied.relative_path) !=
                        (artifact.sha256, artifact.size, artifact.relative_path)):
                    raise ValueError('PT-RETRY: staged input changed during publication')
        # The private stage is closed/cleaned before the destination can commit.
        project = store.save(candidate, checkpoint=_read_budget(2 * sum(item.size for item in candidate.artifacts),
                                                                checkpoint))
        return service_type(store.root, project, store)
    except BaseException as exc:
        if store is not None:
            _rollback_creation(store, database, created, exc)
        raise
