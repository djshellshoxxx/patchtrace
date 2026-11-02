"""Private project preparation and identity-owned failed-publication cleanup.

Only private staging is recursively removed. User-selected destinations retain
persistent kernel-lock files and any unproven, pre-existing or replaced content.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .ingestion import (
    CHUNK_SIZE,
    display_text,
    file_fingerprint,
    inspect_artifact,
    safe_path,
    verify_artifact,
)
from .models import AnalysisRun, Artifact, ComparisonProject
from .persistence import ProjectStore, _abandoned_creation


def _identity(path: Path, *, directory: bool = False) -> tuple[int, int]:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise OSError('creation path is linked or has the wrong file type')
    return info.st_dev, info.st_ino


@contextmanager
def staged_project(older: Path, newer: Path, name: str, *, inspector=inspect_artifact):
    """Validate copies and the first saved snapshot before opening the destination."""
    with tempfile.TemporaryDirectory(prefix='patchtrace-create-') as temporary:
        root = Path(temporary)
        with ProjectStore(root, create=True) as store:
            artifacts = [inspector(older, 'older', root), inspector(newer, 'newer', root)]
            project = ComparisonProject(name=display_text(name.strip()) or 'Untitled comparison',
                                        artifacts=artifacts)
            if artifacts[0].sha256 == artifacts[1].sha256:
                project.runs.append(AnalysisRun(status='identical', backend='none', backend_version='none',
                                                settings={'reason': 'Input SHA-256 hashes are identical'}))
            yield root, store.save(project)


class CreationPublication:
    """Bound publication to a held store lock; never claim an existing file as ours."""

    def __init__(self, store: ProjectStore):
        self.store = store
        self.root = store.root
        self.root_id = _identity(self.root, directory=True)
        held = os.fstat(store.lock.stream.fileno())
        self.lock_id = held.st_dev, held.st_ino
        if _identity(store.lock.path) != self.lock_id:
            raise OSError('creation destination lock identity changed')
        self.database = safe_path(self.root, 'project.sqlite3')
        self.database_id = _identity(self.database)
        self.files: dict[Path, tuple[tuple[int, int], tuple]] = {}
        self.artifacts = safe_path(self.root, 'artifacts')
        self.created_artifact_dir = False
        self.artifacts_id = None

    def _check_root(self) -> None:
        if _identity(self.root, directory=True) != self.root_id:
            raise OSError('creation destination identity changed')
        if self.store.lock is None or self.store.lock.stream is None:
            raise OSError('creation destination lock is not held')
        held = os.fstat(self.store.lock.stream.fileno())
        if ((held.st_dev, held.st_ino) != self.lock_id
                or _identity(self.store.lock.path) != self.lock_id):
            raise OSError('creation destination lock identity changed')

    def publish(self, staged_root: Path, project: ComparisonProject) -> None:
        self._check_root()
        try:
            self.artifacts.mkdir()
            self.created_artifact_dir = True
        except FileExistsError:
            pass
        self.artifacts_id = _identity(self.artifacts, directory=True)
        for artifact in project.artifacts:
            self._publish_artifact(staged_root, artifact)

    def _check_artifacts(self) -> None:
        self._check_root()
        if _identity(self.artifacts, directory=True) != self.artifacts_id:
            raise OSError('creation artifact directory identity changed')

    def _publish_artifact(self, staged_root: Path, artifact: Artifact) -> None:
        self._check_artifacts()
        target = safe_path(self.root, artifact.relative_path)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        try:
            descriptor = os.open(target, flags, 0o600)
        except FileExistsError:
            identity, version = _identity(target), file_fingerprint(target)
            verify_artifact(artifact, self.root)
            self._check_artifacts()
            if _identity(target) != identity or file_fingerprint(target) != version:
                raise OSError('existing artifact changed during publication') from None
            return
        with os.fdopen(descriptor, 'w+b') as copied:
            info = os.fstat(copied.fileno())
            identity = info.st_dev, info.st_ino
            self._check_artifacts()
            if _identity(target) != identity:
                raise OSError('creation artifact identity changed')
            digest, size = hashlib.sha256(), 0
            with safe_path(staged_root, artifact.relative_path).open('rb') as source:
                for chunk in iter(lambda: source.read(CHUNK_SIZE), b''):
                    size += len(chunk)
                    if size > artifact.size:
                        raise OSError('staged artifact grew during publication')
                    digest.update(chunk)
                    if copied.write(chunk) != len(chunk):
                        raise OSError('incomplete artifact publication')
            if size != artifact.size or digest.hexdigest() != artifact.sha256:
                raise OSError('staged artifact changed during publication')
            copied.flush()
            os.fsync(copied.fileno())
            self._check_artifacts()
            if _identity(target) != identity:
                raise OSError('creation artifact identity changed')
            if hasattr(os, 'fchmod'):
                os.fchmod(copied.fileno(), stat.S_IRUSR)
            else:
                target.chmod(stat.S_IRUSR)
        self._check_artifacts()
        if _identity(target) != identity:
            raise OSError('creation artifact identity changed')
        version = file_fingerprint(target)
        verify_artifact(artifact, self.root)
        if _identity(target) != identity or file_fingerprint(target) != version:
            raise OSError('published artifact changed during verification')
        self.files[target] = identity, version

    def discard_if_unpublished(self) -> None:
        """Best effort while locked: preserve committed/foreign/replaced data on doubt."""
        try:
            self._check_root()
            if (_identity(self.database) != self.database_id
                    or not _abandoned_creation(self.database)):
                return
            # Windows requires closing SQLite before unlinking its database, but
            # the separate kernel project lock remains held throughout cleanup.
            if self.store.connection is not None:
                self.store.connection.close()
                self.store.connection = None
            for path, (identity, version) in self.files.items():
                self._check_root()
                if (_identity(self.artifacts, directory=True) == self.artifacts_id
                        and _identity(path) == identity and file_fingerprint(path) == version):
                    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                    path.unlink()
            self._check_root()
            if _identity(self.database) == self.database_id:
                self.database.unlink()
            if self.created_artifact_dir and _identity(self.artifacts, directory=True) == self.artifacts_id:
                try:
                    self.artifacts.rmdir()  # Only empty owned directories; never recursive user-root cleanup.
                except OSError:
                    pass
        except (OSError, ValueError, sqlite3.Error) as exc:
            logging.getLogger(__name__).warning('Creation cleanup preserved unverified paths (%s)', type(exc).__name__)
