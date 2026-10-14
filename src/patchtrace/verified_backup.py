"""Verified SQLite backups taken before any prune deletes rows (SPEC-07h H1/H2, Phase D amendment).

Rule: no backup, no deletion. A new backup is written with the SQLite backup API into
`backups/project-pre-<label>-<UTC stamp>.sqlite3.part`; the writing connection is closed, the file is
re-opened read-only and must pass `PRAGMA integrity_check` and answer the caller's identity queries
(snapshot hash, row counts) exactly like the live database. Only then is it renamed to its final name,
so a crash or a failed check never leaves a half-trusted file under the trusted name.

An existing backup is trusted only after the same read-only re-open with `PRAGMA quick_check`, a
matching project id and the label's table. The verdict (good or bad) is cached per process by
(path, size, mtime_ns): the check runs once per backup file version, not on every save, and a file
that changes or disappears is checked again. The cache is shared between threads (a worker may
verify; the owner thread then only stats the file).

Pure stdlib plus `ingestion.safe_path`; no Qt. Errors are `BackupError` (a `ValueError` whose message
starts with `PT-STORAGE:`); callers keep every row when they see one.
"""
from __future__ import annotations

import sqlite3
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .ingestion import safe_path

BACKUP_DIR = 'backups'
SNAPSHOT_SHA = 'SELECT sha256 FROM current_snapshot WHERE singleton=1'
_PROJECT_ID = "SELECT json_extract(payload, '$.id') FROM current_snapshot WHERE singleton=1"
_TABLES = "SELECT name FROM sqlite_master WHERE type='table'"


class BackupError(ValueError):
    """A backup could not be written or did not verify; the caller must not delete anything."""


@dataclass(frozen=True)
class _Facts:
    project_id: str | None
    snapshot_sha: str | None
    tables: frozenset[str]


_LOCK = threading.Lock()
# str(path) -> ((size, mtime_ns), facts or None for a file that failed its check)
_VERIFIED: dict[str, tuple[tuple[int, int], _Facts | None]] = {}


def forget_all() -> None:
    """Drop every cached verdict (tests; a new process starts empty anyway)."""
    with _LOCK:
        _VERIFIED.clear()


def _fingerprint(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return st.st_size, st.st_mtime_ns


def _open_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f'{Path(path).as_uri()}?mode=ro', uri=True, timeout=5)


def _answers(db: sqlite3.Connection, queries: Sequence[str]) -> list[list[tuple]]:
    return [db.execute(query).fetchall() for query in queries]


def _facts(db: sqlite3.Connection) -> _Facts:
    tables = frozenset(row[0] for row in db.execute(_TABLES))
    project = sha = None
    if 'current_snapshot' in tables:
        row = db.execute(_PROJECT_ID).fetchone()
        project = row[0] if row and isinstance(row[0], str) else None
        row = db.execute(SNAPSHOT_SHA).fetchone()
        sha = row[0] if row else None
    return _Facts(project, sha, tables)


def _after_copy(path: Path) -> None:
    """Test seam: runs after the copy is written and its connection closed, before verification."""


def _verify(path: Path, check: str, queries: Sequence[str] = (),
            expected: list[list[tuple]] | None = None) -> tuple[str | None, _Facts | None]:
    """Re-open `path` read-only and check it. Returns (problem or None, facts)."""
    try:
        db = _open_read_only(path)
        try:
            if db.execute(f'PRAGMA {check}').fetchall() != [('ok',)]:
                return f'{check} failed', None
            if queries and _answers(db, queries) != expected:
                return 'content differs from the live database', None
            return None, _facts(db)
        finally:
            db.close()
    except (sqlite3.Error, OSError, ValueError) as exc:
        return f'{type(exc).__name__} while reading the copy', None


def _remember(path: Path, facts: _Facts | None) -> None:
    fingerprint = _fingerprint(path)
    if fingerprint is not None:
        with _LOCK:
            _VERIFIED[str(path)] = (fingerprint, facts)


def _cached(path: Path) -> tuple[bool, _Facts | None]:
    """(known, facts): known=False when no verdict is cached for this exact file version."""
    with _LOCK:
        entry = _VERIFIED.get(str(path))
    if entry is None:
        return False, None
    if _fingerprint(path) != entry[0]:
        with _LOCK:
            _VERIFIED.pop(str(path), None)
        return False, None
    return True, entry[1]


def _acceptable(facts: _Facts | None, project_id: str | None, snapshot_sha: str | None,
                require_tables: Sequence[str]) -> bool:
    return (facts is not None
            and (project_id is None or facts.project_id == project_id)
            and (snapshot_sha is None or facts.snapshot_sha == snapshot_sha)
            and set(require_tables) <= facts.tables)


def _candidates(root: Path, label: str) -> list[Path]:
    try:
        directory = safe_path(root, BACKUP_DIR)
        if not directory.is_dir():
            return []
        found = [p for p in directory.glob(f'project-pre-{label}-*.sqlite3') if not p.is_symlink() and p.is_file()]
    except (OSError, ValueError):
        return []
    return sorted(found, reverse=True)  # the UTC stamp sorts newest first


def trusted_backup(root: Path, label: str, *, project_id: str | None = None, snapshot_sha: str | None = None,
                   require_tables: Sequence[str] = ()) -> Path | None:
    """A backup with a cached good verdict for its unchanged file. Lists and stats files only (no reads),
    so it is cheap enough to call inside a write transaction."""
    for candidate in _candidates(Path(root), label):
        known, facts = _cached(candidate)
        if known and _acceptable(facts, project_id, snapshot_sha, require_tables):
            return candidate
    return None


def find_verified_backup(root: Path, label: str, *, project_id: str | None = None,
                         snapshot_sha: str | None = None, require_tables: Sequence[str] = ()) -> Path | None:
    """Newest trusted `project-pre-<label>-*` backup, re-opening and `quick_check`ing any whose verdict is
    not cached for its current file version. Never raises for unreadable candidates (they are skipped)."""
    for candidate in _candidates(Path(root), label):
        known, facts = _cached(candidate)
        if not known:
            problem, facts = _verify(candidate, 'quick_check')
            _remember(candidate, facts if problem is None else None)
        if _acceptable(facts, project_id, snapshot_sha, require_tables):
            return candidate
    return None


def write_verified_backup(root: Path, connection: sqlite3.Connection, label: str, *,
                          compare: Sequence[str] = ()) -> Path:
    """Copy `connection` into a new backup and verify it on a re-opened read-only connection."""
    root = Path(root)
    queries = (SNAPSHOT_SHA, *compare)
    try:
        directory = safe_path(root, BACKUP_DIR)
        directory.mkdir(exist_ok=True)
        stamp = datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')
        target = safe_path(root, f'{BACKUP_DIR}/project-pre-{label}-{stamp}.sqlite3')
        part = safe_path(root, f'{BACKUP_DIR}/project-pre-{label}-{stamp}.sqlite3.part')
        expected = _answers(connection, queries)
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise BackupError(f'PT-STORAGE: pre-{label} database backup could not be prepared '
                          f'({type(exc).__name__})') from exc
    try:
        copy = sqlite3.connect(part)
        try:
            connection.backup(copy)
        finally:
            copy.close()
        _after_copy(part)
        problem, facts = _verify(part, 'integrity_check', queries, expected)
        if problem is not None or facts is None:
            raise BackupError(f'PT-STORAGE: pre-{label} database backup failed verification ({problem})')
        part.replace(target)
    except BackupError:
        part.unlink(missing_ok=True)
        raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        part.unlink(missing_ok=True)
        raise BackupError(f'PT-STORAGE: pre-{label} database backup failed ({type(exc).__name__})') from exc
    _remember(target, facts)
    return target


def live_project_id(connection: sqlite3.Connection) -> str | None:
    """Project id of the live database (parses the snapshot JSON: callers that know it should pass it)."""
    try:
        row = connection.execute(_PROJECT_ID).fetchone()
    except sqlite3.Error as exc:
        raise BackupError(f'PT-STORAGE: live database cannot be read ({type(exc).__name__})') from exc
    return row[0] if row and isinstance(row[0], str) else None


def ensure_verified_backup(root: Path, connection: sqlite3.Connection, label: str, *,
                           project_id: str | None = None, compare: Sequence[str] = (),
                           require_tables: Sequence[str] = (), current: bool = False) -> Path:
    """A trusted backup for `label`: a verified existing one of this project, or a new verified copy.
    `current=True` also requires the backup to hold exactly the live snapshot (pre-creation backups).
    Raises BackupError; the caller then deletes nothing."""
    if project_id is None:
        project_id = live_project_id(connection)
    snapshot_sha = None
    if current:
        try:
            row = connection.execute(SNAPSHOT_SHA).fetchone()
        except sqlite3.Error as exc:
            raise BackupError(f'PT-STORAGE: live database cannot be read ({type(exc).__name__})') from exc
        snapshot_sha = row[0] if row else None
    found = find_verified_backup(root, label, project_id=project_id, snapshot_sha=snapshot_sha,
                                 require_tables=require_tables)
    if found is not None:
        return found
    return write_verified_backup(root, connection, label, compare=compare)


__all__ = ['BACKUP_DIR', 'BackupError', 'SNAPSHOT_SHA', 'ensure_verified_backup', 'find_verified_backup',
           'forget_all', 'live_project_id', 'trusted_backup', 'write_verified_backup']
