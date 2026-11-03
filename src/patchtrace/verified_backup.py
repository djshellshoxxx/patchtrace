"""Verified SQLite backups taken before any prune deletes rows (SPEC-07h H1/H2, Phase D amendment).

Rule: no backup, no deletion. A new backup is written with the SQLite backup API into
an exclusively created `backups/project-pre-<label>-<UTC stamp>-*.sqlite3.part`; the writing connection is closed, the file is
re-opened read-only and must pass `PRAGMA integrity_check` and answer the caller's identity queries
(snapshot hash, row counts) exactly like the live database. Only then is it hard-linked to an unused final name,
and revalidated before its unique staging name is removed. Successful return requires that owned
name's removal and observed absence. A matching staging name makes the
final name ineligible for discovery, including after restart; failed publication retains its evidence.

An existing backup is trusted only after the same read-only re-open with `PRAGMA quick_check`, a
matching project id and the label's table. The verdict (good or bad) is cached per process by
path, file identity, size, mtime_ns and SHA-256. Every reuse freshly hashes the bytes: restoring
metadata after an edit cannot retain trust. SQLite checks run once per verified byte version.
The cache is shared between threads (a worker may verify; the owner re-hashes before deletion).

Pure stdlib plus `ingestion.safe_path`; no Qt. Errors are `BackupError` (a `ValueError` whose message
starts with `PT-STORAGE:`); callers keep every row when they see one.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
import threading
from bisect import bisect_left
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .ingestion import file_fingerprint, safe_path

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
_Version = tuple[int, int, int, int, str]
# str(path) -> ((device, inode, size, mtime_ns, fresh SHA-256), facts or failed-check None)
_VERIFIED: dict[str, tuple[_Version, _Facts | None]] = {}


def forget_all() -> None:
    """Drop every cached verdict (tests; a new process starts empty anyway)."""
    with _LOCK:
        _VERIFIED.clear()


def _stat_key(info) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _fingerprint(path: Path) -> _Version | None:
    """Require matching complete byte observations, not just unchanged timestamps.

    A write behind the first read cursor can leave its digest describing old bytes
    even when no timestamp advances. Reopen and hash again before accepting that
    version. Both reads retain their identity and change checks; this is bounded
    revalidation, not a lock against arbitrary subsequent writers.
    """
    first = _fingerprint_once(path)
    return first if first is not None and _fingerprint_once(path) == first else None


def _fingerprint_once(path: Path) -> _Version | None:
    """Hash one regular file in bounded chunks and reject observed changes."""
    try:
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags | getattr(os, 'O_NONBLOCK', 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                return None
            # Windows path stat can expose creation time while fstat exposes
            # change time. Compare ctime only within each observation API.
            # The shared helper also observes FILE_BASIC_INFO.ChangeTime as an
            # independent indication of changes, not proof of unchanged bytes.
            named_before = file_fingerprint(path)
            path_before = path.lstat()
            if (not stat.S_ISREG(path_before.st_mode)
                    or named_before[:4] != _stat_key(before)[:4]
                    or _stat_key(path_before)[:4] != _stat_key(before)[:4]):
                return None
            digest = hashlib.sha256()
            remaining = before.st_size
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                while remaining:
                    block = stream.read(min(1024 * 1024, remaining))
                    if not block:
                        return None
                    digest.update(block)
                    remaining -= len(block)
            after = os.fstat(fd)
            named = path.lstat()
            if (not stat.S_ISREG(named.st_mode) or _stat_key(before) != _stat_key(after)
                    or _stat_key(path_before) != _stat_key(named)
                    or _stat_key(after)[:4] != _stat_key(named)[:4]
                    or file_fingerprint(path) != named_before):
                return None
            return before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, digest.hexdigest()
        finally:
            os.close(fd)
    except OSError:
        return None


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


def _remember(path: Path, facts: _Facts | None, checked: _Version | None) -> bool:
    """Cache a verdict for `checked`, the fingerprint taken before the check. False (nothing cached) if
    the file changed while it was being checked, because the verdict then describes another file."""
    if checked is None or _fingerprint(path) != checked:
        return False
    with _LOCK:
        _VERIFIED[str(path)] = (checked, facts)
    return True


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
        prefix = f'project-pre-{label}-'
        with os.scandir(directory) as entries:
            found = [Path(entry.path) for entry in entries
                     if entry.name.startswith(prefix) and entry.name.endswith('.sqlite3')
                     and not entry.is_symlink() and entry.is_file(follow_symlinks=False)]
        # List finals first: each new final is linked only after its unique stage exists.
        # Stage presence is refusal only, never evidence that bytes may be trusted.
        # Unlike Path.glob, scandir propagates failures during opening or iteration.
        # An unreadable pending-stage scan must never look like an empty one.
        with os.scandir(directory) as entries:
            pending = sorted(entry.name for entry in entries if entry.name.endswith('.sqlite3.part'))
    except (OSError, ValueError):
        return []
    admitted = []
    for candidate in found:
        prefix = candidate.stem + '-'
        position = bisect_left(pending, prefix)
        if position == len(pending) or not pending[position].startswith(prefix):
            admitted.append(candidate)
    return sorted(admitted, reverse=True)  # the UTC stamp sorts newest first


def trusted_backup(root: Path, label: str, *, project_id: str | None = None, snapshot_sha: str | None = None,
                   require_tables: Sequence[str] = ()) -> Path | None:
    """A cached good SQLite verdict whose complete bytes still hash to the verified version.

    This reads the backup even inside a write transaction; mutable timestamps
    cannot authorize irreversible pruning. It does not repeat SQLite queries.
    """
    for candidate in _candidates(Path(root), label):
        # Refusal needs no byte read. Rehash only verdicts that could authorize deletion;
        # the preparatory find_verified_backup path can still verify changed candidates.
        with _LOCK:
            entry = _VERIFIED.get(str(candidate))
        if entry is None or not _acceptable(entry[1], project_id, snapshot_sha, require_tables):
            continue
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
            checked = _fingerprint(candidate)
            if checked is None:
                continue
            problem, facts = _verify(candidate, 'quick_check')
            if not _remember(candidate, facts if problem is None else None, checked):
                continue
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
        expected = _answers(connection, queries)
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise BackupError(f'PT-STORAGE: pre-{label} database backup could not be prepared '
                          f'({type(exc).__name__})') from exc
    part: Path | None = None
    owned: tuple[int, int] | None = None
    retain_stage = False
    try:
        descriptor, name = tempfile.mkstemp(prefix=f'project-pre-{label}-{stamp}-', suffix='.sqlite3.part', dir=directory)
        part = Path(name)
        try:
            info = os.fstat(descriptor)
            owned = info.st_dev, info.st_ino
        finally:
            os.close(descriptor)
        copy = sqlite3.connect(part)
        try:
            connection.backup(copy)
        finally:
            copy.close()
        _after_copy(part)
        checked = _fingerprint(part)
        if checked is None:
            raise BackupError(f'PT-STORAGE: pre-{label} database backup changed during verification')
        problem, facts = _verify(part, 'integrity_check', queries, expected)
        if problem is not None or facts is None:
            raise BackupError(f'PT-STORAGE: pre-{label} database backup failed verification ({problem})')
        if _fingerprint(part) != checked:
            raise BackupError(f'PT-STORAGE: pre-{label} database backup changed during verification')
        os.link(part, target, follow_symlinks=False)
        # Retain the pending name on any post-link failure: a later process must not
        # adopt changed-but-valid SQLite bytes as a newly verified existing backup.
        retain_stage = True
        if not _remember(target, facts, checked):
            raise BackupError(f'PT-STORAGE: pre-{label} database backup changed during publication')
        # Completion authorizes the caller's first prune, so cleanup is not best effort.
        # Leave the final and any replacement staging inode untouched on failure.
        info = part.lstat()
        if (info.st_dev, info.st_ino) != owned:
            raise BackupError(f'PT-STORAGE: pre-{label} database backup staging ownership changed')
        part.unlink()
        try:
            part.lstat()
        except FileNotFoundError:
            pass
        else:
            raise BackupError(f'PT-STORAGE: pre-{label} database backup staging name remains')
    except BackupError:
        raise
    except (sqlite3.Error, OSError, ValueError, NotImplementedError) as exc:
        raise BackupError(f'PT-STORAGE: pre-{label} database backup failed ({type(exc).__name__})') from exc
    finally:
        if part is not None and owned is not None and not retain_stage:
            try:
                info = part.lstat()
                if (info.st_dev, info.st_ino) == owned:
                    part.unlink()
            except OSError:
                # Before publication, retain the original failure even when cleanup
                # fails. Never remove a replacement temporary owned elsewhere.
                pass
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
