"""Legacy duplicate raw-output cleanup on project open (SPEC-07h H8, Phase D amendment). No Qt.

Projects written before the single-copy change hold the backend's Ghidriff JSON twice: the original
under `runs/<id>/raw/json/*.ghidriff.json` and the project-owned copy `runs/<id>/raw/result.ghidriff.json`
that `raw_path` names. This module removes only that original, only when it is byte-identical to the
kept copy, and only after recording the removal in `backups/raw-duplicates.jsonl` (flushed and fsynced
first), so every removal is journalled and reversible from the verified kept copy
(`restore_raw_duplicates`). Anything unexpected is left in place and logged. It never raises.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .ingestion import safe_path

JOURNAL = 'backups/raw-duplicates.jsonl'
JOURNAL_VERSION = 1
_LOG = logging.getLogger(__name__)
_CHUNK = 1 << 20
# The only shapes a journal line may name (restore never writes anywhere else).
_REMOVED = re.compile(r'runs/(?P<run>[0-9a-f-]{36})/raw/json/[^/\\:]+\.ghidriff\.json')
_KEPT = 'runs/{run}/raw/result.ghidriff.json'


@dataclass(frozen=True)
class CleanupReport:
    removed: tuple[str, ...] = ()  # project-relative POSIX paths
    kept: tuple[tuple[str, str], ...] = ()  # (path, reason)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(_CHUNK), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: Path) -> bool:
    """A plain file (no symlink, junction or other reparse point)."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    return not getattr(st, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)


def _real_dir(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode) or path.is_symlink():
        return False
    return not getattr(st, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)


def _append_journal(root: Path, entry: dict) -> None:
    directory = safe_path(root, 'backups')
    directory.mkdir(exist_ok=True)
    line = json.dumps(entry, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
    fd = os.open(safe_path(root, JOURNAL), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_BINARY', 0),
                 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(line.encode('ascii'))
        stream.flush()
        os.fsync(stream.fileno())


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except PermissionError:
        # Read-only files cannot be deleted on Windows until the attribute is cleared.
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        path.unlink()


def _legacy_runs(project):
    for run in project.runs:
        if run.raw_path and run.raw_sha256 and run.raw_path == _KEPT.format(run=run.id):
            yield run


def cleanup_legacy_raw_duplicates(root: Path, project) -> CleanupReport:
    """Remove journalled, byte-identical legacy duplicates of each run's raw output. Never raises."""
    removed: list[str] = []
    kept: list[tuple[str, str]] = []
    try:
        root = Path(root).resolve()
        for run in _legacy_runs(project):
            try:
                json_dir = safe_path(root, f'runs/{run.id}/raw/json')
                if not _real_dir(json_dir):
                    continue
                candidates = sorted(p for p in json_dir.iterdir() if p.name.endswith('.ghidriff.json'))
                if not candidates:
                    continue
                kept_path = safe_path(root, run.raw_path)
                if not _regular(kept_path) or _sha256(kept_path) != run.raw_sha256:
                    kept.extend((p.relative_to(root).as_posix(), 'kept copy does not verify') for p in candidates)
                    continue
                size = kept_path.stat().st_size
            except (OSError, ValueError) as exc:
                _LOG.warning('Legacy raw cleanup skipped run %s (%s)', run.id, type(exc).__name__)
                continue
            for candidate in candidates:
                relative = candidate.relative_to(root).as_posix()
                try:
                    if not _regular(candidate):
                        reason = 'not a regular file'
                    elif candidate.stat().st_size != size or _sha256(candidate) != run.raw_sha256:
                        reason = 'differs from the kept raw output'
                    else:
                        _append_journal(root, {'v': JOURNAL_VERSION, 'run_id': run.id, 'removed': relative,
                                               'kept': run.raw_path, 'sha256': run.raw_sha256, 'size': size,
                                               'utc': datetime.now(UTC).isoformat(timespec='seconds')})
                        _unlink(candidate)
                        removed.append(relative)
                        _LOG.info('Removed legacy duplicate raw output %s (identical to %s)', relative, run.raw_path)
                        continue
                except (OSError, ValueError) as exc:
                    reason = f'not removed ({type(exc).__name__})'
                kept.append((relative, reason))
                _LOG.warning('Legacy raw output %s kept: %s', relative, reason)
    except Exception:  # noqa: BLE001 - maintenance must never block opening a project
        _LOG.warning('Legacy raw cleanup stopped early', exc_info=True)
    return CleanupReport(tuple(removed), tuple(kept))


def restore_raw_duplicates(root: Path) -> int:
    """Recreate every journalled duplicate whose path is absent, from the kept copy after re-checking its
    SHA-256. Returns the number of files written. Idempotent; raises ValueError on a malformed journal."""
    root = Path(root).resolve()
    journal = safe_path(root, JOURNAL)
    if not journal.is_file():
        return 0
    restored = 0
    for number, line in enumerate(journal.read_text(encoding='ascii').splitlines(), 1):
        if not line.strip():
            continue
        entry = json.loads(line)
        shape = _REMOVED.fullmatch(entry.get('removed', '')) if isinstance(entry, dict) and isinstance(
            entry.get('removed'), str) else None
        if (shape is None or entry.get('v') != JOURNAL_VERSION or entry.get('kept') != _KEPT.format(run=shape['run'])
                or not isinstance(entry.get('sha256'), str)):
            raise ValueError(f'PT-STORAGE: raw duplicate journal line {number} is malformed')
        target = safe_path(root, entry['removed'])
        if target.exists() or target.is_symlink():
            continue
        data = safe_path(root, entry['kept']).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError(f'PT-STORAGE: kept raw output for journal line {number} no longer verifies')
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.restore-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
        restored += 1
    return restored


__all__ = ['CleanupReport', 'JOURNAL', 'cleanup_legacy_raw_duplicates', 'restore_raw_duplicates']
