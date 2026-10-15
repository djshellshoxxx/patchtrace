"""Cache layout `<cache>/search/<sha256(project_id)[:16]>/<group>-<digest16>.sqlite3` (WB1 section 7).

The cache is derived data: per-user, local, outside the project root (so OneDrive, backup and release
packaging never see it). Names are Windows-safe by construction (`:` in a group becomes `.`).
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from collections.abc import Mapping
from pathlib import Path

from patchtrace.search.errors import SearchError

SEGMENT_SUFFIX = '.sqlite3'
STAGING_PREFIX = '.staging-'
_GROUP = re.compile(r'^[a-z]{1,8}(:[a-z0-9]{1,16}){0,2}$')
_DIGEST = re.compile(r'^[0-9a-f]{16}$')
_FILE = re.compile(r'^([a-z]{1,8}(?:\.[a-z0-9]{1,16}){0,2})-([0-9a-f]{16})\.sqlite3$')


def _store_error(message: str) -> SearchError:
    return SearchError('PT-SEARCH-STORE', message, recoverable=True)


def default_cache_root(env: Mapping[str, str] | None = None, *, home: Path | None = None) -> Path:
    """``%LOCALAPPDATA%\\PatchTrace\\cache``, else ``$XDG_CACHE_HOME/PatchTrace``, else ``~/.cache/PatchTrace``."""
    env = os.environ if env is None else env
    if env.get('LOCALAPPDATA'):
        return Path(env['LOCALAPPDATA']) / 'PatchTrace' / 'cache'
    if env.get('XDG_CACHE_HOME'):
        return Path(env['XDG_CACHE_HOME']) / 'PatchTrace'
    return (home or Path.home()) / '.cache' / 'PatchTrace'


def _folded(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def validate_cache_root(cache_root: Path, project_root: Path) -> Path:
    """Absolute, and not the project root or anything inside it (symlinks and Windows case resolved)."""
    if not cache_root.is_absolute():
        raise _store_error('the search cache directory must be an absolute path')
    root, project = _folded(cache_root), _folded(project_root)
    if root == project or root.startswith(project.rstrip(os.sep) + os.sep):
        raise _store_error('the search cache must not live inside the project folder')
    return cache_root


def project_dir(cache_root: Path, project_id: str) -> Path:
    if not project_id:
        raise _store_error('a project id is required to locate the search cache')
    return cache_root / 'search' / hashlib.sha256(project_id.encode('utf-8')).hexdigest()[:16]


def segment_filename(group: str, digest16: str) -> str:
    if not _GROUP.match(group) or not _DIGEST.match(digest16):
        raise _store_error('invalid search segment name')
    return f'{group.replace(":", ".")}-{digest16}{SEGMENT_SUFFIX}'


def segment_path(directory: Path, group: str, digest16: str) -> Path:
    return directory / segment_filename(group, digest16)


def staging_path(directory: Path) -> Path:
    return directory / f'{STAGING_PREFIX}{uuid.uuid4().hex}'


def parse_segment_filename(name: str) -> tuple[str, str] | None:
    """(group, digest16) of a published segment file name, else None (staging files, strangers)."""
    match = _FILE.match(name)
    return (match.group(1).replace('.', ':'), match.group(2)) if match else None


def ensure_writable(directory: Path) -> None:
    probe = directory / f'.write-test-{uuid.uuid4().hex}'
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b'')
        probe.unlink()
    except OSError as exc:
        raise _store_error(f'the search cache directory is not writable ({type(exc).__name__})') from exc
