"""Bounded build/source observations, recovered from 62b9a3de (version-provenance.md).

These observations identify available local bytes; they are not release receipts.
Importing this module starts no process and imports no Qt.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import stat
import sys
import time
from datetime import datetime
from pathlib import Path
from threading import Event

from . import __version__
from . import owned_publication as owned

BUILD_INFO_NAME = 'build-info.json'
BUILD_INFO_RELATIVE = f'patchtrace/{BUILD_INFO_NAME}'
UNKNOWN = 'unknown'
VERSION_KEYS = ('version', 'git_commit', 'git_describe', 'dirty', 'source_sha256', 'python',
                'pyinstaller', 'pyside6', 'built_utc', 'frozen')
MAX_ENTRIES = 8192
MAX_DEPTH = 32
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_BUILD_BYTES = 16 * 1024
SOURCE_SECONDS = 10


class BuildInfoError(ValueError):
    """The local source or packaged record cannot support the requested observation."""


class BuildInfoCancelled(Exception):
    """The caller cancelled a source/build observation."""


def _checkpoint(cancel: Event, deadline: float | None = None) -> None:
    if cancel.is_set():
        raise BuildInfoCancelled('cancelled')
    if deadline is not None and time.monotonic() > deadline:
        raise BuildInfoError('source observation exceeded its deadline')


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _inventory(src_root: Path, cancel: Event, deadline: float) -> dict[str, tuple[int, ...]]:
    package = src_root / 'patchtrace'
    pending = [(package, 0)]
    found: dict[str, tuple[int, ...]] = {}
    entries = 0
    while pending:
        _checkpoint(cancel, deadline)
        folder, depth = pending.pop()
        if depth > MAX_DEPTH:
            raise BuildInfoError('source directory depth exceeded')
        owned.directory_anchor(folder)
        found[folder.relative_to(src_root).as_posix() + '/'] = _stamp(folder.lstat())
        with os.scandir(folder) as listing:
            for item in listing:
                _checkpoint(cancel, deadline)
                entries += 1
                if entries > MAX_ENTRIES:
                    raise BuildInfoError('source entry budget exceeded')
                if item.name == '__pycache__':
                    continue
                info = item.stat(follow_symlinks=False)
                linked = stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)
                if linked:
                    raise BuildInfoError('source inventory contains a link or reparse point')
                path = folder / item.name
                if stat.S_ISDIR(info.st_mode):
                    pending.append((path, depth + 1))
                elif path.suffix == '.py':
                    if not stat.S_ISREG(info.st_mode):
                        raise BuildInfoError('Python source is not an ordinary file')
                    relative = path.relative_to(src_root).as_posix()
                    if any(ch in relative for ch in '\t\r\n'):
                        raise BuildInfoError('source path cannot be represented canonically')
                    relative.encode('utf-8', errors='strict')
                    found[relative] = _stamp(info)
    return found


def source_sha256(src_root: Path, *, cancel: Event | None = None) -> str:
    """Historical sorted path/file-digest fingerprint, with bounded owned reads."""
    cancel = cancel if cancel is not None else Event()
    _checkpoint(cancel)
    src_root = Path(os.path.abspath(src_root))
    anchor = owned.directory_anchor(src_root / 'patchtrace')
    deadline = time.monotonic() + SOURCE_SECONDS
    before = _inventory(src_root, cancel, deadline)
    files = sorted(name for name in before if not name.endswith('/'))
    if not files:
        raise BuildInfoError('no Python source files are available')
    digest = hashlib.sha256()
    remaining = MAX_SOURCE_BYTES
    for name in files:
        _checkpoint(cancel, deadline)
        raw = owned.read_bytes(src_root / name, maximum=min(MAX_FILE_BYTES, remaining), anchor=anchor)
        remaining -= len(raw)
        digest.update(f'{name}\t{hashlib.sha256(raw).hexdigest()}\n'.encode())
    if _inventory(src_root, cancel, deadline) != before:
        raise BuildInfoError('source inventory changed during observation')
    owned.verify_anchor(anchor)
    return digest.hexdigest()


def _git(repo_root: Path, executable: str, cancel: Event, *args: str) -> str | None:
    from .jobs import run_process
    _checkpoint(cancel)
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
    env.update(GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL=os.devnull)
    result = run_process([executable, '--no-pager', '-c', 'core.fsmonitor=false', *args],
                         cwd=repo_root, env=env, cancel=cancel, timeout_seconds=3,
                         log_limit=4096, stderr_limit=4096, max_output_bytes=4096, separate_streams=True)
    _checkpoint(cancel)
    if result.returncode != 0 or result.reason is not None:
        return None
    try:
        return (result.log_bytes or b'').decode('utf-8', errors='strict').strip()
    except UnicodeError:
        return None


def git_info(repo_root: Path, *, cancel: Event | None = None) -> dict:
    """Observe refs/objects only; worktree cleanliness is unknown, so configured filters never run."""
    cancel = cancel if cancel is not None else Event()
    _checkpoint(cancel)
    unknown = {'commit': UNKNOWN, 'describe': UNKNOWN, 'dirty': None}
    executable = shutil.which('git')
    if not executable:
        return unknown
    try:
        repo_root = Path(os.path.abspath(repo_root))
        anchor = owned.directory_anchor(repo_root)
        top = _git(repo_root, executable, cancel, 'rev-parse', '--show-toplevel')
        if top is None or not Path(top).is_absolute() or Path(top) != repo_root:
            return unknown
        commit = _git(repo_root, executable, cancel, 'rev-parse', '--verify', 'HEAD^{commit}')
        if commit is None or re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit) is None:
            return unknown
        describe = _git(repo_root, executable, cancel, 'describe', '--always', '--tags')
        after = _git(repo_root, executable, cancel, 'rev-parse', '--verify', 'HEAD^{commit}')
        final_top = _git(repo_root, executable, cancel, 'rev-parse', '--show-toplevel')
        owned.verify_anchor(anchor)
        if after != commit or final_top is None or Path(final_top) != repo_root:
            return unknown
        return {'commit': commit, 'describe': describe or UNKNOWN, 'dirty': None}
    except (OSError, ValueError, owned.OwnedPublicationError):
        return unknown


def _dist_version(name: str) -> str | None:
    try:
        value = importlib.metadata.version(name)
        return value if isinstance(value, str) and len(value) <= 128 else None
    except (importlib.metadata.PackageNotFoundError, OSError, ValueError):
        return None


def _empty(frozen: bool) -> dict:
    return {'version': __version__, 'git_commit': UNKNOWN, 'git_describe': UNKNOWN, 'dirty': None,
            'source_sha256': UNKNOWN, 'python': '.'.join(map(str, sys.version_info[:3])),
            'pyinstaller': None, 'pyside6': _dist_version('PySide6'), 'built_utc': None, 'frozen': frozen}


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise BuildInfoError('duplicate build record key')
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BuildInfoError('nonfinite build record value')


def _text(value: object, maximum: int = 512) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and value.isprintable()


def _validate_record(raw: bytes) -> dict:
    data = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_pairs, parse_constant=_reject_constant)
    if not isinstance(data, dict) or set(data) != set(VERSION_KEYS):
        raise BuildInfoError('build record fields are invalid')
    if data['version'] != __version__ or data['frozen'] is not True:
        raise BuildInfoError('build record belongs to another package')
    if type(data['dirty']) not in (bool, type(None)):
        raise BuildInfoError('build record dirty flag is invalid')
    for key, pattern in (('git_commit', r'(?:[0-9a-f]{40}|[0-9a-f]{64}|unknown)'),
                         ('source_sha256', r'(?:[0-9a-f]{64}|unknown)')):
        if not isinstance(data[key], str) or re.fullmatch(pattern, data[key]) is None:
            raise BuildInfoError('build record digest is invalid')
    if not all(_text(data[key]) for key in ('python', 'git_describe')):
        raise BuildInfoError('build record text is invalid')
    if not all(data[key] is None or _text(data[key], 128) for key in ('pyinstaller', 'pyside6')):
        raise BuildInfoError('build record dependency version is invalid')
    when = data['built_utc']
    if when is not None:
        if not isinstance(when, str) or re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', when) is None:
            raise BuildInfoError('build record timestamp is invalid')
        datetime.strptime(when, '%Y-%m-%dT%H:%M:%SZ')
    return data


def read_info(*, cancel: Event | None = None) -> tuple[dict, list[str]]:
    """Available observations and bounded explanations for unavailable provenance."""
    cancel = cancel if cancel is not None else Event()
    _checkpoint(cancel)
    frozen = bool(getattr(sys, 'frozen', False))
    info = _empty(frozen)
    warnings: list[str] = []
    if frozen:
        try:
            base = getattr(sys, '_MEIPASS', None)
            if not isinstance(base, (str, os.PathLike)):
                raise BuildInfoError('packaged metadata location is unavailable')
            info.update(_validate_record(owned.read_bytes(Path(base) / BUILD_INFO_RELATIVE, maximum=MAX_BUILD_BYTES)))
        except (OSError, ValueError, RecursionError, owned.OwnedPublicationError):
            warnings.append('Packaged build metadata is unavailable or invalid; source/build facts remain unknown.')
    else:
        src_root = Path(os.path.abspath(__file__)).parent.parent
        repo_root = src_root.parent
        if (repo_root / '.git').exists():
            git = git_info(repo_root, cancel=cancel)
            info.update(git_commit=git['commit'], git_describe=git['describe'], dirty=git['dirty'])
        warnings.append('Checkout cleanliness is not evaluated; Git worktree checks may execute configured filters.')
        if info['git_commit'] == UNKNOWN:
            warnings.append('Git commit provenance is unavailable.')
        try:
            info['source_sha256'] = source_sha256(src_root, cancel=cancel)
        except (OSError, ValueError, owned.OwnedPublicationError):
            warnings.append('Source fingerprint is unavailable: the source tree was unreadable, changed or exceeded bounds.')
    _checkpoint(cancel)
    return {'contract': 'build-info/1', 'basis': 'packaged-record' if frozen else 'source-tree', **info}, warnings


def version_info(*, cancel: Event | None = None) -> dict:
    """Version and available build observations; use read_info for diagnostics too."""
    return read_info(cancel=cancel)[0]
