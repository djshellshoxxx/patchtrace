"""Build provenance: version, git commit and source digest (SPEC-05 §2.7, SRC-3).

Standard library only. Importing this module never imports Qt, so the CLI
``version`` command and ``tools/build_windows.py`` can use it headless.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__

BUILD_INFO_NAME = 'build-info.json'
BUILD_INFO_RELATIVE = f'patchtrace/{BUILD_INFO_NAME}'
UNKNOWN = 'unknown'
VERSION_KEYS = ('version', 'git_commit', 'git_describe', 'dirty', 'source_sha256', 'python',
                'pyinstaller', 'pyside6', 'built_utc', 'frozen')


def _file_sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_sha256(src_root: Path) -> str:
    """SHA-256 over sorted ``"<relative posix path>\\t<file sha256>\\n"`` lines.

    ``src_root`` is the directory that contains the ``patchtrace`` package (``src``).
    Only ``patchtrace/**/*.py`` is covered; ``__pycache__`` is excluded.
    """
    src_root = Path(src_root)
    package = src_root / 'patchtrace'
    lines = sorted(
        f'{path.relative_to(src_root).as_posix()}\t{_file_sha256(path)}\n'
        for path in package.rglob('*.py')
        if path.is_file() and '__pycache__' not in path.relative_to(src_root).parts)
    return hashlib.sha256(''.join(lines).encode('utf-8')).hexdigest()


def _git(repo_root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(['git', *args], cwd=repo_root, capture_output=True, text=True,
                                   timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def git_info(repo_root: Path) -> dict[str, Any]:
    """Return ``{commit, describe, dirty}``; ``'unknown'``/``None`` when git is unavailable. Never raises."""
    unknown: dict[str, Any] = {'commit': UNKNOWN, 'describe': UNKNOWN, 'dirty': None}
    try:
        commit = _git(Path(repo_root), 'rev-parse', '--verify', 'HEAD^{commit}')
        if commit is None:
            return unknown
        status = _git(Path(repo_root), 'status', '--porcelain')
        describe = _git(Path(repo_root), 'describe', '--always', '--tags', '--dirty')
        return {'commit': commit.strip() or UNKNOWN,
                'describe': describe.strip() if describe else UNKNOWN,
                'dirty': None if status is None else bool(status.strip())}
    except Exception:  # noqa: BLE001 - provenance lookup must never break the caller
        return unknown


def _dist_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None
    except Exception:  # noqa: BLE001
        return None


def _frozen_info() -> dict[str, Any]:
    info: dict[str, Any] = {key: UNKNOWN for key in VERSION_KEYS}
    info.update({'version': __version__, 'dirty': None, 'pyinstaller': None, 'pyside6': None,
                 'built_utc': None, 'python': platform.python_version()})
    base = getattr(sys, '_MEIPASS', None)
    if base:
        try:
            data = json.loads((Path(base) / BUILD_INFO_RELATIVE).read_text(encoding='utf-8'))
            if isinstance(data, dict):
                info.update({key: data[key] for key in VERSION_KEYS if key in data})
        except (OSError, ValueError):
            pass
    info['frozen'] = True
    return info


def version_info() -> dict[str, Any]:
    """Version and build provenance for ``patchtrace version --json``."""
    if getattr(sys, 'frozen', False):
        return _frozen_info()
    package_dir = Path(__file__).resolve().parent
    src_root = package_dir.parent
    repo_root = src_root.parent
    git = git_info(repo_root) if (repo_root / '.git').exists() else \
        {'commit': UNKNOWN, 'describe': UNKNOWN, 'dirty': None}
    return {'version': __version__,
            'git_commit': git['commit'],
            'git_describe': git['describe'],
            'dirty': git['dirty'],
            'source_sha256': source_sha256(src_root),
            'python': platform.python_version(),
            'pyinstaller': None,
            'pyside6': _dist_version('PySide6'),
            'built_utc': None,
            'frozen': False}
