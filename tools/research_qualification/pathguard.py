"""Confine the CLI's file arguments to the working directory, the system temp directory, or roots the operator
names in RQ_ALLOWED_DIRS (os.pathsep-separated). Paths are resolved first, so `..` and symlinks cannot escape."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


class PathGuardError(ValueError):
    """A path argument points outside the allowed roots."""


def allowed_roots() -> list[Path]:
    roots = [Path.cwd().resolve(), Path(tempfile.gettempdir()).resolve()]
    for extra in filter(None, os.environ.get('RQ_ALLOWED_DIRS', '').split(os.pathsep)):
        roots.append(Path(extra).expanduser().resolve())
    return roots


def confine(path: str | os.PathLike[str], what: str = 'path') -> Path:
    if not str(path) or '\0' in str(path):
        raise PathGuardError(f'{what} is empty or contains a NUL byte')
    resolved = Path(path).expanduser().resolve()
    if any(resolved.is_relative_to(root) for root in allowed_roots()):
        return resolved
    raise PathGuardError(f'{what} is outside the working directory and temp directory '
                         f'(set RQ_ALLOWED_DIRS to allow another root): {path}')
