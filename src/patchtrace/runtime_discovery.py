"""Read-only bounded discovery of already-installed analysis runtimes.

Discovery does not execute Python, Ghidra, Java, pip or files from the input
directories. Runtime compatibility is checked separately by backend.diagnose.
"""
from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

MAX_CHILDREN_PER_ROOT = 64


@dataclass(frozen=True)
class RuntimeCandidates:
    python_executables: tuple[Path, ...]
    ghidra_roots: tuple[Path, ...]
    # SPEC-29 §8: pre-fill only. Never found via PATH, never executed here; the BinDiff probe decides.
    bindiff_executables: tuple[Path, ...] = ()


def _safe_file(path: Path) -> Path | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.parent.is_symlink():
            return None
        return path.resolve()
    except (OSError, RuntimeError):
        return None


def _safe_ghidra(path: Path) -> Path | None:
    try:
        if path.is_symlink() or not path.is_dir():
            return None
        marker = path / 'Ghidra' / 'application.properties'
        if (marker.is_symlink() or marker.parent.is_symlink()
                or not marker.is_file()):
            return None
        return path.resolve()
    except (OSError, RuntimeError):
        return None


def _children(root: Path, prefix: str = ''):
    """Inspect at most one bounded level, without following directory symlinks.

    The name filter runs before the bound, so a crowded root such as Program
    Files cannot push a ghidra_* directory past the first 64 directories.
    """
    try:
        if root.is_symlink() or not root.is_dir():
            return ()
        with os.scandir(root) as entries:
            return tuple(
                Path(entry.path) for entry in islice(
                    (entry for entry in entries if entry.name.casefold().startswith(prefix)
                     and entry.is_dir(follow_symlinks=False)),
                    MAX_CHILDREN_PER_ROOT
                )
            )
    except (OSError, RuntimeError):
        return ()


def _bindiff_candidates(env: Mapping[str, str], system_paths: Sequence[Path] | None) -> set[Path]:
    """Fixed install locations plus one bounded `bindiff*` level under PatchTrace runtime dirs; regular,
    non-symlink files only (so a probable `/usr/bin/bindiff` symlink is intentionally not discovered)."""
    found: set[Path] = set()

    def add(candidate: Path) -> None:
        if (resolved := _safe_file(candidate)) is not None:
            found.add(resolved)

    if env.get('PATCHTRACE_BINDIFF'):
        add(Path(env['PATCHTRACE_BINDIFF']))
    if system_paths is None:
        system_paths = []
        if env.get('PROGRAMFILES'):
            system_paths.append(Path(env['PROGRAMFILES']) / 'BinDiff' / 'bin' / 'bindiff.exe')
        if os.name != 'nt':
            system_paths.append(Path('/opt/bindiff/bin/bindiff'))
    for path in system_paths:
        add(Path(path))
    runtime_roots = []
    if env.get('LOCALAPPDATA'):
        runtime_roots.append((Path(env['LOCALAPPDATA']) / 'PatchTrace' / 'runtimes', 'bindiff.exe'))
    if env.get('HOME'):
        runtime_roots.append((Path(env['HOME']) / '.local' / 'share' / 'patchtrace' / 'runtimes', 'bindiff'))
    for root, name in runtime_roots:
        for child in _children(root, 'bindiff'):
            add(child / 'bin' / name)
    return found


def discover_local_runtimes(
    environ: Mapping[str, str] | None = None,
    search_roots: Sequence[Path] = (),
    bindiff_system_paths: Sequence[Path] | None = None,
) -> RuntimeCandidates:
    """Find existing tools without execution, downloads or disk mutation.

    Environment and roots are injectable for tests and portable deployments.
    A discovered candidate is *not* a verified runtime; diagnosis is required.
    """
    env = os.environ if environ is None else environ
    pythons: set[Path] = set()
    ghidras: set[Path] = set()

    def add_python(candidate: Path) -> None:
        found = _safe_file(candidate)
        if found is not None:
            pythons.add(found)

    def add_ghidra(candidate: Path) -> None:
        found = _safe_ghidra(candidate)
        if found is not None:
            ghidras.add(found)

    explicit_python = env.get('PATCHTRACE_BACKEND_PYTHON')
    if explicit_python:
        add_python(Path(explicit_python))
    explicit_ghidra = env.get('GHIDRA_INSTALL_DIR')
    if explicit_ghidra:
        add_ghidra(Path(explicit_ghidra))

    local = Path(env['LOCALAPPDATA']) if env.get('LOCALAPPDATA') else None
    if local is not None:
        add_python(local / 'PatchTrace-backend' / 'Scripts' / 'python.exe')
        runtimes = local / 'PatchTrace' / 'runtimes'
        for child in _children(runtimes):
            for relative in ('Scripts/python.exe', 'backend/Scripts/python.exe',
                             'python/Scripts/python.exe', 'payload/python/python.exe'):
                add_python(child / relative)
            add_ghidra(child)
            add_ghidra(child / 'payload' / 'ghidra')
            for subdir in _children(child, 'ghidra_'):
                add_ghidra(subdir)

    roots = list(Path(root) for root in search_roots)
    if env.get('USERPROFILE'):
        roots.append(Path(env['USERPROFILE']) / 'Downloads')
    if env.get('PROGRAMFILES'):
        roots.append(Path(env['PROGRAMFILES']))
    if os.name == 'nt' and env.get('SYSTEMDRIVE'):
        roots.append(Path(env['SYSTEMDRIVE'] + os.sep) / 'Tools')

    for root in roots:
        add_ghidra(root)
        for child in _children(root, 'ghidra_'):
            add_ghidra(child)

    # A Windows filesystem may match two aliases with different case.
    return RuntimeCandidates(
        python_executables=tuple(sorted(pythons, key=lambda p: os.path.normcase(str(p)))),
        ghidra_roots=tuple(sorted(ghidras, key=lambda p: os.path.normcase(str(p)))),
        bindiff_executables=tuple(sorted(_bindiff_candidates(env, bindiff_system_paths),
                                         key=lambda p: os.path.normcase(str(p)))),
    )
