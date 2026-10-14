"""Read-only bounded discovery of already-installed analysis runtimes.

Discovery does not execute Python, Ghidra, Java, pip or files from the input
directories. Runtime compatibility is checked separately by backend.diagnose.

Precedence of candidates (BUNDLE plan 7.6): explicit user setting (environment hint) > the
bundle next to the executable > a per-user installed runtime > any other discovered tool.
"""
from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

from .backend_bundle import (
    BundleError,
    BundleProblem,
    BundleRef,
    _default_exe_dir,
    find_bundled_runtime,
    verify_bundle,
)

MAX_CHILDREN_PER_ROOT = 64
EXTRACT_AGAIN = 'extract the complete ZIP again'


@dataclass(frozen=True)
class RuntimeCandidates:
    python_executables: tuple[Path, ...]
    ghidra_roots: tuple[Path, ...]
    # SPEC-29 §8: pre-fill only. Never found via PATH, never executed here; the BinDiff probe decides.
    bindiff_executables: tuple[Path, ...] = ()
    # BUNDLE B7: ``<exe dir>/backend`` when present (even if unusable, so callers can report why).
    bundle_roots: tuple[Path, ...] = ()


@dataclass(frozen=True)
class BundleStatus:
    """Result of the fast check of the bundle next to the executable (no process is started)."""
    ref: BundleRef | None
    problems: tuple[BundleProblem, ...] = ()
    files: int = 0
    bytes: int = 0
    runtime_id: str = ''

    @property
    def ok(self) -> bool:
        return not self.problems

    @property
    def code(self) -> str:
        return self.problems[0].code if self.problems else ''

    def line(self) -> str:
        """The diagnose line: ``Bundled runtime <id>: fast check ok`` or the first PT-BUNDLE problem."""
        if self.ok:
            return f'Bundled runtime {self.runtime_id}: fast check ok'
        return f'{self.problems[0]} - {EXTRACT_AGAIN}'


def bundle_work_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Per-user writable work directory for the bundled runtime (never inside the install dir)."""
    env = os.environ if environ is None else environ
    if os.name == 'nt':
        base = Path(env['LOCALAPPDATA']) if env.get('LOCALAPPDATA') else Path.home() / 'AppData' / 'Local'
        return base / 'PatchTrace' / 'work'
    state = env.get('XDG_STATE_HOME')
    base = Path(state) if state and Path(state).is_absolute() else Path(env.get('HOME') or Path.home()) / '.local' / 'state'
    return base / 'patchtrace' / 'work'


def check_bundle(exe_dir: Path | None = None, environ: Mapping[str, str] | None = None, *,
                 cancel=None, host: str | None = None) -> BundleStatus | None:
    """Fast-check the bundle next to the executable; None when there is no ``backend`` directory.

    Blocking filesystem walk: call from a worker thread in the desktop. BundleCancelled propagates.
    """
    env = os.environ if environ is None else environ
    try:
        ref = find_bundled_runtime(exe_dir, env, host=host)
    except BundleError as exc:
        return BundleStatus(None, (BundleProblem(exc.code, str(exc).partition(': ')[2] or 'backend'),))
    if ref is None:
        return None
    report = verify_bundle(ref, mode='fast', cancel=cancel)
    return BundleStatus(ref, report.problems, report.checked, report.bytes, ref.runtime_id)


def _same_path(left: str, right: Path) -> bool:
    try:
        return os.path.normcase(str(Path(left).resolve())) == os.path.normcase(str(right.resolve()))
    except (OSError, RuntimeError):
        return False


def bundle_config(config, environ: Mapping[str, str] | None = None, work_dir: Path | None = None):
    """``config`` (a BackendConfig) switched to the isolated bundle mode when it points at the bundle.

    Applies when every runtime path of ``config`` is empty (first launch) or already equals the
    bundle's own path (Setup pre-fills them). A different explicit path always wins and the config is
    returned untouched. The profile's raw-cache opt-in (``cache_dir``) is preserved. Reads the manifest
    only; the fast file check runs where the analysis starts (``require_bundle_ok``, in a worker).
    """
    import dataclasses

    from .backend_bundle import bundle_backend_kwargs
    try:
        ref = find_bundled_runtime(None, os.environ if environ is None else environ)
        if ref is None:
            return config
        mine = (ref.python, ref.ghidra, ref.java_home)
        given = (config.python_executable, config.ghidra_dir, config.java_home)
        if not all(not g or _same_path(g, m) for g, m in zip(given, mine, strict=True)):
            return config
        kwargs = bundle_backend_kwargs(ref, work_dir or bundle_work_dir(environ))
    except BundleError:
        return config
    kwargs.pop('cache_dir', None)
    return dataclasses.replace(config, **kwargs)


def exclude_bundle(found: RuntimeCandidates) -> RuntimeCandidates:
    """``found`` without candidates inside a bundle root (an unusable bundle must not be offered)."""
    import dataclasses
    roots = [os.path.normcase(str(root.resolve())) for root in found.bundle_roots]

    def outside(path: Path) -> bool:
        text = os.path.normcase(str(path))
        return not any(text == root or text.startswith(root + os.sep) for root in roots)

    return dataclasses.replace(found, python_executables=tuple(filter(outside, found.python_executables)),
                               ghidra_roots=tuple(filter(outside, found.ghidra_roots)))


def require_bundle_ok(config, cancel=None) -> None:
    """Raise ValueError with the PT-BUNDLE line when a bundle config fails the fast check (worker thread)."""
    if not getattr(config, 'bundle', False):
        return
    status = check_bundle(Path(config.ghidra_dir).resolve().parents[2], cancel=cancel)
    if status is None or not status.ok:
        raise ValueError(status.line() if status else f'PT-BUNDLE-MISSING: no bundled runtime - {EXTRACT_AGAIN}')


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


def _bundle_root(env: Mapping[str, str], exe_dir: Path | None) -> Path | None:
    base = Path(exe_dir) if exe_dir is not None else _default_exe_dir(env)
    if base is None:
        return None
    root = base / 'backend'
    return root if os.path.lexists(root) else None


def _ordered(*tiers) -> tuple[Path, ...]:
    """Concatenate precedence tiers (each sorted internally), dropping repeats of a higher tier."""
    seen: set[str] = set()
    result: list[Path] = []
    for tier in tiers:
        for path in sorted(tier, key=lambda p: os.path.normcase(str(p))):
            key = os.path.normcase(str(path))
            if key not in seen:
                seen.add(key)
                result.append(path)
    return tuple(result)


def discover_local_runtimes(
    environ: Mapping[str, str] | None = None,
    search_roots: Sequence[Path] = (),
    bindiff_system_paths: Sequence[Path] | None = None,
    bundle_exe_dir: Path | None = None,
) -> RuntimeCandidates:
    """Find existing tools without execution, downloads or disk mutation.

    Environment and roots are injectable for tests and portable deployments.
    A discovered candidate is *not* a verified runtime; diagnosis is required.
    Candidate order is the documented precedence: explicit hint, bundle, per-user, other.
    """
    env = os.environ if environ is None else environ
    tiers: dict[str, dict[str, set[Path]]] = {
        kind: {tier: set() for tier in ('explicit', 'bundle', 'user', 'other')} for kind in ('python', 'ghidra')}

    def add_python(candidate: Path, tier: str = 'other') -> None:
        found = _safe_file(candidate)
        if found is not None:
            tiers['python'][tier].add(found)

    def add_ghidra(candidate: Path, tier: str = 'other') -> None:
        found = _safe_ghidra(candidate)
        if found is not None:
            tiers['ghidra'][tier].add(found)

    explicit_python = env.get('PATCHTRACE_BACKEND_PYTHON')
    if explicit_python:
        add_python(Path(explicit_python), 'explicit')
    explicit_ghidra = env.get('GHIDRA_INSTALL_DIR')
    if explicit_ghidra:
        add_ghidra(Path(explicit_ghidra), 'explicit')

    bundle_roots: tuple[Path, ...] = ()
    if (bundle_root := _bundle_root(env, bundle_exe_dir)) is not None:
        bundle_roots = (bundle_root,)
        try:
            ref = find_bundled_runtime(bundle_root.parent, env)
        except BundleError:
            ref = None  # the Setup dialog reports the PT-BUNDLE code from bundle_roots
        if ref is not None:
            add_python(ref.python, 'bundle')
            add_ghidra(ref.ghidra, 'bundle')

    local = Path(env['LOCALAPPDATA']) if env.get('LOCALAPPDATA') else None
    if local is not None:
        add_python(local / 'PatchTrace-backend' / 'Scripts' / 'python.exe', 'user')
        runtimes = local / 'PatchTrace' / 'runtimes'
        for child in _children(runtimes):
            for relative in ('Scripts/python.exe', 'backend/Scripts/python.exe',
                             'python/Scripts/python.exe', 'payload/python/python.exe'):
                add_python(child / relative, 'user')
            add_ghidra(child, 'user')
            add_ghidra(child / 'payload' / 'ghidra', 'user')
            for subdir in _children(child, 'ghidra_'):
                add_ghidra(subdir, 'user')
    if env.get('HOME') and os.name != 'nt':
        for child in _children(Path(env['HOME']) / '.local' / 'share' / 'patchtrace' / 'runtimes'):
            add_python(child / 'payload' / 'python' / 'bin' / 'python3', 'user')
            add_ghidra(child / 'payload' / 'ghidra', 'user')

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
    order = ('explicit', 'bundle', 'user', 'other')
    return RuntimeCandidates(
        python_executables=_ordered(*(tiers['python'][t] for t in order)),
        ghidra_roots=_ordered(*(tiers['ghidra'][t] for t in order)),
        bindiff_executables=tuple(sorted(_bindiff_candidates(env, bindiff_system_paths),
                                         key=lambda p: os.path.normcase(str(p)))),
        bundle_roots=bundle_roots,
    )
