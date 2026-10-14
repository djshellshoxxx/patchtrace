"""Zero-download backend bundle: locate and verify ``<exe dir>/backend`` (BUNDLE plan 7.5).

Pure module: no Qt, no subprocess, no network, never executes anything it finds.
The bundle layout is the SPEC-06 runtime: ``backend/manifest.json`` plus
``backend/payload/<files from manifest>``. A self-consistent manifest proves
integrity (corruption, extra or missing files), NOT publisher authenticity.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .offline_bundle import (
    PLATFORM_LAYOUT,
    BundleFile,
    OfflineBundleError,
    _is_link_or_junction,
    _json_no_duplicates,
    validate_manifest,
)

BUNDLE_DIR_ENV = 'PATCHTRACE_BUNDLE_DIR'
CHUNK = 1024 * 1024
# A loader reads a local file, not a ZIP member, so it tolerates the ~40k-file
# inventories of a real bundle (the importer's 4 MiB cap is too small for them).
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PROBLEMS = 50
CACHE_FORMAT = 'patchtrace-bundle-verified/1'

CODES = ('PT-BUNDLE-MISSING', 'PT-BUNDLE-MANIFEST', 'PT-BUNDLE-PLATFORM', 'PT-BUNDLE-SIZE',
         'PT-BUNDLE-EXTRA', 'PT-BUNDLE-HASH', 'PT-BUNDLE-LINK', 'PT-BUNDLE-WORKDIR',
         'PT-BUNDLE-PIN-MISMATCH', 'PT-BUNDLE-LICENSE', 'PT-BUNDLE-SIZE-LIMIT',
         'PT-BUNDLE-PATH-LENGTH')


class BundleError(ValueError):
    """Predictable, actionable PT-BUNDLE failure; ``code`` is one of CODES."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f'{code}: {message}')
        self.code = code


class BundleCancelled(BundleError):
    """Cooperative cancellation of a verification (nothing is modified either way)."""

    def __init__(self) -> None:
        super().__init__('PT-CANCEL', 'bundle verification cancelled')


@dataclass(frozen=True)
class BundleRef:
    root: Path
    manifest_path: Path
    runtime_id: str
    python: Path
    ghidra: Path
    java_home: Path
    platform: str
    manifest_sha256: str


@dataclass(frozen=True)
class BundleProblem:
    code: str
    path: str = ''

    def __str__(self) -> str:
        return f'{self.code}: {self.path}' if self.path else self.code


@dataclass(frozen=True)
class BundleReport:
    ok: bool
    checked: int
    bytes: int
    problems: tuple[BundleProblem, ...]
    truncated: bool = False


def host_platform() -> str:
    return 'windows' if os.name == 'nt' else 'linux'


def _is_link(path: Path) -> bool:
    return _is_link_or_junction(path)


def _load_manifest(manifest_path: Path, host: str) -> tuple[Mapping[str, object], str, tuple[BundleFile, ...]]:
    """Read, hash and strictly validate the manifest for this host; raise BundleError."""
    if _is_link(manifest_path):
        raise BundleError('PT-BUNDLE-LINK', 'manifest.json is a link')
    try:
        if not manifest_path.is_file():
            raise BundleError('PT-BUNDLE-MISSING', 'backend/manifest.json is missing')
        with manifest_path.open('rb') as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise BundleError('PT-BUNDLE-MISSING', f'cannot read backend/manifest.json ({type(exc).__name__})') from None
    if len(raw) > MAX_MANIFEST_BYTES:
        raise BundleError('PT-BUNDLE-MANIFEST', 'manifest exceeds size limit')
    try:
        data = _json_no_duplicates(raw)
        declared = data.get('platform')
        if declared in PLATFORM_LAYOUT and declared != host:
            raise BundleError('PT-BUNDLE-PLATFORM', f'bundle is for {declared}, this host is {host}')
        if declared not in PLATFORM_LAYOUT:
            raise BundleError('PT-BUNDLE-PLATFORM', 'unknown bundle platform')
        _, files = validate_manifest(data, platforms=(host,))
    except OfflineBundleError as exc:
        raise BundleError('PT-BUNDLE-MANIFEST', str(exc).removeprefix('PT-OFFLINE: ')) from None
    return data, hashlib.sha256(raw).hexdigest(), files


def _default_exe_dir(environ: Mapping[str, str]) -> Path | None:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    value = environ.get(BUNDLE_DIR_ENV, '')
    return Path(value) if value else None


def find_bundled_runtime(exe_dir: Path | None = None, environ: Mapping[str, str] | None = None,
                         *, host: str | None = None) -> BundleRef | None:
    """Return the bundle next to the executable, or None when there is no ``backend`` directory.

    Checks exactly ``<exe_dir>/backend/manifest.json`` (no recursion), refuses a symlinked or
    junctioned ``backend`` and manifest, and executes nothing. A ``backend`` directory that is
    present but unusable raises BundleError so callers can say "extract the complete ZIP again".
    """
    host = host or host_platform()
    if exe_dir is None:
        exe_dir = _default_exe_dir(os.environ if environ is None else environ)
    if exe_dir is None:
        return None
    root = Path(exe_dir) / 'backend'
    if _is_link(root):
        raise BundleError('PT-BUNDLE-LINK', 'backend directory is a link')
    if not root.is_dir():
        return None
    manifest_path = root / 'manifest.json'
    data, digest, _ = _load_manifest(manifest_path, host)
    payload = root / 'payload'
    return BundleRef(
        root=root, manifest_path=manifest_path, runtime_id=str(data['runtime_id']),
        python=payload.joinpath(*str(data['python']).split('/')),
        ghidra=payload / str(data['ghidra']), java_home=payload / str(data['java']),
        platform=host, manifest_sha256=digest)


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise BundleCancelled()


class _Problems:
    def __init__(self) -> None:
        self.items: list[BundleProblem] = []
        self.truncated = False

    def add(self, code: str, path: str = '') -> None:
        if len(self.items) < MAX_PROBLEMS:
            self.items.append(BundleProblem(code, path))
        else:
            self.truncated = True


def _fast_walk(ref: BundleRef, expected: dict[str, BundleFile], problems: _Problems,
               cancel: threading.Event | None) -> tuple[set[str], int]:
    """Bounded iterative os.scandir walk; returns (present expected paths, bytes seen)."""
    seen: set[str] = set()
    total = 0
    try:
        top = list(os.scandir(ref.root))
    except OSError:
        problems.add('PT-BUNDLE-MISSING', 'backend')
        return seen, total
    stack: list[tuple[str, os.DirEntry[str]]] = []
    for entry in top:
        if entry.name == 'manifest.json' and entry.is_file(follow_symlinks=False):
            continue
        if entry.name == 'payload':
            if entry.is_symlink() or _is_link(Path(entry.path)):
                problems.add('PT-BUNDLE-LINK', 'payload')
            elif entry.is_dir(follow_symlinks=False):
                stack.append(('', entry))
            else:
                problems.add('PT-BUNDLE-EXTRA', 'payload')
            continue
        problems.add('PT-BUNDLE-EXTRA', entry.name)
    count = 0
    while stack:
        prefix, directory = stack.pop()
        try:
            children = list(os.scandir(directory.path))
        except OSError:
            problems.add('PT-BUNDLE-MISSING', prefix.rstrip('/') or 'payload')
            continue
        for entry in children:
            count += 1
            if count % 2048 == 0:
                _check_cancel(cancel)
            relative = prefix + entry.name
            if entry.is_symlink():
                problems.add('PT-BUNDLE-LINK', relative)
            elif entry.is_dir(follow_symlinks=False):
                if os.name == 'nt' and _is_link(Path(entry.path)):
                    problems.add('PT-BUNDLE-LINK', relative)
                else:
                    stack.append((relative + '/', entry))
            elif entry.is_file(follow_symlinks=False):
                record = expected.get(relative)
                if record is None:
                    problems.add('PT-BUNDLE-EXTRA', relative)
                    continue
                seen.add(relative)
                size = entry.stat(follow_symlinks=False).st_size
                total += size
                if size != record.size:
                    problems.add('PT-BUNDLE-SIZE', relative)
            else:
                problems.add('PT-BUNDLE-EXTRA', relative)
    return seen, total


def _open_nofollow(path: Path):
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    return os.fdopen(os.open(path, flags), 'rb')


def _hash_files(ref: BundleRef, files: tuple[BundleFile, ...], problems: _Problems,
                cancel: threading.Event | None, event: Callable[[str], None] | None) -> None:
    payload = ref.root / 'payload'
    total = sum(item.size for item in files) or 1
    done = 0
    last = -1
    for item in files:
        hasher = hashlib.sha256()
        try:
            with _open_nofollow(payload.joinpath(*item.path.split('/'))) as stream:
                while chunk := stream.read(CHUNK):
                    _check_cancel(cancel)
                    hasher.update(chunk)
                    done += len(chunk)
                    percent = min(100, done * 100 // total)
                    if event is not None and percent != last:
                        last = percent
                        event(f'Verifying {len(files):,} files... {percent}%')
        except OSError:
            problems.add('PT-BUNDLE-MISSING', item.path)
            continue
        _check_cancel(cancel)
        if hasher.hexdigest() != item.sha256:
            problems.add('PT-BUNDLE-HASH', item.path)


def verify_bundle(ref: BundleRef, *, mode: str = 'fast', cancel: threading.Event | None = None,
                  event: Callable[[str], None] | None = None,
                  work_dir: Path | None = None) -> BundleReport:
    """Verify the on-disk bundle against its manifest; never raises except BundleCancelled.

    ``fast``: scandir walk, path set must equal ``files[]`` exactly and sizes must match.
    ``full``: fast plus streamed SHA-256 of every file. A passing full check with ``work_dir``
    records a nonsecret per-user marker (see ``is_full_verified``); fast always re-checks.
    """
    if mode not in ('fast', 'full'):
        raise ValueError("mode must be 'fast' or 'full'")
    _check_cancel(cancel)
    problems = _Problems()
    try:
        _, digest, files = _load_manifest(ref.manifest_path, ref.platform)
    except BundleError as exc:
        return BundleReport(False, 0, 0, (BundleProblem(exc.code, 'manifest.json'),))
    if digest != ref.manifest_sha256:
        return BundleReport(False, 0, 0, (BundleProblem('PT-BUNDLE-MANIFEST', 'manifest.json changed'),))
    expected = {item.path: item for item in files}
    seen, seen_bytes = _fast_walk(ref, expected, problems, cancel)
    for item in files:
        if item.path not in seen:
            problems.add('PT-BUNDLE-MISSING', item.path)
    if mode == 'full' and not problems.items:
        _hash_files(ref, files, problems, cancel, event)
    ok = not problems.items
    report = BundleReport(ok, len(seen), seen_bytes, tuple(problems.items), problems.truncated)
    if ok and mode == 'full' and work_dir is not None:
        _write_marker(ref, report, Path(work_dir))
    return report


def _marker_path(ref: BundleRef, work_dir: Path) -> Path:
    return Path(work_dir) / f'bundle-verified-{ref.manifest_sha256}.json'


def check_work_dir(ref: BundleRef, work_dir: Path) -> Path:
    """Return the resolved work dir; PT-BUNDLE-WORKDIR when it lies inside the install tree."""
    work = Path(work_dir).resolve()
    root = ref.root.resolve()
    if work == root or work.is_relative_to(root):
        raise BundleError('PT-BUNDLE-WORKDIR', 'the work directory must be outside the backend directory')
    return work


def _write_marker(ref: BundleRef, report: BundleReport, work_dir: Path) -> None:
    try:
        work = check_work_dir(ref, work_dir)
        work.mkdir(parents=True, exist_ok=True)
        body = json.dumps({'format': CACHE_FORMAT, 'manifest_sha256': ref.manifest_sha256,
                           'files': report.checked, 'bytes': report.bytes,
                           'verified_at': int(time.time())}, sort_keys=True)
        fd, temporary = tempfile.mkstemp(prefix='.bundle-verified-', dir=work)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(body)
        os.replace(temporary, _marker_path(ref, work))
    except (OSError, BundleError):
        pass  # the marker is advisory; failing to write it never fails verification


def is_full_verified(ref: BundleRef, work_dir: Path) -> bool:
    """True when a marker for exactly this manifest hash exists; never raises."""
    try:
        data = json.loads(_marker_path(ref, work_dir).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    return (isinstance(data, dict) and data.get('format') == CACHE_FORMAT
            and data.get('manifest_sha256') == ref.manifest_sha256)


def bundle_backend_kwargs(ref: BundleRef, work_dir: Path) -> dict[str, object]:
    """Keyword arguments for ``BackendConfig`` that use the bundled runtime."""
    work = check_work_dir(ref, work_dir)
    return {'python_executable': str(ref.python), 'ghidra_dir': str(ref.ghidra),
            'java_home': str(ref.java_home), 'restrict_env': True, 'bundle': True,
            'cache_dir': str(work / 'cache')}
