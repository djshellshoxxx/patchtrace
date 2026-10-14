"""Zero-download backend bundle builder (BUNDLE plan, slices B2 `check` and B4 `build`).

`check` is a read-only inventory dry-run of an already extracted Ghidra, JDK or Python tree against the
SPEC-06 path policy (`patchtrace.offline_bundle`).

`build` assembles the complete private runtime for one platform from `tools/backend_pin.json`:
fetch and verify every component (downloads happen only here, never in the app), assemble
`backend/payload/{python,ghidra,jdk,LICENSES,SOURCES}`, install hash-locked wheels with
`pip install --target` (wheels only, no index), build the Ghidriff wheel from the exact source tarball and
byte-compare it, build the mdutils sdist into a wheel, apply the pinned strip rules, precompile, write
notices and THIRD-PARTY.json, check path/mode/size gates, package the SPEC-06 importer archive through
`build_offline_bundle` and split it under the release asset limit when asked. It never executes a target
binary: the only subprocesses are the builder's own `python -m pip` calls with `--no-index`.
"""
from __future__ import annotations

import argparse
import compileall
import datetime
import hashlib
import importlib.util
import json
import os
import posixpath
import py_compile
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, model_validator

from patchtrace import offline_bundle as policy

# BUNDLE plan section 6: longest relative path under backend/ must stay <= 150.
MAX_RELATIVE_PATH = 150
PAYLOAD_PREFIX = 'payload'
EXIT_OK, EXIT_OFFENDERS, EXIT_USAGE, EXIT_BUILD = 0, 1, 2, 3


@dataclass(frozen=True)
class Offender:
    path: str
    reason: str


def _part_reasons(part: str) -> list[str]:
    reasons = []
    if part in ('', '.', '..'):
        reasons.append('empty-or-dot-component')
    if part.endswith(' ') or part.endswith('.'):
        reasons.append('trailing-space-or-dot')
    if ':' in part or any(char in part for char in '<>"|?*'):
        reasons.append('windows-forbidden-character')
    if any(ord(char) < 32 or ord(char) == 127 for char in part):
        reasons.append('control-character')
    if '\\' in part:
        reasons.append('backslash')
    if part.split('.')[0].rstrip(' ').upper() in policy.WINDOWS_RESERVED:
        reasons.append('windows-reserved-device-name')
    return reasons


def path_reasons(relative: str) -> list[str]:
    """Reasons a payload-relative POSIX path violates the SPEC-06 policy (empty: allowed)."""
    try:
        relative.encode('utf-8')
    except UnicodeEncodeError:
        return ['not-valid-utf8']
    reasons = []
    if len(relative) > 512:
        reasons.append('path-over-512')
    for part in relative.split('/'):
        for reason in _part_reasons(part):
            if reason not in reasons:
                reasons.append(reason)
    if not reasons:
        try:
            policy._safe_relative(relative)
        except policy.OfflineBundleError:
            reasons.append('rejected-by-spec06-policy')
    return reasons


@dataclass(frozen=True)
class CheckReport:
    root: str
    prefix: str
    files: int
    directories: int
    total_bytes: int
    longest_path: int
    offenders: tuple[Offender, ...]

    @property
    def clean(self) -> bool:
        return not self.offenders

    def to_json(self) -> dict:
        return {
            'schema': 'patchtrace-bundle-check/1', 'root': self.root, 'prefix': self.prefix,
            'files': self.files, 'directories': self.directories, 'total_bytes': self.total_bytes,
            'longest_path': self.longest_path, 'clean': self.clean,
            'offenders': [{'path': item.path, 'reason': item.reason} for item in self.offenders],
        }


def check_tree(root: Path, *, prefix: str = '') -> CheckReport:
    """Inventory `root` as it would sit at `<prefix>/` inside backend/payload (lstat only)."""
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise NotADirectoryError(f'not a real directory: {root}')
    prefix = prefix.strip('/')
    offenders: list[Offender] = []
    seen: dict[str, str] = {}
    counts = {'files': 0, 'directories': 0, 'bytes': 0, 'longest': 0}
    base = len(PAYLOAD_PREFIX) + 1 + (len(prefix) + 1 if prefix else 0)

    def visit(relative: str, *, directory: bool, mode: int, size: int) -> None:
        shown = f'{prefix}/{relative}' if prefix else relative
        if directory:
            counts['directories'] += 1
        else:
            counts['files'] += 1
            counts['bytes'] += size
        counts['longest'] = max(counts['longest'], len(shown))
        reasons = path_reasons(shown)
        if base + len(relative) > MAX_RELATIVE_PATH:
            reasons.append(f'longer-than-{MAX_RELATIVE_PATH}-under-backend')
        if stat.S_ISLNK(mode):
            reasons.append('symbolic-link')
        elif not directory and not stat.S_ISREG(mode):
            reasons.append('special-file')
        if not directory and size > policy.MAX_FILE:
            reasons.append('file-over-2GiB')
        canonical = unicodedata.normalize('NFC', shown).casefold()
        if canonical in seen and seen[canonical] != shown:
            reasons.append(f'collides-with:{seen[canonical]}')
        seen.setdefault(canonical, shown)
        offenders.extend(Offender(shown, reason) for reason in reasons)

    for current, names, leaves in os.walk(root, followlinks=False):
        names.sort()
        here = Path(current).relative_to(root).as_posix()
        here = '' if here == '.' else here
        for name in list(names):
            info = os.lstat(os.path.join(current, name))
            visit(f'{here}/{name}' if here else name, directory=True, mode=info.st_mode, size=0)
            if stat.S_ISLNK(info.st_mode):
                names.remove(name)
        for name in sorted(leaves):
            info = os.lstat(os.path.join(current, name))
            visit(f'{here}/{name}' if here else name, directory=False, mode=info.st_mode,
                  size=info.st_size)
    if counts['files'] > policy.MAX_MEMBERS:
        offenders.append(Offender('(tree)', f'more-than-{policy.MAX_MEMBERS}-files'))
    if counts['bytes'] > policy.MAX_TOTAL:
        offenders.append(Offender('(tree)', 'total-over-8GiB'))
    return CheckReport(str(root), prefix, counts['files'], counts['directories'], counts['bytes'],
                       counts['longest'], tuple(offenders))


def _run_check(args: argparse.Namespace) -> int:
    try:
        report = check_tree(args.tree, prefix=args.prefix)
    except OSError as error:
        print(f'error: {error}', file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        print(json.dumps(report.to_json(), indent=2, ensure_ascii=True))
    else:
        print(f'{report.root}: {report.files} files, {report.directories} directories, '
              f'{report.total_bytes} bytes, longest path {report.longest_path}')
        for item in report.offenders[:args.limit]:
            print(f'OFFENDER {item.reason}: {item.path!r}')
        if len(report.offenders) > args.limit:
            print(f'... {len(report.offenders) - args.limit} more')
        print('clean' if report.clean else f'{len(report.offenders)} offender(s)')
    return EXIT_OK if report.clean else EXIT_OFFENDERS


# ---------------------------------------------------------------------------------------------------------
# B4: build pipeline
# ---------------------------------------------------------------------------------------------------------
GENERATED_BY = 'build_backend_bundle/1'
THIRD_PARTY_SCHEMA = 'patchtrace-third-party/1'
ASSET_LIMIT = int(1.9 * 1024**3)      # hard release-asset gate (GitHub allows 2 GiB)
SIZE_WARN = int(1.2 * 1000**3)         # plan 7.4: investigate before shipping above ~1.2 GB
MAX_ARCHIVE_MEMBERS = 120_000
CHUNK = 1024 * 1024
PLATFORMS = ('windows', 'linux')
# Only the paths the build needs; anything else is dropped from the pip/compile environment.
_ENV_KEEP = ('PATH', 'SYSTEMROOT', 'SystemRoot', 'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'LANG',
             'LC_ALL', 'COMSPEC', 'PATHEXT', 'SOURCE_DATE_EPOCH')

# Linux file-mode gate (plan section 6): every pattern must match at least one file and every match must
# keep the execute bit that the vendor archive recorded.
LINUX_EXEC_PATTERNS = (
    'ghidra/support/analyzeHeadless', 'ghidra/support/*.sh',
    'ghidra/Ghidra/**/os/linux_x86_64/decompile', 'ghidra/Ghidra/**/os/linux_x86_64/sleigh*',
    'ghidra/Ghidra/**/os/linux_x86_64/demangler_gnu*',
    'jdk/bin/*', 'python/bin/*',
)
# The distribution whose licence file stands in for a wheel that ships none (pyghidra is part of Ghidra).
LICENSE_BORROW = {'pyghidra': 'ghidra'}
_LICENSE_NAME = re.compile(r'^(licen[cs]e|copying|notice)', re.IGNORECASE)
_SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+\-]{0,200}$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


class BundleBuildError(ValueError):
    """A build-time gate failure with a stable PT-BUNDLE-* code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f'{code}: {message}')
        self.code = code


def _fail(code: str, message: str) -> None:
    raise BundleBuildError(code, message)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(CHUNK):
            hasher.update(chunk)
    return hasher.hexdigest()


def _load_sibling(name: str):
    """Import tools/<name>.py without requiring tools/ on sys.path (tools is not a package)."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


Fetcher = Callable[[str, Path, int], None]
Runner = Callable[[Sequence[str], Path], None]
Progress = Callable[[str], None]


# ----- fetch and verify ----------------------------------------------------------------------------------
def download(url: str, destination: Path, max_bytes: int) -> None:
    """The only network access in the builder: HTTPS GET into `destination`, bounded by `max_bytes`."""
    if not url.startswith('https://'):
        _fail('PT-BUNDLE-FETCH', f'refusing non-HTTPS URL {url}')
    request = urllib.request.Request(url, headers={'User-Agent': 'patchtrace-backend-builder/1'})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 (https checked above)
            if not response.geturl().startswith('https://'):
                _fail('PT-BUNDLE-FETCH', f'redirect left HTTPS for {url}')
            total = 0
            with Path(destination).open('wb') as output:
                while chunk := response.read(CHUNK):
                    total += len(chunk)
                    if total > max_bytes:
                        _fail('PT-BUNDLE-PIN-MISMATCH', f'{url} is larger than the pinned size')
                    output.write(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise BundleBuildError('PT-BUNDLE-FETCH', f'cannot download {url}: {error}') from None


def _pin_file_name(entry: Mapping, url: str) -> str:
    name = entry.get('name') or urllib.parse.unquote(url.rsplit('/', 1)[-1])
    if not isinstance(name, str) or not _SAFE_NAME.match(name):
        _fail('PT-BUNDLE-PIN', f'unsafe download file name {name!r}')
    return name


def fetch_verified(entry: Mapping, cache_dir: Path, fetcher: Fetcher, label: str) -> Path:
    """Return a cached, sha256- and size-verified copy of a pinned download (hard failure on mismatch)."""
    url, expected, size = entry['url'], entry['sha256'], entry['size']
    if not _HEX64.match(str(expected)) or not isinstance(size, int) or size <= 0:
        _fail('PT-BUNDLE-PIN', f'{label}: pin entry is not resolved')
    cache_dir.mkdir(parents=True, exist_ok=True)
    destination = cache_dir / f'{expected[:16]}-{_pin_file_name(entry, url)}'
    if destination.is_file() and destination.stat().st_size == size and sha256_file(destination) == expected:
        return destination
    destination.unlink(missing_ok=True)
    part = destination.with_name(destination.name + '.part')
    part.unlink(missing_ok=True)
    fetcher(url, part, size)
    try:
        actual_size, actual = part.stat().st_size, sha256_file(part)
    except OSError:
        _fail('PT-BUNDLE-FETCH', f'{label}: nothing was downloaded from {url}')
    if actual_size != size or actual != expected:
        part.unlink(missing_ok=True)
        _fail('PT-BUNDLE-PIN-MISMATCH',
              f'{label}: downloaded {actual_size} bytes sha256 {actual}, pinned {size} bytes sha256 {expected}')
    os.replace(part, destination)
    return destination


# ----- safe extraction -----------------------------------------------------------------------------------
def _windows_host() -> bool:
    return os.name == 'nt'


def _member_parts(name: str) -> list[str]:
    if (not isinstance(name, str) or not name or name.startswith('/') or '\\' in name
            or re.match(r'^[A-Za-z]:', name) or '\x00' in name):
        _fail('PT-BUNDLE-ARCHIVE', f'unsafe archive member name {name!r}')
    parts = [part for part in name.split('/') if part not in ('', '.')]
    if '..' in parts:
        _fail('PT-BUNDLE-ARCHIVE', f'archive member escapes the destination: {name!r}')
    return parts


class _Extractor:
    """Single-pass, link-free extraction into `dest`; records the normalized file modes."""

    def __init__(self, dest: Path, strip_top: bool) -> None:
        self.dest, self.strip_top = dest, strip_top
        self.top: str | None = None
        self.modes: dict[str, int] = {}
        self.links: list[tuple[str, str]] = []
        self.count = 0
        self.folded: dict[str, str] = {}
        dest.mkdir(parents=True, exist_ok=True)

    def _guard_host_fs(self, relative: str) -> None:
        """On a Windows host NTFS mangles hostile names ('x.' -> 'x', 'a:b' -> stream, case-insensitive
        collisions overwrite) the moment they are written, so refuse them before touching the disk. On other
        hosts the same names are caught later by `check_tree`."""
        if not _windows_host():
            return
        reasons = path_reasons(relative)
        canonical = unicodedata.normalize('NFC', relative).casefold()
        previous = self.folded.setdefault(canonical, relative)
        if previous != relative:
            reasons.append(f'collides-with:{previous}')
        if reasons:
            _fail('PT-BUNDLE-PATH', f'archive member {relative!r} is not safe on a Windows file system: {reasons[0]}')

    def relative(self, name: str) -> str | None:
        """Destination-relative POSIX path for an archive member (None: the top directory itself)."""
        parts = _member_parts(name)
        if self.strip_top:
            if not parts:
                return None
            if self.top is None:
                self.top = parts[0]
            elif parts[0] != self.top:
                _fail('PT-BUNDLE-ARCHIVE', f'archive has more than one top-level entry ({parts[0]!r})')
            parts = parts[1:]
        return '/'.join(parts) if parts else None

    def _count(self) -> None:
        self.count += 1
        if self.count > MAX_ARCHIVE_MEMBERS:
            _fail('PT-BUNDLE-ARCHIVE', f'archive has more than {MAX_ARCHIVE_MEMBERS} members')

    def directory(self, relative: str) -> None:
        self._count()
        self._guard_host_fs(relative)
        (self.dest / relative).mkdir(parents=True, exist_ok=True)

    def file(self, relative: str, stream, mode: int) -> None:
        self._count()
        self._guard_host_fs(relative)
        target = self.dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            _fail('PT-BUNDLE-ARCHIVE', f'duplicate archive member {relative!r}')
        written = 0
        with target.open('xb') as output:
            while chunk := stream.read(CHUNK):
                written += len(chunk)
                if written > policy.MAX_FILE:
                    _fail('PT-BUNDLE-SIZE-LIMIT', f'{relative} exceeds the per-file limit')
                output.write(chunk)
        self.modes[relative] = 0o755 if mode & 0o111 else 0o644

    def resolve_links(self) -> None:
        """Replace symlinks/hardlinks by copies of their (in-tree, regular-file) targets."""
        pending = list(self.links)
        for _ in range(8):
            unresolved = []
            for relative, target in pending:
                source = self.dest / target
                if source.is_file() and target in self.modes:
                    destination = self.dest / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
                    self.modes[relative] = self.modes[target]
                else:
                    unresolved.append((relative, target))
            pending = unresolved
            if not pending:
                return
        _fail('PT-BUNDLE-LINK', f'unresolvable or non-file link target(s): {pending[:3]!r}')


def _link_target(relative: str, linkname: str) -> str:
    if linkname.startswith('/') or '\\' in linkname:
        _fail('PT-BUNDLE-LINK', f'absolute or backslash link target {linkname!r} for {relative!r}')
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(relative), linkname))
    if joined.startswith('..') or joined == '.':
        _fail('PT-BUNDLE-LINK', f'link {relative!r} points outside its component ({linkname!r})')
    return joined


def extract_component(archive: Path, dest: Path, *, strip_top: bool) -> dict[str, int]:
    """Extract a .zip or .tar.gz into `dest` (optionally dropping the single top directory).

    Returns {relative path: normalized mode (0o755 or 0o644)}. Symlinks and hardlinks are replaced by
    copies when they resolve to a regular file inside the archive; anything else is refused.
    """
    archive = Path(archive)
    extractor = _Extractor(dest, strip_top)
    try:
        if archive.name.endswith('.zip'):
            _extract_zip(archive, extractor)
        elif archive.name.endswith(('.tar.gz', '.tgz')):
            _extract_tar(archive, extractor)
        else:
            _fail('PT-BUNDLE-ARCHIVE', f'unsupported archive type: {archive.name}')
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as error:
        raise BundleBuildError('PT-BUNDLE-ARCHIVE', f'cannot extract {archive.name}: {error}') from None
    extractor.resolve_links()
    return extractor.modes


def _reject_raw_backslash_names(zf: zipfile.ZipFile) -> None:
    """Refuse backslash member names from the raw central directory.

    `zipfile` rewrites os.sep to '/' while reading (ZipInfo.__init__ -> _sanitize_filename), so on Windows a
    name like 'a\\b' would silently become 'a/b' and pass the name check that Linux hosts apply.
    """
    zf.fp.seek(zf.start_dir)
    directory = zf.fp.read()
    pos = 0
    for _ in range(len(zf.infolist())):
        if directory[pos:pos + 4] != b'PK\x01\x02':
            break
        name_len, extra_len, comment_len = struct.unpack_from('<HHH', directory, pos + 28)
        name = directory[pos + 46:pos + 46 + name_len]
        if b'\\' in name:
            _fail('PT-BUNDLE-ARCHIVE', f'unsafe archive member name {name.decode("utf-8", "replace")!r}')
        pos += 46 + name_len + extra_len + comment_len


def _extract_zip(archive: Path, extractor: _Extractor) -> None:
    with zipfile.ZipFile(archive) as zf:
        _reject_raw_backslash_names(zf)
        for info in zf.infolist():
            relative = extractor.relative(info.filename)
            if relative is None:
                continue
            unix_mode = info.external_attr >> 16
            kind = stat.S_IFMT(unix_mode)
            if kind == stat.S_IFLNK:
                _fail('PT-BUNDLE-LINK', f'symbolic link in ZIP: {info.filename!r}')
            if info.is_dir():
                extractor.directory(relative)
                continue
            if kind not in (0, stat.S_IFREG):
                _fail('PT-BUNDLE-ARCHIVE', f'special file in ZIP: {info.filename!r}')
            with zf.open(info) as stream:
                extractor.file(relative, stream, unix_mode & 0o777)


def _extract_tar(archive: Path, extractor: _Extractor) -> None:
    with tarfile.open(archive, 'r:gz') as tf:
        for member in tf:
            if member.name in ('.', './') and member.isdir():
                continue
            relative = extractor.relative(member.name)
            if relative is None:
                continue
            if member.isdir():
                extractor.directory(relative)
            elif member.isreg():
                stream = tf.extractfile(member)
                extractor.file(relative, stream, member.mode)
            elif member.issym():
                extractor._count()
                extractor.links.append((relative, _link_target(relative, member.linkname)))
            elif member.islnk():
                extractor._count()
                target = extractor.relative(member.linkname)
                if target is None:
                    _fail('PT-BUNDLE-LINK', f'hardlink {member.name!r} points at the top directory')
                extractor.links.append((relative, target))
            else:
                _fail('PT-BUNDLE-ARCHIVE', f'special file in tar: {member.name!r}')


# ----- strip rules ---------------------------------------------------------------------------------------
def glob_regex(pattern: str) -> re.Pattern[str]:
    """`**/` = any directories, `**` = anything, `*` = within one component, `?` = one character."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith('**/', i):
            out.append('(?:[^/]+/)*')
            i += 3
        elif pattern.startswith('**', i):
            out.append('.*')
            i += 2
        elif pattern[i] == '*':
            out.append('[^/]*')
            i += 1
        elif pattern[i] == '?':
            out.append('[^/]')
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile('^' + ''.join(out) + '$')


def expand_strip_patterns(patterns: Sequence[str], target: str) -> list[re.Pattern[str]]:
    """Expand `{other-OS}` to the native directory prefixes of the platforms we do NOT ship."""
    other = {'windows': ('linux_*', 'mac_*'), 'linux': ('win_*', 'mac_*')}[target]
    compiled = []
    for pattern in patterns:
        if '{other-OS}' in pattern:
            compiled.extend(glob_regex(pattern.replace('{other-OS}', item)) for item in other)
        else:
            compiled.append(glob_regex(pattern))
    return compiled


def _tree_files(root: Path) -> list[str]:
    found = []
    for current, _dirs, names in os.walk(root, followlinks=False):
        base = Path(current).relative_to(root).as_posix()
        found.extend(f'{base}/{name}' if base != '.' else name for name in names)
    return sorted(found)


def strip_tree(root: Path, strip: Sequence[str], keep: Sequence[str], target: str) -> tuple[list[str], int]:
    """Remove files matching the pinned strip globs, then prune empty directories.

    The `keep` globs are a regression gate, not an override: any keep pattern that matched a file before
    stripping must still match one afterwards (PT-BUNDLE-STRIP), so a bad strip rule cannot remove the
    licences, GPL sources, processors or javac.
    """
    files = _tree_files(root)
    keepers = [glob_regex(pattern) for pattern in keep]
    before = [any(rx.match(name) for name in files) for rx in keepers]
    rules = expand_strip_patterns(strip, target)
    removed, freed = [], 0
    for name in files:
        if any(rx.match(name) for rx in rules):
            path = root / name
            freed += path.stat().st_size
            path.unlink()
            removed.append(name)
    for current, _dirs, _names in os.walk(root, topdown=False):
        if Path(current) != root and not any(Path(current).iterdir()):
            Path(current).rmdir()
    remaining = _tree_files(root)
    for rx, had, pattern in zip(keepers, before, keep, strict=True):
        if had and not any(rx.match(name) for name in remaining):
            _fail('PT-BUNDLE-STRIP', f'strip rules removed everything matching keep pattern {pattern!r}')
    return removed, freed


# ----- subprocess runner and pip -------------------------------------------------------------------------
def run_tool(argv: Sequence[str], cwd: Path) -> None:
    """Run a builder tool (python -m pip ...) with a scrubbed environment; no proxy or index variables."""
    env = {key: value for key, value in os.environ.items() if key in _ENV_KEEP}
    env.update(PIP_CONFIG_FILE=os.devnull, PIP_NO_INPUT='1', PIP_DISABLE_PIP_VERSION_CHECK='1',
               PIP_NO_INDEX='1', PYTHONDONTWRITEBYTECODE='1')
    env.setdefault('SOURCE_DATE_EPOCH', '315532800')
    try:
        result = subprocess.run(list(argv), cwd=cwd, env=env, capture_output=True, text=True,
                                timeout=1800, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BundleBuildError('PT-BUNDLE-TOOL', f'{argv[0]} failed to run: {error}') from None
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or '').strip()[-1500:]
        _fail('PT-BUNDLE-TOOL', f'{" ".join(argv[:5])} exited {result.returncode}: {tail}')


def _normalize_dist(name: str) -> str:
    return re.sub(r'[-_.]+', '_', name).lower()


@dataclass(frozen=True)
class WheelRequirement:
    distribution: str
    version: str
    file: str
    sha256: str


def pip_platform_args(target: str, py_version: str) -> list[str]:
    major, minor = py_version.split('.')[:2]
    platform_args = (['--platform', 'win_amd64'] if target == 'windows'
                     else ['--platform', 'manylinux_2_17_x86_64', '--platform', 'manylinux2014_x86_64'])
    return [*platform_args, '--python-version', f'{major}.{minor}', '--implementation', 'cp',
            '--abi', f'cp{major}{minor}']


def pip_install_argv(python: str, requirements: Path, wheelhouse: Path, site: Path, target: str,
                     py_version: str) -> list[str]:
    """Hash-locked, wheels-only, index-free, dependency-free install into a target directory."""
    return [python, '-I', '-m', 'pip', 'install', '--no-index', '--find-links', str(wheelhouse),
            '--no-deps', '--only-binary=:all:', '--require-hashes', '--no-compile', '--target', str(site),
            *pip_platform_args(target, py_version), '-r', str(requirements)]


def write_requirements(path: Path, requirements: Sequence[WheelRequirement]) -> None:
    lines = [f'{item.distribution}=={item.version} --hash=sha256:{item.sha256}' for item in requirements]
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')


def install_wheels(requirements: Sequence[WheelRequirement], wheelhouse: Path, site: Path, target: str,
                   py_version: str, runner: Runner, python: str, work: Path) -> None:
    for item in requirements:
        wheel = wheelhouse / item.file
        if not wheel.is_file() or sha256_file(wheel) != item.sha256:
            _fail('PT-BUNDLE-PIN-MISMATCH', f'wheelhouse file {item.file} does not match its lock hash')
    site.mkdir(parents=True, exist_ok=True)
    requirements_file = work / 'requirements.lock.txt'
    write_requirements(requirements_file, requirements)
    runner(pip_install_argv(python, requirements_file, wheelhouse, site, target, py_version), work)
    present = {entry.name.lower() for entry in site.iterdir()}
    for item in requirements:
        marker = f'{_normalize_dist(item.distribution)}-{item.version}.dist-info'.lower()
        if marker not in present:
            _fail('PT-BUNDLE-TOOL', f'pip did not install {item.distribution} {item.version}')
    for scripts in ('bin', 'Scripts'):  # console-script stubs carry the builder's absolute interpreter path
        shutil.rmtree(site / scripts, ignore_errors=True)


# ----- wheel from source, byte comparison ----------------------------------------------------------------
@dataclass(frozen=True)
class BuiltWheel:
    path: Path
    distribution: str
    version: str
    source_dir: Path
    sha256: str


def _wheel_identity(name: str) -> tuple[str, str]:
    match = re.match(r'^([A-Za-z0-9_.]+)-([A-Za-z0-9_.+!]+)-py3-none-any\.whl$', name)
    if not match:
        _fail('PT-BUNDLE-WHEEL-MISMATCH', f'built wheel {name!r} is not a py3-none-any wheel')
    return match.group(1), match.group(2)


def compare_wheel_to_source(wheel: Path, source_root: Path, package: str) -> int:
    """Every non-metadata wheel file must equal the source file byte for byte, and no source `.py` of the
    package may be missing from the wheel. Returns the number of compared files."""
    root = source_root / package
    parent = source_root
    if not root.is_dir():
        root, parent = source_root / 'src' / package, source_root / 'src'
    if not root.is_dir():
        _fail('PT-BUNDLE-WHEEL-MISMATCH', f'source tree has no {package}/ package')
    compared, in_wheel = 0, set()
    with zipfile.ZipFile(wheel) as zf:
        for info in zf.infolist():
            name = info.filename
            if info.is_dir() or name.split('/')[0].endswith(('.dist-info', '.data')):
                continue
            original = parent / name
            in_wheel.add(name)
            if not original.is_file() or original.read_bytes() != zf.read(info):
                _fail('PT-BUNDLE-WHEEL-MISMATCH', f'{wheel.name}: {name} differs from the source tarball')
            compared += 1
    for path in root.rglob('*.py'):
        relative = path.relative_to(parent).as_posix()
        if '__pycache__' not in relative and relative not in in_wheel:
            _fail('PT-BUNDLE-WHEEL-MISMATCH', f'{wheel.name}: source file {relative} is not in the wheel')
    if compared == 0:
        _fail('PT-BUNDLE-WHEEL-MISMATCH', f'{wheel.name}: wheel contains no package files')
    return compared


def build_wheel_from_source(tarball: Path, distribution: str, package: str, work: Path,
                            runner: Runner, python: str) -> BuiltWheel:
    """Build a py3-none-any wheel offline from a hash-verified source tarball and byte-compare it."""
    source = work / 'src' / distribution
    extract_component(tarball, source, strip_top=True)
    wheel_dir = work / 'built' / distribution
    wheel_dir.mkdir(parents=True, exist_ok=True)
    runner([python, '-I', '-m', 'pip', 'wheel', '--no-deps', '--no-index', '--no-build-isolation',
            '--wheel-dir', str(wheel_dir), str(source)], work)
    wheels = sorted(wheel_dir.glob('*.whl'))
    if len(wheels) != 1:
        _fail('PT-BUNDLE-TOOL', f'building {distribution} produced {len(wheels)} wheels, expected 1')
    dist, version = _wheel_identity(wheels[0].name)
    compare_wheel_to_source(wheels[0], source, package)
    return BuiltWheel(wheels[0], dist, version, source, sha256_file(wheels[0]))


def require_host_python(py_version: str, host: tuple[int, int] | None = None) -> None:
    """Bytecode is only valid for the interpreter minor version it was compiled with."""
    host = host or (sys.version_info.major, sys.version_info.minor)
    wanted = tuple(int(part) for part in py_version.split('.')[:2])
    if host != wanted:
        _fail('PT-BUNDLE-PYTHON-MISMATCH',
              f'builder runs Python {host[0]}.{host[1]} but the bundle is Python {py_version}: bytecode would '
              'not load. Run the builder with the pinned Python minor version, or pass --no-compile.')


def compile_site_packages(site: Path, py_version: str, host: tuple[int, int] | None = None) -> None:
    """Precompile with unchecked-hash pycs so the read-only tree never needs to write bytecode."""
    require_host_python(py_version, host)
    done = compileall.compile_dir(str(site), quiet=2, force=True, workers=1, stripdir=str(site),
                                  invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    if not done:
        _fail('PT-BUNDLE-TOOL', 'compileall reported a failure')


# ----- licences, notices, THIRD-PARTY.json ---------------------------------------------------------------
class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)


class TpArtifact(_Strict):
    name: str
    sha256: str
    size: int
    url: str


class TpSource(_Strict):
    kind: Literal['in-bundle', 'offer', 'upstream-public']
    path: str | None = None
    url: str | None = None
    sha256: str | None = None

    @model_validator(mode='after')
    def _shape(self) -> TpSource:
        if self.kind == 'in-bundle' and not (self.path and self.sha256):
            raise ValueError('an in-bundle source needs path and sha256')
        if self.kind != 'in-bundle' and not self.url:
            raise ValueError('an offer or upstream source needs a url')
        return self


class TpComponent(_Strict):
    id: str
    name: str
    version: str
    spdx: str = Field(min_length=1)
    role: Literal['runtime', 'analysis-engine', 'library', 'tool']
    upstream_url: str
    artifact: TpArtifact
    license_files: list[str] = Field(min_length=1)
    source: TpSource
    modified: Literal[False] = False
    process_boundary: Literal['separate-process', 'embedded-runtime']

    @model_validator(mode='after')
    def _ghidriff_rules(self) -> TpComponent:
        if self.id == 'ghidriff' and not (
                self.role == 'analysis-engine' and self.source.kind == 'in-bundle'
                and self.process_boundary == 'separate-process'):
            raise ValueError('ghidriff must be an in-bundle analysis-engine in a separate process')
        return self


class ThirdPartyDoc(_Strict):
    model_config = ConfigDict(extra='forbid', frozen=True, populate_by_name=True)
    schema_id: str = Field(alias='schema', default=THIRD_PARTY_SCHEMA)
    generated_by: str = GENERATED_BY
    pin_sha256: str
    built_at: str
    git_commit: str
    components: list[TpComponent] = Field(min_length=1)


def find_tree_licenses(root: Path) -> list[str]:
    """Licence-like files of an extracted component, payload-component-relative POSIX paths."""
    found = []
    for entry in sorted(root.iterdir()):
        if entry.is_file() and _LICENSE_NAME.match(entry.name):
            found.append(entry.name)
        elif entry.is_dir() and entry.name.lower() in ('legal', 'licenses', 'license'):
            found.extend(f'{entry.name}/{name}' for name in _tree_files(entry))
    for stdlib in sorted(root.glob('lib/python3*')) + sorted(root.glob('Lib')):
        if (stdlib / 'LICENSE.txt').is_file():
            found.append(f'{stdlib.relative_to(root).as_posix()}/LICENSE.txt')
    return found


def find_dist_info_licenses(site: Path, distribution: str, version: str) -> list[tuple[Path, str]]:
    """(absolute path, relative name) of licence files inside an installed dist-info directory."""
    wanted = f'{_normalize_dist(distribution)}-{version}.dist-info'.lower()
    for entry in site.iterdir():
        if entry.is_dir() and entry.name.lower() == wanted:
            result = []
            for name in _tree_files(entry):
                top = name.split('/')[0]
                if _LICENSE_NAME.match(posixpath.basename(name)) and ('/' not in name or top == 'licenses'):
                    result.append((entry / name, name))
            return result
    return []


def _copy_into(payload: Path, destination: str, source: Path) -> str:
    target = payload / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return destination


def _utc_text(clock: Callable[[], datetime.datetime] | None) -> str:
    if clock is not None:
        moment = clock()
    elif os.environ.get('SOURCE_DATE_EPOCH', '').isdigit():
        moment = datetime.datetime.fromtimestamp(int(os.environ['SOURCE_DATE_EPOCH']), datetime.UTC)
    else:
        moment = datetime.datetime.now(datetime.UTC)
    return moment.astimezone(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def _git_commit() -> str:
    if os.environ.get('GITHUB_SHA'):
        return os.environ['GITHUB_SHA']
    try:
        out = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=Path(__file__).resolve().parent, check=True,
                             capture_output=True, text=True, timeout=20, shell=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 'unknown'
    return out if re.fullmatch(r'[0-9a-f]{40}', out) else 'unknown'


def notice_text(doc: ThirdPartyDoc, ghidriff: Mapping, runtime_id: str) -> str:
    lines = [
        f'PatchTrace analysis runtime {runtime_id}', '',
        'This directory tree is an aggregate of separate programs. Each component keeps its own licence;',
        'the full texts are under LICENSES/<component>/. Nothing here was modified by PatchTrace.', '',
        'Ghidriff is licensed GPL-3.0 (' + str(ghidriff.get('spdx_note', '')) + ').',
        'It is shipped unmodified as an independent program that PatchTrace starts only as a separate process',
        '(python -I -m ghidriff). PatchTrace does not import or link it. The complete corresponding source is',
        'in SOURCES/ (see SOURCES/SOURCE-OFFER.txt). The GPL-3.0 text is LICENSES/GPL-3.0.txt.', '',
        'Components:',
    ]
    for item in doc.components:
        lines.append(f'  {item.name} {item.version}  [{item.spdx}]  {item.artifact.name}  sha256 {item.artifact.sha256}')
        lines.extend(f'      licence file: {path}' for path in item.license_files[:6])
        if len(item.license_files) > 6:
            lines.append(f'      ... and {len(item.license_files) - 6} more licence files')
    lines += ['', 'Machine-readable inventory: LICENSES/THIRD-PARTY.json', '']
    return '\n'.join(lines)


def source_offer_text(ghidriff_sha: str, tarball_name: str, tarball_sha: str, jdk_offer: Mapping,
                      jdk_version: str) -> str:
    return '\n'.join([
        'WRITTEN OFFER OF CORRESPONDING SOURCE', '',
        f'1. Ghidriff (GPL-3.0), commit {ghidriff_sha}: the exact, unmodified source tarball is included in',
        f'   this bundle as SOURCES/{tarball_name} (sha256 {tarball_sha}). The Ghidriff files in',
        '   python site-packages were built from that tarball and compared byte for byte with it.', '',
        f'2. Eclipse Temurin JDK {jdk_version} (GPL-2.0-only WITH Classpath-exception-2.0): the matching source',
        '   is not bundled for size. It is available from the upstream publisher:',
        f'   {jdk_offer.get("url", "")}', f'   sha256 {jdk_offer.get("sha256", "")}',
        '   This offer is valid for at least three years after the release that contains this file.', '',
    ])


# ----- gates ---------------------------------------------------------------------------------------------
def gate_pin(pin_bytes: bytes) -> dict:
    """Parse and validate the pin with check_backend_pin semantics; refuse any remaining placeholder."""
    checker = _load_sibling('check_backend_pin')
    try:
        data = json.loads(pin_bytes.decode('utf-8'))
    except (UnicodeError, ValueError) as error:
        raise BundleBuildError('PT-BUNDLE-PIN', f'pin is not JSON: {error}') from None
    problems = checker.validate_pin(data) or checker.release_problems(data)
    if problems:
        shown = '; '.join(problems[:6]) + (f' (+{len(problems) - 6} more)' if len(problems) > 6 else '')
        _fail('PT-BUNDLE-PIN', f'pin refused (check_backend_pin --release semantics): {shown}')
    return data


def gate_paths(payload: Path) -> None:
    """SPEC-06 path policy, collisions, length (<=150 under backend/), links, per-file and total size."""
    report = check_tree(payload)
    if report.clean:
        return
    codes = []
    for item in report.offenders:
        if item.reason.startswith('longer-than'):
            codes.append('PT-BUNDLE-PATH-LENGTH')
        elif item.reason.startswith(('file-over', 'total-over', 'more-than')):
            codes.append('PT-BUNDLE-SIZE-LIMIT')
        elif item.reason in ('symbolic-link', 'special-file'):
            codes.append('PT-BUNDLE-LINK')
        else:
            codes.append('PT-BUNDLE-PATH')
    for code in ('PT-BUNDLE-LINK', 'PT-BUNDLE-PATH', 'PT-BUNDLE-PATH-LENGTH', 'PT-BUNDLE-SIZE-LIMIT'):
        if code in codes:
            break
    samples = ', '.join(f'{item.reason}: {item.path!r}' for item in report.offenders[:5])
    _fail(code, f'{len(report.offenders)} offending path(s); first: {samples}')


def gate_manifest_size(payload: Path) -> int:
    """Estimate the manifest.json size from the file list and fail loudly above the importer's cap."""
    total = 512
    for current, _dirs, names in os.walk(payload, followlinks=False):
        base = Path(current).relative_to(payload).as_posix()
        for name in names:
            relative = name if base == '.' else f'{base}/{name}'
            total += len(json.dumps({'path': relative, 'size': 2**31, 'sha256': '0' * 64},
                                    separators=(',', ':'))) + 1
    if total > policy.MAX_MANIFEST:
        _fail('PT-BUNDLE-MANIFEST-SIZE',
              f'manifest.json would be about {total} bytes, above the {policy.MAX_MANIFEST} byte importer cap')
    return total


def gate_modes(modes: Mapping[str, int], target: str) -> None:
    """Linux only: the vendor-recorded execute bit must be present on natives, launchers, JDK and Python bin."""
    if target != 'linux':
        return
    for pattern in LINUX_EXEC_PATTERNS:
        rx = glob_regex(pattern)
        matched = [name for name in modes if rx.match(name)]
        if not matched:
            _fail('PT-BUNDLE-MODE', f'no file matches required executable pattern {pattern!r}')
        bad = [name for name in matched if not modes[name] & 0o111]
        if bad:
            _fail('PT-BUNDLE-MODE', f'{len(bad)} file(s) lost the execute bit (pattern {pattern!r}): {bad[:3]!r}')


def apply_modes(payload: Path, modes: Mapping[str, int]) -> None:
    """POSIX only: directories 0755, files 0755 when recorded executable else 0644."""
    if os.name == 'nt':
        return
    for current, dirs, names in os.walk(payload, followlinks=False):
        os.chmod(current, 0o755)
        for name in names:
            relative = (Path(current) / name).relative_to(payload).as_posix()
            os.chmod(Path(current) / name, 0o755 if modes.get(relative, 0) & 0o111 else 0o644)
        dirs.sort()


def gate_size(archive: Path, limit: int, *, split: bool, warnings: list[str]) -> list[Path]:
    """Hard-fail above `limit` unless splitting is requested; returns the parts (or just the archive)."""
    size = archive.stat().st_size
    if size > SIZE_WARN:
        warnings.append(f'{archive.name} is {size} bytes (> {SIZE_WARN}); investigate before shipping')
    if size <= limit:
        return [archive]
    if not split:
        _fail('PT-BUNDLE-SIZE-LIMIT',
              f'{archive.name} is {size} bytes, above the {limit} byte release-asset limit: re-run with '
              '--split, or fall back to the lite build plus the backend ZIP pair')
    return split_file(archive, limit)


def split_file(path: Path, part_size: int) -> list[Path]:
    """Split into `<name>.001`, `<name>.002`... of at most `part_size` bytes; removes the original."""
    if part_size <= 0:
        raise ValueError('part_size must be positive')
    parts = []
    with path.open('rb') as source:
        index = 0
        while True:
            chunk_left, empty = part_size, True
            part = path.with_name(f'{path.name}.{index + 1:03d}')
            with part.open('wb') as output:
                while chunk_left > 0:
                    data = source.read(min(CHUNK, chunk_left))
                    if not data:
                        break
                    empty = False
                    output.write(data)
                    chunk_left -= len(data)
            if empty:
                part.unlink()
                break
            parts.append(part)
            index += 1
    path.unlink()
    return parts


def join_parts(parts: Sequence[Path], destination: Path, expected_sha256: str | None = None) -> Path:
    """Concatenate split parts in order; verifies the whole-file digest when given."""
    hasher = hashlib.sha256()
    with Path(destination).open('wb') as output:
        for part in parts:
            with Path(part).open('rb') as stream:
                while chunk := stream.read(CHUNK):
                    hasher.update(chunk)
                    output.write(chunk)
    if expected_sha256 is not None and hasher.hexdigest() != expected_sha256:
        Path(destination).unlink(missing_ok=True)
        _fail('PT-BUNDLE-PIN-MISMATCH', 'joined parts do not match the recorded sha256')
    return Path(destination)


# ----- Ghidriff source tarball: rebuilt from the pinned commit, never downloaded -------------------------
SourceBuilder = Callable[[str, str, Path], Path]


def _default_source_builder(repo: str, commit: str, work: Path) -> Path:
    """Fetch exactly `commit` and write the deterministic tarball (tools/verify_backend_pins.py recipe)."""
    recipe = _load_sibling('verify_backend_pins')
    try:
        path, _info = recipe.rebuild_tarball(repo, commit, work)
    except recipe.VerifyError as error:
        raise BundleBuildError('PT-BUNDLE-FETCH', f'cannot rebuild the Ghidriff source tarball: {error}') from None
    return path


def rebuild_ghidriff_tarball(ghidriff: Mapping, work: Path, source_builder: SourceBuilder | None = None) -> Path:
    """Produce the source tarball from the pinned commit and check it against the pinned sha256/size."""
    entry = ghidriff['source_tarball']
    if entry.get('digest_source') != 'git-rebuilt':
        _fail('PT-BUNDLE-PIN', 'ghidriff.source_tarball: digest_source must be git-rebuilt')
    if not _HEX64.match(str(entry.get('sha256'))) or not isinstance(entry.get('size'), int) or entry['size'] <= 0:
        _fail('PT-BUNDLE-PIN', 'ghidriff.source_tarball: pin entry is not resolved')
    work.mkdir(parents=True, exist_ok=True)
    path = Path((source_builder or _default_source_builder)(ghidriff['repo'], ghidriff['sha'], work))
    try:
        size, actual = path.stat().st_size, sha256_file(path)
    except OSError:
        _fail('PT-BUNDLE-FETCH', 'ghidriff.source_tarball: nothing was rebuilt')
    if size != entry['size'] or actual != entry['sha256']:
        _fail('PT-BUNDLE-PIN-MISMATCH', f'ghidriff.source_tarball: rebuilt {size} bytes sha256 {actual}, '
                                        f'pinned {entry["size"]} bytes sha256 {entry["sha256"]}')
    return path


# ----- the build -----------------------------------------------------------------------------------------
@dataclass
class BuildResult:
    runtime_id: str
    platform: str
    backend_dir: Path
    payload_dir: Path
    manifest_path: Path
    manifest_sha256: str
    archive: Path
    archive_sha256: str
    archive_parts: list[Path]
    source_tarball: Path
    third_party: Path
    file_count: int
    total_bytes: int
    stripped_files: int
    stripped_bytes: int
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            'schema': 'patchtrace-backend-build/1', 'runtime_id': self.runtime_id, 'platform': self.platform,
            'backend_dir': str(self.backend_dir), 'manifest_sha256': self.manifest_sha256,
            'archive': self.archive.name, 'archive_sha256': self.archive_sha256,
            'archive_parts': [part.name for part in self.archive_parts], 'files': self.file_count,
            'payload_bytes': self.total_bytes, 'stripped_files': self.stripped_files,
            'stripped_bytes': self.stripped_bytes, 'warnings': self.warnings,
        }


def _component_licenses(payload: Path, component_id: str, root: Path) -> list[str]:
    names = find_tree_licenses(root)
    return [_copy_into(payload, f'LICENSES/{component_id}/{name}', root / name) for name in names]


def build_backend(pin_path: Path, platform: str, out_dir: Path, *, cache_dir: Path | None = None,
                  version: str = 'dev', fetcher: Fetcher | None = None, runner: Runner | None = None,
                  python: str | None = None, clock: Callable[[], datetime.datetime] | None = None,
                  git_commit: str | None = None, compile_bytecode: bool = True,
                  asset_limit: int = ASSET_LIMIT, split: bool = False,
                  progress: Progress | None = None, source_builder: SourceBuilder | None = None) -> BuildResult:
    """Build `<out_dir>/backend/{manifest.json,payload/}` plus the SPEC-06 importer ZIP for one platform."""
    if platform not in PLATFORMS:
        raise ValueError('platform must be windows or linux')
    say = progress or (lambda _message: None)
    fetcher = fetcher or download
    runner = runner or run_tool
    python = python or sys.executable
    pin_path, out_dir = Path(pin_path), Path(out_dir).resolve()
    pin_bytes = pin_path.read_bytes()
    pin = gate_pin(pin_bytes)
    components = pin['components']
    py_version = components[f'python-{platform}']['version']
    if compile_bytecode:  # fail before any download
        require_host_python(py_version)
    if out_dir.exists() and any(out_dir.iterdir()):
        _fail('PT-BUNDLE-OUT', f'output directory {out_dir} is not empty; the builder never overwrites')
    cache = Path(cache_dir) if cache_dir else Path(tempfile.gettempdir()) / 'patchtrace-backend-cache'
    ghidra_version = components['ghidra']['version']
    jdk_version = components[f'jdk-{platform}']['version']
    sha = pin['ghidriff']['sha']
    runtime_id = pin['runtime_id_format'].format(ghidra=ghidra_version, sha7=sha[:7], os=platform)
    backend, payload = out_dir / 'backend', out_dir / 'backend' / 'payload'
    work = out_dir / '.work'
    warnings: list[str] = []
    payload.mkdir(parents=True)
    work.mkdir()
    try:
        # 1. fetch and verify everything first (a mismatch must fail before any assembly work)
        say('fetching and verifying pinned components')
        downloads = {key: fetch_verified(components[key], cache, fetcher, key)
                     for key in (f'python-{platform}', 'ghidra', f'jdk-{platform}')}
        tarball_entry = pin['ghidriff']['source_tarball']
        ghidriff_tar = rebuild_ghidriff_tarball(pin['ghidriff'], work / 'ghidriff-src', source_builder)
        wheelhouse = work / 'wheelhouse'
        wheelhouse.mkdir()
        locked: list[WheelRequirement] = []
        sdists: list[tuple[Mapping, Path]] = []
        for lane in (platform, 'any'):
            for entry in pin['wheels'][lane]:
                fetched = fetch_verified(entry, cache, fetcher, f'wheel {entry["name"]}')
                if entry['kind'] == 'wheel':
                    shutil.copyfile(fetched, wheelhouse / entry['name'])
                    locked.append(WheelRequirement(entry['distribution'], entry['version'], entry['name'],
                                                   entry['sha256']))
                else:
                    sdists.append((entry, fetched))

        # 2. assemble component trees
        say('assembling payload trees')
        modes: dict[str, int] = {}
        for key, folder, strip_top in ((f'python-{platform}', 'python', platform == 'linux'),
                                       ('ghidra', 'ghidra', True), (f'jdk-{platform}', 'jdk', True)):
            extracted = extract_component(downloads[key], payload / folder, strip_top=strip_top)
            modes.update({f'{folder}/{name}': mode for name, mode in extracted.items()})
        markers = {'windows': ('python/python.exe', 'ghidra/Ghidra/application.properties', 'jdk/bin/java.exe'),
                   'linux': ('python/bin/python3', 'ghidra/Ghidra/application.properties', 'jdk/bin/java')}
        for marker in markers[platform]:
            if not (payload / marker).is_file():
                _fail('PT-BUNDLE-ARCHIVE', f'expected {marker} after extraction: wrong archive layout')
        properties = (payload / 'ghidra/Ghidra/application.properties').read_text(encoding='utf-8', errors='replace')
        found = re.search(r'^application\.version=(\S+)', properties, re.MULTILINE)
        if not found or found.group(1) != ghidra_version:
            _fail('PT-BUNDLE-PIN-MISMATCH',
                  f'Ghidra application.properties says {found.group(1) if found else "nothing"}, pinned {ghidra_version}')

        # 3. strip (pinned, gated by the keep patterns) -- before any licence copy
        say('applying pinned strip rules')
        stripped_files = stripped_bytes = 0
        for folder in ('ghidra', 'jdk'):
            removed, freed = strip_tree(payload / folder, pin['strip'][folder], pin['strip']['keep'], platform)
            stripped_files += len(removed)
            stripped_bytes += freed
            for name in removed:
                modes.pop(f'{folder}/{name}', None)

        # 4. wheels from source, then the hash-locked install
        say('building wheels from source and installing hash-locked wheels')
        builds: list[BuiltWheel] = []
        for entry, fetched in sdists:
            built = build_wheel_from_source(fetched, entry['distribution'], entry['distribution'], work, runner, python)
            if (built.distribution.lower(), built.version) != (entry['distribution'].lower(), entry['version']):
                _fail('PT-BUNDLE-WHEEL-MISMATCH', f'sdist {entry["name"]} built {built.path.name}')
            builds.append(built)
        ghidriff_build = build_wheel_from_source(ghidriff_tar, 'ghidriff', 'ghidriff', work, runner, python)
        builds.append(ghidriff_build)
        for built in builds:
            shutil.copyfile(built.path, wheelhouse / built.path.name)
            locked.append(WheelRequirement(built.distribution, built.version, built.path.name, built.sha256))
        major, minor = py_version.split('.')[:2]
        site = (payload / 'python/Lib/site-packages' if platform == 'windows'
                else payload / f'python/lib/python{major}.{minor}/site-packages')
        install_wheels(locked, wheelhouse, site, platform, py_version, runner, python, work)
        if platform == 'windows':
            pth = payload / f'python/python{major}{minor}._pth'
            pth.write_bytes(f'python{major}{minor}.zip\n.\nLib/site-packages\nimport site\n'.encode('ascii'))
        if compile_bytecode:
            compile_site_packages(site, py_version)

        # 5. licences, source, notices, THIRD-PARTY.json
        say('collecting licences and writing notices')
        tp_components = _third_party_components(pin, platform, payload, site, downloads, builds, locked,
                                                ghidriff_tar, version=(py_version, ghidra_version, jdk_version))
        license_text = (ghidriff_build.source_dir / 'LICENSE')
        if not license_text.is_file() or 'GNU GENERAL PUBLIC LICENSE' not in license_text.read_text(
                encoding='utf-8', errors='replace'):
            _fail('PT-BUNDLE-LICENSE', 'the Ghidriff source tarball has no GPL LICENSE file to ship')
        _copy_into(payload, 'LICENSES/GPL-3.0.txt', license_text)
        source_name = f'ghidriff-{sha[:7]}.tar.gz'
        _copy_into(payload, f'SOURCES/{source_name}', ghidriff_tar)
        doc = ThirdPartyDoc(pin_sha256=hashlib.sha256(pin_bytes).hexdigest(), built_at=_utc_text(clock),
                            git_commit=git_commit or _git_commit(), components=tp_components)
        missing = [path for item in doc.components for path in item.license_files if not (payload / path).is_file()]
        if missing:
            _fail('PT-BUNDLE-LICENSE', f'licence file(s) not in the payload: {missing[:3]!r}')
        (payload / 'SOURCES/SOURCE-OFFER.txt').write_text(
            source_offer_text(sha, source_name, tarball_entry['sha256'], pin['jdk_source_offer'], jdk_version),
            encoding='utf-8', newline='\n')
        (payload / 'LICENSES/NOTICE.txt').write_text(notice_text(doc, pin['ghidriff'], runtime_id),
                                                     encoding='utf-8', newline='\n')
        third_party_json = json.dumps(doc.model_dump(by_alias=True, mode='json', exclude_none=True),
                                      indent=2, sort_keys=True) + '\n'
        (payload / 'LICENSES/THIRD-PARTY.json').write_text(third_party_json, encoding='utf-8', newline='\n')

        # 6. gates, modes, manifest, archive
        say('checking path, mode and size gates')
        gate_modes(modes, platform)
        gate_paths(payload)
        gate_manifest_size(payload)
        apply_modes(payload, modes)
        versions = {'python': py_version, 'ghidra': ghidra_version, 'jdk': jdk_version, 'ghidriff_revision': sha}
        archive = out_dir / f'PatchTrace-{version}-backend-{platform}-amd64.zip'
        policy.build_offline_bundle(payload, runtime_id, versions, archive, platform=platform)
        plan = policy.inspect_offline_bundle(archive, platforms=(platform,))
        manifest_path = backend / 'manifest.json'
        manifest_path.write_bytes(plan.manifest_bytes)
        archive_sha = sha256_file(archive)
        parts = gate_size(archive, asset_limit, split=split, warnings=warnings)
        (out_dir / f'{archive.name}.sha256').write_text(f'{archive_sha}  {archive.name}\n', encoding='ascii',
                                                        newline='\n')
        if parts != [archive]:
            sums = ''.join(f'{sha256_file(part)}  {part.name}\n' for part in parts)
            (out_dir / f'{archive.name}.parts.sha256').write_text(sums, encoding='ascii', newline='\n')
        release_tarball = out_dir / tarball_entry['name']
        shutil.copyfile(ghidriff_tar, release_tarball)
        (out_dir / f'{release_tarball.name}.sha256').write_text(
            f'{tarball_entry["sha256"]}  {release_tarball.name}\n', encoding='ascii', newline='\n')
        third_party = out_dir / 'THIRD-PARTY.json'
        third_party.write_text(third_party_json, encoding='utf-8', newline='\n')
        result = BuildResult(
            runtime_id=runtime_id, platform=platform, backend_dir=backend, payload_dir=payload,
            manifest_path=manifest_path, manifest_sha256=hashlib.sha256(plan.manifest_bytes).hexdigest(),
            archive=archive, archive_sha256=archive_sha, archive_parts=parts, source_tarball=release_tarball,
            third_party=third_party, file_count=plan.file_count, total_bytes=plan.total_bytes,
            stripped_files=stripped_files, stripped_bytes=stripped_bytes, warnings=warnings)
        (out_dir / 'build-report.json').write_text(json.dumps(result.to_json(), indent=2, sort_keys=True) + '\n',
                                                   encoding='utf-8', newline='\n')
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _third_party_components(pin: Mapping, platform: str, payload: Path, site: Path, downloads: Mapping[str, Path],
                            builds: Sequence[BuiltWheel], locked: Sequence[WheelRequirement],
                            ghidriff_tar: Path, version: tuple[str, str, str]) -> list[TpComponent]:
    py_version, ghidra_version, jdk_version = version
    components = pin['components']
    result: list[TpComponent] = []
    license_paths: dict[str, list[str]] = {}

    def artifact(entry: Mapping, path: Path | None = None) -> TpArtifact:
        return TpArtifact(name=path.name if path else entry.get('name') or entry['url'].rsplit('/', 1)[-1],
                          sha256=sha256_file(path) if path else entry['sha256'],
                          size=path.stat().st_size if path else entry['size'], url=entry['url'])

    tree_specs = (
        ('python', f'python-{platform}', 'CPython', py_version, 'runtime', 'https://www.python.org/',
         TpSource(kind='upstream-public', url=f'https://www.python.org/downloads/release/python-{py_version.replace(".", "")}/')),
        ('ghidra', 'ghidra', 'Ghidra', ghidra_version, 'analysis-engine', 'https://github.com/NationalSecurityAgency/ghidra',
         TpSource(kind='upstream-public', url=f'https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_{ghidra_version}_build')),
        ('jdk', f'jdk-{platform}', 'Eclipse Temurin JDK', jdk_version, 'runtime', 'https://adoptium.net/',
         TpSource(kind='offer', url=pin['jdk_source_offer']['url'], sha256=pin['jdk_source_offer']['sha256'])),
    )
    for folder, key, name, ver, role, upstream, source in tree_specs:
        entry = components[key]
        files = _component_licenses(payload, folder, payload / folder)
        license_paths[folder] = files
        result.append(TpComponent(id=folder, name=name, version=ver, spdx=entry['spdx'], role=role,
                                  upstream_url=upstream, artifact=artifact(entry, downloads[key]),
                                  license_files=files or _no_license(folder), source=source,
                                  process_boundary='embedded-runtime'))
    by_name = {}
    for lane in (platform, 'any'):
        for entry in pin['wheels'][lane]:
            by_name[entry['distribution']] = entry
    built_by_dist = {built.distribution.lower(): built for built in builds}
    for item in locked:
        dist = item.distribution
        if dist.lower() == 'ghidriff':
            continue
        entry = by_name[dist]
        built = built_by_dist.get(dist.lower())
        files = [_copy_into(payload, f'LICENSES/{dist}/{rel}', path)
                 for path, rel in find_dist_info_licenses(site, dist, item.version)]
        if not files and built is not None:
            files = [_copy_into(payload, f'LICENSES/{dist}/{name}', built.source_dir / name)
                     for name in sorted(p.name for p in built.source_dir.iterdir()
                                        if p.is_file() and _LICENSE_NAME.match(p.name))]
        if not files and LICENSE_BORROW.get(dist) in license_paths:
            borrowed = license_paths[LICENSE_BORROW[dist]]
            files = [p for p in borrowed if posixpath.basename(p).upper() == 'LICENSE'] or borrowed
        license_paths[dist] = files
        tp_artifact = (TpArtifact(name=built.path.name, sha256=built.sha256, size=built.path.stat().st_size,
                                  url=entry['url']) if built else artifact(entry))
        result.append(TpComponent(
            id=dist, name=dist, version=item.version, spdx=entry['spdx'], role='library',
            upstream_url=f'https://pypi.org/project/{dist}/{item.version}/', artifact=tp_artifact,
            license_files=files or _no_license(dist),
            source=TpSource(kind='upstream-public', url=entry['url'], sha256=entry['sha256']),
            process_boundary='embedded-runtime'))
    ghidriff = pin['ghidriff']
    built = built_by_dist['ghidriff']
    tarball_name = f'SOURCES/ghidriff-{ghidriff["sha"][:7]}.tar.gz'
    files = [_copy_into(payload, f'LICENSES/ghidriff/{name}', built.source_dir / name)
             for name in sorted(p.name for p in built.source_dir.iterdir()
                                if p.is_file() and _LICENSE_NAME.match(p.name))]
    files += [_copy_into(payload, f'LICENSES/ghidriff/{rel}', path)
              for path, rel in find_dist_info_licenses(site, 'ghidriff', built.version)
              if f'LICENSES/ghidriff/{rel}' not in files]
    result.append(TpComponent(
        id='ghidriff', name='Ghidriff', version=built.version, spdx=ghidriff['spdx'], role='analysis-engine',
        upstream_url=ghidriff['repo'],
        artifact=TpArtifact(name=built.path.name, sha256=built.sha256, size=built.path.stat().st_size,
                            url=ghidriff['source_tarball']['url']),
        license_files=files or _no_license('ghidriff'),
        source=TpSource(kind='in-bundle', path=tarball_name, sha256=sha256_file(ghidriff_tar)),
        process_boundary='separate-process'))
    return result


def _no_license(component: str) -> NoReturn:
    raise BundleBuildError('PT-BUNDLE-LICENSE', f'component {component} ships no licence file')


# ----- thin packaging entry used by tools/make_offline_bundle.py -----------------------------------------
def package_payload(payload: Path, out: Path, runtime_id: str, versions: Mapping[str, str], *,
                    platform: str = 'windows') -> tuple[Path, str]:
    """Package an already assembled payload (the legacy producer path): ZIP plus `.sha256` sidecar."""
    archive = policy.build_offline_bundle(payload, runtime_id, versions, out, platform=platform)
    digest = sha256_file(archive)
    sidecar = archive.with_suffix(archive.suffix + '.sha256')
    sidecar.write_bytes(f'{digest}  {archive.name}\n'.encode('ascii'))
    return archive, digest


def _run_build(args: argparse.Namespace) -> int:
    def progress(message: str) -> None:
        print(message, file=sys.stderr)

    try:
        result = build_backend(args.pin, args.platform, args.out, cache_dir=args.cache_dir,
                               version=args.version, compile_bytecode=not args.no_compile,
                               split=args.split, asset_limit=args.asset_limit, progress=progress)
    except BundleBuildError as error:
        print(f'error: {error}', file=sys.stderr)
        return EXIT_BUILD
    except OSError as error:
        print(f'error: {error}', file=sys.stderr)
        return EXIT_USAGE
    except policy.OfflineBundleError as error:
        print(f'error: {error}', file=sys.stderr)
        return EXIT_BUILD
    if args.json:
        print(json.dumps(result.to_json(), indent=2))
    else:
        print(f'built {result.runtime_id}: {result.file_count} files, {result.total_bytes} payload bytes, '
              f'{result.archive_sha256}  {result.archive.name}')
        for warning in result.warnings:
            print(f'warning: {warning}')
    return EXIT_OK

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='PatchTrace backend bundle tooling')
    sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('check', help='dry-run an extracted tree against the SPEC-06 path policy')
    check.add_argument('tree', type=Path, help='extracted Ghidra, JDK or Python directory')
    check.add_argument('--prefix', default='', help='payload folder it will occupy (ghidra, jdk, python)')
    check.add_argument('--json', action='store_true')
    check.add_argument('--limit', type=int, default=200, help='max offenders printed in text mode')
    check.set_defaults(func=_run_check)
    build = sub.add_parser('build', help='fetch, verify and assemble the full backend bundle (needs network)')
    build.add_argument('--platform', required=True, choices=PLATFORMS)
    build.add_argument('--out', required=True, type=Path, help='new or empty output directory')
    build.add_argument('--pin', type=Path, default=Path(__file__).resolve().with_name('backend_pin.json'))
    build.add_argument('--cache-dir', type=Path, default=None, help='download cache (content addressed)')
    build.add_argument('--version', default='dev', help='release version used in archive names')
    build.add_argument('--split', action='store_true', help='split the archive when above the asset limit')
    build.add_argument('--asset-limit', type=int, default=ASSET_LIMIT)
    build.add_argument('--no-compile', action='store_true', help='skip bytecode precompilation')
    build.add_argument('--json', action='store_true')
    build.set_defaults(func=_run_build)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
