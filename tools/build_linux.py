"""Build a Linux x86-64 onedir desktop distribution (run on Linux only).

Python and Qt are bundled. System X11/Wayland, EGL/OpenGL and fontconfig
libraries remain host prerequisites. Ghidra, Java and Ghidriff stay external.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path

VERSION = '0.1.0'
EXCLUDED = ['PySide6.QtWebEngineCore', 'PySide6.QtWebEngineQuick', 'PySide6.QtWebEngineWidgets',
            'PySide6.QtPdf', 'PySide6.QtPdfWidgets']
DISTRIBUTIONS = ['PySide6', 'PySide6_Essentials', 'PySide6_Addons', 'shiboken6', 'pydantic', 'pydantic_core',
                 'PyInstaller', 'annotated-types', 'typing_extensions', 'typing-inspection', 'protobuf']
OPTIONAL_DISTRIBUTIONS = ['rapidfuzz', 'yara-x', 'iced-x86']  # B-0 extras: bundled and licensed when installed


def _installed(name: str) -> bool:
    try:
        importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


PROTOBUF_PIN = '7.36.2'
# SPEC-10b §2/§9: notices that must ship; the build refuses to publish without them.
REQUIRED_NOTICES = ['qtbase-6.12.0/LICENSES/LGPL-3.0-only.txt', f'protobuf-{PROTOBUF_PIN}/LICENSE',
                    'binexport-2bff7af/LICENSE', 'binexport-2bff7af/binexport2.proto',
                    'binexport-2bff7af/PROVENANCE.txt',
                    # SPEC-31 s9: the unified engine's MD index re-expresses BinDiff v8 (Apache-2.0)
                    'bindiff-v8-aecc14d/LICENSE', 'bindiff-v8-aecc14d/PROVENANCE.txt']
# SPEC-31 03 s3: the Ghidra extractor script runs in the user's external Python, so it travels as a data file.
EXTRACTOR_SCRIPT = 'patchtrace/unified/extract/ghidra_script.py'


# --- full variant (BUNDLE-integration-plan B8): pure helpers, shared with build_windows.py ---------------
FULL_SIZE_LIMIT = int(1.9 * 1024 ** 3)  # release assets are capped at 2 GiB
MAX_BACKEND_PATH = 150  # Explorer extraction limit is 260 chars; leave room for the install prefix
VERSION_RE = re.compile(r'^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$')
WINDOWS_RESERVED = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)),
                    *(f'lpt{i}' for i in range(1, 10))}
# Files that must keep +x in the Linux tarball (ZIP extraction loses Unix mode bits, so Linux ships tar.gz).
EXEC_PATTERNS = ('payload/jdk/bin/*', 'payload/python/bin/*', 'payload/ghidra/support/*',
                 'payload/ghidra/*/os/linux_x86_64/decompile', 'payload/ghidra/*/os/linux_x86_64/sleigh*',
                 'payload/ghidra/*/os/linux_x86_64/demangler_gnu*')


class FullBuildError(RuntimeError):
    """Build-only failure carrying a stable PT-BUNDLE-* code in the message."""


def validate_version(version: str) -> str:
    if not VERSION_RE.match(version):
        raise ValueError(f'invalid --version {version!r}')
    return version


def full_archive_name(version: str, platform_key: str) -> str:
    """Release asset names are exact (BUNDLE section 7.7)."""
    validate_version(version)
    if platform_key == 'windows':
        return f'PatchTrace-{version}-windows-x64-full.zip'
    if platform_key == 'linux':
        return f'PatchTrace-{version}-linux-x86_64-full.tar.gz'
    raise ValueError(f'unknown platform {platform_key!r}')


def sha256_file(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def list_regular_files(root: Path) -> list[str]:
    """Sorted POSIX relative paths of regular, non-symlink files (bounded scandir walk, no rglob)."""
    found: list[str] = []
    stack = [root]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    found.append(Path(entry.path).relative_to(root).as_posix())
    return sorted(found)


def payload_problems(backend: Path, *, allow_internal_symlinks: bool) -> list[str]:
    """Reasons a backend directory cannot be shipped; empty means acceptable. Never executes anything."""
    problems: list[str] = []
    if not (backend / 'manifest.json').is_file():
        problems.append('PT-BUNDLE-MISSING: backend/manifest.json is absent')
    if not (backend / 'payload').is_dir():
        problems.append('PT-BUNDLE-MISSING: backend/payload/ is absent')
    base = backend.resolve()
    stack = [backend]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                path = Path(entry.path)
                rel = path.relative_to(backend).as_posix()
                if len(rel) > MAX_BACKEND_PATH:
                    problems.append(f'PT-BUNDLE-PATH-LENGTH: {rel[:60]}... ({len(rel)} > {MAX_BACKEND_PATH})')
                if entry.is_symlink():
                    target = path.resolve()
                    if not allow_internal_symlinks or base not in (target, *target.parents):
                        problems.append(f'PT-BUNDLE-LINK: {rel}')
                elif entry.is_dir(follow_symlinks=False):
                    stack.append(path)
    return sorted(problems)


def windows_name_problems(files: list[str]) -> list[str]:
    """Names Windows extraction rejects: reserved devices (even with extension), trailing dot/space."""
    bad = []
    for rel in files:
        for part in rel.split('/'):
            if part.split('.')[0].lower() in WINDOWS_RESERVED or part.endswith(('.', ' ')):
                bad.append(rel)
                break
    return bad


def sha256sums_text(digests: dict[str, str]) -> str:
    """`sha256sum -c` compatible text: `<hex>  <path>` per file, sorted, LF endings."""
    return ''.join(f'{digests[name]}  {name}\n' for name in sorted(digests))


def missing_exec_bits(files_with_modes: dict[str, int]) -> list[str]:
    """Backend-relative files matching EXEC_PATTERNS that lack any execute bit."""
    return sorted(name for name, mode in files_with_modes.items()
                  if any(fnmatchcase(name, pattern) for pattern in EXEC_PATTERNS) and not mode & 0o111)


def normalized_mode(mode: int, *, is_dir: bool) -> int:
    """0755 for directories and anything executable, 0644 otherwise (no setuid or world-write)."""
    return 0o755 if is_dir or mode & 0o111 else 0o644


def tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    if not info.issym() and not info.islnk():
        info.mode = normalized_mode(info.mode, is_dir=info.isdir())
    return info


def write_tar_gz(package: Path, archive: Path, arcname: str = 'PatchTrace') -> None:
    """Sorted entries, gzip mtime 0, normalised owners and modes; symlinks stay links."""
    with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
        tar.add(package, arcname=arcname, recursive=False, filter=tar_filter)
        stack = [package]
        while stack:
            with os.scandir(stack.pop()) as entries:
                for entry in sorted(entries, key=lambda e: e.name, reverse=True):
                    path = Path(entry.path)
                    tar.add(path, arcname=f'{arcname}/{path.relative_to(package).as_posix()}',
                            recursive=False, filter=tar_filter)
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(path)


def build_provenance(*, version: str, platform_key: str, built_at: str, git_commit: str,
                     manifest_sha256: str, sums_sha256: str, file_count: int, python_version: str) -> dict:
    return {'schema': 'patchtrace-build-provenance/1', 'variant': 'full', 'version': version,
            'platform': platform_key, 'built_at': built_at, 'git_commit': git_commit,
            'backend_manifest_sha256': manifest_sha256, 'sha256sums_sha256': sums_sha256,
            'file_count': file_count, 'build_python': python_version,
            'generated_by': 'tools/build_*.py --full'}


def current_commit(root: Path) -> str:
    sha = os.environ.get('GITHUB_SHA')
    if sha:
        return sha
    try:
        out = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True, text=True,
                             timeout=30, check=True)
        return out.stdout.strip() or 'unknown'
    except (OSError, subprocess.SubprocessError):
        return 'unknown'


def attach_backend(package: Path, backend_payload: Path, *, version: str, platform_key: str, root: Path,
                   allow_internal_symlinks: bool) -> None:
    """Copy `backend/`, then write SHA256SUMS.txt and build-provenance.json into the package root."""
    problems = payload_problems(backend_payload, allow_internal_symlinks=allow_internal_symlinks)
    if platform_key == 'windows':
        problems += [f'PT-BUNDLE-PATH: reserved Windows name in {name}'
                     for name in windows_name_problems(list_regular_files(backend_payload))]
    if problems:
        raise FullBuildError('Backend payload rejected: ' + '; '.join(problems[:10]))
    target = package / 'backend'
    if target.exists():
        raise FullBuildError('package already contains backend/')
    shutil.copytree(backend_payload, target, symlinks=True)
    for name in ('SHA256SUMS.txt', 'build-provenance.json'):
        (package / name).unlink(missing_ok=True)
    files = list_regular_files(package)
    digests = {rel: sha256_file(package / rel) for rel in files}
    sums = package / 'SHA256SUMS.txt'
    sums.write_bytes(sha256sums_text(digests).encode('utf-8'))
    provenance = build_provenance(
        version=version, platform_key=platform_key, git_commit=current_commit(root),
        built_at=datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
        manifest_sha256=digests['backend/manifest.json'], sums_sha256=sha256_file(sums),
        file_count=len(files), python_version=sys.version.split()[0])
    (package / 'build-provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n',
                                                   encoding='utf-8')


def check_archive_size(archive: Path) -> None:
    size = archive.stat().st_size
    if size > FULL_SIZE_LIMIT:
        raise FullBuildError(f'PT-BUNDLE-SIZE-LIMIT: {archive.name} is {size} bytes; '
                             'split or fall back to lite + backend ZIP pair')


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Build the PatchTrace desktop distribution.')
    parser.add_argument('--full', action='store_true', help='also build the full variant with backend/')
    parser.add_argument('--backend-payload', type=Path, help='directory shaped like an installed backend/')
    parser.add_argument('--version', default=VERSION)
    args = parser.parse_args(argv)
    try:
        validate_version(args.version)
    except ValueError as exc:
        parser.error(str(exc))
    if args.full and not args.backend_payload:
        parser.error('--full requires --backend-payload DIR')
    if args.backend_payload and not args.full:
        parser.error('--backend-payload is only valid with --full')
    if args.full and not args.backend_payload.is_dir():
        parser.error(f'--backend-payload {args.backend_payload} is not a directory')
    return args


def require_upb_protobuf() -> None:
    """Fail before freezing if the pinned protobuf is absent or would run as the pure-Python fallback."""
    from google.protobuf.internal import api_implementation
    if importlib.metadata.version('protobuf') != PROTOBUF_PIN or api_implementation.Type() != 'upb':
        raise RuntimeError(f'protobuf {PROTOBUF_PIN} with the upb backend is required '
                           "(pip install --only-binary=:all: -e '.[dev]')")


def python_license() -> Path:
    major_minor = f'{sys.version_info.major}.{sys.version_info.minor}'
    for candidate in [Path(sys.base_prefix) / 'LICENSE.txt',
                      Path(sys.base_prefix) / 'lib' / f'python{major_minor}' / 'LICENSE.txt',
                      Path(f'/usr/lib/python{major_minor}/LICENSE.txt'),
                      Path('/usr/share/doc') / f'python{major_minor}' / 'copyright']:
        if candidate.is_file():
            return candidate
    raise RuntimeError('Python redistribution license is missing')


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not sys.platform.startswith('linux') or platform.machine() not in {'x86_64', 'AMD64'}:
        raise SystemExit('Build on Linux x86-64: PyInstaller does not cross-compile.')
    root = Path(__file__).resolve().parents[1]
    require_upb_protobuf()
    argv = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--name', 'PatchTrace',
            '--additional-hooks-dir', str(root / 'tools' / 'pyinstaller_hooks'), '--paths', str(root / 'src')]
    for module in EXCLUDED:
        argv += ['--exclude-module', module]
    subprocess.run([*argv, str(root / 'tools' / 'desktop_entry.py')], cwd=root, check=True)
    package = root / 'dist' / 'PatchTrace'
    shutil.copy2(root / 'LICENSE', package / 'LICENSE.txt')
    shutil.copy2(root / 'README.md', package / 'README.md')
    shutil.copytree(root / 'docs', package / 'docs', dirs_exist_ok=True)
    notices = package / 'licenses'
    notices.mkdir(exist_ok=True)
    bundled_notices = root / 'third_party' / 'notices'
    if any(not (bundled_notices / item).is_file() for item in REQUIRED_NOTICES):
        raise RuntimeError('Pinned third-party notices are missing; refusing to publish distribution')
    shutil.copytree(bundled_notices, notices / 'upstream', dirs_exist_ok=True)
    versions = {'Python': sys.version.split()[0], 'platform': 'linux-x86_64'}
    for name in DISTRIBUTIONS + [n for n in OPTIONAL_DISTRIBUTIONS if _installed(n)]:
        dist = importlib.metadata.distribution(name)
        versions[name] = dist.version
        for file in dist.files or []:
            if any(word in file.name.lower() for word in ['license', 'copying', 'notice']):
                source = Path(dist.locate_file(file))
                if source.is_file():
                    target = notices / name / str(file).replace('../', '_')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
    shutil.copy2(python_license(), notices / 'Python-LICENSE.txt')
    (package / 'dependency-versions.json').write_text(json.dumps(versions, indent=2), encoding='utf-8')
    inventory = sorted(str(p.relative_to(package)) for p in package.rglob('*') if p.is_file())
    unexpected = [item for item in inventory if Path(item).name.lower().startswith(
        ('libqt6webengine', 'libqt6pdf', 'libqt6quick', 'libqt6qml'))]
    if unexpected:
        raise RuntimeError(f'Unexpected unused WebEngine/PDF/Quick libraries collected: {unexpected}')
    # A missing upb extension means a silent pure-Python protobuf fallback (85x memory): never publish that.
    if not any(item.startswith(('google/_upb/_message.', '_internal/google/_upb/_message.')) for item in inventory):
        raise RuntimeError('google/_upb/_message extension missing from the frozen package')
    # The extractor script must be in the package and byte-identical to the source tree's copy.
    packaged = [item for item in inventory if item.endswith('/' + EXTRACTOR_SCRIPT)]
    if len(packaged) != 1 or (package / packaged[0]).read_bytes() != (root / 'src' / EXTRACTOR_SCRIPT).read_bytes():
        raise RuntimeError('Extractor script data file is missing or differs from the source tree')
    (package / 'file-inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    executable = package / 'PatchTrace'
    if not os.access(executable, os.X_OK):
        raise RuntimeError('Frozen executable is not executable')
    env = {**os.environ, 'QT_QPA_PLATFORM': os.environ.get('QT_QPA_PLATFORM', 'offscreen')}
    subprocess.run([str(executable), '--self-test'], timeout=120, check=True, env=env)
    cli = subprocess.run([str(executable), 'rank', '--help'], timeout=120, capture_output=True, text=True, env=env)
    if cli.returncode != 0 or 'usage:' not in cli.stdout:
        raise RuntimeError(f'Frozen CLI smoke failed ({cli.returncode}): {cli.stderr[-500:]}')
    archive = root / 'dist' / f'PatchTrace-{args.version}-linux-x86_64.tar.gz'
    write_tar_gz(package, archive)  # tar keeps executable bits; ZIP from shutil may not
    Path(f'{archive}.sha256').write_text(f'{sha256_file(archive)}  {archive.name}\n', encoding='ascii')
    print(archive)
    if args.full:  # the lite smoke above is unchanged; backend/ is attached after it
        attach_backend(package, args.backend_payload, version=args.version, platform_key='linux', root=root,
                       allow_internal_symlinks=True)
        modes = {rel: (package / 'backend' / rel).stat().st_mode
                 for rel in list_regular_files(package / 'backend')}
        missing = missing_exec_bits(modes)
        if missing:
            raise FullBuildError(f'Backend files lost their execute bit: {missing[:10]}')
        full = root / 'dist' / full_archive_name(args.version, 'linux')
        write_tar_gz(package, full)
        check_archive_size(full)
        Path(f'{full}.sha256').write_text(f'{sha256_file(full)}  {full.name}\n', encoding='ascii')
        print(full)


if __name__ == '__main__':
    main()
