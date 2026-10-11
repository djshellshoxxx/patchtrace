"""Build an auditable, replaceable-DLL Windows desktop distribution.

Provenance (SPEC-05 §2.7, SRC-2..SRC-5): the build refuses a dirty or HEAD-less
tree unless ``--allow-dirty`` is given, embeds ``patchtrace/build-info.json``,
ships ``SOURCE.txt`` and a ``git archive`` source ZIP next to the binary ZIP.
The pure helpers below are unit-tested on Linux (tests/test_packaging.py).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPO_URL = 'https://github.com/djshellshoxxx/patchtrace'
# Must match the "Build on Windows from source" block in docs/windows.md (tested).
BUILD_COMMANDS = ("py -3.12 -m pip install -e '.[dev]'",
                  'py -3.12 -m pytest -q',
                  'py -3.12 tools/build_windows.py')
USAGE_EXIT_CODES = {2, 64}


class DirtyTreeError(RuntimeError):
    """The source tree is not a clean commit; refusing to build."""


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(['git', *args], cwd=repo_root, capture_output=True, text=True, check=False)


def check_source_tree(repo_root: Path, allow_dirty: bool = False) -> dict[str, Any]:
    """Return ``{commit, describe, dirty}`` or raise :class:`DirtyTreeError` (SRC-2)."""
    head = _git(repo_root, 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}')
    commit = head.stdout.strip() if head.returncode == 0 else ''
    status = _git(repo_root, 'status', '--porcelain')
    if status.returncode != 0:
        raise DirtyTreeError(f'Refusing to build: git status failed: {status.stderr.strip()}')
    dirty = bool(status.stdout.strip()) or not commit
    if dirty and not allow_dirty:
        reason = 'HEAD is not a commit' if not commit else \
            'working tree has uncommitted or untracked changes:\n' + status.stdout.rstrip()
        raise DirtyTreeError(f'Refusing to build: {reason}\nCommit first, or pass --allow-dirty '
                             'for a local-only build (recorded as dirty: true).')
    describe = _git(repo_root, 'describe', '--always', '--tags', '--dirty') if commit else None
    return {'commit': commit or 'unknown',
            'describe': describe.stdout.strip() if describe and describe.returncode == 0 else 'unknown',
            'dirty': dirty}


def make_build_info(version: str, git: dict[str, Any], source_digest: str, python: str,
                    pyinstaller: str | None, pyside6: str | None, built_utc: str) -> dict[str, Any]:
    """The ``build-info.json`` document (SRC-3)."""
    return {'version': version, 'git_commit': git['commit'], 'git_describe': git['describe'],
            'dirty': bool(git['dirty']), 'source_sha256': source_digest, 'python': python,
            'pyinstaller': pyinstaller, 'pyside6': pyside6, 'built_utc': built_utc}


def source_txt(version: str, commit: str, dirty: bool) -> str:
    """Text of ``SOURCE.txt`` shipped inside the binary ZIP (SRC-4)."""
    lines = [f'PatchTrace {version}', '',
             f'Source repository: {REPO_URL}',
             f'Commit: {commit}' + (' (built from a DIRTY tree; not a release build)' if dirty else ''),
             f'Source archive: PatchTrace-{version}-source.zip (git archive of this commit)',
             f'Browse: {REPO_URL}/tree/{commit}', '',
             'Application code is stored as bytecode inside the frozen archive by design.',
             'The editable source is src/patchtrace in the repository. Every fix starts in src/;',
             'hand-patching .pyc files or the PYZ is prohibited.', '',
             'Build on Windows from source (repository root):']
    lines += [f'  {command}' for command in BUILD_COMMANDS]
    lines += ['', 'Ghidra, Java and Ghidriff are external and not included; see docs/windows.md.', '']
    return '\n'.join(lines)


def check_version_output(returncode: int, stdout: str, expected_commit: str) -> str | None:
    """Validate ``PatchTrace.exe version --json``. Return a warning, or ``None`` when verified.

    The ``version`` command may not exist yet in older entry points: usage exits (2/64)
    and non-JSON output only warn. A JSON reply with a different commit is fatal.
    """
    if returncode in USAGE_EXIT_CODES:
        return f'warning: PatchTrace.exe version --json unsupported (exit {returncode}); provenance not checked'
    if returncode != 0:
        raise RuntimeError(f'PatchTrace.exe version --json failed with exit code {returncode}')
    try:
        data = json.loads(stdout)
    except ValueError:
        return 'warning: PatchTrace.exe version --json printed no JSON; provenance not checked'
    got = data.get('git_commit') if isinstance(data, dict) else None
    if got != expected_commit:
        raise RuntimeError(f'Built exe reports git_commit {got!r}, expected {expected_commit!r}')
    return None


def sha256_file(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_sha256(path: Path) -> Path:
    target = path.with_name(path.name + '.sha256')
    target.write_text(f'{sha256_file(path)}  {path.name}\n', encoding='ascii')
    return target


def _dist_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Build the PatchTrace Windows distribution.')
    parser.add_argument('--allow-dirty', action='store_true',
                        help='local-only: build an uncommitted tree; recorded as dirty: true')
    return parser.parse_args(argv)


def main(argv: list[str] | None = None):
    args = parse_args(argv)
    if sys.platform != 'win32':
        raise SystemExit('Build on Windows: PyInstaller cannot cross-compile the Windows runtime.')
    root = ROOT
    sys.path.insert(0, str(root / 'src'))
    from patchtrace import __version__ as version
    from patchtrace.buildinfo import BUILD_INFO_NAME, source_sha256

    try:
        git = check_source_tree(root, allow_dirty=args.allow_dirty)
    except DirtyTreeError as error:
        raise SystemExit(str(error)) from None
    github_sha = os.environ.get('GITHUB_SHA')
    if github_sha and git['commit'] != github_sha:
        raise SystemExit(f'HEAD {git["commit"]} does not match GITHUB_SHA {github_sha}')
    info = make_build_info(version, git, source_sha256(root / 'src'), platform.python_version(),
                           _dist_version('pyinstaller'), _dist_version('PySide6'),
                           datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'))
    staging = root / 'build' / 'provenance'
    staging.mkdir(parents=True, exist_ok=True)
    build_info_path = staging / BUILD_INFO_NAME
    build_info_path.write_text(json.dumps(info, indent=2) + '\n', encoding='utf-8')
    # Console subsystem so terminals wait and receive exit codes; the bootloader hides the
    # console only when the exe owns it (double-click). SPEC-05 §3.2.
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                    '--onedir', '--console', '--hide-console', 'hide-early', '--name', 'PatchTrace',
                    '--specpath', str(root / 'build'),
                    '--add-data', f'{build_info_path}{os.pathsep}patchtrace',
                    '--exclude-module', 'PySide6.QtWebEngineCore',
                    '--exclude-module', 'PySide6.QtWebEngineQuick',
                    '--exclude-module', 'PySide6.QtWebEngineWidgets',
                    '--exclude-module', 'PySide6.QtPdf',
                    '--exclude-module', 'PySide6.QtPdfWidgets',
                    '--additional-hooks-dir', str(root / 'tools' / 'pyinstaller_hooks'),
                    '--paths', str(root / 'src'),
                    str(root / 'tools' / 'desktop_entry.py')], cwd=root, check=True)
    package = root / 'dist' / 'PatchTrace'
    if not (package / '_internal' / 'patchtrace' / BUILD_INFO_NAME).is_file():
        raise RuntimeError('build-info.json was not bundled at _internal/patchtrace/build-info.json')
    shutil.copy2(root / 'LICENSE', package / 'LICENSE.txt')
    shutil.copy2(root / 'README.md', package / 'README.md')
    shutil.copytree(root / 'docs', package / 'docs', dirs_exist_ok=True)
    source_text = source_txt(version, git['commit'], git['dirty'])
    (package / 'SOURCE.txt').write_text(source_text, encoding='utf-8')
    notices = package / 'licenses'
    notices.mkdir(exist_ok=True)
    versions = {'Python': sys.version.split()[0]}
    bundled_notices = root / 'third_party' / 'notices'
    required = ['qtbase-6.12.0/LICENSES/LGPL-3.0-only.txt',
                'pyside-setup-6.12.0/LICENSES/LGPL-3.0-only.txt',
                'pyinstaller-6.22.3/COPYING.txt', 'README.md',
                'qtbase-6.12.0/attributions/README.md',
                'pyside-setup-6.12.0/sources/PySide6-licensecomment.txt']
    required += [f'openssl-{ssl_version}/{name}'
                 for ssl_version in ['3.0.16', '3.5.5']
                 for name in ['LICENSE.txt', 'ACKNOWLEDGEMENTS.md']]
    required += [f'{module}-6.12.0/LICENSES/{name}.txt'
                 for module in ['qtbase', 'pyside-setup']
                 for name in ['GPL-2.0-only', 'GPL-3.0-only', 'Qt-GPL-exception-1.0']]
    if any(not (bundled_notices / item).is_file() for item in required):
        raise RuntimeError('Pinned third-party notices are missing; refusing to publish distribution')
    if len(list((bundled_notices / 'qtbase-6.12.0/attributions').glob('*.html'))) != 49:
        raise RuntimeError('Qt Core/GUI/Network attribution set is incomplete')
    shutil.copytree(bundled_notices, notices / 'upstream', dirs_exist_ok=True)
    for name in ['PySide6', 'PySide6_Essentials', 'PySide6_Addons', 'PySide6_WebEngine', 'PySide6_Pdf', 'shiboken6', 'pydantic',
                 'pydantic_core', 'PyInstaller', 'annotated-types', 'typing_extensions', 'typing-inspection']:
        dist = importlib.metadata.distribution(name)
        versions[name] = dist.version
        for file in dist.files or []:
            if any(word in file.name.lower() for word in ['license', 'copying', 'notice']):
                source = Path(dist.locate_file(file))
                if source.is_file():
                    target = notices / name / str(file).replace('../', '_')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
    # Python redistribution notice accompanies the bundled interpreter.
    py_license = Path(sys.base_prefix) / 'LICENSE.txt'
    if not py_license.is_file():
        raise RuntimeError('Python redistribution license is missing')
    shutil.copy2(py_license, notices / 'Python-LICENSE.txt')
    (package / 'dependency-versions.json').write_text(json.dumps(versions, indent=2), encoding='utf-8')
    inventory = sorted(str(path.relative_to(package)).replace('\\', '/')
                       for path in package.rglob('*') if path.is_file())
    unexpected = [item for item in inventory
                  if Path(item).suffix.lower() in {'.dll', '.pyd', '.exe', '.pak'}
                  and any(name in Path(item).name.lower() for name in
                          ['webengine', 'pdf', 'virtualkeyboard', 'qt6quick', 'qt6qml'])]
    if unexpected:
        raise RuntimeError(f'Unexpected unused WebEngine/PDF binaries collected: {unexpected}')
    (package / 'file-inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    exe = package / 'PatchTrace.exe'
    subprocess.run([str(exe), '--self-test'], timeout=60, check=True)
    # SRC-5 provenance check. Entry points without the `version` command reject it (2/64)
    # or open the GUI (timeout); both only warn until the CLI lands.
    try:
        probe = subprocess.run([str(exe), 'version', '--json'], capture_output=True, text=True,
                               timeout=60, check=False)
        warning = check_version_output(probe.returncode, probe.stdout, git['commit'])
    except subprocess.TimeoutExpired:
        warning = 'warning: PatchTrace.exe version --json timed out (command not available); not checked'
    print(warning or f'verified: PatchTrace.exe version --json git_commit == {git["commit"]}')
    dist = root / 'dist'
    archive = Path(shutil.make_archive(str(dist / f'PatchTrace-{version}-windows-x64'),
                                       'zip', root_dir=dist, base_dir='PatchTrace'))
    write_sha256(archive)
    (dist / 'SOURCE.txt').write_text(source_text, encoding='utf-8')
    if git['commit'] == 'unknown':
        print('warning: no HEAD commit; source ZIP not created (local --allow-dirty build)')
    else:
        source_zip = dist / f'PatchTrace-{version}-source.zip'
        subprocess.run(['git', 'archive', '--format=zip', f'--prefix=PatchTrace-{version}-source/',
                        '-o', str(source_zip), git['commit']], cwd=root, check=True)
        write_sha256(source_zip)
        print(source_zip)
    print(archive)


if __name__ == '__main__':
    main()
