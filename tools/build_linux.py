"""Build a Linux x86-64 onedir desktop distribution (run on Linux only).

Python and Qt are bundled. System X11/Wayland, EGL/OpenGL and fontconfig
libraries remain host prerequisites. Ghidra, Java and Ghidriff stay external.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

VERSION = '0.1.0'
EXCLUDED = ['PySide6.QtWebEngineCore', 'PySide6.QtWebEngineQuick', 'PySide6.QtWebEngineWidgets',
            'PySide6.QtPdf', 'PySide6.QtPdfWidgets']
DISTRIBUTIONS = ['PySide6', 'PySide6_Essentials', 'PySide6_Addons', 'shiboken6', 'pydantic', 'pydantic_core',
                 'PyInstaller', 'annotated-types', 'typing_extensions', 'typing-inspection']


def python_license() -> Path:
    major_minor = f'{sys.version_info.major}.{sys.version_info.minor}'
    for candidate in [Path(sys.base_prefix) / 'LICENSE.txt',
                      Path(sys.base_prefix) / 'lib' / f'python{major_minor}' / 'LICENSE.txt',
                      Path(f'/usr/lib/python{major_minor}/LICENSE.txt'),
                      Path('/usr/share/doc') / f'python{major_minor}' / 'copyright']:
        if candidate.is_file():
            return candidate
    raise RuntimeError('Python redistribution license is missing')


def main() -> None:
    if not sys.platform.startswith('linux') or platform.machine() not in {'x86_64', 'AMD64'}:
        raise SystemExit('Build on Linux x86-64: PyInstaller does not cross-compile.')
    root = Path(__file__).resolve().parents[1]
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
    if not (bundled_notices / 'qtbase-6.12.0/LICENSES/LGPL-3.0-only.txt').is_file():
        raise RuntimeError('Pinned third-party notices are missing; refusing to publish distribution')
    shutil.copytree(bundled_notices, notices / 'upstream', dirs_exist_ok=True)
    versions = {'Python': sys.version.split()[0], 'platform': 'linux-x86_64'}
    for name in DISTRIBUTIONS:
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
    (package / 'file-inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    executable = package / 'PatchTrace'
    if not os.access(executable, os.X_OK):
        raise RuntimeError('Frozen executable is not executable')
    env = {**os.environ, 'QT_QPA_PLATFORM': os.environ.get('QT_QPA_PLATFORM', 'offscreen')}
    subprocess.run([str(executable), '--self-test'], timeout=120, check=True, env=env)
    cli = subprocess.run([str(executable), 'rank', '--help'], timeout=120, capture_output=True, text=True, env=env)
    if cli.returncode != 0 or 'usage:' not in cli.stdout:
        raise RuntimeError(f'Frozen CLI smoke failed ({cli.returncode}): {cli.stderr[-500:]}')
    archive = root / 'dist' / f'PatchTrace-{VERSION}-linux-x86_64.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:  # tar keeps executable bits; ZIP from shutil may not
        tar.add(package, arcname='PatchTrace')
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    Path(f'{archive}.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(archive)


if __name__ == '__main__':
    main()
