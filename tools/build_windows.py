"""Build an auditable, replaceable-DLL Windows desktop distribution."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    if sys.platform != 'win32':
        raise SystemExit('Build on Windows: PyInstaller cannot cross-compile the Windows runtime.')
    root = Path(__file__).resolve().parents[1]
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                    '--onedir', '--windowed', '--name', 'PatchTrace',
                    '--exclude-module', 'PySide6.QtWebEngineCore',
                    '--exclude-module', 'PySide6.QtWebEngineQuick',
                    '--exclude-module', 'PySide6.QtWebEngineWidgets',
                    '--exclude-module', 'PySide6.QtPdf',
                    '--exclude-module', 'PySide6.QtPdfWidgets',
                    '--paths', str(root / 'src'),
                    str(root / 'tools' / 'desktop_entry.py')], cwd=root, check=True)
    package = root / 'dist' / 'PatchTrace'
    shutil.copy2(root / 'LICENSE', package / 'LICENSE.txt')
    shutil.copy2(root / 'README.md', package / 'README.md')
    shutil.copytree(root / 'docs', package / 'docs', dirs_exist_ok=True)
    notices = package / 'licenses'
    notices.mkdir(exist_ok=True)
    versions = {'Python': sys.version.split()[0]}
    bundled_notices = root / 'third_party' / 'notices'
    required = ['qtbase-6.12.0/LICENSES/LGPL-3.0-only.txt',
                'pyside-setup-6.12.0/LICENSES/LGPL-3.0-only.txt',
                'pyinstaller-6.22.3/COPYING.txt', 'README.md']
    if any(not (bundled_notices / item).is_file() for item in required):
        raise RuntimeError('Pinned third-party notices are missing; refusing to publish distribution')
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
    if any('webengine' in item.lower() or 'qtpdf' in item.lower() for item in inventory):
        raise RuntimeError('Unexpected unused WebEngine/PDF binaries collected')
    (package / 'file-inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    subprocess.run([str(package / 'PatchTrace.exe'), '--self-test'], timeout=60, check=True)
    archive = Path(shutil.make_archive(str(root / 'dist' / 'PatchTrace-0.1.0-windows-x64'),
                                     'zip', root_dir=root / 'dist', base_dir='PatchTrace'))
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    archive.with_suffix('.zip.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(archive)


if __name__ == '__main__':
    main()
