"""Build an auditable, replaceable-DLL Windows desktop distribution."""
from __future__ import annotations

import importlib.metadata
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Pure shared helpers; importing build_linux runs no build.
from build_linux import attach_backend, check_archive_size, full_archive_name, parse_args, sha256_file  # noqa: E402

PROTOBUF_PIN = '7.36.2'
# SPEC-10b §2/§9: BinExport2 notices; build refuses to publish without them.
BINEXPORT_NOTICES = [f'protobuf-{PROTOBUF_PIN}/LICENSE', 'binexport-2bff7af/LICENSE',
                     'binexport-2bff7af/binexport2.proto', 'binexport-2bff7af/PROVENANCE.txt']


def require_upb_protobuf():
    """Fail before freezing if the pinned protobuf is absent or would run as the pure-Python fallback."""
    from google.protobuf.internal import api_implementation
    if importlib.metadata.version('protobuf') != PROTOBUF_PIN or api_implementation.Type() != 'upb':
        raise RuntimeError(f'protobuf {PROTOBUF_PIN} with the upb backend is required '
                           "(pip install --only-binary=:all: -e '.[dev]')")


def main(argv=None):
    args = parse_args(argv)
    if sys.platform != 'win32':
        raise SystemExit('Build on Windows: PyInstaller cannot cross-compile the Windows runtime.')
    root = Path(__file__).resolve().parents[1]
    require_upb_protobuf()
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
                    # Console subsystem so headless commands return output and exit codes to the
                    # invoking shell; the bootloader hides a console the process owns (double-click),
                    # leaving an inherited terminal attached (PyInstaller >= 6, SPEC-05 §3.2).
                    '--onedir', '--console', '--hide-console', 'hide-early', '--name', 'PatchTrace',
                    '--exclude-module', 'PySide6.QtWebEngineCore',
                    '--exclude-module', 'PySide6.QtWebEngineQuick',
                    '--exclude-module', 'PySide6.QtWebEngineWidgets',
                    '--exclude-module', 'PySide6.QtPdf',
                    '--exclude-module', 'PySide6.QtPdfWidgets',
                    '--additional-hooks-dir', str(root / 'tools' / 'pyinstaller_hooks'),
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
                'pyinstaller-6.22.3/COPYING.txt', 'README.md',
                'qtbase-6.12.0/attributions/README.md',
                'pyside-setup-6.12.0/sources/PySide6-licensecomment.txt']
    required += [f'openssl-{version}/{name}'
                 for version in ['3.0.16', '3.5.5']
                 for name in ['LICENSE.txt', 'ACKNOWLEDGEMENTS.md']]
    required += [f'{module}-6.12.0/LICENSES/{name}.txt'
                 for module in ['qtbase', 'pyside-setup']
                 for name in ['GPL-2.0-only', 'GPL-3.0-only', 'Qt-GPL-exception-1.0']]
    required += BINEXPORT_NOTICES
    if any(not (bundled_notices / item).is_file() for item in required):
        raise RuntimeError('Pinned third-party notices are missing; refusing to publish distribution')
    if len(list((bundled_notices / 'qtbase-6.12.0/attributions').glob('*.html'))) != 49:
        raise RuntimeError('Qt Core/GUI/Network attribution set is incomplete')
    shutil.copytree(bundled_notices, notices / 'upstream', dirs_exist_ok=True)
    for name in ['PySide6', 'PySide6_Essentials', 'PySide6_Addons', 'PySide6_WebEngine', 'PySide6_Pdf', 'shiboken6', 'pydantic',
                 'pydantic_core', 'PyInstaller', 'annotated-types', 'typing_extensions', 'typing-inspection',
                 'protobuf']:
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
    # A missing upb extension means a silent pure-Python protobuf fallback (85x memory): never publish that.
    if not any(item.startswith(('google/_upb/_message.', '_internal/google/_upb/_message.')) for item in inventory):
        raise RuntimeError('google/_upb/_message extension missing from the frozen package')
    (package / 'file-inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
    subprocess.run([str(package / 'PatchTrace.exe'), '--self-test'], timeout=60, check=True)
    # Frozen headless smoke: help must reach stdout and exit 0 without Qt.
    cli = subprocess.run([str(package / 'PatchTrace.exe'), 'rank', '--help'], timeout=60,
                         capture_output=True, text=True)
    if cli.returncode != 0 or 'usage:' not in cli.stdout:
        raise RuntimeError(f'Frozen CLI smoke failed ({cli.returncode}): {cli.stderr[-500:]}')
    archive = Path(shutil.make_archive(str(root / 'dist' / f'PatchTrace-{args.version}-windows-x64'),
                                     'zip', root_dir=root / 'dist', base_dir='PatchTrace'))
    archive.with_suffix('.zip.sha256').write_bytes(f'{sha256_file(archive)}  {archive.name}\n'.encode('ascii'))
    print(archive)
    if args.full:  # the lite smoke above is unchanged; backend/ is attached after it
        attach_backend(package, args.backend_payload, version=args.version, platform_key='windows', root=root,
                       allow_internal_symlinks=False)
        full = Path(shutil.make_archive(str(root / 'dist' / full_archive_name(args.version, 'windows')[:-4]),
                                        'zip', root_dir=root / 'dist', base_dir='PatchTrace'))
        check_archive_size(full)
        full.with_suffix('.zip.sha256').write_bytes(f'{sha256_file(full)}  {full.name}\n'.encode('ascii'))
        print(full)

if __name__ == '__main__':
    main()
