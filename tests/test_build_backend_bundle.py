"""B4: tools/build_backend_bundle.py build pipeline.

Hermetic: tiny fake components served by an in-memory fetcher (no network, no Microsoft binaries) and a
fake pip/wheel runner. The real-pip tests at the end run `python -m pip --no-index` on tiny local files.
All of this is synthetic evidence for the pipeline logic, not proof that the real Ghidra/JDK/Python trees build.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from patchtrace import offline_bundle as policy

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'build_backend_bundle.py'
_spec = importlib.util.spec_from_file_location('build_backend_bundle_b4', TOOL)
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)

REAL_PIN = ROOT / 'tools' / 'backend_pin.json'
POSIX = pytest.mark.skipif(sys.platform == 'win32', reason='POSIX file modes')
PLATFORMS = pytest.mark.parametrize('platform', ['windows', 'linux'])
GPL = b'GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n'


# ----- fake components -----------------------------------------------------------------------------------
def make_zip(entries: dict[str, bytes | tuple[bytes, int]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, value in entries.items():
            body, mode = value if isinstance(value, tuple) else (value, 0o644)
            info = zipfile.ZipInfo('member', date_time=(2020, 1, 1, 0, 0, 0))
            info.filename = name  # ZipInfo.__init__ rewrites os.sep (a backslash on Windows) to '/'
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            zf.writestr(info, body)
    return buffer.getvalue()


def make_tar(entries: dict[str, bytes | tuple[bytes, int] | str]) -> bytes:
    """bytes -> 0644 file, (bytes, mode) -> file, str starting with '->' -> symlink."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tf:
        for name, value in entries.items():
            info = tarfile.TarInfo(name)
            if isinstance(value, str):
                info.type, info.linkname, info.mode = tarfile.SYMTYPE, value[2:], 0o777
                tf.addfile(info)
                continue
            body, mode = value if isinstance(value, tuple) else (value, 0o644)
            info.size, info.mode = len(body), mode
            tf.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


def make_wheel(dist: str, version: str, *, licensed: bool = True) -> bytes:
    norm = dist.replace('-', '_')
    info = f'{norm}-{version}.dist-info'
    entries = {f'{norm}/__init__.py': f'NAME = {dist!r}\n'.encode(),
               f'{info}/METADATA': f'Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n'.encode(),
               f'{info}/WHEEL': b'Wheel-Version: 1.0\nGenerator: fake\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
               f'{info}/RECORD': b''}
    if licensed:
        entries[f'{info}/LICENSE'] = f'licence of {dist}\n'.encode()
    return make_zip(entries)


class World:
    """Blobs, pin file and fetcher for one fake build."""

    def __init__(self, tmp_path: Path, platform: str, *, no_exec: bool = False, jdk_license: bool = True,
                 gpl_license: bool = True, unlicensed_wheel: str = '', extra_ghidra: dict | None = None,
                 py_version: str = '3.12.10') -> None:
        self.platform, self.blobs, self.calls = platform, {}, []
        self.tamper: dict[str, bytes] = {}
        pin = json.loads(REAL_PIN.read_text(encoding='utf-8'))
        components = pin['components']
        ex = 0o644 if no_exec else 0o755
        ghidra_entries = {
            'ghidra_12.0.4_PUBLIC/Ghidra/application.properties': b'application.name=Ghidra\napplication.version=12.0.4\n',
            'ghidra_12.0.4_PUBLIC/LICENSE': b'Apache License 2.0\n',
            'ghidra_12.0.4_PUBLIC/licenses/Apache.txt': b'apache text\n',
            'ghidra_12.0.4_PUBLIC/docs/index.html': b'x' * 400,
            'ghidra_12.0.4_PUBLIC/Extensions/Eclipse/GhidraDev.zip': b'y' * 400,
            'ghidra_12.0.4_PUBLIC/GPL/decompiler.txt': b'gpl sources\n',
            'ghidra_12.0.4_PUBLIC/support/analyzeHeadless': (b'#!/bin/sh\n', ex),
            'ghidra_12.0.4_PUBLIC/support/launch.sh': (b'#!/bin/sh\n', ex),
            'ghidra_12.0.4_PUBLIC/support/launch.properties': b'VMARGS=-Xmx1g\n',
            'ghidra_12.0.4_PUBLIC/Ghidra/Processors/x86/x86.sla': b'sla\n',
        }
        for os_dir, exe in (('win_x86_64', 'decompile.exe'), ('mac_arm_64', 'decompile')):
            ghidra_entries[f'ghidra_12.0.4_PUBLIC/Ghidra/Features/Decompiler/os/{os_dir}/{exe}'] = b'native\n'
        for exe in ('decompile', 'sleigh', 'demangler_gnu_v2_41'):
            ghidra_entries[f'ghidra_12.0.4_PUBLIC/Ghidra/Features/Decompiler/os/linux_x86_64/{exe}'] = (b'ELF\n', ex)
        ghidra_entries.update({f'ghidra_12.0.4_PUBLIC/{k}': v for k, v in (extra_ghidra or {}).items()})
        windows = platform == 'windows'
        if windows:
            python = make_zip({'python.exe': b'MZ', 'python312.dll': b'MZ', 'python312.zip': b'PK',
                               'python312._pth': b'python312.zip\n.\n#import site\n', 'LICENSE.txt': b'PSF\n'})
            jdk = make_zip({'jdk-21.0.12+1/bin/java.exe': b'MZ', 'jdk-21.0.12+1/bin/javac.exe': b'MZ',
                            'jdk-21.0.12+1/lib/src.zip': b's' * 300, 'jdk-21.0.12+1/jmods/a.jmod': b'j' * 300,
                            **({'jdk-21.0.12+1/legal/java.base/LICENSE': b'GPLv2+CE\n'} if jdk_license else {})})
        else:
            python = make_tar({'python/bin/python3.12': (b'ELF\n', 0o755), 'python/bin/python3': '->python3.12',
                               'python/bin/python': '->python3',
                               'python/lib/python3.12/LICENSE.txt': b'PSF\n'})
            jdk = make_tar({'jdk-21.0.12+1/bin/java': (b'ELF\n', 0o755 if not no_exec else 0o644),
                            'jdk-21.0.12+1/bin/javac': (b'ELF\n', 0o755),
                            'jdk-21.0.12+1/lib/src.zip': b's' * 300, 'jdk-21.0.12+1/jmods/a.jmod': b'j' * 300,
                            **({'jdk-21.0.12+1/legal/java.base/LICENSE': b'GPLv2+CE\n'} if jdk_license else {})})
        for key, blob in ((f'python-{platform}', python), ('ghidra', make_zip(ghidra_entries)),
                          (f'jdk-{platform}', jdk)):
            self._pin(components[key], blob)
        for other in set(components) - {f'python-{platform}', 'ghidra', f'jdk-{platform}'}:
            self._pin(components[other], f'unused {other}'.encode())  # never fetched
        components['python-windows']['version'] = components['python-linux']['version'] = py_version
        for lane in ('windows', 'linux', 'any'):
            for entry in pin['wheels'][lane]:
                if entry['kind'] == 'wheel':
                    blob = make_wheel(entry['distribution'], entry['version'],
                                      licensed=entry['distribution'] != unlicensed_wheel)
                else:
                    blob = make_tar({f'mdutils-{entry["version"]}/mdutils/__init__.py': b'MD = 1\n',
                                     f'mdutils-{entry["version"]}/LICENSE': b'MIT\n'})
                self._pin(entry, blob)
        sha = pin['ghidriff']['sha']
        self.gpl = gpl_license
        source = {f'ghidriff-{sha}/ghidriff/__init__.py': b'__version__ = "1.0.0"\n',
                  f'ghidriff-{sha}/ghidriff/__main__.py': b'def main():\n    return 0\n',
                  f'ghidriff-{sha}/setup.cfg': b'[metadata]\nname = ghidriff\n'}
        if gpl_license:
            source[f'ghidriff-{sha}/LICENSE'] = GPL
        self.source_tarball = make_tar(source)
        self._pin(pin['ghidriff']['source_tarball'], self.source_tarball)
        pin['jdk_source_offer'].update(sha256='cd' * 32, size=5)
        self.pin = pin
        self.pin_path = tmp_path / 'pin.json'
        self.pin_path.write_text(json.dumps(pin, indent=1), encoding='utf-8')

    def _pin(self, entry: dict, blob: bytes) -> None:
        entry.update(sha256=hashlib.sha256(blob).hexdigest(), size=len(blob))
        if entry.get('status') == 'placeholder':
            entry.update(status='pinned', digest_source='git-rebuilt' if 'ghidriff' in entry['url'] else 'sigstore-verified')
        self.blobs[entry['url']] = blob

    def source_builder(self, repo: str, commit: str, work: Path) -> Path:
        self.calls.append(f'rebuild {repo} {commit}')
        path = work / 'ghidriff-source.tar.gz'
        path.write_bytes(self.tamper.get('source', self.source_tarball))
        return path

    def write_pin(self) -> None:
        self.pin_path.write_text(json.dumps(self.pin, indent=1), encoding='utf-8')

    def fetcher(self, url: str, dest: Path, max_bytes: int) -> None:
        self.calls.append(url)
        dest.write_bytes(self.tamper.get(url, self.blobs[url]))  # KeyError = an URL outside the pin


class FakeRunner:
    """Stands in for `python -I -m pip install/wheel`: validates the argv and unpacks/zips locally."""

    def __init__(self, *, mutate: bool = False, wheel_tag: str = 'py3-none-any') -> None:
        self.calls, self.mutate, self.wheel_tag = [], mutate, wheel_tag

    def __call__(self, argv, cwd) -> None:
        self.calls.append(list(argv))
        if 'install' in argv:
            self._install(argv)
        else:
            self._wheel(argv)

    @staticmethod
    def _opt(argv, name):
        return argv[argv.index(name) + 1]

    def _install(self, argv) -> None:
        lines = Path(self._opt(argv, '-r')).read_text(encoding='utf-8').splitlines()
        house, target = Path(self._opt(argv, '--find-links')), Path(self._opt(argv, '--target'))
        for line in lines:
            requirement, hash_part = line.split(' --hash=sha256:')
            dist, version = requirement.split('==')
            wheel = next(p for p in house.glob('*.whl') if p.name.lower().startswith(f'{dist}-{version}-'.lower()))
            assert hashlib.sha256(wheel.read_bytes()).hexdigest() == hash_part
            with zipfile.ZipFile(wheel) as zf:
                zf.extractall(target)
        (target / 'bin').mkdir(exist_ok=True)
        (target / 'bin' / 'ghidriff').write_text('#!/builder/python\n')

    def _wheel(self, argv) -> None:
        source, out = Path(argv[-1]), Path(self._opt(argv, '--wheel-dir'))
        version = {'mdutils': '1.6.0', 'ghidriff': '1.0.0'}[source.name]
        files = {}
        for path in (source / source.name).rglob('*.py'):
            body = path.read_bytes()
            files[path.relative_to(source).as_posix()] = body + b'#x\n' if self.mutate else body
        info = f'{source.name}-{version}.dist-info'
        files[f'{info}/METADATA'] = f'Name: {source.name}\nVersion: {version}\n'.encode()
        files[f'{info}/RECORD'] = b''
        if (source / 'LICENSE').is_file():
            files[f'{info}/LICENSE'] = (source / 'LICENSE').read_bytes()
        (out / f'{source.name}-{version}-{self.wheel_tag}.whl').write_bytes(make_zip(files))


def build(world: World, tmp_path: Path, runner: FakeRunner | None = None, **kwargs):
    kwargs.setdefault('compile_bytecode', False)
    return tool.build_backend(world.pin_path, world.platform, tmp_path / 'out', cache_dir=tmp_path / 'cache',
                              fetcher=world.fetcher, runner=runner or FakeRunner(), git_commit='f' * 40,
                              source_builder=world.source_builder,
                              **kwargs)


# ----- happy path ----------------------------------------------------------------------------------------
@PLATFORMS
def test_fake_component_build_passes_manifest_inspection(tmp_path, platform):
    world = World(tmp_path, platform)
    result = build(world, tmp_path)
    plan = policy.inspect_offline_bundle(result.archive, platforms=(platform,))
    assert plan.runtime_id == f'ghidra-12.0.4-ghidriff-4f5d895-{platform}-amd64'
    assert result.manifest_path.read_bytes() == plan.manifest_bytes
    assert result.archive_sha256 == hashlib.sha256(result.archive.read_bytes()).hexdigest()
    payload = result.payload_dir
    names = {p.relative_to(payload).as_posix() for p in payload.rglob('*') if p.is_file()}
    assert {item.path for item in plan.files} == names
    assert plan.manifest['versions'] == {'python': '3.12.10', 'ghidra': '12.0.4', 'jdk': '21.0.12.1+1',
                                         'ghidriff_revision': world.pin['ghidriff']['sha']}
    for required in ('LICENSES/NOTICE.txt', 'LICENSES/GPL-3.0.txt', 'LICENSES/THIRD-PARTY.json',
                     'SOURCES/SOURCE-OFFER.txt', 'SOURCES/ghidriff-4f5d895.tar.gz'):
        assert required in names
    assert (payload / 'SOURCES/ghidriff-4f5d895.tar.gz').read_bytes() == world.source_tarball
    assert (result.source_tarball).read_bytes() == world.source_tarball


@PLATFORMS
def test_downloads_stay_inside_the_pin_and_site_packages_are_complete(tmp_path, platform):
    world = World(tmp_path, platform)
    result = build(world, tmp_path)
    pinned = {entry['url'] for entry in world.pin['wheels']['any']}
    urls = [c for c in world.calls if not c.startswith('rebuild ')]
    assert pinned <= set(urls) and all(url.startswith('https://') for url in urls)
    gh = world.pin['ghidriff']
    assert world.calls.count(f'rebuild {gh["repo"]} {gh["sha"]}') == 1  # rebuilt from the commit, not downloaded
    site = (result.payload_dir / ('python/Lib/site-packages' if platform == 'windows'
                                  else 'python/lib/python3.12/site-packages'))
    dists = {p.name for p in site.iterdir()}
    for expected in ('jpype1-1.5.2.dist-info', 'pyghidra-3.0.2.dist-info', 'packaging-25.0.dist-info',
                     'mdutils-1.6.0.dist-info', 'ghidriff-1.0.0.dist-info', 'ghidriff'):
        assert expected in dists
    assert 'bin' not in dists  # console-script stubs would carry the builder's interpreter path


def test_windows_pth_is_lf_and_names_site_packages(tmp_path):
    result = build(World(tmp_path, 'windows'), tmp_path)
    pth = (result.payload_dir / 'python/python312._pth').read_bytes()
    assert pth == b'python312.zip\n.\nLib/site-packages\nimport site\n'


@PLATFORMS
def test_strip_rules_remove_docs_and_other_os_natives(tmp_path, platform):
    result = build(World(tmp_path, platform), tmp_path)
    ghidra = result.payload_dir / 'ghidra'
    assert not (ghidra / 'docs').exists() and not (ghidra / 'Extensions/Eclipse').exists()
    assert not (result.payload_dir / 'jdk/lib/src.zip').exists() and not (result.payload_dir / 'jdk/jmods').exists()
    os_dirs = {p.name for p in (ghidra / 'Ghidra/Features/Decompiler/os').iterdir()}
    assert os_dirs == ({'win_x86_64'} if platform == 'windows' else {'linux_x86_64'})
    assert (ghidra / 'LICENSE').is_file() and (ghidra / 'GPL/decompiler.txt').is_file()
    assert result.stripped_files >= 5 and result.stripped_bytes >= 800


def test_third_party_json_documents_every_component(tmp_path):
    result = build(World(tmp_path, 'windows', unlicensed_wheel='pyghidra'), tmp_path)
    doc = tool.ThirdPartyDoc.model_validate_json(result.third_party.read_text(encoding='utf-8'))
    by_id = {item.id: item for item in doc.components}
    assert set(by_id) == {'python', 'ghidra', 'jdk', 'jpype1', 'pyghidra', 'packaging', 'mdutils', 'ghidriff'}
    ghidriff = by_id['ghidriff']
    assert (ghidriff.role, ghidriff.source.kind, ghidriff.process_boundary, ghidriff.modified) == (
        'analysis-engine', 'in-bundle', 'separate-process', False)
    assert ghidriff.source.path == 'SOURCES/ghidriff-4f5d895.tar.gz'
    assert by_id['pyghidra'].license_files == ['LICENSES/ghidra/LICENSE']  # part of Ghidra, borrowed notice
    assert doc.git_commit == 'f' * 40 and doc.pin_sha256 == hashlib.sha256(
        (tmp_path / 'pin.json').read_bytes()).hexdigest()
    plan = policy.inspect_offline_bundle(result.archive)
    inventory = {item.path for item in plan.files}
    assert all(path in inventory for item in doc.components for path in item.license_files)
    notice = (result.payload_dir / 'LICENSES/NOTICE.txt').read_text(encoding='utf-8')
    assert 'separate process' in notice and 'SOURCE-OFFER' in notice


def test_third_party_model_rejects_a_modified_or_linked_ghidriff():
    base = dict(id='ghidriff', name='G', version='1', spdx='GPL-3.0-only', role='analysis-engine',
                upstream_url='https://x', artifact=dict(name='a', sha256='0' * 64, size=1, url='https://x'),
                license_files=['LICENSES/ghidriff/LICENSE'],
                source=dict(kind='in-bundle', path='SOURCES/x', sha256='0' * 64),
                process_boundary='separate-process')
    assert tool.TpComponent.model_validate(base).modified is False
    for change in ({'modified': True}, {'process_boundary': 'embedded-runtime'}, {'role': 'library'},
                   {'source': dict(kind='offer', url='https://x')}, {'license_files': []}, {'extra': 1}):
        with pytest.raises(ValueError):
            tool.TpComponent.model_validate({**base, **change})


@POSIX
def test_linux_modes_are_applied_and_symlinks_become_copies(tmp_path):
    result = build(World(tmp_path, 'linux'), tmp_path)
    payload = result.payload_dir
    for name in ('python/bin/python3', 'python/bin/python', 'jdk/bin/java', 'ghidra/support/launch.sh',
                 'ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile'):
        path = payload / name
        assert path.is_file() and not path.is_symlink() and path.stat().st_mode & stat.S_IXUSR, name
    assert not (payload / 'ghidra/support/launch.properties').stat().st_mode & stat.S_IXUSR
    assert (payload / 'LICENSES/NOTICE.txt').stat().st_mode & 0o777 == 0o644
    assert (payload / 'python').stat().st_mode & 0o777 == 0o755


# ----- gates (each red) ----------------------------------------------------------------------------------
def _pin_with_placeholder(tmp_path):
    """The committed pin is fully resolved now; keep the refusal tests hermetic by re-opening one component."""
    pin = json.loads(REAL_PIN.read_text(encoding='utf-8'))
    pin['components']['python-windows'].update(status='placeholder', sha256='PLACEHOLDER-UNRESOLVED', size=None,
                                               digest_source='none')
    path = tmp_path / 'placeholder-pin.json'
    path.write_text(json.dumps(pin), encoding='utf-8')
    return path


def test_unresolved_pin_placeholders_are_refused_before_any_download(tmp_path):
    calls = []
    with pytest.raises(tool.BundleBuildError) as caught:
        tool.build_backend(_pin_with_placeholder(tmp_path), 'linux', tmp_path / 'out', cache_dir=tmp_path / 'c',
                           fetcher=lambda *a: calls.append(a), runner=FakeRunner())
    assert caught.value.code == 'PT-BUNDLE-PIN' and 'placeholder' in str(caught.value) and calls == []


def test_malformed_pin_is_refused(tmp_path):
    world = World(tmp_path, 'linux')
    world.pin['wheels']['any'] = world.pin['wheels']['any'][:1]
    world.write_pin()
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-PIN'):
        build(world, tmp_path)
    assert world.calls == []


@pytest.mark.parametrize('target', ['ghidra', 'jdk', 'wheel', 'tarball', 'sdist'])
@pytest.mark.parametrize('same_size', [False, True], ids=['truncated', 'bitflip'])
def test_digest_mismatch_is_a_hard_failure(tmp_path, target, same_size):
    world = World(tmp_path, 'linux')
    url = {'ghidra': world.pin['components']['ghidra']['url'],
           'jdk': world.pin['components']['jdk-linux']['url'],
           'wheel': world.pin['wheels']['linux'][0]['url'],
           'tarball': 'source',
           'sdist': world.pin['wheels']['any'][2]['url']}[target]
    blob = bytearray(world.source_tarball if url == 'source' else world.blobs[url])
    if same_size:
        blob[len(blob) // 2] ^= 1
    else:
        blob = blob[:-1]
    world.tamper[url] = bytes(blob)
    with pytest.raises(tool.BundleBuildError) as caught:
        build(world, tmp_path)
    assert caught.value.code == 'PT-BUNDLE-PIN-MISMATCH'
    assert not list((tmp_path / 'cache').glob('*.part')) and not (tmp_path / 'out/.work').exists()


def test_cached_download_is_reverified(tmp_path):
    world = World(tmp_path, 'linux')
    build(world, tmp_path)
    shutil.rmtree(tmp_path / 'out')
    for cached in (tmp_path / 'cache').iterdir():  # corrupt the cache: it must be re-downloaded, not trusted
        cached.write_bytes(cached.read_bytes()[:-1] + b'!')
    world.calls.clear()
    build(world, tmp_path)
    assert len(world.calls) >= 8


def test_wrong_ghidra_version_in_the_archive_is_a_mismatch(tmp_path):
    world = World(tmp_path, 'linux')
    entry = world.pin['components']['ghidra']
    world._pin(entry, make_zip({'ghidra_12.0.4_PUBLIC/Ghidra/application.properties': b'application.version=11.0\n'}))
    world.write_pin()
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-PIN-MISMATCH.*11.0'):
        build(world, tmp_path)


@PLATFORMS
def test_missing_licence_for_a_runtime_component_fails_the_build(tmp_path, platform):
    with pytest.raises(tool.BundleBuildError) as caught:
        build(World(tmp_path, platform, jdk_license=False), tmp_path)
    assert caught.value.code == 'PT-BUNDLE-LICENSE' and 'jdk' in str(caught.value)


def test_missing_licence_for_a_wheel_fails_the_build(tmp_path):
    with pytest.raises(tool.BundleBuildError, match=r'PT-BUNDLE-LICENSE.*jpype1'):
        build(World(tmp_path, 'windows', unlicensed_wheel='jpype1'), tmp_path)


def test_ghidriff_source_without_gpl_text_fails_the_build(tmp_path):
    with pytest.raises(tool.BundleBuildError) as caught:
        build(World(tmp_path, 'linux', gpl_license=False), tmp_path)
    assert caught.value.code == 'PT-BUNDLE-LICENSE'


@POSIX
def test_lost_execute_bit_fails_the_linux_mode_gate(tmp_path):
    with pytest.raises(tool.BundleBuildError) as caught:
        build(World(tmp_path, 'linux', no_exec=True), tmp_path)
    assert caught.value.code == 'PT-BUNDLE-MODE'


def test_mode_gate_does_not_apply_to_windows(tmp_path):
    assert build(World(tmp_path, 'windows', no_exec=True), tmp_path).archive.is_file()


@pytest.mark.parametrize(('recorded', 'ok'), [
    ({'ghidra/support/analyzeHeadless': 0o755, 'ghidra/support/launch.sh': 0o755,
      'ghidra/Ghidra/F/os/linux_x86_64/decompile': 0o755, 'ghidra/Ghidra/F/os/linux_x86_64/sleigh': 0o755,
      'ghidra/Ghidra/F/os/linux_x86_64/demangler_gnu_v2_41': 0o755, 'jdk/bin/java': 0o755,
      'python/bin/python3': 0o755}, True),
    ({'ghidra/support/analyzeHeadless': 0o755, 'ghidra/support/launch.sh': 0o755,
      'ghidra/Ghidra/F/os/linux_x86_64/decompile': 0o755, 'ghidra/Ghidra/F/os/linux_x86_64/sleigh': 0o755,
      'ghidra/Ghidra/F/os/linux_x86_64/demangler_gnu_v2_41': 0o755, 'jdk/bin/java': 0o755}, False),
    ({'ghidra/support/analyzeHeadless': 0o644}, False),
], ids=['complete', 'missing-python', 'not-exec'])
def test_gate_modes_unit(recorded, ok):
    if ok:
        tool.gate_modes(recorded, 'linux')
    else:
        with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-MODE'):
            tool.gate_modes(recorded, 'linux')


def test_archive_above_the_asset_limit_fails_without_split(tmp_path):
    with pytest.raises(tool.BundleBuildError) as caught:
        build(World(tmp_path, 'windows'), tmp_path, asset_limit=1000)
    assert caught.value.code == 'PT-BUNDLE-SIZE-LIMIT' and '--split' in str(caught.value)


def test_split_archive_parts_fit_the_limit_and_join_back(tmp_path):
    result = build(World(tmp_path, 'windows'), tmp_path, asset_limit=4000, split=True)
    assert len(result.archive_parts) > 1 and not result.archive.exists()
    assert all(part.stat().st_size <= 4000 for part in result.archive_parts)
    assert [p.name for p in result.archive_parts] == sorted(p.name for p in result.archive_parts)
    joined = tool.join_parts(result.archive_parts, tmp_path / 'joined.zip', result.archive_sha256)
    assert policy.inspect_offline_bundle(joined).runtime_id == result.runtime_id
    sums = (tmp_path / 'out' / f'{result.archive.name}.parts.sha256').read_text()
    assert all(f'{tool.sha256_file(p)}  {p.name}' in sums for p in result.archive_parts)


@pytest.mark.parametrize(('size', 'limit', 'parts'), [(10, 5, 2), (11, 5, 3), (5, 5, 1), (1, 5, 1)],
                         ids=['exact-2', 'remainder', 'exact-1', 'tiny'])
def test_split_file_unit(tmp_path, size, limit, parts):
    path = tmp_path / 'a.bin'
    path.write_bytes(bytes(range(size)))
    pieces = tool.split_file(path, limit)
    assert len(pieces) == parts and not path.exists()
    assert tool.join_parts(pieces, tmp_path / 'b.bin').read_bytes() == bytes(range(size))


def test_join_parts_detects_a_wrong_digest(tmp_path):
    part = tmp_path / 'a.001'
    part.write_bytes(b'abc')
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-PIN-MISMATCH'):
        tool.join_parts([part], tmp_path / 'j', '00' * 32)
    assert not (tmp_path / 'j').exists()


def test_single_file_over_the_member_limit_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, 'MAX_FILE', 150)
    with pytest.raises(tool.BundleBuildError) as caught:
        build(World(tmp_path, 'windows'), tmp_path)
    assert caught.value.code == 'PT-BUNDLE-SIZE-LIMIT'


def test_manifest_larger_than_the_importer_cap_fails_loudly(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, 'MAX_MANIFEST', 600)
    with pytest.raises(tool.BundleBuildError) as caught:
        build(World(tmp_path, 'windows'), tmp_path)
    assert caught.value.code == 'PT-BUNDLE-MANIFEST-SIZE' and 'importer cap' in str(caught.value)


def test_importer_accepts_a_manifest_beyond_the_old_4_mib_cap():
    assert policy.MAX_MANIFEST >= 16 * 1024 * 1024
    # 60,000 records of realistic length (~190 bytes) stay below the cap.
    record = json.dumps({'path': 'ghidra/Ghidra/Features/Decompiler/' + 'p' * 44, 'size': 2**31,
                         'sha256': '0' * 64}, separators=(',', ':'))
    assert 60_000 * (len(record) + 1) < policy.MAX_MANIFEST
    assert 40_000 * (len(record) + 1) > 4 * 1024 * 1024  # why the old cap was too small


def test_overlong_relative_path_fails_with_the_length_code(tmp_path):
    world = World(tmp_path, 'windows', extra_ghidra={'Ghidra/Features/' + 'x' * 140 + '.txt': b'long'})
    with pytest.raises(tool.BundleBuildError) as caught:
        build(world, tmp_path)
    assert caught.value.code == 'PT-BUNDLE-PATH-LENGTH'


@pytest.mark.parametrize('name', ['aux.txt', 'trail.', 'CON', 'a:b'], ids=['aux', 'dot', 'con', 'colon'])
def test_windows_unsafe_names_fail_with_the_path_code(tmp_path, name):
    world = World(tmp_path, 'linux', extra_ghidra={f'Ghidra/Features/{name}': b'x'})
    with pytest.raises(tool.BundleBuildError) as caught:
        build(world, tmp_path)
    assert caught.value.code == 'PT-BUNDLE-PATH'


def test_casefold_collision_fails(tmp_path):
    world = World(tmp_path, 'linux', extra_ghidra={'Ghidra/Features/Read.me': b'a', 'Ghidra/Features/read.ME': b'b'})
    with pytest.raises(tool.BundleBuildError) as caught:
        build(world, tmp_path)
    assert caught.value.code == 'PT-BUNDLE-PATH'


@pytest.mark.parametrize('names', [['top/trail.'], ['top/a:b'], ['top/Read.me', 'top/read.ME']],
                         ids=['dot', 'colon', 'casefold'])
def test_windows_host_extraction_refuses_names_ntfs_would_mangle(tmp_path, monkeypatch, names):
    # Pure-logic twin of the real-filesystem tests above: simulate a Windows host on any OS.
    monkeypatch.setattr(tool, '_windows_host', lambda: True)
    archive = tmp_path / 'a.zip'
    archive.write_bytes(make_zip({name: b'x' for name in names}))
    with pytest.raises(tool.BundleBuildError) as caught:
        tool.extract_component(archive, tmp_path / 'dest', strip_top=True)
    assert caught.value.code == 'PT-BUNDLE-PATH'


def test_wheel_not_byte_equal_to_the_tarball_fails(tmp_path):
    with pytest.raises(tool.BundleBuildError) as caught:
        build(World(tmp_path, 'windows'), tmp_path, FakeRunner(mutate=True))
    assert caught.value.code == 'PT-BUNDLE-WHEEL-MISMATCH'


def test_binary_tagged_built_wheel_fails(tmp_path):
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-WHEEL-MISMATCH.*py3-none-any'):
        build(World(tmp_path, 'windows'), tmp_path, FakeRunner(wheel_tag='cp312-cp312-win_amd64'))


def test_compare_wheel_reports_source_file_missing_from_wheel(tmp_path):
    source = tmp_path / 'src'
    (source / 'pkg').mkdir(parents=True)
    (source / 'pkg/__init__.py').write_bytes(b'a')
    (source / 'pkg/extra.py').write_bytes(b'b')
    wheel = tmp_path / 'pkg-1-py3-none-any.whl'
    wheel.write_bytes(make_zip({'pkg/__init__.py': b'a', 'pkg-1.dist-info/METADATA': b'x'}))
    with pytest.raises(tool.BundleBuildError, match='extra.py'):
        tool.compare_wheel_to_source(wheel, source, 'pkg')
    (source / 'pkg/extra.py').unlink()
    assert tool.compare_wheel_to_source(wheel, source, 'pkg') == 1


def test_strip_keep_gate_blocks_a_rule_that_removes_licences(tmp_path):
    world = World(tmp_path, 'windows')
    world.pin['strip']['ghidra'].append('licenses/**')
    world.pin['strip']['keep'] = ['licenses/**']
    world.write_pin()
    with pytest.raises(tool.BundleBuildError) as caught:
        build(world, tmp_path)
    assert caught.value.code == 'PT-BUNDLE-STRIP'


def test_pip_install_is_hash_locked_wheels_only_and_index_free(tmp_path):
    runner = FakeRunner()
    build(World(tmp_path, 'linux'), tmp_path, runner)
    install = next(call for call in runner.calls if 'install' in call)
    for flag in ('--no-index', '--no-deps', '--only-binary=:all:', '--require-hashes', '--no-compile', '-I'):
        assert flag in install
    assert install.count('--platform') == 2 and 'manylinux2014_x86_64' in install
    assert install[install.index('--abi') + 1] == 'cp312'
    builds = [call for call in runner.calls if 'wheel' in call]
    assert len(builds) == 2 and all('--no-build-isolation' in c and '--no-index' in c for c in builds)
    assert not any('--index-url' in c or '--extra-index-url' in c for c in runner.calls)


def test_requirements_file_lists_every_wheel_with_a_hash(tmp_path):
    world = World(tmp_path, 'windows')
    runner = FakeRunner()
    seen = {}
    original = runner._install

    def spy(argv):
        seen['text'] = Path(runner._opt(argv, '-r')).read_text(encoding='utf-8')
        original(argv)

    runner._install = spy
    build(world, tmp_path, runner)
    lines = seen['text'].splitlines()
    assert sorted(line.split('==')[0] for line in lines) == [
        'ghidriff', 'jpype1', 'mdutils', 'packaging', 'pyghidra']
    assert all(re.search(r' --hash=sha256:[0-9a-f]{64}$', line) for line in lines)
    jpype = next(line for line in lines if line.startswith('jpype1'))
    assert world.pin['wheels']['windows'][0]['sha256'] in jpype


def test_pip_platform_args_windows_and_linux():
    assert tool.pip_platform_args('windows', '3.12.10')[:2] == ['--platform', 'win_amd64']
    assert 'manylinux_2_17_x86_64' in tool.pip_platform_args('linux', '3.12.10')


def test_bytecode_precompile_needs_the_pinned_python_minor_and_fails_before_download(tmp_path):
    world = World(tmp_path, 'windows', py_version='3.99.1')
    with pytest.raises(tool.BundleBuildError) as caught:
        build(world, tmp_path, compile_bytecode=True)
    assert caught.value.code == 'PT-BUNDLE-PYTHON-MISMATCH' and world.calls == []


def test_precompile_writes_unchecked_hash_pycs(tmp_path):
    site = tmp_path / 'site'
    site.mkdir()
    (site / 'mod.py').write_text('X = 1\n')
    version = f'{sys.version_info.major}.{sys.version_info.minor}.0'
    tool.compile_site_packages(site, version)
    pyc = next((site / '__pycache__').glob('mod.*.pyc'))
    assert int.from_bytes(pyc.read_bytes()[4:8], 'little') == 0b01  # hash-based, not checked
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-PYTHON-MISMATCH'):
        tool.compile_site_packages(site, '3.1.0', host=(3, 12))


def test_output_directory_must_be_empty(tmp_path):
    (tmp_path / 'out').mkdir()
    (tmp_path / 'out' / 'keep.txt').write_text('x')
    world = World(tmp_path, 'linux')
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-OUT'):
        build(world, tmp_path)
    assert world.calls == [] and (tmp_path / 'out/keep.txt').read_text() == 'x'


def test_build_report_and_sidecars_are_written(tmp_path):
    result = build(World(tmp_path, 'linux'), tmp_path)
    out = tmp_path / 'out'
    report = json.loads((out / 'build-report.json').read_text())
    assert report['archive_sha256'] == result.archive_sha256 and report['platform'] == 'linux'
    assert (out / f'{result.archive.name}.sha256').read_text() == f'{result.archive_sha256}  {result.archive.name}\n'
    assert (out / 'THIRD-PARTY.json').read_text() == (result.payload_dir / 'LICENSES/THIRD-PARTY.json').read_text()
    assert not (out / '.work').exists()


# ----- extraction safety ---------------------------------------------------------------------------------
@pytest.mark.parametrize('name', ['../evil', '/abs', 'a/../../evil', 'a\\b', 'C:/x'],
                         ids=['dotdot', 'abs', 'nested', 'backslash', 'drive'])
def test_zip_traversal_is_refused(tmp_path, name):
    archive = tmp_path / 'a.zip'
    archive.write_bytes(make_zip({name: b'x'}))
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-ARCHIVE'):
        tool.extract_component(archive, tmp_path / 'dest', strip_top=False)
    assert not (tmp_path / 'evil').exists()


def test_zip_backslash_name_is_refused_even_when_zipfile_rewrites_separators(tmp_path, monkeypatch):
    # Simulate Windows: zipfile then turns '\\' into '/' while reading, which hid the name from the check.
    archive = tmp_path / 'a.zip'
    archive.write_bytes(make_zip({'top/a\\b': b'x'}))
    class WindowsOs:
        sep, altsep = '\\', '/'

        def __getattr__(self, name):
            return getattr(os, name)

    shim = WindowsOs()
    monkeypatch.setattr(zipfile, 'os', shim)
    assert zipfile.ZipFile(archive).namelist() == ['top/a/b']  # the premise: zipfile hides the backslash
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-ARCHIVE'):
        tool.extract_component(archive, tmp_path / 'dest', strip_top=True)


@pytest.mark.parametrize('entries', [
    {'top/a': b'x', 'top/l': '->../../outside'},
    {'top/a': b'x', 'top/l': '->/etc/passwd'},
    {'top/a': b'x', 'top/l': '->missing'},
    {'top/d/a': b'x', 'top/l': '->d'},
], ids=['escape', 'absolute', 'dangling', 'dir-link'])
def test_unsafe_tar_links_are_refused(tmp_path, entries):
    archive = tmp_path / 'a.tar.gz'
    archive.write_bytes(make_tar(entries))
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-LINK'):
        tool.extract_component(archive, tmp_path / 'dest', strip_top=True)


def test_tar_with_two_top_level_entries_is_refused_when_stripping(tmp_path):
    archive = tmp_path / 'a.tar.gz'
    archive.write_bytes(make_tar({'one/a': b'x', 'two/b': b'y'}))
    with pytest.raises(tool.BundleBuildError, match='top-level'):
        tool.extract_component(archive, tmp_path / 'dest', strip_top=True)


def test_zip_symlink_member_is_refused(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        info = zipfile.ZipInfo('l')
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, 'target')
    archive = tmp_path / 'a.zip'
    archive.write_bytes(buffer.getvalue())
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-LINK'):
        tool.extract_component(archive, tmp_path / 'dest', strip_top=False)


def test_tar_symlink_chain_resolves_to_copies_with_target_mode(tmp_path):
    archive = tmp_path / 'a.tar.gz'
    archive.write_bytes(make_tar({'t/bin/real': (b'ELF', 0o755), 't/bin/a': '->real', 't/bin/b': '->a'}))
    modes = tool.extract_component(archive, tmp_path / 'dest', strip_top=True)
    assert modes == {'bin/real': 0o755, 'bin/a': 0o755, 'bin/b': 0o755}
    assert (tmp_path / 'dest/bin/b').read_bytes() == b'ELF' and not (tmp_path / 'dest/bin/b').is_symlink()


@pytest.mark.parametrize(('pattern', 'path', 'matches'), [
    ('docs/**', 'docs/a/b.html', True), ('docs/**', 'x/docs/a', False),
    ('**/os/win_*/**', 'Ghidra/Features/D/os/win_x86_64/d.exe', True),
    ('**/os/win_*/**', 'os/win_x86_64/d.exe', True), ('**/os/win_*/**', 'Ghidra/os/linux_x86_64/d', False),
    ('jmods/**', 'jmods/java.base.jmod', True), ('lib/src.zip', 'lib/src.zip', True),
    ('bin/javac*', 'bin/javac.exe', True), ('bin/javac*', 'bin/sub/javac', False),
    ('a?c', 'abc', True), ('a?c', 'a/c', False),
], ids=['docs', 'docs-anchored', 'os-deep', 'os-root', 'os-other', 'jmods', 'exact', 'javac', 'star-no-slash',
        'qmark', 'qmark-no-slash'])
def test_glob_regex(pattern, path, matches):
    assert bool(tool.glob_regex(pattern).match(path)) is matches


def test_other_os_expansion():
    assert [rx.pattern for rx in tool.expand_strip_patterns(['**/os/{other-OS}/**'], 'windows')] == [
        tool.glob_regex('**/os/linux_*/**').pattern, tool.glob_regex('**/os/mac_*/**').pattern]
    assert len(tool.expand_strip_patterns(['docs/**'], 'linux')) == 1


# ----- thin legacy caller --------------------------------------------------------------------------------
def test_make_offline_bundle_cli_is_unchanged_and_uses_the_shared_module(tmp_path, monkeypatch, capsys):
    payload = tmp_path / 'payload'
    for name in ('python/python.exe', 'ghidra/Ghidra/application.properties', 'jdk/bin/java.exe',
                 'LICENSES/NOTICE.txt'):
        (payload / name).parent.mkdir(parents=True, exist_ok=True)
        (payload / name).write_bytes(name.encode())
    spec = importlib.util.spec_from_file_location('make_offline_bundle_t', ROOT / 'tools/make_offline_bundle.py')
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    out = tmp_path / 'rt.zip'
    monkeypatch.setattr(sys, 'argv', [
        'make', '--payload', str(payload), '--out', str(out), '--runtime-id', 'rt-1', '--python-version', '3.12.10',
        '--ghidra-version', '12.0.4', '--jdk-version', '21.0.1', '--ghidriff-revision', 'abc1234'])
    assert legacy.main() == 0
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    assert (tmp_path / 'rt.zip.sha256').read_text() == f'{digest}  rt.zip\n'
    assert f'Packed rt.zip SHA-256 {digest}' in capsys.readouterr().out
    assert policy.inspect_offline_bundle(out).runtime_id == 'rt-1'
    assert legacy._builder().package_payload.__module__ == 'build_backend_bundle'


def test_cli_build_refuses_a_pin_with_a_placeholder_with_a_clear_exit_code(tmp_path, capsys):
    code = tool.main(['build', '--platform', 'linux', '--out', str(tmp_path / 'o'), '--pin', str(_pin_with_placeholder(tmp_path))])
    assert code == tool.EXIT_BUILD and 'PT-BUNDLE-PIN' in capsys.readouterr().err


# ----- real pip, offline (tiny local files) --------------------------------------------------------------
def _has(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


@pytest.mark.skipif(not _has('pip'), reason='pip not installed')
def test_real_pip_installs_a_hash_locked_wheel_offline(tmp_path):
    house, site, work = tmp_path / 'house', tmp_path / 'site', tmp_path / 'work'
    house.mkdir()
    work.mkdir()
    wheel = house / 'tiny-1.0-py3-none-any.whl'
    wheel.write_bytes(make_wheel('tiny', '1.0'))
    requirement = tool.WheelRequirement('tiny', '1.0', wheel.name, tool.sha256_file(wheel))
    tool.install_wheels([requirement], house, site, 'linux', '3.12.10', tool.run_tool, sys.executable, work)
    assert (site / 'tiny/__init__.py').is_file() and (site / 'tiny-1.0.dist-info').is_dir()
    bad = tool.WheelRequirement('tiny', '1.0', wheel.name, 'ab' * 32)
    with pytest.raises(tool.BundleBuildError, match='PT-BUNDLE-PIN-MISMATCH'):
        tool.install_wheels([bad], house, tmp_path / 'site2', 'linux', '3.12.10', tool.run_tool, sys.executable, work)


@pytest.mark.skipif(not (_has('pip') and _has('setuptools') and _has('wheel')), reason='needs setuptools+wheel')
def test_real_wheel_build_from_a_source_tarball_is_byte_compared(tmp_path):
    tarball = tmp_path / 'tinypkg.tar.gz'
    tarball.write_bytes(make_tar({
        'tinypkg-1.0/pyproject.toml': b'[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n',
        'tinypkg-1.0/setup.cfg': b'[metadata]\nname = tinypkg\nversion = 1.0\n\n[options]\npackages = tinypkg\n',
        'tinypkg-1.0/tinypkg/__init__.py': b'VALUE = 1\n',
        'tinypkg-1.0/LICENSE': b'MIT\n'}))
    work = tmp_path / 'work'
    work.mkdir()
    try:
        built = tool.build_wheel_from_source(tarball, 'tinypkg', 'tinypkg', work, tool.run_tool, sys.executable)
    except tool.BundleBuildError as error:
        if 'install_layout' in str(error):  # Debian-patched setuptools vs. pip build env, not our code
            pytest.skip('distro setuptools cannot build wheels here (install_layout)')
        raise
    assert built.path.name == 'tinypkg-1.0-py3-none-any.whl' and built.sha256 == tool.sha256_file(built.path)
    copy.deepcopy(built)  # frozen dataclass stays copyable
