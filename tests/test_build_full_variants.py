"""B8: pure helpers of the full-variant builders (synthetic payloads; real builds run only in CI)."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import os
import sys
import tarfile
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'


def _load(name: str):
    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    spec = importlib.util.spec_from_file_location(f'_b8_{name}', TOOLS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


linux = _load('build_linux')
windows = _load('build_windows')


PIN = json.loads((TOOLS / 'backend_pin.json').read_text(encoding='utf-8'))
JDK_SPDX = 'GPL-2.0-only WITH Classpath-exception-2.0'
LAYOUT = {'linux': {'python/bin/python3': b'#!py', 'jdk/bin/java': b'ELF'},
          'windows': {'python/python.exe': b'MZ', 'jdk/bin/java.exe': b'MZ'}}


def _components(*extra: tuple[str, str]) -> bytes:
    items = [('ghidriff', 'GPL-3.0-only'), ('jdk', JDK_SPDX), ('python', 'PSF-2.0'), *extra]
    return json.dumps({'components': [{'id': i, 'spdx': x} for i, x in items]}).encode()


def _write_manifest(backend: Path, files: dict[str, bytes], platform: str, **override) -> None:
    manifest = {
        'format': 'patchtrace-offline-runtime', 'schema_version': 1,
        'runtime_id': f'ghidra-12.0.4-ghidriff-4f5d895-{platform}-amd64', 'platform': platform,
        'architecture': 'amd64', 'python': 'python/python.exe' if platform == 'windows' else 'python/bin/python3',
        'ghidra': 'ghidra', 'java': 'jdk',
        'versions': {'python': '3.12.10', 'ghidra': '12.0.4', 'jdk': '21.0.5', 'ghidriff_revision': '4f5d895'},
        'files': [{'path': n, 'size': len(c), 'sha256': hashlib.sha256(c).hexdigest()}
                  for n, c in sorted(files.items())]}
    manifest.update(override)
    (backend / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')


def _payload(root: Path, *, extra: dict[str, bytes] | None = None, platform: str = 'linux',
             third_party: bytes | None = None) -> Path:
    """A tiny but fully valid backend/ (manifest inventory == tree); `extra` files are declared too."""
    backend = root / 'backend-src'
    files = {**LAYOUT[platform], 'ghidra/Ghidra/application.properties': b'application.version=12.0.4',
             'LICENSES/NOTICE.txt': b'notice',
             'LICENSES/THIRD-PARTY.json': _components() if third_party is None else third_party, **(extra or {})}
    for rel, data in files.items():
        path = backend / 'payload' / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    _write_manifest(backend, files, platform)
    return backend


def _pin_file(root: Path, *, approve_jdk: bool, name: str = 'pin.json') -> Path:
    pin = json.loads(json.dumps(PIN))
    pin['license_policy']['allowed']['temurin-jdk']['owner_approved'] = approve_jdk
    path = root / name
    path.write_text(json.dumps(pin), encoding='utf-8')
    return path


def _package(root: Path) -> Path:
    package = root / 'PatchTrace'
    package.mkdir()
    (package / 'PatchTrace').write_bytes(b'exe')
    return package


@pytest.mark.parametrize('version', ['0.1.0', '1.2.3-rc1', 'v2'], ids=['plain', 'rc', 'prefixed'])
def test_archive_names_exact(version):
    assert linux.full_archive_name(version, 'windows') == f'PatchTrace-{version}-windows-x64-full.zip'
    assert linux.full_archive_name(version, 'linux') == f'PatchTrace-{version}-linux-x86_64-full.tar.gz'


@pytest.mark.parametrize('version', ['', '../x', 'a b', '-x', 'a' * 40], ids=['empty', 'dots', 'space', 'dash', 'long'])
def test_bad_version_rejected(version):
    with pytest.raises(ValueError):
        linux.validate_version(version)


def test_unknown_platform_rejected():
    with pytest.raises(ValueError):
        linux.full_archive_name('1.0', 'macos')


def test_sha256sums_text_sorted_lf_and_checkable():
    text = linux.sha256sums_text({'b.txt': 'b' * 64, 'a/x': 'a' * 64})
    assert text == f"{'a' * 64}  a/x\n{'b' * 64}  b.txt\n"
    assert '\r' not in text


@pytest.mark.parametrize('rel', ['con', 'NUL.txt', 'a/Com1.log', 'dir/aux.c', 'x/trail.', 'x/space '],
                         ids=['con', 'nul-ext', 'com1', 'aux', 'dot', 'space'])
def test_windows_reserved_names_flagged(rel):
    assert linux.windows_name_problems([rel, 'ok/file.txt']) == [rel]


def test_windows_clean_names_pass():
    assert linux.windows_name_problems(['console.txt', 'a/b/c.dll']) == []


def test_missing_exec_bits():
    modes = {'payload/jdk/bin/java': 0o644, 'payload/python/bin/python3': 0o755,
             'payload/ghidra/support/launch.sh': 0o600,
             'payload/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile': 0o644,
             'payload/LICENSES/NOTICE.txt': 0o644}
    assert linux.missing_exec_bits(modes) == [
        'payload/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile',
        'payload/ghidra/support/launch.sh', 'payload/jdk/bin/java']


@pytest.mark.parametrize(('mode', 'is_dir', 'expected'),
                         [(0o4755, False, 0o755), (0o600, False, 0o644), (0o664, False, 0o644),
                          (0o700, True, 0o755), (0o754, False, 0o755)],
                         ids=['setuid', 'private', 'groupw', 'dir', 'x'])
def test_normalized_mode(mode, is_dir, expected):
    assert linux.normalized_mode(mode, is_dir=is_dir) == expected


def test_payload_problems_clean_and_missing(tmp_path):
    assert linux.payload_problems(_payload(tmp_path), allow_internal_symlinks=False) == []
    (tmp_path / 'w').mkdir()
    assert linux.payload_problems(_payload(tmp_path / 'w', platform='windows'), allow_internal_symlinks=False,
                                  platform_key='windows') == []
    (tmp_path / 'empty').mkdir()
    problems = linux.payload_problems(tmp_path / 'empty', allow_internal_symlinks=False)
    assert [p.split(':')[0] for p in problems] == ['PT-BUNDLE-MISSING'] * 2


def test_payload_long_path_rejected(tmp_path):
    backend = _payload(tmp_path, extra={'d' * 160 + '/f': b'x'})
    problems = linux.payload_problems(backend, allow_internal_symlinks=True)
    assert any(p.startswith('PT-BUNDLE-PATH-LENGTH') for p in problems)


@pytest.mark.skipif(sys.platform == 'win32', reason='symlink creation needs privileges on Windows')
@pytest.mark.parametrize(('target', 'allow', 'bad'),
                         [('payload/jdk/bin/java', True, False), ('payload/jdk/bin/java', False, True),
                          ('OUTSIDE', True, True)], ids=['internal-ok', 'internal-denied', 'escape'])
def test_payload_symlinks(tmp_path, target, allow, bad):
    backend = _payload(tmp_path)
    (tmp_path / 'outside.txt').write_text('x')
    dest = tmp_path / 'outside.txt' if target == 'OUTSIDE' else backend / target
    (backend / 'payload' / 'link').symlink_to(dest)
    problems = linux.payload_problems(backend, allow_internal_symlinks=allow)
    assert bool([p for p in problems if p.startswith('PT-BUNDLE-LINK')]) is bad


def test_attach_backend_writes_sums_and_provenance(tmp_path):
    package = _package(tmp_path)
    backend = _payload(tmp_path)
    linux.attach_backend(package, backend, version='9.9.9', platform_key='linux', root=tmp_path,
                         allow_internal_symlinks=True)
    sums = (package / 'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines()
    listed = dict(line.split('  ', 1)[::-1] for line in sums)
    assert 'backend/manifest.json' in listed and 'PatchTrace' in listed
    assert 'SHA256SUMS.txt' not in listed and 'build-provenance.json' not in listed
    for rel, digest in listed.items():
        assert hashlib.sha256((package / rel).read_bytes()).hexdigest() == digest
    prov = json.loads((package / 'build-provenance.json').read_text(encoding='utf-8'))
    assert prov['schema'] == 'patchtrace-build-provenance/1' and prov['variant'] == 'full'
    assert prov['version'] == '9.9.9' and prov['file_count'] == len(listed)
    assert prov['backend_manifest_sha256'] == listed['backend/manifest.json']
    assert prov['sha256sums_sha256'] == hashlib.sha256((package / 'SHA256SUMS.txt').read_bytes()).hexdigest()
    with pytest.raises(linux.FullBuildError):  # second attach refuses to overlay
        linux.attach_backend(package, backend, version='9.9.9', platform_key='linux', root=tmp_path,
                             allow_internal_symlinks=True)


def test_attach_backend_rejects_reserved_windows_name(tmp_path):
    package = tmp_path / 'PatchTrace'
    package.mkdir()
    backend = _payload(tmp_path, extra={'ghidra/nul.txt': b'x'}, platform='windows')
    with pytest.raises(RuntimeError, match='reserved Windows name'):
        windows.attach_backend(package, backend, version='1.0', platform_key='windows', root=tmp_path,
                               allow_internal_symlinks=False)
    assert not (package / 'backend').exists()


def test_tar_gz_modes_owners_and_determinism(tmp_path):
    package = tmp_path / 'PatchTrace'
    (package / 'backend' / 'bin').mkdir(parents=True)
    run = package / 'backend' / 'bin' / 'java'
    run.write_bytes(b'x')
    run.chmod(0o775)
    data = package / 'data.txt'
    data.write_bytes(b'd')
    data.chmod(0o666)
    first, second = tmp_path / 'a.tar.gz', tmp_path / 'b.tar.gz'
    linux.write_tar_gz(package, first)
    linux.write_tar_gz(package, second)
    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first) as tar:
        members = {m.name: m for m in tar.getmembers()}
    # NTFS has no exec bit, so chmod(0o775) cannot survive on a Windows host (the Linux archive is built on
    # Linux in CI); the mode rule itself is covered platform-independently by test_tar_filter_mode_rule.
    assert members['PatchTrace/backend/bin/java'].mode == (0o644 if os.name == 'nt' else 0o755)
    assert members['PatchTrace/data.txt'].mode == 0o644
    assert members['PatchTrace'].isdir() and members['PatchTrace'].mode == 0o755
    assert all(m.uid == 0 and m.gid == 0 and m.uname == '' for m in members.values())
    assert gzip.decompress(first.read_bytes())[:1]  # valid gzip stream


@pytest.mark.parametrize(('mode', 'expected'), [(0o775, 0o755), (0o100, 0o755), (0o666, 0o644), (0o600, 0o644)],
                         ids=['group-exec', 'owner-exec', 'rw-all', 'owner-rw'])
def test_tar_filter_mode_rule(mode, expected):
    info = tarfile.TarInfo('PatchTrace/f')
    info.mode = mode
    out = linux.tar_filter(info)
    assert out.mode == expected and out.uid == out.gid == 0 and out.uname == out.gname == ''


def test_size_limit(tmp_path, monkeypatch):
    archive = tmp_path / 'x.zip'
    archive.write_bytes(b'12345')
    linux.check_archive_size(archive)
    monkeypatch.setattr(linux, 'FULL_SIZE_LIMIT', 4)
    with pytest.raises(linux.FullBuildError, match='PT-BUNDLE-SIZE-LIMIT'):
        linux.check_archive_size(archive)


def test_parse_args_defaults_are_lite():
    args = linux.parse_args([])
    assert (args.full, args.backend_payload, args.version) == (False, None, linux.VERSION)


@pytest.mark.parametrize('argv', [['--full'], ['--backend-payload', 'x'], ['--version', '../x'],
                                  ['--full', '--backend-payload', 'does-not-exist']],
                         ids=['full-needs-payload', 'payload-needs-full', 'bad-version', 'missing-dir'])
def test_parse_args_rejects(argv):
    with pytest.raises(SystemExit):
        linux.parse_args(argv)


def test_parse_args_full(tmp_path):
    args = windows.parse_args(['--full', '--backend-payload', str(tmp_path), '--version', '2.0.0'])
    assert args.full and args.backend_payload == tmp_path and args.version == '2.0.0'



# ---- CODEX-13: strict manifest + complete tree verification before anything is copied ---------------------

def _codes(problems):
    return sorted({p.split(':')[0] for p in problems})


def test_empty_manifest_and_empty_payload_is_refused(tmp_path):
    backend = tmp_path / 'backend-src'
    (backend / 'payload').mkdir(parents=True)
    (backend / 'manifest.json').write_text('{}', encoding='utf-8')
    assert 'PT-BUNDLE-MANIFEST' in _codes(linux.payload_problems(backend, allow_internal_symlinks=False))
    package = _package(tmp_path)
    with pytest.raises(linux.FullBuildError, match='PT-BUNDLE-MANIFEST'):
        linux.attach_backend(package, backend, version='1.0', platform_key='linux', root=tmp_path,
                             allow_internal_symlinks=False)
    assert sorted(p.name for p in package.iterdir()) == ['PatchTrace']  # nothing copied, no sums or provenance


def _extra_file(backend):
    (backend / 'payload' / 'stray.txt').write_bytes(b'x')


def _missing_file(backend):
    (backend / 'payload' / 'LICENSES' / 'NOTICE.txt').unlink()


def _wrong_size(backend):
    (backend / 'payload' / 'LICENSES' / 'NOTICE.txt').write_bytes(b'longer notice')


def _wrong_hash(backend):
    (backend / 'payload' / 'LICENSES' / 'NOTICE.txt').write_bytes(b'NOTICE')


def _duplicate_key(backend):
    text = (backend / 'manifest.json').read_text(encoding='utf-8')
    (backend / 'manifest.json').write_text(text.replace('{"format"', '{"format": "x", "format"', 1), encoding='utf-8')


@pytest.mark.parametrize(('tamper', 'code'), [(_extra_file, 'PT-BUNDLE-EXTRA'), (_missing_file, 'PT-BUNDLE-MISSING'),
                                              (_wrong_size, 'PT-BUNDLE-SIZE'), (_wrong_hash, 'PT-BUNDLE-HASH'),
                                              (_duplicate_key, 'PT-BUNDLE-MANIFEST')],
                         ids=['extra', 'missing', 'size', 'hash', 'duplicate-key'])
def test_tree_must_equal_manifest_exactly(tmp_path, tamper, code):
    backend = _payload(tmp_path)
    tamper(backend)
    assert code in _codes(linux.payload_problems(backend, allow_internal_symlinks=False))
    package = _package(tmp_path)
    with pytest.raises(linux.FullBuildError, match=code):
        linux.attach_backend(package, backend, version='1.0', platform_key='linux', root=tmp_path,
                             allow_internal_symlinks=False)
    assert not (package / 'backend').exists() and not (package / 'SHA256SUMS.txt').exists()


def test_manifest_platform_must_match_the_target(tmp_path):
    backend = _payload(tmp_path, platform='windows')
    assert 'PT-BUNDLE-MANIFEST' in _codes(linux.payload_problems(backend, allow_internal_symlinks=False,
                                                                 platform_key='linux'))


# ---- CODEX-15: licence policy gate ------------------------------------------------------------------------

@pytest.mark.parametrize('spdx', ['GPL-3.0-only', 'LGPL-2.1-only', 'AGPL-3.0-or-later'], ids=['gpl', 'lgpl', 'agpl'])
def test_unlisted_copyleft_component_is_refused(tmp_path, spdx):
    backend = _payload(tmp_path, third_party=_components(('mystery', spdx)))
    problems = linux.payload_problems(backend, allow_internal_symlinks=False)
    assert any(p.startswith('PT-BUNDLE-LICENSE') and 'mystery' in p for p in problems)


def test_listed_component_with_changed_spdx_is_refused(tmp_path):
    other = json.dumps({'components': [{'id': 'jdk', 'spdx': 'GPL-3.0-only'}]}).encode()
    problems = linux.payload_problems(_payload(tmp_path, third_party=other), allow_internal_symlinks=False)
    assert any(p.startswith('PT-BUNDLE-LICENSE') and 'jdk' in p for p in problems)


@pytest.mark.parametrize('content', [b'not json', b'{"components": 5}'], ids=['garbage', 'shape'])
def test_licence_inventory_must_be_readable(tmp_path, content):
    backend = _payload(tmp_path, third_party=content)
    assert any(p.startswith('PT-BUNDLE-LICENSE') for p in linux.payload_problems(backend, allow_internal_symlinks=False))


def test_missing_licence_inventory_is_refused(tmp_path):
    backend = _payload(tmp_path)
    (backend / 'payload' / 'LICENSES' / 'THIRD-PARTY.json').unlink()
    files = {p.relative_to(backend / 'payload').as_posix(): p.read_bytes()
             for p in (backend / 'payload').rglob('*') if p.is_file()}
    _write_manifest(backend, files, 'linux')
    assert any(p.startswith('PT-BUNDLE-LICENSE') for p in linux.payload_problems(backend, allow_internal_symlinks=False))


def test_ghidra_gpl_directory_in_payload_is_refused(tmp_path):
    backend = _payload(tmp_path, extra={'ghidra/GPL/Demangler/readme.txt': b'gpl'})
    assert any('GPL/' in p for p in linux.payload_problems(backend, allow_internal_symlinks=False))


def test_release_attach_refuses_pending_approval_and_acceptance_warns(tmp_path, capsys):
    backend = _payload(tmp_path)
    pending = _pin_file(tmp_path, approve_jdk=False, name='pending.json')
    approved = _pin_file(tmp_path, approve_jdk=True, name='approved.json')
    package = _package(tmp_path)
    with pytest.raises(linux.FullBuildError, match='PT-BUNDLE-LICENSE.*temurin-jdk'):
        linux.attach_backend(package, backend, version='1.0', platform_key='linux', root=tmp_path,
                             allow_internal_symlinks=False, release=True, pin_path=pending)
    assert not (package / 'backend').exists()
    linux.attach_backend(package, backend, version='1.0', platform_key='linux', root=tmp_path,
                         allow_internal_symlinks=False, release=False, pin_path=pending)
    assert 'PENDING' in capsys.readouterr().err
    prov = json.loads((package / 'build-provenance.json').read_text(encoding='utf-8'))
    assert prov['license_policy_pending_owner_approval'] == ['temurin-jdk']
    package2 = tmp_path / 'p2'
    package2.mkdir()
    linux.attach_backend(package2, backend, version='1.0', platform_key='linux', root=tmp_path,
                         allow_internal_symlinks=False, release=True, pin_path=approved)
    prov = json.loads((package2 / 'build-provenance.json').read_text(encoding='utf-8'))
    assert prov['license_policy_pending_owner_approval'] == []


def test_release_flag_requires_full():
    with pytest.raises(SystemExit):
        linux.parse_args(['--release'])
