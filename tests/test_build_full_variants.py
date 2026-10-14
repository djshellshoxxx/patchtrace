"""B8: pure helpers of the full-variant builders (synthetic payloads; real builds run only in CI)."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
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


def _payload(root: Path, *, extra: dict[str, bytes] | None = None) -> Path:
    backend = root / 'backend-src'
    files = {'manifest.json': b'{"schema":1}', 'payload/python/bin/python3': b'#!py',
             'payload/jdk/bin/java': b'ELF', 'payload/LICENSES/NOTICE.txt': b'notice', **(extra or {})}
    for rel, data in files.items():
        path = backend / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if '/bin/' in rel else 0o600)
    return backend


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
    (tmp_path / 'empty').mkdir()
    problems = linux.payload_problems(tmp_path / 'empty', allow_internal_symlinks=False)
    assert [p.split(':')[0] for p in problems] == ['PT-BUNDLE-MISSING'] * 2


def test_payload_long_path_rejected(tmp_path):
    backend = _payload(tmp_path, extra={'payload/' + 'd' * 160 + '/f': b'x'})
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
    package = tmp_path / 'PatchTrace'
    package.mkdir()
    (package / 'PatchTrace').write_bytes(b'exe')
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
    backend = _payload(tmp_path, extra={'payload/ghidra/nul.txt': b'x'})
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
    assert members['PatchTrace/backend/bin/java'].mode == 0o755
    assert members['PatchTrace/data.txt'].mode == 0o644
    assert members['PatchTrace'].isdir() and members['PatchTrace'].mode == 0o755
    assert all(m.uid == 0 and m.gid == 0 and m.uname == '' for m in members.values())
    assert gzip.decompress(first.read_bytes())[:1]  # valid gzip stream


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

