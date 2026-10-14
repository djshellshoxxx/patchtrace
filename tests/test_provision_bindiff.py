"""SPEC-29 D4/D5/§10: CI provisioning of the pinned BinDiff without installing or executing it (mocked I/O).

Synthetic `.deb`/`.msi` stand-ins are built here; no network, no `dpkg`, no `msiexec`. The committed pin is
checked for the real v8 values (trust-on-first-use, see tools/bindiff_pin.json).
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import provision_bindiff as pb  # noqa: E402

EXE_BYTES = b'\x7fELF fake bindiff, never executed\n'
DEB_SHA = '821990e3974a9df6733794370e485486ac276ba5d777a06b4ebe575f092f4dda'
MSI_SHA = '688831e490bef8a20c9917048b693bad591f346b3b96489fc79ad8d20d7cb15f'


def _tar(entries, compression: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=f'w:{compression}' if compression else 'w') as tar:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == 'dir':
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            elif kind == 'file':
                info.size, info.mode = len(payload), 0o755 if name.endswith('bindiff') else 0o644
                tar.addfile(info, io.BytesIO(payload))
            elif kind == 'symlink':
                info.type, info.linkname = tarfile.SYMTYPE, payload
                tar.addfile(info)
            elif kind == 'hardlink':
                info.type, info.linkname = tarfile.LNKTYPE, payload
                tar.addfile(info)
    return buf.getvalue()


DEFAULT_ENTRIES = [
    ('./', 'dir', None), ('./opt/', 'dir', None), ('./opt/bindiff/', 'dir', None),
    ('./opt/bindiff/bin/', 'dir', None), ('./opt/bindiff/bin/bindiff', 'file', EXE_BYTES),
    ('./opt/bindiff/bin/bindiff_ui', 'symlink', 'bindiff'), ('./opt/bindiff/LICENSE', 'file', b'Apache-2.0\n'),
    ('./usr/', 'dir', None), ('./usr/bin/', 'dir', None),
    ('./usr/bin/bindiff', 'symlink', '/opt/bindiff/bin/bindiff'),
    ('./usr/bin/hard', 'hardlink', './opt/bindiff/LICENSE'),
]


def make_deb(path: Path, entries=None, *, compression: str = 'xz', data_name: str | None = None,
             debian_binary: bytes = b'2.0\n') -> Path:
    data = _tar(DEFAULT_ENTRIES if entries is None else entries, compression)
    control = _tar([('./control', 'file', b'Package: bindiff\n')], 'gz')
    out = bytearray(b'!<arch>\n')
    members = [('debian-binary', debian_binary), ('control.tar.gz', control),
               (data_name or ('data.tar.' + compression if compression else 'data.tar'), data)]
    for name, payload in members:
        out += f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(payload):<10}`\n'.encode('ascii')
        out += payload + (b'\n' if len(payload) % 2 else b'')
    path.write_bytes(bytes(out))
    return path


def write_pin(tmp_path: Path, os_name: str, archive_bytes: bytes, **extra) -> Path:
    asset = {'name': 'x', 'url': pb.ALLOWED_PREFIX + 'v8/x', 'size': len(archive_bytes),
             'sha256': hashlib.sha256(archive_bytes).hexdigest(), **extra}
    path = tmp_path / 'pin.json'
    path.write_text(json.dumps({'contract': 'bindiff-pin/1', 'version': '8', 'version_text': 'BinDiff 8 (@1)',
                                'trust': 'trust-on-first-use', 'assets': {os_name: asset}}), encoding='utf-8')
    return path


def serve(monkeypatch, payload: bytes) -> list[str]:
    urls: list[str] = []

    def urlopen(url, timeout):
        urls.append(url)
        return io.BytesIO(payload)

    monkeypatch.setattr(pb.urllib.request, 'urlopen', urlopen)
    return urls


def no_subprocess(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError(f'provisioning must not run external programs on Linux: {args!r}')

    monkeypatch.setattr(pb.subprocess, 'run', refuse)


def status(tmp_path: Path) -> dict:
    return json.loads((tmp_path / 'status' / 'bindiff-provision.json').read_text(encoding='utf-8'))


def run_main(tmp_path: Path, os_name: str, pin: Path, *extra: str) -> int:
    return pb.main(['--os', os_name, '--pin', str(pin), '--cache', str(tmp_path / 'cache'), '--dest',
                    str(tmp_path / 'dest'), '--status-dir', str(tmp_path / 'status'), '--github-env',
                    str(tmp_path / 'github.env'), *extra])


def github_env(tmp_path: Path) -> dict[str, str]:
    path = tmp_path / 'github.env'
    if not path.exists():
        return {}
    return dict(line.split('=', 1) for line in path.read_text(encoding='utf-8').splitlines() if line)


# ---- committed pin ---------------------------------------------------------------------------------------------

def test_committed_pin_holds_real_v8_values_marked_trust_on_first_use():
    pin = json.loads((ROOT / 'tools' / 'bindiff_pin.json').read_text(encoding='utf-8'))
    assert pin['contract'] == 'bindiff-pin/1' and pin['version'] == '8'
    assert pin['version_text'] == 'BinDiff 8 (@568181968, Sep 25 2023)'
    assert pin['verified'] is False and 'trust-on-first-use' in pin['trust']
    assert pin['signature']['verified'] is False and pin['signature']['issuer_key_id'] == '4EB27DB2A3B88B8B'
    linux, windows = pin['assets']['linux'], pin['assets']['windows']
    assert (linux['name'], linux['size'], linux['sha256']) == ('bindiff_8_amd64.deb', 62_663_460, DEB_SHA)
    assert linux['url'] == pb.ALLOWED_PREFIX + 'v8/bindiff_8_amd64.deb' and not linux['advisory']
    assert linux['executable'] == 'opt/bindiff/bin/bindiff' and linux['executable_size'] == 3_894_808
    assert linux['executable_sha256'] == 'eb0a88eb6518e000bc3c4eef66c22db7ace197173eb933ea5d1c8ac3f7d8d0fb'
    assert (windows['name'], windows['size'], windows['sha256']) == ('bindiff8.msi', 72_237_056, MSI_SHA)
    assert windows['url'] == pb.ALLOWED_PREFIX + 'v8/bindiff8.msi' and windows['advisory'] is True
    assert windows['executable_sha256'] == 'b1d4844d7c7f1ca7f9684e280e0807668633e1b2410b31beca5c9ace79b747dd'
    for os_name in ('linux', 'windows'):
        loaded = pb.load_pin(ROOT / 'tools' / 'bindiff_pin.json', os_name)
        assert loaded['sha256'] == pin['assets'][os_name]['sha256']


def test_pin_without_values_still_blocks_without_downloading(tmp_path, monkeypatch):
    urls = serve(monkeypatch, b'never')
    pin = tmp_path / 'pin.json'
    pin.write_text(json.dumps({'contract': 'bindiff-pin/1', 'version': '8', 'gap': 'no values',
                               'assets': {'linux': {'url': None, 'sha256': None, 'size': None}}}))
    assert run_main(tmp_path, 'linux', pin) == 0
    assert status(tmp_path)['status'] == 'blocked' and status(tmp_path)['reason'].startswith('pin-missing')
    assert urls == [] and not (tmp_path / 'cache').exists() and github_env(tmp_path) == {}


# ---- stdlib .deb extraction -------------------------------------------------------------------------------------

@pytest.mark.parametrize('compression', ['xz', 'gz', 'bz2', ''])
def test_deb_extraction_writes_regular_files_and_dirs_only(tmp_path, compression):
    deb = make_deb(tmp_path / 'b.deb', compression=compression)
    dest = tmp_path / 'dest'
    dest.mkdir()
    stats = pb.extract_deb(deb, dest)
    exe = dest / 'opt' / 'bindiff' / 'bin' / 'bindiff'
    assert exe.read_bytes() == EXE_BYTES and not exe.is_symlink()
    if sys.platform != 'win32':
        assert exe.stat().st_mode & 0o777 == 0o755
        assert (dest / 'opt' / 'bindiff' / 'LICENSE').stat().st_mode & 0o777 == 0o644
    for link in ('opt/bindiff/bin/bindiff_ui', 'usr/bin/bindiff', 'usr/bin/hard'):
        assert not (dest / link).exists() and not (dest / link).is_symlink()  # links are never materialised
    assert stats == {'files': 2, 'dirs': 5, 'skipped_links': 3, 'bytes': len(EXE_BYTES) + len(b'Apache-2.0\n')}


@pytest.mark.parametrize('name', ['../evil', '/abs/evil', './opt/../../evil', 'C:/evil', 'a\\..\\evil'])
def test_deb_extraction_rejects_unsafe_member_names(tmp_path, name):
    deb = make_deb(tmp_path / 'b.deb', [('./opt/', 'dir', None), (name, 'file', b'x')])
    dest = tmp_path / 'deep' / 'dest'
    dest.mkdir(parents=True)
    with pytest.raises(pb.Failed, match='unsafe'):
        pb.extract_deb(deb, dest)
    assert not (tmp_path / 'evil').exists() and not (tmp_path / 'deep' / 'evil').exists()


def test_deb_extraction_rejects_duplicates_bad_ar_and_unsupported_compression(tmp_path):
    dup = make_deb(tmp_path / 'dup.deb', [('./a', 'file', b'1'), ('./a', 'file', b'2')])
    with pytest.raises(pb.Failed, match='duplicate'):
        pb.extract_deb(dup, tmp_path / 'd1')
    bad = tmp_path / 'bad.deb'
    bad.write_bytes(b'not an ar archive')
    with pytest.raises(pb.Failed, match='ar magic'):
        pb.extract_deb(bad, tmp_path / 'd2')
    truncated = tmp_path / 'trunc.deb'
    truncated.write_bytes(make_deb(tmp_path / 'ok.deb').read_bytes()[:-500])
    with pytest.raises(pb.Failed):
        pb.extract_deb(truncated, tmp_path / 'd3')
    zst = make_deb(tmp_path / 'zst.deb', compression='xz', data_name='data.tar.zst')
    with pytest.raises(pb.Failed, match='zst'):
        pb.extract_deb(zst, tmp_path / 'd4')
    not_deb = make_deb(tmp_path / 'v1.deb', debian_binary=b'1.0\n')
    with pytest.raises(pb.Failed, match='debian-binary'):
        pb.extract_deb(not_deb, tmp_path / 'd5')


def test_deb_extraction_caps_total_size_and_member_count(tmp_path, monkeypatch):
    deb = make_deb(tmp_path / 'b.deb')
    monkeypatch.setattr(pb, 'MAX_EXTRACT_BYTES', 8)
    with pytest.raises(pb.Failed, match='size limit'):
        pb.extract_deb(deb, tmp_path / 'd1')
    monkeypatch.setattr(pb, 'MAX_EXTRACT_BYTES', 1 << 30)
    monkeypatch.setattr(pb, 'MAX_MEMBERS', 3)
    with pytest.raises(pb.Failed, match='members'):
        pb.extract_deb(deb, tmp_path / 'd2')


# ---- end-to-end provisioning (mocked download) ------------------------------------------------------------------

def test_linux_provisioning_extracts_verifies_and_exports_env_without_running_anything(tmp_path, monkeypatch):
    deb = make_deb(tmp_path / 'b.deb').read_bytes()
    pin = write_pin(tmp_path, 'linux', deb, executable='opt/bindiff/bin/bindiff', executable_size=len(EXE_BYTES),
                    executable_sha256=hashlib.sha256(EXE_BYTES).hexdigest(), advisory=False)
    urls = serve(monkeypatch, deb)
    no_subprocess(monkeypatch)
    assert run_main(tmp_path, 'linux', pin) == 0
    record = status(tmp_path)
    exe = (tmp_path / 'dest' / 'opt' / 'bindiff' / 'bin' / 'bindiff').resolve()
    assert record['status'] == 'passed' and record['extraction'].startswith('stdlib ar+tar')
    assert record['executable'] == 'opt/bindiff/bin/bindiff' and record['skipped_links'] == 3
    assert record['executable_sha256'] == hashlib.sha256(EXE_BYTES).hexdigest() and record['advisory'] is False
    assert github_env(tmp_path) == {'PATCHTRACE_BINDIFF': str(exe), 'PATCHTRACE_REQUIRE_LIVE_BINDIFF': '1',
                                    'PATCHTRACE_BINDIFF_EXPECTED_VERSION': '8 (@1)'}
    assert urls == [pb.ALLOWED_PREFIX + 'v8/x']
    # Second run is served from the cache (no download) and re-extracts into the tool's own destination.
    assert run_main(tmp_path, 'linux', pin) == 0 and len(urls) == 1


def test_linux_executable_hash_mismatch_fails(tmp_path, monkeypatch):
    deb = make_deb(tmp_path / 'b.deb').read_bytes()
    pin = write_pin(tmp_path, 'linux', deb, executable='opt/bindiff/bin/bindiff', executable_size=len(EXE_BYTES),
                    executable_sha256='0' * 64, advisory=False)
    serve(monkeypatch, deb)
    assert run_main(tmp_path, 'linux', pin) == 1
    assert status(tmp_path)['status'] == 'failed' and 'executable' in status(tmp_path)['reason']
    assert github_env(tmp_path) == {}


def test_asset_digest_mismatch_fails_even_in_advisory_mode(tmp_path, monkeypatch):
    pin = write_pin(tmp_path, 'windows', b'expected msi bytes', advisory=True)
    serve(monkeypatch, b'tampered msi bytes')
    assert run_main(tmp_path, 'windows', pin, '--advisory') == 1
    assert status(tmp_path)['status'] == 'failed' and 'mismatch' in status(tmp_path)['reason']


def test_destination_not_created_by_the_tool_is_never_deleted(tmp_path, monkeypatch):
    deb = make_deb(tmp_path / 'b.deb').read_bytes()
    pin = write_pin(tmp_path, 'linux', deb, executable='opt/bindiff/bin/bindiff', advisory=False)
    serve(monkeypatch, deb)
    (tmp_path / 'dest').mkdir()
    keep = tmp_path / 'dest' / 'precious.txt'
    keep.write_text('user data')
    assert run_main(tmp_path, 'linux', pin) == 1
    assert keep.read_text() == 'user data' and 'not created by' in status(tmp_path)['reason']


def _fake_msiexec(tmp_path: Path, exe_bytes: bytes | None, returncode: int = 0):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        target = Path(next(a for a in argv if a.startswith('TARGETDIR=')).split('=', 1)[1])
        if exe_bytes is not None:
            (target / 'PFiles64' / 'BinDiff' / 'bin').mkdir(parents=True)
            (target / 'PFiles64' / 'BinDiff' / 'bin' / 'bindiff.exe').write_bytes(exe_bytes)

        class Done:
            pass

        done = Done()
        done.returncode, done.stdout, done.stderr = returncode, '', ''
        return done

    return calls, run


def _system_root(tmp_path: Path, dlls=('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll')) -> Path:
    root = tmp_path / 'Windows'
    (root / 'System32').mkdir(parents=True)
    for dll in dlls:
        (root / 'System32' / dll).write_bytes(b'MZ')
    return root


@pytest.mark.parametrize('exe_bytes, returncode, dlls, needle', [
    (None, 1603, ('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll'), 'msiexec'),
    (None, 0, ('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll'), 'bindiff.exe'),
    (b'MZ other build', 0, ('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll'), 'executable'),
    (EXE_BYTES, 0, ('vcruntime140.dll', 'msvcp140.dll'), 'vcruntime140_1.dll'),
])
def test_windows_advisory_problems_are_blocked_unverified_not_failed(tmp_path, monkeypatch, exe_bytes, returncode,
                                                                      dlls, needle):
    msi = b'msi bytes'
    pin = write_pin(tmp_path, 'windows', msi, executable='ProgramFiles/BinDiff/bin/bindiff.exe',
                    executable_size=len(EXE_BYTES), executable_sha256=hashlib.sha256(EXE_BYTES).hexdigest(),
                    advisory=True)
    serve(monkeypatch, msi)
    calls, fake = _fake_msiexec(tmp_path, exe_bytes, returncode)
    monkeypatch.setattr(pb.subprocess, 'run', fake)
    monkeypatch.setenv('SystemRoot', str(_system_root(tmp_path, dlls)))
    assert run_main(tmp_path, 'windows', pin, '--advisory') == 0
    record = status(tmp_path)
    assert record['status'] == 'blocked' and record['reason'].startswith('unverified:') and needle in record['reason']
    assert record['advisory'] is True and github_env(tmp_path) == {}
    assert calls and calls[0][:2] == ['msiexec', '/a'] and '/qn' in calls[0]


def test_windows_advisory_success_exports_tool_but_does_not_require_live(tmp_path, monkeypatch):
    msi = b'msi bytes'
    pin = write_pin(tmp_path, 'windows', msi, executable='ProgramFiles/BinDiff/bin/bindiff.exe',
                    executable_size=len(EXE_BYTES), executable_sha256=hashlib.sha256(EXE_BYTES).hexdigest(),
                    advisory=True)
    serve(monkeypatch, msi)
    _, fake = _fake_msiexec(tmp_path, EXE_BYTES)
    monkeypatch.setattr(pb.subprocess, 'run', fake)
    monkeypatch.setenv('SystemRoot', str(_system_root(tmp_path)))
    assert run_main(tmp_path, 'windows', pin, '--advisory') == 0
    record = status(tmp_path)
    assert record['status'] == 'passed' and record['executable'] == 'PFiles64/BinDiff/bin/bindiff.exe'
    assert record['redist'] == {'vcruntime140.dll': True, 'vcruntime140_1.dll': True, 'msvcp140.dll': True}
    env = github_env(tmp_path)
    assert env['PATCHTRACE_BINDIFF'].endswith('bindiff.exe') and 'PATCHTRACE_REQUIRE_LIVE_BINDIFF' not in env


def test_windows_without_advisory_fails_on_extraction_problems(tmp_path, monkeypatch):
    msi = b'msi bytes'
    pin = write_pin(tmp_path, 'windows', msi, advisory=True)
    serve(monkeypatch, msi)
    _, fake = _fake_msiexec(tmp_path, None, 1603)
    monkeypatch.setattr(pb.subprocess, 'run', fake)
    assert run_main(tmp_path, 'windows', pin) == 1
    assert status(tmp_path)['status'] == 'failed'


def test_redist_preflight_reports_each_runtime_dll(tmp_path):
    root = _system_root(tmp_path, ('msvcp140.dll',))
    assert pb.redist_status(str(root)) == {'vcruntime140.dll': False, 'vcruntime140_1.dll': False,
                                           'msvcp140.dll': True}
    assert pb.redist_status(None) == {'vcruntime140.dll': False, 'vcruntime140_1.dll': False,
                                      'msvcp140.dll': False}


def test_github_env_values_cannot_inject_lines(tmp_path):
    with pytest.raises(pb.Failed, match='newline'):
        pb.export_env(tmp_path / 'env', {'PATCHTRACE_BINDIFF': '/x\nEVIL=1'})
