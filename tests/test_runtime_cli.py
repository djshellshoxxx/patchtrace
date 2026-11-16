"""Runtime CLI contract with authored text archives; never native runtime evidence."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import zipfile
from pathlib import Path

import pytest
from test_offline_bundle import make_bundle
from test_offline_bundle_linux import LINUX_FILES, VERSIONS, linux_zip

from patchtrace import cli, offline_bundle, runtime_cli
from patchtrace.cli_commands import discover


def invoke(capsys, *args):
    code = cli.main(['runtime', *map(str, args), '--json'])
    output = capsys.readouterr()
    return code, json.loads(output.out), output.err


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def archive(tmp_path):
    return linux_zip(tmp_path) if sys.platform == 'linux' else make_bundle(tmp_path)


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))


def test_registration_and_help(capsys):
    commands, errors = discover()
    assert 'runtime' in commands and 'runtime' not in errors
    assert cli.main(['runtime', '--help']) == 0
    assert 'install-zip' in capsys.readouterr().out


@pytest.mark.parametrize('factory', [make_bundle, linux_zip])
@pytest.mark.parametrize('with_hash', [False, True])
def test_inspect_cross_platform_read_only(tmp_path, capsys, factory, with_hash):
    archive = factory(tmp_path)
    before = sorted(tmp_path.rglob('*'))
    extra = ['--sha256', digest(archive).upper()] if with_hash else []
    code, doc, _ = invoke(capsys, 'inspect-zip', archive, *extra)
    assert code == 0 and doc['command'] == 'runtime inspect-zip'
    result = doc['result']
    assert result['sha256'] == digest(archive)
    assert result['sha256_matched'] is (True if with_hash else None)
    assert result['files'] == 4 and result['contract'] == 'runtime-cli/1'
    assert 'not publisher authenticity' in result['authenticity']
    assert sorted(tmp_path.rglob('*')) == before


@pytest.mark.parametrize('value', ['x', '0' * 64])
def test_invalid_or_wrong_hash_refused(archive, capsys, value):
    code, doc, _ = invoke(capsys, 'inspect-zip', archive, '--sha256', value)
    assert code == 2 and doc['error'].startswith('PT-OFFLINE:')


def test_missing_confirmation_reads_nothing(archive, capsys, monkeypatch):
    monkeypatch.setattr(offline_bundle, 'inspect_offline_bundle', lambda *a, **k: pytest.fail('archive read'))
    code, doc, _ = invoke(capsys, 'install-zip', archive, '--sha256', digest(archive))
    assert code == 2 and '--confirm' in doc['error']


def test_install_roundtrip_and_no_overwrite(archive, tmp_path, capsys):
    root = tmp_path / 'nested' / 'runtimes'
    arguments = ('install-zip', archive, '--sha256', digest(archive).upper(), '--confirm', '--runtimes-dir', root)
    code, doc, _ = invoke(capsys, *arguments)
    assert code == 0
    result = doc['result']
    assert Path(result['python_executable']).is_file()
    assert Path(result['manifest']).is_file()
    assert result['archive_sha256'] == digest(archive)
    files = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    code, doc, _ = invoke(capsys, *arguments)
    assert code == 2 and 'already installed' in doc['error']
    assert files == {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert not list(root.glob('.install-*')) and not list(root.glob('*.lock'))


def test_install_rejects_other_platform(tmp_path, capsys):
    archive = make_bundle(tmp_path) if sys.platform == 'linux' else linux_zip(tmp_path)
    root = tmp_path / 'runtimes'
    code, _, _ = invoke(capsys, 'install-zip', archive, '--sha256', digest(archive), '--confirm', '--runtimes-dir', root)
    assert code == 2 and not root.exists()


@pytest.mark.parametrize('failure', ['cancel', 'keyboard', 'error'])
def test_failed_install_removes_only_owned_empty_ancestors(archive, tmp_path, capsys, monkeypatch, failure):
    root = tmp_path / 'fresh' / 'nested' / 'runtimes'
    original = offline_bundle._verify_stream
    calls = 0

    def stop(stream, expected, cancel, output=None):
        nonlocal calls
        if output is not None:
            calls += 1
            if failure == 'cancel':
                raise offline_bundle.OfflineBundleCancelled('PT-CANCEL: synthetic interruption')
            if failure == 'keyboard':
                raise KeyboardInterrupt()
            raise OSError('synthetic write error')
        return original(stream, expected, cancel, output)

    monkeypatch.setattr(offline_bundle, '_verify_stream', stop)
    code, _, _ = invoke(capsys, 'install-zip', archive, '--sha256', digest(archive), '--confirm', '--runtimes-dir', root)
    assert code == (3 if failure == 'error' else 5) and calls == 1
    assert not (tmp_path / 'fresh').exists()


def test_interrupt_after_publish_keeps_runtime(archive, tmp_path, capsys, monkeypatch):
    original = offline_bundle.install_offline_bundle
    root = tmp_path / 'nested' / 'runtimes'

    def installed_then_interrupted(*args, **kwargs):
        original(*args, **kwargs)
        raise KeyboardInterrupt()

    monkeypatch.setattr(offline_bundle, 'install_offline_bundle', installed_then_interrupted)
    code, doc, _ = invoke(capsys, 'install-zip', archive, '--sha256', digest(archive), '--confirm', '--runtimes-dir', root)
    assert code == 5 and 'retained' in doc['error']
    assert len(list(root.glob('*/manifest.json'))) == 1


def test_cleanup_preserves_replacement_and_foreign_contents(tmp_path):
    root = tmp_path / 'owned'
    root.mkdir()
    identity = root.stat()
    root.rename(tmp_path / 'original')
    root.mkdir()
    runtime_cli._cleanup([(root, identity)])
    assert root.exists()
    identity = root.stat()
    (root / 'foreign').write_text('keep')
    runtime_cli._cleanup([(root, identity)])
    assert (root / 'foreign').read_text() == 'keep'


@pytest.mark.parametrize('mode', ['relative', 'missing-home', 'unsupported'])
def test_invalid_environment_refuses_before_archive_read(archive, capsys, monkeypatch, mode):
    extra = []
    if mode == 'relative':
        extra = ['--runtimes-dir', 'relative']
    elif mode == 'missing-home':
        monkeypatch.delenv('HOME', raising=False)
        monkeypatch.delenv('LOCALAPPDATA', raising=False)
    else:
        monkeypatch.setattr(runtime_cli.sys, 'platform', 'darwin')
    monkeypatch.setattr(offline_bundle, 'inspect_offline_bundle', lambda *a, **k: pytest.fail('read'))
    code, _, _ = invoke(capsys, 'install-zip', archive, '--sha256', digest(archive), '--confirm', *extra)
    assert code == 2


def test_default_root(archive, capsys, tmp_path):
    code, doc, _ = invoke(capsys, 'install-zip', archive, '--sha256', digest(archive), '--confirm')
    assert code == 0 and Path(doc['result']['root']).is_relative_to(tmp_path)


def test_cancel_before_inspection(archive):
    args = cli._parser(['runtime']).parse_args(['runtime', 'inspect-zip', str(archive), '--json'])
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(runtime_cli.CliError) as error:
        runtime_cli.run(args, cancel)
    assert error.value.code == 5


def test_no_qt_and_no_execution_or_network(archive):
    code = '''import sys, socket, subprocess
from patchtrace import cli
from patchtrace import runtime_cli
def fail(*args, **kwargs): raise AssertionError("unexpected execution/network")
socket.socket = fail
subprocess.Popen = fail
assert cli.main(["runtime", "inspect-zip", sys.argv[1], "--json"]) == 0
import hashlib
digest = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
assert cli.main(["runtime", "install-zip", sys.argv[1], "--sha256", digest, "--confirm", "--runtimes-dir", sys.argv[2], "--json"]) == 0
assert not any(n.startswith("PySide6") for n in sys.modules)
'''
    env = dict(os.environ, PYTHONPATH=str(Path(cli.__file__).resolve().parents[1]))
    result = subprocess.run([sys.executable, '-c', code, str(archive), str(archive.parent / 'subprocess-runtime')], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name == 'nt', reason='POSIX executable modes')
def test_linux_producer_install_preserves_only_safe_modes(tmp_path):
    source = tmp_path / 'source'
    for name, data in LINUX_FILES.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o6777 if name in ('python/bin/python3', 'jdk/bin/java') else 0o666)
    archive = offline_bundle.build_offline_bundle(source, 'linux-safe', VERSIONS, tmp_path / 'runtime.zip', platform='linux')
    installed = offline_bundle.install_offline_bundle(
        offline_bundle.inspect_offline_bundle(archive, platforms=('linux',)), tmp_path / 'runtimes')
    assert stat.S_IMODE(installed.python_executable.stat().st_mode) == 0o755
    assert stat.S_IMODE((installed.java_home / 'bin/java').stat().st_mode) == 0o755
    assert stat.S_IMODE((installed.root / 'payload/LICENSES/NOTICE.txt').stat().st_mode) == 0o644


def test_legacy_linux_missing_execute_bits_refused_before_writes(tmp_path):
    source = linux_zip(tmp_path)
    legacy = tmp_path / 'legacy.zip'
    with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(legacy, 'w') as outgoing:
        for info in incoming.infolist():
            info.external_attr = 0o100644 << 16
            outgoing.writestr(info, incoming.read(info.filename))
    plan = offline_bundle.inspect_offline_bundle(legacy, platforms=('linux',))
    with pytest.raises(offline_bundle.OfflineBundleError, match='rebuild'):
        offline_bundle.install_offline_bundle(plan, tmp_path / 'runtimes')
    assert not (tmp_path / 'runtimes').exists()


def test_mkdir_failure_has_typed_error_and_owned_ancestor_cleanup(archive, tmp_path, capsys, monkeypatch):
    root = tmp_path / 'fresh' / 'runtimes'
    original = Path.mkdir

    def fail(path, *args, **kwargs):
        if path == root:
            raise PermissionError('injected')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'mkdir', fail)
    code, doc, _ = invoke(capsys, 'install-zip', archive, '--sha256', digest(archive), '--confirm', '--runtimes-dir', root)
    assert code == 3 and doc['error'].startswith('PT-OFFLINE:')
    assert not root.parent.exists()


def test_linux_metadata_recheck_failure_is_typed(tmp_path, monkeypatch):
    archive = linux_zip(tmp_path)
    plan = offline_bundle.inspect_offline_bundle(archive, platforms=('linux',))
    original = offline_bundle.inspect_offline_bundle

    def replace_after_verification(*args, **kwargs):
        verified = original(*args, **kwargs)
        archive.write_bytes(b'corrupt after reinspection')
        return verified

    monkeypatch.setattr(offline_bundle, 'inspect_offline_bundle', replace_after_verification)
    with pytest.raises(offline_bundle.OfflineBundleError, match='PT-OFFLINE: cannot verify Linux launcher metadata'):
        offline_bundle.install_offline_bundle(plan, tmp_path / 'runtimes')
    assert not (tmp_path / 'runtimes').exists()


def test_inspection_does_not_advertise_installation_on_unsupported_host(tmp_path, capsys, monkeypatch):
    archive = linux_zip(tmp_path)
    monkeypatch.setattr(runtime_cli.sys, 'platform', 'darwin')
    code, doc, _ = invoke(capsys, 'inspect-zip', archive)
    assert code == 0 and doc['result']['host_platform'] == 'darwin'
    assert doc['result']['installable_here'] is False
