"""Source capture controls use authored bytes, independent of any decompressor."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from contextlib import contextmanager
from pathlib import PureWindowsPath
from threading import Event

import pytest

from patchtrace import cli
from patchtrace.acquisition import package_source as capture
from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.acquisition.package_budget import PackageBudget
from patchtrace.acquisition.package_contracts import PackageLimits


@pytest.mark.parametrize('path', [r'\\server\share\update.msu', r'\\?\C:\update.cab',
                                  r'\\.\pipe\test', r'C:drive-relative.cab', r'\rooted.cab',
                                  r'C:\updates\..\update.cab', r'C:\updates\update.cab:stream',
                                  r'C:\updates\NUL.cab', r'C:\updates\bad.\file.msu'])
def test_source_path_requires_ordinary_local_spelling(path):
    with pytest.raises(AcquisitionError):
        capture._local_path(PureWindowsPath(path))


@pytest.mark.parametrize('path', [r'C:\Updates\Monthly Update.msu', r'inputs\épreuve.cab'])
def test_local_source_accepts_absolute_or_working_directory_path(path):
    capture._local_path(PureWindowsPath(path))


@pytest.mark.parametrize('step', [1, 3, 99, 262144])
def test_hash_observes_entire_file_and_rewinds(tmp_path, step, monkeypatch):
    raw = b'MSCF' + bytes(range(53)) * 29
    path = tmp_path / 'input.cab'
    path.write_bytes(raw)
    real_read = os.read
    monkeypatch.setattr(capture.os, 'read', lambda fd, size: real_read(fd, min(size, step)))
    budget = PackageBudget(PackageLimits())
    with path.open('rb') as file:
        assert capture._hash_cabinet(file.fileno(), len(raw), budget) == hashlib.sha256(raw).hexdigest()
        assert file.tell() == 0
    assert budget.snapshot().hashed_input_bytes == len(raw)


@pytest.mark.parametrize(('delta', 'error'), [(-1, 'exceeds its captured size'), (1, 'ended before')])
def test_hash_rejects_length_disagreement(tmp_path, delta, error):
    raw = b'MSCF' + bytes(67)
    path = tmp_path / 'input'
    path.write_bytes(raw)
    budget = PackageBudget(PackageLimits())
    with path.open('rb') as file, pytest.raises(AcquisitionError, match=error):
        capture._hash_cabinet(file.fileno(), len(raw) + delta, budget)
    assert budget.snapshot().hashed_input_bytes == len(raw)


def test_hash_rejects_wrong_magic(tmp_path):
    path = tmp_path / 'renamed.msu'
    path.write_bytes(b'wrong prefix' + bytes(60))
    with path.open('rb') as file, pytest.raises(AcquisitionError, match='signature'):
        capture._hash_cabinet(file.fileno(), path.stat().st_size, PackageBudget(PackageLimits()))


def test_hash_observes_cancellation_before_next_read(tmp_path, monkeypatch):
    cancel = Event()
    budget = PackageBudget(PackageLimits(), cancel=cancel)
    cancel.set()
    monkeypatch.setattr(capture.os, 'read', lambda *_: pytest.fail('read after cancellation'))
    with pytest.raises(AcquisitionError, match='PT-ACQ-CANCEL'):
        capture._hash_cabinet(42, 64, budget)


def test_cli_waits_for_final_source_check(monkeypatch, capsys):
    class SyntheticSource:
        def model_dump(self, **kwargs):
            return {'authored': 'pending'}

    @contextmanager
    def changed(*_):
        yield SyntheticSource(), 42
        raise AcquisitionError('PT-ACQ-VERIFY', 'source identity changed')

    monkeypatch.setattr(capture, 'open_package_source', changed)
    assert cli.main(['package-source', 'irrelevant', '--json']) == 3
    output = json.loads(capsys.readouterr().out)
    assert output['status'] == 'failed' and output['result'] is None


@pytest.mark.skipif(sys.platform == 'win32', reason='unsupported-system refusal')
def test_nonwindows_cli_refuses_before_accessing_path(monkeypatch, capsys):
    monkeypatch.setattr(capture, 'WindowsPublication', lambda: pytest.fail('opened native library'))
    assert cli.main(['package-source', 'missing.cab', '--json']) == 2
    body = json.loads(capsys.readouterr().out)
    assert body['result'] is None and 'PT-ACQ-UNSUPPORTED' in body['error']


@pytest.mark.skipif(sys.platform != 'win32', reason='native Windows file identity and sharing')
def test_native_source_is_held_until_completion_and_released(tmp_path, capsys):
    raw = b'MSCF' + bytes(range(256)) * 2048
    package = tmp_path / 'authored package.msu'
    package.write_bytes(raw)
    with capture.open_package_source(package, PackageBudget(PackageLimits())) as (source, handle):
        assert handle > 0 and source.sha256 == hashlib.sha256(raw).hexdigest()
        assert source.file_identity.size == len(raw) and int(source.file_identity.file_id, 16)
        with pytest.raises(PermissionError), package.open('r+b'):
            pass
        with pytest.raises(PermissionError):
            package.rename(tmp_path / 'moved.msu')
    assert cli.main(['package-source', str(package), '--json']) == 0
    body = json.loads(capsys.readouterr().out)
    assert body['result'] == source.model_dump(mode='json')
    assert str(tmp_path) not in json.dumps(body)
    renamed = package.rename(tmp_path / 'after.cab')
    with capture.open_package_source(renamed, PackageBudget(PackageLimits())) as (later, _):
        assert later.file_identity == source.file_identity and later.source_id == source.source_id


@pytest.mark.skipif(sys.platform != 'win32', reason='native Windows size limit and handle cleanup')
def test_native_overlimit_refuses_and_releases_original(tmp_path):
    package = tmp_path / 'authored.cab'
    package.write_bytes(b'MSCF' + bytes(68))
    with pytest.raises(AcquisitionError, match='PT-ACQ-LIMIT'), capture.open_package_source(
        package, PackageBudget(PackageLimits(max_source_bytes=64))
    ):
        pytest.fail('source exceeded caller limit')
    package.unlink()


@pytest.mark.parametrize('fault', ['none', 'identity-after-hash', 'identity-at-close', 'parent-at-close', 'crt'])
def test_capture_transfers_or_closes_each_held_file_once(tmp_path, monkeypatch, fault):
    from types import SimpleNamespace

    data = b'MSCF' + bytes(64)
    leaf = tmp_path / 'payload.cab'
    leaf.write_bytes(data)
    handles = []
    native_closes = []

    class NativePath(PureWindowsPath):
        def absolute(self):
            return self

    class Win:
        def __init__(self):
            self.kernel = SimpleNamespace(GetDriveTypeW=lambda _: 3, CloseHandle=self.close)
            self.wt = SimpleNamespace(LPCWSTR=object, UINT=object)

        def directory(self, path, stack, *, create):
            assert not create
            return 'parent'

        def open_child(self, parent, name, *, directory, create):
            assert parent == 'parent' and name == 'input.cab' and not directory and not create
            fd = os.open(leaf, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
            handles.append(fd)
            return fd

        def close(self, handle):
            native_closes.append(handle)
            os.close(handle)
            return True

        def check_parent(self, *_):
            if fault == 'parent-at-close':
                raise capture.OwnedPublicationError('private path')

    class Descriptor:
        @staticmethod
        def open_osfhandle(handle, flags):
            if fault == 'crt':
                raise OSError('private path')
            return handle

    calls = 0

    def identity(_win, _handle, maximum):
        nonlocal calls
        calls += 1
        changed = (fault, calls) in {('identity-after-hash', 2), ('identity-at-close', 4)}
        return capture.PackageFileIdentity(volume_serial=1, file_id=('f' if changed else 'a') * 32,
                                           size=len(data), last_write_ticks=1)

    monkeypatch.setattr(capture, 'require_supported_platform', lambda: 'windows-amd64')
    monkeypatch.setattr(capture, 'WindowsPublication', Win)
    monkeypatch.setattr(capture, '_identity', identity)
    monkeypatch.setattr(os, 'O_BINARY', getattr(os, 'O_BINARY', 0), raising=False)
    monkeypatch.setitem(sys.modules, 'msvcrt', Descriptor)
    path = NativePath('C:/fixture/input.cab')
    if fault == 'none':
        assert capture.inspect_source(path).sha256 == hashlib.sha256(data).hexdigest()
    else:
        budget = PackageBudget(PackageLimits())
        with pytest.raises(AcquisitionError, match='PT-ACQ-VERIFY') as failure, capture.open_package_source(path, budget):
            pass
        assert budget.snapshot().failure_code == 'PT-ACQ-VERIFY'
        with pytest.raises(AcquisitionError) as retry:
            budget.check()
        assert failure.value is retry.value
        assert 'private path' not in str(failure.value)
    assert len(handles) == (2 if fault in ('none', 'identity-at-close') else 1)
    assert native_closes == (handles[-1:] if fault in ('none', 'identity-at-close', 'crt') else [])
    for fd in handles:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize('fault', ['none', 'digest', 'no-signature', 'renamed', 'warnings', 'stderr', 'mutated'])
def test_frozen_source_smoke_requires_complete_unchanged_fixture(tmp_path, monkeypatch, fault):
    from types import SimpleNamespace

    from tools import frozen_smoke

    def run(launcher, command, path, option):
        assert (launcher, command, option) == (['frozen-exe'], 'package-source', '--json')
        raw = path.read_bytes()
        identity = dict(volume_serial=1, file_id='a' * 32, size=len(raw), last_write_ticks=1)
        result = dict(sha256=hashlib.sha256(raw).hexdigest(), size=len(raw), display_name=path.name,
                      file_identity=identity, source_claims=[], signature_state='signature-unknown')
        if fault == 'digest':
            result['sha256'] = 'b' * 64
        if fault == 'no-signature':
            del result['signature_state']
        if fault == 'renamed':
            result['display_name'] = 'other.cab'
        if fault == 'mutated':
            path.write_bytes(b'changed')
        body = dict(contract='enrichment-cli/1', command=command, warnings=['warning'] if fault == 'warnings' else [],
                    status='complete', result=result)
        return SimpleNamespace(returncode=0, stdout=json.dumps(body) + '\n', stderr='warning' if fault == 'stderr' else '')

    monkeypatch.setattr(frozen_smoke, 'run', run)
    outcomes = []
    frozen_smoke.package_source_check(['frozen-exe'], tmp_path, lambda label, ok, detail: outcomes.append(ok))
    assert outcomes == [fault == 'none']
