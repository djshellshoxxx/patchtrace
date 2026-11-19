"""Real receipt filesystem races; substitute engine work supplies no native engine evidence."""
from __future__ import annotations

import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import receipts
from tools.calibration.tier_r import research_build as B
from tools.calibration.tier_r import research_pilot as P
from tools.calibration.tier_r.receipts import write_new_receipt
from tools.calibration.tier_r.schemas import example_labels


def _invoke(monkeypatch, tmp_path, output, kind):
    receipt = {'status': 'built', 'entries': [{'pair_id': 'kept', 'sha256': 'a' * 64}],
               'engines': {'ghidriff': {'status': 'ok'}}}
    if kind == 'build':
        monkeypatch.setattr(B, 'build_pilot', lambda *a, **k: receipt)
        return B.main(['--store', str(tmp_path / 'store'), '--output', str(output)]), receipt
    labels = tmp_path / 'labels.json'
    labels.write_bytes(C.dump_json(C.finalize_labels(example_labels())))
    monkeypatch.setattr(P, 'run_pilot', lambda *a, **k: receipt)
    return P.main(['--labels', str(labels), '--store', str(tmp_path / 'store'),
                   '--work', str(output.parent), '--output', str(output),
                   '--ghidra-dir', str(tmp_path / 'ghidra')]), receipt


@pytest.mark.skipif(os.name != 'posix', reason='POSIX rename/symlink race; Windows has separate handle-lock tests')
@pytest.mark.parametrize('kind', ['build', 'pilot'])
@pytest.mark.parametrize('replace_ancestor', [False, True])
def test_parent_replacement_at_final_create_cannot_redirect_receipt(
        monkeypatch, tmp_path, capsys, kind, replace_ancestor):
    output = tmp_path / 'original' / 'nested' / 'receipt.json'
    output.parent.mkdir(parents=True)
    victim_parent = output.parent.parent if replace_ancestor else output.parent
    retained = tmp_path / 'retained'
    attacker = tmp_path / 'attacker'
    attacker.mkdir()
    if replace_ancestor:
        (attacker / 'nested').mkdir()
    redirected = attacker / ('nested/receipt.json' if replace_ancestor else 'receipt.json')
    original_open, original_os_open = Path.open, os.open
    replaced = False

    def replace_parent():
        nonlocal replaced
        if not replaced:
            victim_parent.rename(retained)
            victim_parent.symlink_to(attacker, target_is_directory=True)
            replaced = True

    def path_open(path, mode='r', *args, **kwargs):
        if path == output and 'x' in mode:
            replace_parent()
        return original_open(path, mode, *args, **kwargs)

    def fd_open(path, flags, *args, **kwargs):
        if flags & os.O_CREAT and Path(path).name == output.name:
            replace_parent()
        return original_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', path_open)
    monkeypatch.setattr(os, 'open', fd_open)
    code, receipt = _invoke(monkeypatch, tmp_path, output, kind)
    assert replaced, 'the test must reach the real final creation boundary'
    assert not redirected.exists(), 'receipt bytes escaped into the substituted directory'
    assert code == 2, 'a moved output parent must be reported rather than claiming its old path was published'
    error = json.loads(capsys.readouterr().out)
    assert error['status'] == 'error' and error['receipt'] == receipt
    retained_receipt = retained / ('nested/receipt.json' if replace_ancestor else 'receipt.json')
    assert json.loads(retained_receipt.read_bytes()) == receipt, 'original directory evidence is retained'


@pytest.mark.parametrize('kind', ['build', 'pilot'])
def test_late_existing_receipt_preserves_all_run_evidence(monkeypatch, tmp_path, capsys, kind):
    output = tmp_path / 'work' / 'receipt.json'
    output.parent.mkdir()
    original_open, original_os_open = Path.open, os.open
    raced = False

    def occupy():
        nonlocal raced
        if not raced:
            with original_open(output, 'xb') as stream:
                stream.write(b'other run evidence')
            raced = True

    def path_open(path, mode='r', *args, **kwargs):
        if path == output and 'x' in mode:
            occupy()
        return original_open(path, mode, *args, **kwargs)

    def fd_open(path, flags, *args, **kwargs):
        if flags & os.O_CREAT and Path(path).name == output.name:
            occupy()
        return original_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', path_open)
    monkeypatch.setattr(os, 'open', fd_open)
    code, receipt = _invoke(monkeypatch, tmp_path, output, kind)
    assert raced and code == 2
    assert output.read_bytes() == b'other run evidence'
    error = json.loads(capsys.readouterr().out)
    assert error['status'] == 'error' and error['receipt'] == receipt


@pytest.mark.skipif(os.name != 'posix', reason='POSIX directory-relative primitive test')
def test_link_substituted_between_missing_parent_creation_and_open_is_rejected(monkeypatch, tmp_path):
    output = tmp_path / 'missing' / 'receipt.json'
    other = tmp_path / 'other'
    other.mkdir()
    original_mkdir = os.mkdir

    def mkdir(path, *args, **kwargs):
        if path == 'missing' and kwargs.get('dir_fd') is not None:
            output.parent.symlink_to(other, target_is_directory=True)
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(os, 'mkdir', mkdir)
    with pytest.raises(OSError):
        write_new_receipt(output, b'private receipt', create_parents=True)
    assert not (other / output.name).exists()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX special-file tests')
@pytest.mark.parametrize('special', ['fifo', 'symlink', 'hardlink'])
def test_special_destination_is_never_opened_or_replaced(tmp_path, special):
    output = tmp_path / 'receipt.json'
    other = tmp_path / 'other'
    other.write_bytes(b'original')
    if special == 'fifo':
        os.mkfifo(output)
    elif special == 'symlink':
        output.symlink_to(other)
    else:
        os.link(other, output)
    with pytest.raises(FileExistsError):
        write_new_receipt(output, b'private receipt')
    assert other.read_bytes() == b'original'


@pytest.mark.parametrize('kind', ['build', 'pilot'])
def test_write_failure_preserves_complete_completed_receipt(monkeypatch, tmp_path, capsys, kind):
    output = tmp_path / 'work' / 'receipt.json'
    output.parent.mkdir()

    def fail_sync(_fd):
        raise OSError('injected disk-full/sync failure')

    monkeypatch.setattr(os, 'fsync', fail_sync)
    code, receipt = _invoke(monkeypatch, tmp_path, output, kind)
    assert code == 2
    error = json.loads(capsys.readouterr().out)
    assert error['receipt'] == receipt
    assert 'disk-full' in error['reason']


@pytest.mark.skipif(os.name != 'posix', reason='POSIX fd ownership test')
def test_failed_stream_construction_closes_the_created_descriptor(monkeypatch, tmp_path):
    descriptors = []

    def failed_fdopen(fd, *_args, **_kwargs):
        descriptors.append(fd)
        raise OSError('injected stream construction failure')

    monkeypatch.setattr(os, 'fdopen', failed_fdopen)
    with pytest.raises(OSError, match='stream construction failure'):
        write_new_receipt(tmp_path / 'receipt.json', b'private receipt')
    assert len(descriptors) == 1
    try:
        with pytest.raises(OSError):
            os.fstat(descriptors[0])
    finally:
        try:
            os.close(descriptors[0])
        except OSError:
            pass


@pytest.mark.skipif(os.name != 'posix', reason='POSIX unsupported-primitive contract')
def test_missing_anchoring_primitive_fails_before_creating_any_output(monkeypatch, tmp_path):
    monkeypatch.setattr(receipts, '_HAS_DIR_FD', False)
    output = tmp_path / 'new-parent' / 'receipt.json'
    with pytest.raises(OSError, match='unsupported'):
        write_new_receipt(output, b'private receipt', create_parents=True)
    assert not output.parent.exists()


@pytest.mark.skipif(os.name != 'nt', reason='requires native Windows directory-sharing semantics')
@pytest.mark.parametrize('kind', ['build', 'pilot'])
@pytest.mark.parametrize('replace_ancestor', [False, True])
def test_windows_open_parents_deny_replacement_during_publication(
        monkeypatch, tmp_path, kind, replace_ancestor):
    output = tmp_path / 'original' / 'nested' / 'receipt.json'
    output.parent.mkdir(parents=True)
    parent = output.parent.parent if replace_ancestor else output.parent
    probe = tmp_path / 'rename-before-lock'
    parent.rename(probe)
    probe.rename(parent)
    original_open = Path.open
    denied = []

    def raced_open(path, mode='r', *args, **kwargs):
        if path == output and 'x' in mode:
            try:
                parent.rename(tmp_path / 'renamed')
            except OSError as exc:
                denied.append(exc.winerror)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', raced_open)
    code, receipt = _invoke(monkeypatch, tmp_path, output, kind)
    assert code == 0
    assert denied and denied[0] in (5, 32), 'the real OS must refuse the directory rename'
    assert json.loads(output.read_bytes()) == receipt
    assert not (tmp_path / 'renamed').exists()


@contextmanager
def _windows_reparse_writer(path):
    import ctypes
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p,
                                  w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    # FILE_WRITE_DATA with all sharing allowed. A protected directory must still
    # reject it; attribute-only publisher handles would not enforce sharing.
    handle = kernel.CreateFileW(str(path), 0x2, 0x7, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield kernel, handle
    finally:
        kernel.CloseHandle(handle)


def _windows_set_junction(path, target):
    import ctypes
    import struct
    from ctypes import wintypes as w
    substitute = ('\\??\\' + str(target)).encode('utf-16le')
    display = str(target).encode('utf-16le')
    body = (struct.pack('<HHHH', 0, len(substitute), len(substitute) + 2, len(display))
            + substitute + b'\0\0' + display + b'\0\0')
    data = struct.pack('<IHH', 0xA0000003, len(body), 0) + body
    with _windows_reparse_writer(path) as (kernel, handle):
        kernel.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, ctypes.c_void_p, w.DWORD,
                                          ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
        kernel.DeviceIoControl.restype = w.BOOL
        returned = w.DWORD()
        buffer = ctypes.create_string_buffer(data)
        if not kernel.DeviceIoControl(handle, 0x900A4, buffer, len(data), None, 0,
                                      ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())


@pytest.mark.skipif(os.name != 'nt', reason='requires native Windows in-place reparse mutation')
@pytest.mark.parametrize('kind', ['build', 'pilot'])
def test_windows_in_place_junction_mutation_is_denied(monkeypatch, tmp_path, kind):
    output = tmp_path / 'work' / 'receipt.json'
    output.parent.mkdir()
    attacker = tmp_path / 'attacker'
    attacker.mkdir()
    baseline = tmp_path / 'unprotected'
    baseline.mkdir()
    # First prove this process/filesystem can perform this exact attack when the
    # directory is not held. Privilege or buffer errors cannot count as a pass.
    _windows_set_junction(baseline, attacker)
    assert baseline.is_junction()
    baseline.rmdir()
    original_open = Path.open
    denied = []

    def raced_open(path, mode='r', *args, **kwargs):
        if path == output and 'x' in mode:
            try:
                _windows_set_junction(output.parent, attacker)
            except OSError as exc:
                denied.append(exc.winerror)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', raced_open)
    code, receipt = _invoke(monkeypatch, tmp_path, output, kind)
    assert code == 0
    assert denied == [32], 'reparse writer must be refused specifically by sharing protection'
    assert not output.parent.is_junction()
    assert not (attacker / output.name).exists()
    assert json.loads(output.read_bytes()) == receipt


@pytest.mark.skipif(os.name != 'nt', reason='requires native Windows share enforcement against existing writers')
@pytest.mark.parametrize('kind', ['build', 'pilot'])
def test_windows_existing_reparse_writer_blocks_publication(monkeypatch, tmp_path, capsys, kind):
    output = tmp_path / 'work' / 'receipt.json'
    output.parent.mkdir()
    with _windows_reparse_writer(output.parent):
        code, receipt = _invoke(monkeypatch, tmp_path, output, kind)
    assert code == 2
    assert not output.exists()
    assert json.loads(capsys.readouterr().out)['receipt'] == receipt


@pytest.mark.skipif(os.name != 'nt', reason='requires native Windows junctions')
@pytest.mark.parametrize('kind', ['build', 'pilot'])
def test_windows_junction_parent_is_rejected_before_work(monkeypatch, tmp_path, kind):
    original = tmp_path / 'original'
    original.mkdir()
    junction = tmp_path / 'junction'
    # Create only a test directory junction, never execute a compared target.
    subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(junction), str(original)],
                   check=True, capture_output=True)
    monkeypatch.setattr(B, 'build_pilot', lambda *a, **k: pytest.fail('junction reached build'))
    monkeypatch.setattr(P, 'run_pilot', lambda *a, **k: pytest.fail('junction reached engine'))
    output = junction / 'receipt.json'
    try:
        if kind == 'build':
            code = B.main(['--store', str(tmp_path / 'store'), '--output', str(output)])
        else:
            labels = tmp_path / 'labels.json'
            labels.write_bytes(C.dump_json(C.finalize_labels(example_labels())))
            code = P.main(['--labels', str(labels),
                           '--store', str(tmp_path / 'store'), '--work', str(junction),
                           '--output', str(output), '--ghidra-dir', str(tmp_path / 'ghidra')])
        assert code == 2
        assert not (original / output.name).exists()
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != 'nt', reason='requires native Windows path syntax')
@pytest.mark.parametrize('name', ['NUL.json', 'COM1.json', 'receipt.json:stream.json', 'alias. /receipt.json'])
def test_windows_special_path_is_rejected_before_build(monkeypatch, tmp_path, name):
    monkeypatch.setattr(B, 'build_pilot', lambda *a, **k: pytest.fail('device/alias reached build'))
    output = tmp_path / name
    assert B.main(['--store', str(tmp_path / 'store'), '--output', str(output)]) == 2
