"""Independent portable boundary controls; no native Windows acceptance claim."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from tools.research_qualification import winpairs as wp


def test_constructor_binds_native_information_call_without_win32_fallback(monkeypatch):
    class Function:
        pass

    kernel = SimpleNamespace(**{name: Function() for name in (
        'CreateFileW', 'CloseHandle', 'GetFileInformationByHandle')})
    native = SimpleNamespace(**{name: Function() for name in (
        'NtCreateFile', 'NtSetInformationFile', 'RtlNtStatusToDosError')})
    calls = []

    def dll(name, **kwargs):
        calls.append((name, kwargs))
        return {'kernel32': kernel, 'ntdll': native}[name]

    monkeypatch.setattr(ctypes, 'WinDLL', dll, raising=False)
    win = wp._WindowsPublication()
    assert calls == [('kernel32', {'use_last_error': True}), ('ntdll', {})]
    assert native.NtSetInformationFile.argtypes == [
        wintypes.HANDLE, ctypes.POINTER(win.IoStatus), wintypes.LPVOID, wintypes.ULONG, ctypes.c_int]
    assert native.NtSetInformationFile.restype is wintypes.LONG
    assert wintypes.LONG(-1).value < 0
    assert native.RtlNtStatusToDosError.argtypes == [wintypes.LONG]
    assert not hasattr(kernel, 'SetFileInformationByHandle')


class Rename(ctypes.Structure):
    _fields_ = [('replace', ctypes.c_ubyte), ('parent', ctypes.c_void_p),
                ('length', ctypes.c_uint32), ('name', ctypes.c_uint16 * 1)]


class Io(ctypes.Structure):
    _fields_ = [('status_or_pointer', ctypes.c_void_p), ('information', ctypes.c_size_t)]


@pytest.mark.parametrize('name', ['x', '\u0394.json', '\U0001f9ea-\U0001f642.json'])
def test_raw_buffer_and_fresh_completion_storage(name):
    source, parent = 0x1234567800000017, 0x1234567800000029
    calls = []

    def native(handle, completion, buffer, size, kind):
        state = ctypes.cast(completion, ctypes.POINTER(Io)).contents
        assert state.status_or_pointer is None and state.information == 0
        raw = ctypes.string_at(buffer, size)
        calls.append((handle, kind, raw))
        state.status_or_pointer = 0x1234
        state.information = 0x5678
        return 0

    win = wp._WindowsPublication.__new__(wp._WindowsPublication)
    win.ct, win.wt = ctypes, SimpleNamespace(BOOLEAN=ctypes.c_ubyte)
    # Production methods must see the Windows field names, while assertions decode bytes independently.
    class WireRename(ctypes.Structure):
        _fields_ = [('ReplaceIfExists', ctypes.c_ubyte), ('RootDirectory', ctypes.c_void_p),
                    ('FileNameLength', ctypes.c_uint32), ('FileName', ctypes.c_uint16 * 1)]
    win.RenameInfo, win.IoStatus = WireRename, Io
    win.nt = SimpleNamespace(NtSetInformationFile=native)
    win.rename(source, parent, name)
    win.discard(source)
    assert len(calls) == 2
    handle, kind, raw = calls[0]
    fields = Rename.from_buffer_copy(raw)
    encoded = name.encode('utf-16-le')
    assert (handle, kind, fields.replace, fields.parent, fields.length) == (source, 10, 0, parent, len(encoded))
    assert len(raw) >= ctypes.sizeof(Rename) + len(encoded)
    assert raw[Rename.name.offset:Rename.name.offset + len(encoded)] == encoded
    assert not any(raw[Rename.name.offset + len(encoded):])
    assert calls[1] == (source, 13, b'\x01')


def install_lifecycle(monkeypatch, *, primary_phase=None, primary=None, discard_error=None,
                      close_error=None, raw_close_false=False):
    events, parent_checks, identities = [], 0, 0

    def identity(source):
        nonlocal identities
        identities += 1
        if primary_phase == 'identity-before' and identities == 1:
            raise primary
        if primary_phase == 'identity-after' and identities == 3:
            return (9, 9, 9)
        return (1, 2, 3)

    def transfer(source, flags):
        events.append(('transfer', source))
        if primary_phase == 'transfer':
            raise primary
        return 91

    def check_parent(path, parent):
        nonlocal parent_checks
        parent_checks += 1
        if primary_phase == 'parent-after' and parent_checks == 2:
            raise primary

    def rename(source, parent, name):
        events.append(('rename', source, parent, name))
        if primary_phase == 'rename':
            raise primary

    def stage(fd, data):
        events.append(('stage', fd))
        if primary_phase == 'stage':
            raise primary

    def discard(source):
        events.append(('discard', source))
        if discard_error is not None:
            raise discard_error

    def close(fd):
        events.append(('close', fd))
        if close_error is not None:
            raise close_error

    def close_handle(source):
        events.append(('close_handle', source))
        return not raw_close_false

    def error(code=None):
        assert code is None
        raise OSError(6, 'authored CloseHandle failure')

    win = SimpleNamespace(directory=lambda *args, **kwargs: 29, open_child=lambda *args, **kwargs: 17,
                          identity=identity, check_parent=check_parent, rename=rename, discard=discard,
                          kernel=SimpleNamespace(CloseHandle=close_handle), error=error)
    monkeypatch.setattr(wp, '_WindowsPublication', lambda: win)
    monkeypatch.setattr(wp, '_write_stage', stage)
    monkeypatch.setattr(wp, 'os', SimpleNamespace(O_RDWR=2, O_BINARY=0, close=close))
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(open_osfhandle=transfer))
    return events


@pytest.mark.parametrize('phase', ['identity-before', 'transfer'])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit])
def test_before_fd_transfer_preserves_primary_even_when_both_raw_cleanup_steps_fail(monkeypatch, phase, error_type):
    primary = error_type('primary')
    events = install_lifecycle(monkeypatch, primary_phase=phase, primary=primary,
                               discard_error=OSError(87, 'secondary'), raw_close_false=True)
    with pytest.raises(error_type) as caught:
        wp._publish_windows(Path('/authored/receipt.json'), b'authored')
    assert caught.value is primary
    assert events[-2:] == [('discard', 17), ('close_handle', 17)]
    assert not any(event[0] == 'close' for event in events)
    assert len(primary.__notes__) == 2


@pytest.mark.parametrize('cleanup_type', [KeyboardInterrupt, SystemExit])
def test_primary_collision_survives_cleanup_baseexceptions(monkeypatch, cleanup_type):
    primary = FileExistsError('existing foreign destination')
    events = install_lifecycle(monkeypatch, primary_phase='rename', primary=primary,
                               discard_error=cleanup_type('secondary discard'), close_error=cleanup_type('secondary close'))
    with pytest.raises(FileExistsError) as caught:
        wp._publish_windows(Path('/authored/receipt.json'), b'authored')
    assert caught.value is primary
    assert events[-2:] == [('discard', 17), ('close', 91)]
    assert len(primary.__notes__) == 2


@pytest.mark.parametrize('phase', ['parent-after', 'identity-after'])
def test_post_rename_guard_failure_does_not_discard_published_object_and_survives_close_failure(monkeypatch, phase):
    primary = wp.PublicationBlocked('authored post-publication parent mismatch')
    events = install_lifecycle(monkeypatch, primary_phase=phase, primary=primary,
                               discard_error=AssertionError('must not discard'), close_error=OSError(6, 'secondary close'))
    with pytest.raises(wp.PublicationBlocked) as caught:
        wp._publish_windows(Path('/authored/receipt.json'), b'authored')
    if phase == 'parent-after':
        assert caught.value is primary
    else:
        assert 'destination identity changed' in str(caught.value)
    assert not any(event[0] == 'discard' for event in events)
    assert events[-1] == ('close', 91)
    assert len(caught.value.__notes__) == 1


@pytest.mark.parametrize('close_error', [None, KeyboardInterrupt('close interrupted')])
def test_successful_rename_never_disposes_source_and_does_not_hide_close_cancellation(monkeypatch, close_error):
    events = install_lifecycle(monkeypatch, close_error=close_error)
    if close_error is None:
        wp._publish_windows(Path('/authored/receipt.json'), b'authored')
    else:
        with pytest.raises(KeyboardInterrupt) as caught:
            wp._publish_windows(Path('/authored/receipt.json'), b'authored')
        assert caught.value is close_error
    assert not any(event[0] == 'discard' for event in events)
    assert events[-1] == ('close', 91)


def test_wrapper_retains_only_bounded_secondary_notes_and_original_errno(monkeypatch, tmp_path):
    primary = OSError(5, 'primary')
    for value in ('a' * 900, 'b' * 900, 'must not propagate'):
        primary.add_note(value)
    def fail(*args):
        raise primary
    monkeypatch.setattr(wp, '_publish_linux', fail)
    with pytest.raises(wp.PublicationBlocked, match='OS error 5') as caught:
        wp._publish_bytes(tmp_path / 'receipt.json', b'authored')
    assert caught.value.__notes__ == ['a' * 160, 'b' * 160]
