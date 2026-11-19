"""Only authored temporary files: publication must retain filesystem ownership."""
from __future__ import annotations

import ctypes
import json
import os
import sys
from contextlib import ExitStack
from pathlib import PureWindowsPath
from types import SimpleNamespace

import pytest
from test_research_qualification_winpairs import BIN_A, URL_A, A, B, Fake, cli, index, routes
from test_research_qualification_winpairs_integrity import record

from tools.research_qualification import winpairs as wp


@pytest.mark.parametrize('failure', [None, OSError('injected failure'), KeyboardInterrupt()])
def test_parent_replacement_cannot_redirect_publication_or_cleanup(tmp_path, monkeypatch, failure):
    parent = tmp_path / 'owned'
    parent.mkdir()
    moved = tmp_path / 'original-parent'
    destination = parent / 'tcpip.sys'
    foreign = []
    real_fsync = os.fsync
    replaced = False

    def replace_parent(fd):
        nonlocal replaced
        real_fsync(fd)
        names = [p.name for p in parent.glob('.winpairs-*')] or ['.winpairs-unowned.tmp']
        try:
            parent.rename(moved)
        except PermissionError:
            assert os.name == 'nt', 'only native Windows sharing locks may prevent this rename'
        else:
            replaced = True
            parent.mkdir()
            for name in names:
                path = parent / name
                path.write_bytes(b'foreign file in replacement parent')
                foreign.append(path)
        if failure is not None:
            raise failure

    monkeypatch.setattr(os, 'fsync', replace_parent)
    result = record()
    if isinstance(failure, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    else:
        wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
        if replaced or failure is not None:
            assert result['status'] == 'missing'
            assert not result.get('sha256_verified')
        else:
            assert result['status'] == 'found'
            assert destination.read_bytes() == BIN_A
    if replaced:
        assert not destination.exists()
        assert not (moved / destination.name).exists()
        for path in foreign:
            assert path.read_bytes() == b'foreign file in replacement parent'


@pytest.mark.skipif(os.name == 'nt', reason='POSIX atomic-link race; Windows uses a held rename handle')
def test_parent_replaced_at_link_never_publishes_or_cleans_in_replacement(tmp_path, monkeypatch):
    parent = tmp_path / 'owned'
    parent.mkdir()
    moved = tmp_path / 'original-parent'
    destination = parent / 'tcpip.sys'
    foreign = []
    real_link = os.link

    def replace_at_link(source, target, **kwargs):
        names = [p.name for p in parent.glob('.winpairs-*')] or ['.winpairs-unowned.tmp']
        parent.rename(moved)
        parent.mkdir()
        for name in names:
            path = parent / name
            path.write_bytes(b'foreign file in replacement parent')
            foreign.append(path)
        return real_link(source, target, **kwargs)

    monkeypatch.setattr(os, 'link', replace_at_link)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    assert result['status'] == 'missing' and 'BLOCKED' in result['reason']
    assert not result.get('sha256_verified') and not destination.exists()
    assert (moved / destination.name).read_bytes() == BIN_A
    for path in foreign:
        assert path.read_bytes() == b'foreign file in replacement parent'


def test_named_stage_replacement_never_publishes_or_deletes_foreign_bytes(tmp_path, monkeypatch):
    destination = tmp_path / 'tcpip.sys'
    foreign = []
    real_fsync = os.fsync

    def replace_stage(fd):
        real_fsync(fd)
        for source in tmp_path.glob('.winpairs-*'):
            try:
                source.rename(tmp_path / 'displaced-owned-stage')
            except PermissionError:
                assert os.name == 'nt', 'only native Windows sharing locks may prevent this rename'
            else:
                source.write_bytes(b'foreign replacement stage')
                foreign.append(source)

    monkeypatch.setattr(os, 'fsync', replace_stage)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    assert result['status'] == 'found' and result['sha256_verified']
    assert destination.read_bytes() == BIN_A
    for source in foreign:
        assert source.read_bytes() == b'foreign replacement stage'


def test_corrupted_open_stage_is_not_reported_as_verified(tmp_path, monkeypatch):
    destination = tmp_path / 'tcpip.sys'
    real_fsync = os.fsync

    def corrupt(fd):
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, b'corrupt')
        os.ftruncate(fd, 7)
        real_fsync(fd)

    monkeypatch.setattr(os, 'fsync', corrupt)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    assert result['status'] == 'missing' and not result.get('sha256_verified')
    assert not destination.exists() and list(tmp_path.iterdir()) == []


def test_destination_created_while_stage_is_flushed_is_preserved(tmp_path, monkeypatch):
    destination = tmp_path / 'tcpip.sys'
    real_fsync = os.fsync

    def concurrent_destination(fd):
        destination.write_bytes(b'concurrent immutable evidence')
        real_fsync(fd)

    monkeypatch.setattr(os, 'fsync', concurrent_destination)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    assert result['status'] == 'missing' and not result.get('sha256_verified')
    assert destination.read_bytes() == b'concurrent immutable evidence'
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize('name', ['p', 'receipt-\u0394.json', 'receipt-\U0001f9ea.json'])
def test_publication_supports_unicode_parent_and_file_names(tmp_path, name):
    destination = tmp_path / 'owned-\U0001f9ea' / name
    wp._publish_bytes(destination, b'{"authored":true}')
    assert destination.read_bytes() == b'{"authored":true}'
    assert list(destination.parent.iterdir()) == [destination]


def _portable_windows_information_calls(status_code=0):
    """Fixed Windows-width dispatch oracle; this does not emulate a filesystem."""
    class RenameInfo(ctypes.Structure):
        _fields_ = [('ReplaceIfExists', ctypes.c_ubyte), ('RootDirectory', ctypes.c_void_p),
                    ('FileNameLength', ctypes.c_uint32), ('FileName', ctypes.c_uint16 * 1)]

    class IoStatus(ctypes.Structure):
        _fields_ = [('StatusOrPointer', ctypes.c_void_p), ('Information', ctypes.c_size_t)]

    calls, translated = [], []

    def set_information(source, status, buffer, size, information_class):
        pending = ctypes.cast(status, ctypes.POINTER(IoStatus)).contents
        assert pending.StatusOrPointer is None and pending.Information == 0
        calls.append((source, information_class, ctypes.string_at(buffer, size)))
        return status_code

    def translate(code):
        translated.append(code)
        return 183  # actual .error() must preserve the no-replacement collision classification

    def forbidden_win32(*args):
        pytest.fail('publication must use the specified native information classes')

    win = wp._WindowsPublication.__new__(wp._WindowsPublication)
    win.ct, win.wt = ctypes, SimpleNamespace(BOOLEAN=ctypes.c_ubyte)
    win.RenameInfo, win.IoStatus = RenameInfo, IoStatus
    win.nt = SimpleNamespace(NtSetInformationFile=set_information, RtlNtStatusToDosError=translate)
    win.kernel = SimpleNamespace(SetFileInformationByHandle=forbidden_win32)
    return win, calls, translated


def _portable_windows_open_calls():
    """Capture requested access, not a Windows filesystem or native success oracle."""
    class UnicodeString(ctypes.Structure):
        _fields_ = [('Length', ctypes.c_uint16), ('MaximumLength', ctypes.c_uint16),
                    ('Buffer', ctypes.c_wchar_p)]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [('Length', ctypes.c_uint32), ('RootDirectory', ctypes.c_void_p),
                    ('ObjectName', ctypes.POINTER(UnicodeString)), ('Attributes', ctypes.c_uint32),
                    ('SecurityDescriptor', ctypes.c_void_p), ('SecurityQualityOfService', ctypes.c_void_p)]

    win, _, _ = _portable_windows_information_calls()
    win.wt.HANDLE, win.wt.LPWSTR = ctypes.c_void_p, ctypes.c_wchar_p
    win.UnicodeString, win.ObjectAttributes = UnicodeString, ObjectAttributes
    calls = []

    def root_open(name, access, share, security, disposition, flags, template):
        calls.append((access, share, None, flags))
        return len(calls)

    def child_open(result, access, attributes, status, allocation, file_attributes,
                   share, disposition, options, extra, extra_length):
        parent = ctypes.cast(attributes, ctypes.POINTER(ObjectAttributes)).contents
        assert parent.Attributes & 0x1000  # OBJ_DONT_REPARSE
        calls.append((access, share, parent.RootDirectory, options))
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p)).contents.value = len(calls)
        return 0

    win.kernel = SimpleNamespace(CreateFileW=root_open, CloseHandle=lambda handle: True)
    win.nt.NtCreateFile = child_open
    win.identity = lambda handle, **kwargs: (1, 0, handle)
    return win, calls


def _sharing_compatible(access, share, incoming_access, incoming_share):
    """Microsoft sharing contract, with generic read/write included for source handles."""
    for access_bits, share_bit in ((0x80000021, 1), (0x40000006, 2), (0x10000, 4)):
        if incoming_access & access_bits and not share & share_bit:
            return False
        if access & access_bits and not incoming_share & share_bit:
            return False
    return True


@pytest.mark.parametrize('guard_index', [0, 1, 2])
def test_windows_directory_guards_allow_native_rename_target_open_without_delete_sharing(guard_index):
    win, calls = _portable_windows_open_calls()
    with ExitStack() as stack:
        assert win.directory(PureWindowsPath('C:/owned/parent'), stack, create=True) == 3
    assert len(calls) == 3
    access, share, parent, options = calls[guard_index]
    assert parent == (None if guard_index == 0 else guard_index)
    # FileRenameInformation internally requests FILE_WRITE_DATA | SYNCHRONIZE
    # for the destination directory. Its guard must admit that open in both directions.
    assert _sharing_compatible(access, share, 0x100002, 3)
    # Retaining a handle without FILE_SHARE_DELETE must still prevent namespace replacement.
    assert not _sharing_compatible(access, share, 0x10000, 7)
    assert options & 0x200000  # FILE_OPEN_REPARSE_POINT


@pytest.mark.parametrize('incoming_access', [0x2, 0x4, 0x40000000, 0x10000])
def test_windows_staging_source_still_denies_other_writers_and_renamers(incoming_access):
    win, calls = _portable_windows_open_calls()
    assert win.open_child(29, '.winpairs-authored.tmp', directory=False, create=True) == 1
    access, share, parent, options = calls[0]
    assert parent == 29 and options & 0x200000
    assert access & 0x10000  # only the owned source can be renamed/discarded
    assert not _sharing_compatible(access, share, incoming_access, 7)


@pytest.mark.parametrize('name', ['p', 'receipt-\u0394.json', 'receipt-\U0001f9ea.json'])
def test_windows_native_rename_dispatch_keeps_exact_parent_and_utf16_leaf(name):
    win, calls, translated = _portable_windows_information_calls()
    win.rename(17, 29, name)
    assert len(calls) == 1 and not translated
    source, information_class, raw = calls[0]
    assert source == 17 and information_class == 10
    info = win.RenameInfo.from_buffer_copy(raw)
    encoded = name.encode('utf-16-le')
    assert not info.ReplaceIfExists and info.RootDirectory == 29
    assert info.FileNameLength == len(encoded)
    assert len(raw) >= ctypes.sizeof(win.RenameInfo) + len(encoded)
    offset = win.RenameInfo.FileName.offset
    assert raw[offset:offset + len(encoded)] == encoded
    assert not any(raw[offset + len(encoded):])


def test_windows_native_disposition_targets_only_the_owned_handle():
    win, calls, translated = _portable_windows_information_calls()
    win.discard(17)
    assert calls == [(17, 13, b'\x01')] and not translated


@pytest.mark.parametrize('operation', ['rename', 'discard'])
def test_windows_native_negative_status_uses_nt_translation(operation):
    win, calls, translated = _portable_windows_information_calls(-1073741771)
    with pytest.raises(FileExistsError, match='prior evidence'):
        getattr(win, operation)(17, 29, 'p') if operation == 'rename' else win.discard(17)
    assert len(calls) == 1 and translated == [-1073741771]


@pytest.mark.parametrize('operation', ['rename', 'discard'])
@pytest.mark.parametrize('status', [0x103, 0x40000000])
def test_windows_native_incomplete_status_never_credits_success(operation, status):
    win, calls, translated = _portable_windows_information_calls(status)
    with pytest.raises(wp.PublicationBlocked, match='synchronously'):
        getattr(win, operation)(17, 29, 'p') if operation == 'rename' else win.discard(17)
    assert len(calls) == 1 and not translated


@pytest.mark.parametrize('primary_kind', ['write', 'collision', 'cancel'])
@pytest.mark.parametrize('cleanup_failure', ['discard', 'close', 'both'])
def test_windows_cleanup_preserves_primary_error_and_closes_owned_fd(
        tmp_path, monkeypatch, primary_kind, cleanup_failure):
    primary = {'write': OSError(5, 'primary write failure'),
               'collision': FileExistsError('primary collision'), 'cancel': KeyboardInterrupt()}[primary_kind]
    calls = []

    def stage(fd, data):
        assert fd == 91 and data == b'authored'
        if primary_kind != 'collision':
            raise primary

    def rename(source, parent, name):
        assert (source, parent, name) == (17, 29, 'receipt.json')
        raise primary

    def discard(source):
        calls.append(('discard', source))
        if cleanup_failure in ('discard', 'both'):
            raise OSError(87, 'secondary discard failure')

    def close(fd):
        calls.append(('close', fd))
        if cleanup_failure in ('close', 'both'):
            raise OSError(6, 'secondary close failure')

    win = SimpleNamespace(directory=lambda *args, **kwargs: 29, open_child=lambda *args, **kwargs: 17,
                          identity=lambda *args: (1, 2, 3), check_parent=lambda *args: None,
                          rename=rename, discard=discard)
    monkeypatch.setattr(wp, '_WindowsPublication', lambda: win)
    monkeypatch.setattr(wp, '_write_stage', stage)
    monkeypatch.setattr(wp, 'os', SimpleNamespace(O_RDWR=os.O_RDWR, O_BINARY=0, close=close))
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(open_osfhandle=lambda *args: 91))
    with pytest.raises(type(primary)) as caught:
        wp._publish_windows(tmp_path / 'receipt.json', b'authored')
    assert caught.value is primary
    assert calls == [('discard', 17), ('close', 91)]
    notes = primary.__notes__
    assert len(notes) == (2 if cleanup_failure == 'both' else 1)
    assert all('cleanup' in note and len(note) <= 160 for note in notes)


def test_windows_cleanup_before_fd_transfer_closes_only_the_owned_handle(tmp_path, monkeypatch):
    primary = KeyboardInterrupt()
    calls = []

    def no_transfer(*args):
        raise primary

    def discard(source):
        calls.append(('discard', source))
        raise OSError(87, 'secondary discard failure')

    def close_handle(source):
        calls.append(('close_handle', source))
        return True

    win = SimpleNamespace(directory=lambda *args, **kwargs: 29, open_child=lambda *args, **kwargs: 17,
                          identity=lambda *args: (1, 2, 3), discard=discard,
                          kernel=SimpleNamespace(CloseHandle=close_handle))
    monkeypatch.setattr(wp, '_WindowsPublication', lambda: win)
    monkeypatch.setattr(wp, 'os', SimpleNamespace(O_RDWR=os.O_RDWR, O_BINARY=0))
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(open_osfhandle=no_transfer))
    with pytest.raises(KeyboardInterrupt) as caught:
        wp._publish_windows(tmp_path / 'receipt.json', b'authored')
    assert caught.value is primary
    assert calls == [('discard', 17), ('close_handle', 17)]


def test_windows_close_failure_after_rename_is_not_reported_as_success(tmp_path, monkeypatch):
    calls = []
    failure = OSError(6, 'owned close failure')

    def close(fd):
        calls.append(('close', fd))
        raise failure

    win = SimpleNamespace(directory=lambda *args, **kwargs: 29, open_child=lambda *args, **kwargs: 17,
                          identity=lambda *args: (1, 2, 3), check_parent=lambda *args: None,
                          rename=lambda *args: calls.append(('rename', args)),
                          discard=lambda *args: pytest.fail('published evidence must not be discarded'))
    monkeypatch.setattr(wp, '_WindowsPublication', lambda: win)
    monkeypatch.setattr(wp, '_write_stage', lambda *args: None)
    monkeypatch.setattr(wp, 'os', SimpleNamespace(O_RDWR=os.O_RDWR, O_BINARY=0, close=close))
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(open_osfhandle=lambda *args: 91))
    with pytest.raises(OSError) as caught:
        wp._publish_windows(tmp_path / 'receipt.json', b'authored')
    assert caught.value is failure
    assert calls == [('rename', (17, 29, 'receipt.json')), ('close', 91)]


def test_blocked_publication_retains_bounded_secondary_cleanup_diagnostics(tmp_path, monkeypatch):
    primary = OSError(5, 'primary failure')
    primary.add_note('Windows discard cleanup also failed: OSError')

    def fail(*args):
        raise primary

    monkeypatch.setattr(wp, '_publish_windows', fail)
    monkeypatch.setattr(wp, '_publish_linux', fail)
    with pytest.raises(wp.PublicationBlocked, match='OS error 5') as caught:
        wp._publish_bytes(tmp_path / 'receipt.json', b'authored')
    assert caught.value.__notes__ == primary.__notes__


@pytest.mark.skipif(os.name != 'nt', reason='native Windows sharing/handle acceptance')
def test_windows_held_ancestors_and_stage_block_replacement_and_writes(tmp_path, monkeypatch):
    parent = tmp_path / 'owned-ancestor' / 'owned-parent'
    parent.mkdir(parents=True)
    destination = parent / 'tcpip.sys'
    real_fsync = os.fsync
    attempted = []

    def attempt_replacement(fd):
        real_fsync(fd)
        assert not destination.exists()
        for ancestor in (parent, parent.parent):
            with pytest.raises(PermissionError):
                ancestor.rename(tmp_path / ('moved-' + ancestor.name))
        stages = list(parent.glob('.winpairs-*'))
        assert len(stages) == 1
        with pytest.raises(PermissionError):
            stages[0].rename(parent / 'substituted-stage')
        with pytest.raises(PermissionError):
            stages[0].write_bytes(b'foreign mutation')
        attempted.append(True)

    monkeypatch.setattr(os, 'fsync', attempt_replacement)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    assert attempted == [True], result
    assert result['status'] == 'found' and result['sha256_verified']
    assert destination.read_bytes() == BIN_A and list(parent.iterdir()) == [destination]


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux anonymous staging capability')
def test_missing_anonymous_staging_support_blocks_without_a_named_fallback(tmp_path, monkeypatch):
    monkeypatch.delattr(os, 'O_TMPFILE')
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, tmp_path / 'tcpip.sys', 'case/older/tcpip.sys')
    assert result['status'] == 'missing' and result['reason'].startswith('BLOCKED: safe publication')
    assert not result.get('sha256_verified') and list(tmp_path.iterdir()) == []
    assert wp.exit_code({'cases': [{'status': 'missing', 'older': result, 'newer': result}]}) == 2


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux exact-descriptor linking capability')
def test_unavailable_descriptor_link_blocks_and_discards_only_owned_stage(tmp_path, monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise NotImplementedError('no exact-descriptor link support')

    monkeypatch.setattr(os, 'link', unavailable)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, tmp_path / 'tcpip.sys', 'case/older/tcpip.sys')
    assert result['status'] == 'missing' and result['reason'].startswith('BLOCKED: safe publication')
    assert not result.get('sha256_verified') and list(tmp_path.iterdir()) == []


def test_unsupported_platform_blocks_without_using_an_unanchored_publisher(tmp_path, monkeypatch):
    monkeypatch.setattr(wp.sys, 'platform', 'unsupported-test-platform')
    monkeypatch.setattr(wp, 'os', SimpleNamespace(name='unsupported-test-platform', path=os.path))
    with pytest.raises(wp.PublicationBlocked, match='unsupported'):
        wp._publish_bytes(tmp_path / 'receipt.json', b'authored')
    assert list(tmp_path.iterdir()) == []


def test_blocked_binary_publication_is_recorded_and_returns_exit_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    real_publish = wp._publish_bytes

    def unavailable_binary(target, data):
        if target.suffix == '.sys':
            raise wp.PublicationBlocked('safe publication unsupported in authored test')
        real_publish(target, data)

    monkeypatch.setattr(wp, '_publish_bytes', unavailable_binary)
    assert cli(tmp_path, Fake(routes(index(A, B)))) == 2
    document = json.loads((tmp_path / 'pm.json').read_bytes())
    assert document['schema'] == wp.OUT_SCHEMA
    assert document['cases'][0]['status'] == 'missing'
    for side in ('older', 'newer'):
        result = document['cases'][0][side]
        assert result['status'] == 'missing' and result['reason'].startswith('BLOCKED: safe publication')
        assert not result.get('sha256_verified')


@pytest.mark.skipif(os.name != 'nt', reason='native Windows reparse mutation and rooted-open acceptance')
def test_windows_attribute_reparse_mutation_cannot_redirect_stage_creation(tmp_path, monkeypatch):
    import struct

    parent = tmp_path / 'owned-parent'
    parent.mkdir()
    other = tmp_path / 'foreign-parent'
    other.mkdir()
    real_open = wp._WindowsPublication.open_child
    attempted = []

    def mutate_empty_parent(win, owned, name, *, directory, create):
        if not directory:
            # FILE_WRITE_ATTRIBUTES is deliberately used: sharing flags do not
            # deny it. The junction points only at another synthetic temp dir.
            handle = win.kernel.CreateFileW(str(parent), 0x100, 7, None, 3, 0x2200000, None)
            if handle == win.ct.c_void_p(-1).value:
                win.error()
            try:
                substitute = ('\\??\\' + str(other)).encode('utf-16-le')
                printable = str(other).encode('utf-16-le')
                names = substitute + b'\0\0' + printable + b'\0\0'
                raw = struct.pack('<LHHHHHH', 0xA0000003, 8 + len(names), 0,
                                  0, len(substitute), len(substitute) + 2, len(printable)) + names
                buffer = win.ct.create_string_buffer(raw)
                returned = win.wt.DWORD()
                control = win.kernel.DeviceIoControl
                control.argtypes = [win.wt.HANDLE, win.wt.DWORD, win.wt.LPVOID, win.wt.DWORD,
                                    win.wt.LPVOID, win.wt.DWORD, win.ct.POINTER(win.wt.DWORD), win.wt.LPVOID]
                control.restype = win.wt.BOOL
                if not control(handle, 0x900A4, buffer, len(raw), None, 0, win.ct.byref(returned), None):
                    win.error()
                attempted.append(True)
            finally:
                win.kernel.CloseHandle(handle)
        result = real_open(win, owned, name, directory=directory, create=create)
        if list(other.iterdir()):
            win.discard(result)
            win.kernel.CloseHandle(result)
            pytest.fail('rooted staging followed the replacement reparse point')
        return result

    monkeypatch.setattr(wp._WindowsPublication, 'open_child', mutate_empty_parent)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, parent / 'tcpip.sys', 'case/older/tcpip.sys')
    assert attempted == [True], result
    assert parent.is_junction(), result
    assert result['status'] == 'missing' and result['reason'].startswith('BLOCKED:')
    assert not result.get('sha256_verified') and list(other.iterdir()) == []
