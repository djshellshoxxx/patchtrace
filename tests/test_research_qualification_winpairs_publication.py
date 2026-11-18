"""Only authored temporary files: publication must retain filesystem ownership."""
from __future__ import annotations

import json
import os
import sys
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


def test_publication_supports_unicode_parent_and_file_names(tmp_path):
    destination = tmp_path / 'owned-\U0001f9ea' / 'receipt-\u0394.json'
    wp._publish_bytes(destination, b'{"authored":true}')
    assert destination.read_bytes() == b'{"authored":true}'
    assert list(destination.parent.iterdir()) == [destination]


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
