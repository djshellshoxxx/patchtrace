"""Owned local download stages under fake responses; no live network or target execution."""
from __future__ import annotations

import hashlib
import os
import threading

import pytest
from test_tier_w_fetch import BLOB, PDB1, PDB2, URL, Opener, Resp, serve

from patchtrace import owned_publication as owned
from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.acquisition.transport import AcquisitionConsent
from tools.calibration.tier_w import msf
from tools.calibration.tier_w import transport as T


def transport(opener, **kwargs):
    return T.SymbolTransport(opener=opener, min_interval=0, sleep=lambda *args: None, **kwargs)


@pytest.mark.parametrize('cap', [False, True, 0, -1, 2**31 + 1, 1024.0, None])
def test_invalid_pdb_cap_is_refused_before_request(tmp_path, cap):
    opener = serve(PDB1.read_bytes(), redirect=False)
    with pytest.raises(AcquisitionError) as caught:
        transport(opener).download_pdb(URL, AcquisitionConsent.for_urls([URL]), tmp_path, cap)
    assert caught.value.code == 'PT-ACQ-INPUT' and not opener.calls and not list(tmp_path.iterdir())


@pytest.mark.parametrize('value', [False, True, 1.0, float('inf'), float('nan')])
def test_pdb_mib_cap_requires_an_integer(value):
    with pytest.raises(AcquisitionError):
        T.pdb_cap_bytes(value)


@pytest.mark.parametrize('value', [False, True, -1, float('inf'), float('nan'), '2', 10**1000])
def test_invalid_request_interval_is_refused_before_request(value):
    opener = Opener()
    with pytest.raises(AcquisitionError):
        T.SymbolTransport(opener=opener, min_interval=value)
    assert not opener.calls


@pytest.mark.parametrize('kind', ['pdb', 'binary'])
def test_same_inode_mutation_after_streaming_cannot_receive_a_receipt(tmp_path, monkeypatch, kind):
    from test_tier_w_fetch import _planned_pe

    raw, planned = _planned_pe()
    if kind == 'pdb':
        raw = PDB1.read_bytes()
    sync = os.fsync
    armed = True

    def mutate(fd):
        nonlocal armed
        sync(fd)
        if armed:
            armed = False
            position = os.lseek(fd, 0, os.SEEK_CUR)
            os.lseek(fd, 64, os.SEEK_SET)
            os.write(fd, b'X')
            os.lseek(fd, position, os.SEEK_SET)

    monkeypatch.setattr(os, 'fsync', mutate)
    subject = transport(serve(raw, redirect=False))
    with pytest.raises(AcquisitionError) as caught:
        if kind == 'pdb':
            subject.download_pdb(URL, AcquisitionConsent.for_urls([URL]), tmp_path, len(raw))
        else:
            subject.download(planned, AcquisitionConsent.for_urls([planned.url]), tmp_path)
    assert caught.value.code == 'PT-ACQ-VERIFY' and not list(tmp_path.iterdir())


def test_pdb_identity_is_checked_on_the_streamed_snapshot(tmp_path):
    expected = msf.read_identity(PDB1)
    raw = PDB1.read_bytes()
    assert owned.inspect_file(PDB1, maximum=len(raw), inspect=msf.read_identity_snapshot) == expected
    result = transport(serve(raw)).download_pdb(URL, AcquisitionConsent.for_urls([URL]), tmp_path, len(raw),
                                              expected_guid=expected.guid, expected_age=expected.age)
    assert result.path.read_bytes() == raw and result.sha256 == hashlib.sha256(raw).hexdigest()
    assert result.redirect_host == 'acct.blob.core.windows.net'
    assert BLOB not in str(result)


@pytest.mark.parametrize('damage', ['wrong-pdb', 'age', 'guid'])
def test_pdb_identity_failure_leaves_no_named_partial(tmp_path, damage):
    expected = msf.read_identity(PDB1)
    raw = PDB2.read_bytes() if damage == 'wrong-pdb' else PDB1.read_bytes()
    age = expected.age + 1 if damage == 'age' else expected.age
    guid = '00000000-0000-0000-0000-000000000000' if damage == 'guid' else expected.guid
    with pytest.raises(AcquisitionError) as caught:
        transport(serve(raw)).download_pdb(URL, AcquisitionConsent.for_urls([URL]), tmp_path, len(raw),
                                           expected_guid=guid, expected_age=age)
    assert caught.value.code == 'PT-ACQ-VERIFY' and not list(tmp_path.iterdir())


@pytest.mark.parametrize('identity', [dict(expected_guid='invalid', expected_age=1),
                                     dict(expected_guid=None, expected_age=1),
                                     dict(expected_guid='00000000-0000-0000-0000-000000000000', expected_age=True)])
def test_malformed_expected_identity_is_refused_before_request(tmp_path, identity):
    opener = Opener()
    with pytest.raises(AcquisitionError) as caught:
        transport(opener).download_pdb(URL, AcquisitionConsent.for_urls([URL]), tmp_path, 1024, **identity)
    assert caught.value.code == 'PT-ACQ-INPUT' and not opener.calls


def test_response_close_cancellation_does_not_mask_download_failure(tmp_path):
    class BrokenClose(Resp):
        def close(self):
            raise KeyboardInterrupt('secondary response close cancellation')

    subject = transport(Opener(BrokenClose(200, b'not-pdb')))
    with pytest.raises(AcquisitionError) as caught:
        subject.download_pdb(URL, AcquisitionConsent.for_urls([URL]), tmp_path, 1024)
    assert caught.value.code == 'PT-ACQ-VERIFY'
    assert caught.value.__notes__ == ['HTTP response cleanup also failed: KeyboardInterrupt']
    assert not list(tmp_path.iterdir())


def test_standalone_response_close_cancellation_remains_visible_inside_caller_handler(tmp_path):
    class BrokenClose(Resp):
        def close(self):
            raise KeyboardInterrupt('response close cancellation')

    subject = transport(Opener(BrokenClose(200, PDB1.read_bytes())))
    try:
        raise ValueError('unrelated caller error')
    except ValueError as unrelated:
        with pytest.raises(KeyboardInterrupt, match='response close'):
            subject.download_pdb(URL, AcquisitionConsent.for_urls([URL]), tmp_path, 2**20)
        assert not getattr(unrelated, '__notes__', [])
    retained = list(tmp_path.iterdir())
    assert len(retained) == 1 and retained[0].read_bytes() == PDB1.read_bytes()


def test_cancel_during_streaming_closes_partial_without_deleting_another_file(tmp_path):
    foreign = tmp_path / '.pdb-foreign'
    foreign.write_bytes(b'prior evidence')
    event = threading.Event()

    def progress(size, cap):
        if size:
            event.set()

    subject = transport(serve(PDB1.read_bytes()), cancel=event)
    with pytest.raises(AcquisitionError) as caught:
        subject.download_pdb(URL, AcquisitionConsent.for_urls([URL]), tmp_path, 2**20, progress=progress)
    assert caught.value.code == 'PT-ACQ-CANCEL'
    assert list(tmp_path.iterdir()) == [foreign] and foreign.read_bytes() == b'prior evidence'


def test_supported_two_gib_pdb_budget_uses_bounded_reads_and_no_full_stream_identity(tmp_path, monkeypatch):
    raw = PDB1.read_bytes() + b'\0' * (3 * owned.STREAM_CHUNK)
    expected = msf.read_identity(PDB1)
    original_read, requests = os.read, []

    def bounded(fd, size):
        requests.append(size)
        assert 0 < size <= owned.STREAM_CHUNK
        return original_read(fd, size)

    def refuse_whole_stream(*args, **kwargs):
        pytest.fail('identity admission cannot materialize a complete PDB logical stream')

    monkeypatch.setattr(os, 'read', bounded)
    monkeypatch.setattr(msf.MsfFile, 'stream', refuse_whole_stream)
    result = transport(serve(raw, redirect=False)).download_pdb(
        URL, AcquisitionConsent.for_urls([URL]), tmp_path, 2**31,
        expected_guid=expected.guid, expected_age=expected.age)
    assert requests and max(requests) == owned.STREAM_CHUNK
    assert result.size == len(raw) and result.sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize('options', [dict(flags=2), dict(omap=[(0x1000, 0x2000)]), dict(thunk=True)])
def test_bounded_pdb_identity_agrees_with_full_parser_for_authored_variants(tmp_path, options):
    from test_tier_w_msf import synthetic

    path = tmp_path / 'synthetic.pdb'
    path.write_bytes(synthetic(**options))
    actual = owned.inspect_file(path, maximum=2**31, inspect=msf.read_identity_snapshot)
    assert actual == msf.read_identity(path)
