"""Short held reads preserve the existing finite PE prefix, never widen it."""
from __future__ import annotations

import hashlib
import os
import struct

import pytest
from held_input_support import Checkpoint, HeldFile, authored_pair, deny_source_opens

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.sample import synthetic_pe


@pytest.mark.parametrize('limit', [None, 4096, 1, 17, 127])
def test_short_reads_match_ordinary_complete_inspection(tmp_path, monkeypatch, limit):
    with authored_pair(tmp_path / 'inputs', padding=8192) as (paths, readers):
        expected = wiring.inspect_local_file(str(paths[0]))
        readers.older.read_limit = limit
        deny_source_opens(monkeypatch, paths)
        actual = wiring.inspect_local_file(str(paths[0]), reader=readers.older)
        assert actual == expected and actual.machine == 'amd64'
        assert readers.older.bytes_read == expected.size
        assert sum(n for _, n in readers.checkpoint.counts) == expected.size
        assert readers.older.opened == readers.older.closed == 1 and not readers.older.active
        assert os.fstat(readers.older.fd).st_size == expected.size


@pytest.mark.parametrize('limit', [None, 17])
@pytest.mark.parametrize('offset', [4090, 4096, 4160])
def test_inspection_prefix_bound_is_unchanged(tmp_path, monkeypatch, limit, offset):
    data = bytearray(synthetic_pe() + b'P' * 8192)
    struct.pack_into('<I', data, 0x3C, offset)
    data[offset:offset + 6] = b'PE\0\0\x64\x86'
    path = tmp_path / 'bounded.sys'
    path.write_bytes(data)
    expected_hash = hashlib.sha256(data).hexdigest()
    observed = []
    real_machine = wiring._machine

    def machine(head):
        observed.append(head)
        return real_machine(head)

    monkeypatch.setattr(wiring, '_machine', machine)
    lease = HeldFile(path, Checkpoint())
    lease.read_limit = limit
    try:
        deny_source_opens(monkeypatch, [path])
        if offset == 4090:
            actual = wiring.inspect_local_file(str(path), reader=lease)
            assert actual.machine == 'amd64' and actual.sha256 == expected_hash
            assert actual.size == len(data)
        else:
            with pytest.raises(KbcStoreError, match='not a PE file') as caught:
                wiring.inspect_local_file(str(path), reader=lease)
            assert caught.value.code == 'PT-KBC-INPUT'
        assert observed == [bytes(data[:4096])]
        assert lease.bytes_read == len(data)  # Full read remains required even when the header is refused.
        assert sum(n for _, n in lease.checkpoint.counts) == len(data)
        assert lease.opened == lease.closed == 1 and not lease.active
    finally:
        lease.close()
