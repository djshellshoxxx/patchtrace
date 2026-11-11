"""PIL sidecar writes are flushed to disk before they are moved into place (same contract as the KEV, KBC and rules stores).

Without the fsync a power loss after the rename can leave an empty file at the final name on some file systems.
"""
from __future__ import annotations

import os

from patchtrace.pilot import store


def test_write_syncs_the_part_file_before_it_is_published(tmp_path, monkeypatch):
    synced: list[int] = []
    real_fsync = os.fsync

    def spy(fd: int) -> None:
        synced.append(os.fstat(fd).st_size)
        real_fsync(fd)

    monkeypatch.setattr(store.os, 'fsync', spy)
    target = tmp_path / 'assessment.json.gz'
    store._write(target, b'payload')
    assert target.read_bytes() == b'payload'
    assert synced == [len(b'payload')]
    assert not (tmp_path / 'assessment.json.gz.part').exists()
