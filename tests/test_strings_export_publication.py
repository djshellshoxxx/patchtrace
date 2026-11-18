"""Strings exports preserve concurrent files and never reuse a predictable stage."""
from __future__ import annotations

import os

import pytest

from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError


def test_destination_created_during_sync_is_preserved(tmp_path, monkeypatch):
    target = tmp_path / 'report.json'
    original_sync = os.fsync

    def sync_and_publish_other(descriptor):
        original_sync(descriptor)
        target.write_bytes(b'concurrent complete report')

    monkeypatch.setattr(export.os, 'fsync', sync_and_publish_other)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'new export', force=False)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert target.read_bytes() == b'concurrent complete report'
    assert list(tmp_path.iterdir()) == [target]


def test_dangling_destination_link_is_preserved_without_force(tmp_path):
    target = tmp_path / 'report.json'
    absent = tmp_path / 'absent.json'
    target.symlink_to(absent)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'new export', force=False)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert target.is_symlink() and target.readlink() == absent
    assert not absent.exists()
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize('force', [False, True])
def test_predictable_stage_link_never_receives_export_bytes(tmp_path, force):
    target = tmp_path / 'report.json'
    outside = tmp_path / 'previous-evidence'
    outside.write_bytes(b'preserve prior evidence')
    old_stage = target.with_name(f'.{target.name}.{os.getpid()}.tmp')
    old_stage.symlink_to(outside)
    export.write_atomic(target, b'new export', force=force)
    assert outside.read_bytes() == b'preserve prior evidence'
    assert old_stage.is_symlink()
    assert target.read_bytes() == b'new export' and not target.is_symlink()
    assert set(tmp_path.iterdir()) == {target, outside, old_stage}


def test_interruption_removes_only_its_stage(tmp_path, monkeypatch):
    target = tmp_path / 'report.json'
    prior = tmp_path / 'other-report.json'
    prior.write_bytes(b'keep')

    def interrupt(_descriptor):
        raise KeyboardInterrupt('authored cancellation')

    monkeypatch.setattr(export.os, 'fsync', interrupt)
    with pytest.raises(KeyboardInterrupt, match='authored cancellation'):
        export.write_atomic(target, b'new export', force=False)
    assert set(tmp_path.iterdir()) == {prior}
    assert prior.read_bytes() == b'keep'
