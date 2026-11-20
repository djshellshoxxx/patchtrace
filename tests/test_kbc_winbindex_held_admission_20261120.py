"""Hostile offline Winbindex pathname admission; synthetic records, no sockets or target execution."""
from __future__ import annotations

import os

import pytest

from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.kbcorrelation.wiring import WorkspaceFileIndex


NAME = "exampledrv.sys"
KEY = "11-24H2"


def test_newest_matching_directory_cannot_silently_select_older_record(tmp_path):
    directory = tmp_path / "winbindex"
    directory.mkdir()
    old = directory / f"{NAME}@2098-01-01.json"
    old.write_bytes(b"{}")
    (directory / f"{NAME}@2099-02-12.json").mkdir()
    with pytest.raises(KbcStoreError) as failed:
        WorkspaceFileIndex(tmp_path).rows_for(NAME, KEY)
    assert failed.value.code == "PT-KBC-SOURCE"
    assert "regular" in failed.value.message
    assert old.read_bytes() == b"{}"


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="host has no O_NOFOLLOW descriptor admission")
def test_matching_record_swapped_to_symlink_after_scan_is_never_read(tmp_path, monkeypatch):
    directory = tmp_path / "winbindex"
    directory.mkdir()
    record = directory / f"{NAME}@2099-02-12.json"
    record.write_bytes(b"{}")
    foreign = tmp_path / "foreign.json"
    foreign.write_bytes(b'{"foreign":true}')
    original_record = WorkspaceFileIndex._record

    def substitute_after_admission(self, file_name):
        selected = original_record(self, file_name)
        assert selected is not None and selected[0] == record
        record.unlink()
        record.symlink_to(foreign)
        return selected

    monkeypatch.setattr(WorkspaceFileIndex, "_record", substitute_after_admission)
    with pytest.raises(KbcStoreError) as failed:
        WorkspaceFileIndex(tmp_path).rows_for(NAME, KEY)
    assert failed.value.code == "PT-KBC-SOURCE"
    assert "alias" in failed.value.message
    assert record.is_symlink()
    assert foreign.read_bytes() == b'{"foreign":true}'
