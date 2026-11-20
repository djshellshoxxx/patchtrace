"""Synthetic offline index tests: bound each opened read and report only current-source gaps."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from patchtrace.acquisition import winbindex
from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.kbcorrelation.wiring import WorkspaceFileIndex

NAME = 'exampledrv.sys'
KEY = '11-24H2'


def _record(tmp_path: Path, body: bytes) -> Path:
    directory = tmp_path / 'winbindex'
    directory.mkdir()
    path = directory / f'{NAME}@2099-02-12.json'
    path.write_bytes(body)
    return path


def test_stale_path_size_cannot_allow_an_unbounded_raw_index_read(tmp_path, monkeypatch):
    # Simulate a writer growing a record after the size metadata was observed.
    # The current 64 MiB cap is lowered only within this regression test.
    record = _record(tmp_path, b'{"discarded": null, "another": null}')
    assert record.stat().st_size > 20
    monkeypatch.setattr(winbindex, 'MAX_COMPRESSED', 20)
    actual_stat = Path.stat

    def stale_stat(self, *args, **kwargs):
        result = actual_stat(self, *args, **kwargs)
        if self == record:
            fields = list(result)
            fields[6] = 1  # st_size, deliberately stale; other fields remain real
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, 'stat', stale_stat)
    with pytest.raises(KbcStoreError) as error:
        WorkspaceFileIndex(tmp_path).rows_for(NAME, KEY)
    assert error.value.code == 'PT-KBC-LIMIT'
    assert record.read_bytes() == b'{"discarded": null, "another": null}'


def test_missing_record_does_not_reuse_a_previous_skipped_entry_count(tmp_path):
    record = _record(tmp_path, b'{"not-a-sha": null}')
    index = WorkspaceFileIndex(tmp_path)
    assert index.rows(NAME, KEY) == ((), 1)

    record.unlink()
    assert index.rows(NAME, KEY) == ((), 0)
    assert index.rows_for(NAME, KEY) == []
    assert not record.exists()
