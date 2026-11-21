"""Offline Winbindex row losses must describe the same read as returned rows.

Synthetic source records; no network, target binary execution, or accuracy claims.
"""
from __future__ import annotations

import json

from patchtrace.kbcorrelation import wiring

NAME = "exampledrv.sys"
KEY = "11-24H2"
DATE = "2099-02-12"
A = "a" * 64
B = "b" * 64


def _record(*, missing_container: bool) -> bytes:
    valid = {
        "fileInfo": {
            "sha256": A,
            "size": 4096,
            "timestamp": 4000000000,
            "machineType": 34404,
            "virtualSize": 8192,
        },
        "windowsVersions": {
            KEY: {
                "KB5099001": {
                    "updateInfo": {
                        "releaseDate": "2099-02-11",
                        "releaseVersion": "26100.120",
                    },
                },
            },
        },
    }
    entries = {A: valid}
    if missing_container:
        entries[B] = {
            "fileInfo": {
                "sha256": B,
                "size": 4096,
                "timestamp": 4000000000,
                "machineType": 34404,
                "virtualSize": 8192,
            },
        }
    return json.dumps(entries, sort_keys=True).encode("utf-8")


def _index(tmp_path):
    root = tmp_path / "workspace"
    folder = root / "winbindex"
    folder.mkdir(parents=True)
    file = folder / f"{NAME}@{DATE}.json"
    file.write_bytes(_record(missing_container=True))
    return wiring.WorkspaceFileIndex(root), file


def test_conversion_reentrancy_does_not_replace_first_read_gap_count(tmp_path, monkeypatch):
    index, file = _index(tmp_path)
    original = wiring.index_rows
    calls = 0

    def convert(mappings, *, file_name):
        nonlocal calls
        calls += 1
        assert calls == 1
        # The first read has one valid row and one unreadable container.
        # Replace its source with a complete record and re-enter the same adapter
        # *before* the first conversion returns. Prior mutable counters lost the gap.
        file.write_bytes(_record(missing_container=False))
        assert [m["sha256"] for m in index.rows_for(NAME, KEY)] == [A]
        return original(mappings, file_name=file_name)

    monkeypatch.setattr(wiring, "index_rows", convert)
    rows, gaps = index.rows(NAME, KEY)
    assert [r.sha256 for r in rows] == [A]
    assert gaps == 1
    # A distinct later read correctly reports the replacement's own zero gaps.
    monkeypatch.setattr(wiring, "index_rows", original)
    newer_rows, newer_gaps = index.rows(NAME, KEY)
    assert [r.sha256 for r in newer_rows] == [A]
    assert newer_gaps == 0


def test_same_read_count_adds_downstream_conversion_losses(tmp_path, monkeypatch):
    index, _ = _index(tmp_path)
    monkeypatch.setattr(wiring, "index_rows", lambda _rows, *, file_name: ((), 2))
    rows, gaps = index.rows(NAME, KEY)
    assert rows == () and gaps == 3


def test_absent_current_record_has_zero_gaps_after_prior_unreadable_source(tmp_path):
    index, file = _index(tmp_path)
    assert index.rows(NAME, KEY)[1] == 1
    file.unlink()
    assert index.rows(NAME, KEY) == ((), 0)
    assert index.rows_for(NAME, KEY) == []
