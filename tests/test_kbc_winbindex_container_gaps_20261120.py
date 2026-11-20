"""Synthetic Winbindex entry containers must not vanish from offline gap accounting.

No network requests, target execution or vendor accuracy assertions.
"""
from __future__ import annotations

import json

import pytest

from patchtrace.acquisition.winbindex import parse, parse_rows
from patchtrace.kbcorrelation.wiring import WorkspaceFileIndex, save_winbindex_record

NAME = "exampledrv.sys"
KEY = "11-24H2"
DATE = "2099-02-12"
A = "a" * 64
B = "b" * 64


def _entry(sha: str, windows: object) -> dict:
    return {
        "fileInfo": {
            "sha256": sha,
            "size": 4096,
            "timestamp": 4000000000,
            "machineType": 34404,
            "virtualSize": 8192,
        },
        "windowsVersions": windows,
    }


def _document(kind: str) -> bytes:
    entries = {
        A: _entry(A, {KEY: {"KB5099001": {
            "updateInfo": {"releaseDate": "2099-02-11", "releaseVersion": "26100.120"},
        }}}),
        B: _entry(B, {}),
    }
    if kind == "missing":
        del entries[B]["windowsVersions"]
    elif kind == "array":
        entries[B]["windowsVersions"] = []
    elif kind == "null":
        entries[B]["windowsVersions"] = None
    elif kind == "string":
        entries[B]["windowsVersions"] = "not-an-object"
    elif kind == "empty":
        pass
    elif kind == "bad-top-level":
        entries[B]["fileInfo"] = None
        del entries[B]["windowsVersions"]
    else:
        raise AssertionError(kind)
    return json.dumps(entries, sort_keys=True).encode("utf-8")


@pytest.mark.parametrize("kind", ["missing", "array", "null", "string"])
def test_unreadable_entry_container_is_one_gap_not_a_complete_index(kind):
    result = parse_rows(_document(kind), NAME, DATE, compressed=False)
    assert (len(result.rows), result.skipped, result.skipped_bodies) == (1, 0, 1)
    assert any("1 version/KB bodies unreadable" in warning for warning in result.warnings)


def test_unreadable_entry_container_reaches_workspace_and_import_receipt(tmp_path):
    body = _document("array")
    source = tmp_path / "original.json"
    source.write_bytes(body)
    receipt = save_winbindex_record(tmp_path / "workspace", source, NAME, DATE)
    assert (receipt["rows"], receipt["skipped"], receipt["skipped_bodies"]) == (1, 0, 1)
    assert (tmp_path / "workspace" / receipt["stored_as"]).read_bytes() == body

    rows, gaps = WorkspaceFileIndex(tmp_path / "workspace").rows(NAME, KEY)
    assert len(rows) == 1 and rows[0].sha256 == A
    assert gaps == 1


def test_explicit_empty_container_is_observed_not_invalid():
    result = parse_rows(_document("empty"), NAME, DATE, compressed=False)
    assert (len(result.rows), result.skipped, result.skipped_bodies) == (1, 0, 0)


def test_rejected_top_level_is_not_double_counted_as_container_loss():
    result = parse_rows(_document("bad-top-level"), NAME, DATE, compressed=False)
    assert (len(result.rows), result.skipped, result.skipped_bodies) == (1, 1, 0)


def test_existing_candidate_parser_is_independent_of_row_gap_accounting():
    result = parse(_document("array"), NAME, DATE, compressed=False)
    assert len(result.candidates) == 2 and result.skipped == 0
