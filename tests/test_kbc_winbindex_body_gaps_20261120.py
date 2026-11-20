"""Untrusted Winbindex body losses must not disappear from offline pair coverage.

All records are synthetic; no sockets, target execution, or live provider claims.
"""
from __future__ import annotations

import json
from io import StringIO

from patchtrace.acquisition.winbindex import parse_rows
from patchtrace.kbcorrelation.wiring import WorkspaceFileIndex, save_winbindex_record

NAME = "exampledrv.sys"
KEY = "11-24H2"
DATE = "2099-02-12"
SHA = "a" * 64


def _body(*, bad_top_level=False, bad_version=False) -> bytes:
    versions = {
        KEY: {
            "KB5099001": {"updateInfo": {
                "releaseDate": "2099-02-11",
                "releaseVersion": "26100.120",
                "heading": "Synthetic update",
            }},
            "KB5099002": {"updateInfo": []},  # invalid body; not a usable row
        },
    }
    if bad_version:
        versions["invalid/version"] = {"KB5099003": {"updateInfo": {}}}
    document = {
        SHA: {
            "fileInfo": {
                "sha256": SHA,
                "size": 1234,
                "timestamp": 4000000000,
                "machineType": 34404,
                "virtualSize": 8192,
            },
            "windowsVersions": versions,
        },
    }
    if bad_top_level:
        document["not-a-sha"] = {"fileInfo": {}}
    return json.dumps(document, sort_keys=True).encode("utf-8")


def _write(tmp_path, body: bytes):
    folder = tmp_path / "winbindex"
    folder.mkdir()
    source = folder / f"{NAME}@{DATE}.json"
    source.write_bytes(body)
    return source


def test_unreadable_kb_body_is_a_resolver_gap_not_silent_completeness(tmp_path):
    body = _body()
    source = _write(tmp_path, body)
    parsed = parse_rows(body, NAME, DATE, compressed=False)
    assert (parsed.skipped, parsed.skipped_bodies, len(parsed.rows)) == (0, 1, 1)
    index = WorkspaceFileIndex(tmp_path)

    rows, gaps = index.rows(NAME, KEY)
    assert len(rows) == 1 and rows[0].kb == "KB5099001"
    assert gaps == 1
    assert source.read_bytes() == body

    source.unlink()
    assert index.rows(NAME, KEY) == ((), 0)


def test_top_level_and_unreadable_version_and_body_are_all_counted(tmp_path):
    body = _body(bad_top_level=True, bad_version=True)
    _write(tmp_path, body)
    parsed = parse_rows(body, NAME, DATE, compressed=False)
    assert (parsed.skipped, parsed.skipped_bodies, len(parsed.rows)) == (1, 2, 1)

    rows, gaps = WorkspaceFileIndex(tmp_path).rows(NAME, KEY)
    assert len(rows) == 1
    assert gaps == 3


def test_import_receipt_exposes_body_rejections_without_redefining_entry_skips(tmp_path):
    body = _body()
    original = tmp_path / "original.json"
    original.write_bytes(body)
    receipt = save_winbindex_record(tmp_path / "workspace", original, NAME, DATE)
    assert receipt["rows"] == 1
    assert receipt["skipped"] == 0
    assert receipt["skipped_bodies"] == 1
    assert (tmp_path / "workspace" / receipt["stored_as"]).read_bytes() == body


def test_plain_import_does_not_hide_unreadable_version_or_kb_bodies(tmp_path):
    from patchtrace.kbcorrelation import cli_index

    body = _body()
    original = tmp_path / "original.json"
    original.write_bytes(body)
    output = StringIO()
    result = cli_index.main(
        ["import", "--winbindex", NAME, "--data-date", DATE,
         "--workspace", str(tmp_path / "workspace"), str(original)],
        ports=cli_index.IndexPorts(winbindex=save_winbindex_record),
        stdout=output,
    )
    assert result == 0
    assert "0 entr(ies) skipped" in output.getvalue()
    assert "1 version/KB body unit(s) unreadable" in output.getvalue()
