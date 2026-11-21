"""Malformed Winbindex BASE metadata is a coverage gap, not an undated row.

Synthetic fixtures only. No provider calls, target execution or accuracy claims.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from patchtrace.acquisition.winbindex import parse_rows
from patchtrace.kbcorrelation.wiring import save_winbindex_record

FIXTURE = Path(__file__).parent / "fixtures/kbcorrelation/winbindex/exampledrv.sys.json"
FILE_NAME = "exampledrv.sys"
DATE = "2099-02-12"
BASE_SHA = "a" * 64


def _document() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _parsed(document: dict):
    return parse_rows(json.dumps(document).encode("utf-8"), FILE_NAME, DATE, compressed=False)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"windowsVersionInfo": None},
        {"windowsVersionInfo": []},
        {"windowsVersionInfo": "not-an-object"},
        {"windowsVersionInfo": 4},
    ],
    ids=["missing", "null", "array", "string", "integer"],
)
def test_bad_base_metadata_counts_one_body_loss_without_an_undated_baseline(body):
    document = _document()
    document[BASE_SHA]["windowsVersions"]["11-24H2"]["BASE"] = copy.deepcopy(body)

    parsed = _parsed(document)

    assert parsed.skipped == 2  # independently malformed SHA entries in the fixture
    assert parsed.skipped_bodies == 2  # existing bad KB/version plus this unreadable BASE
    assert not any(row.sha256 == BASE_SHA and row.kb is None for row in parsed.rows)
    assert any(row.kb == "KB5099001" for row in parsed.rows)
    assert any("2 version/KB bodies unreadable" in warning for warning in parsed.warnings)


@pytest.mark.parametrize(
    "body",
    [
        {"windowsVersionInfo": {}},
        {"windowsVersionInfo": {"releaseDate": "not-a-date"}},
        {"windowsVersionInfo": {"releaseDate": "2098-10-01"}},
    ],
    ids=["observed-empty", "unknown-date", "dated-base"],
)
def test_readable_base_metadata_preserves_row_and_never_fabricates_date(body):
    document = _document()
    document[BASE_SHA]["windowsVersions"]["11-24H2"]["BASE"] = copy.deepcopy(body)
    parsed = _parsed(document)

    baseline = next(row for row in parsed.rows if row.sha256 == BASE_SHA and row.kb is None)
    expected_date = body["windowsVersionInfo"].get("releaseDate")
    assert baseline.release_date == (expected_date if expected_date == "2098-10-01" else None)
    assert parsed.skipped_bodies == 1


def test_import_receipt_accounts_for_base_body_loss_without_losing_raw_source(tmp_path):
    document = _document()
    document[BASE_SHA]["windowsVersions"]["11-24H2"]["BASE"] = {}
    raw = json.dumps(document).encode("utf-8")
    source = tmp_path / "source.json"
    source.write_bytes(raw)

    receipt = save_winbindex_record(tmp_path / "workspace", source, FILE_NAME, DATE)

    assert receipt["skipped"] == 2
    assert receipt["skipped_bodies"] == 2
    saved = tmp_path / "workspace" / receipt["stored_as"]
    assert saved.read_bytes() == raw
