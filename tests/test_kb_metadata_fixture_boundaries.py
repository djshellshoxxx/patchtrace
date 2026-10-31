"""Metadata-only Winbindex and update-package fixtures must never imply verified payload bytes."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"


def test_winbindex_candidates_preserve_missing_and_conflicting_fields() -> None:
    data = json.loads((ROOT / "winbindex_synthetic.json").read_text(encoding="utf-8"))
    rows = data["records"]
    assert len(rows) >= 5
    missing_signature = next(row for row in rows if row["fixture_id"] == "SYN-WBI-002")
    assert missing_signature["signature"] == "not-present"
    conflicting = next(row for row in rows if row["fixture_id"] == "SYN-WBI-003")
    assert conflicting["fileInfo"]["sha256"] != conflicting["windowsVersions"]["24H2"]["KB9000003"]["sha256"]
    incomplete = next(row for row in rows if row["fixture_id"] == "SYN-WBI-004")
    assert "sha256" not in incomplete["fileInfo"]


def test_update_package_fixtures_contain_metadata_but_no_payload() -> None:
    data = json.loads((ROOT / "update_packages_synthetic.json").read_text(encoding="utf-8"))
    rows = data["listings"]
    assert {row["container"] for row in rows} >= {"MSU", "CAB", "PSFX"}
    for row in rows:
        assert "payload" not in row
        assert "payload_bytes" not in row
        for file in row["files"]:
            assert "bytes_base64" not in file
            assert "path_on_disk" not in file


def test_checkpoint_cycle_fixture_remains_an_unresolved_dependency_graph() -> None:
    """The fixture intentionally describes a cycle; consumers must detect rather than order it silently."""
    data = json.loads((ROOT / "update_packages_synthetic.json").read_text(encoding="utf-8"))
    rows = {row["update_id"]: row for row in data["listings"]}
    assert "SYN-UPDATE-005" in rows["SYN-UPDATE-004"]["prerequisites"]
    assert "SYN-UPDATE-004" in rows["SYN-UPDATE-005"]["prerequisites"]
