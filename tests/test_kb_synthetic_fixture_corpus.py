"""Structure and provenance checks for the new synthetic KB fixture corpus.

These tests validate authored test data only. They are not evidence of live MSRC, CSAF, VEX, Winbindex or package
provider compatibility.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
pytestmark = pytest.mark.usefixtures("no_sockets")


def load(path: str) -> dict[str, object]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_manifest_selects_exactly_sixty_synthetic_documents() -> None:
    """The active corpus has 20 CVRF-shaped, 20 CSAF-shaped and 20 VEX-shaped documents."""
    cvrf = load("cvrf_v3_synthetic.json")["documents"]
    csaf = load("csaf_synthetic.json")["documents"]
    vex = load("vex_synthetic.json")["documents"]
    assert isinstance(cvrf, list) and isinstance(csaf, list) and isinstance(vex, list)
    selected = [*cvrf[:20], *csaf, *vex]
    assert MANIFEST["fixture_document_count"] == 60
    assert len(selected) == 60
    assert len({item["fixture_id"] for item in selected}) == 60


def test_selected_advisory_records_have_synthetic_provenance() -> None:
    """Every selected advisory record declares synthetic origin and leaves computed metadata UNVERIFIED."""
    groups = [
        load("cvrf_v3_synthetic.json")["documents"][:20],
        load("csaf_synthetic.json")["documents"],
        load("vex_synthetic.json")["documents"],
    ]
    for group in groups:
        for item in group:
            metadata = item["metadata"]
            assert metadata["synthetic"] is True
            assert metadata["origin"].startswith("hand-authored synthetic")
            assert metadata["sha256"] == "UNVERIFIED"
            assert metadata["byte_length"] == "UNVERIFIED"
            assert metadata["license"].startswith("UNVERIFIED")


def test_corpus_covers_the_required_adversarial_families() -> None:
    """The corpus labels the required data-shape, hostile-text and revision scenarios."""
    scenarios = {
        item["scenario"]
        for filename in ("cvrf_v3_synthetic.json", "csaf_synthetic.json", "vex_synthetic.json")
        for item in load(filename)["documents"]
    }
    required = {
        "cumulative-update",
        "checkpoint-update",
        "supersedence-chain",
        "many-to-many",
        "product-name-variant",
        "multiple-architectures",
        "withdrawn-advisory",
        "reissued-advisory",
        "missing-title",
        "missing-revision",
        "duplicate-cve-id",
        "oversized-title",
        "oversized-notes",
        "markup-in-title",
        "script-like-note",
        "unicode-confusable",
        "numeric-kb-as-string",
        "large-array",
        "deep-nesting",
        "type5-known-issue",
        "unknown-remediation-type",
        "csaf-known-not-affected",
        "csaf-vendor-fix-without-kb",
        "conflicting-status",
        "supersedence-cycle",
    }
    assert required <= scenarios


def test_all_advisory_ids_are_fictional_namespace_values() -> None:
    """No selected record uses a real CVE or KB identifier namespace."""
    groups = [
        load("cvrf_v3_synthetic.json")["documents"][:20],
        load("csaf_synthetic.json")["documents"],
        load("vex_synthetic.json")["documents"],
    ]
    for group in groups:
        for item in group:
            document = item["document"]
            assert item["fixture_id"].startswith("SYN-")
            assert document["vulnerabilities"]
            for vulnerability in document["vulnerabilities"]:
                assert vulnerability["cve"].startswith("CVE-2099-")
