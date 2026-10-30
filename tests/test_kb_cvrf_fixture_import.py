"""Offline integration checks for valid synthetic CVRF placeholder documents."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kbc_k1_support import import_doc

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"
pytestmark = pytest.mark.usefixtures("no_sockets")


def test_first_ten_cvrf_placeholder_documents_import_with_provenance() -> None:
    """Valid base cases cross the existing synthetic cvrf-json/0 importer boundary."""
    payload = json.loads((ROOT / "cvrf_v3_synthetic.json").read_text(encoding="utf-8"))
    documents = payload["documents"]
    for item in documents[:10]:
        imported = import_doc(item["document"])
        assert imported.source.dialect == "cvrf-json/0"
        assert imported.source.release_id == item["document"]["document"]["release_id"]
        assert imported.source.sha256
        assert all(edge.ref.doc_id == imported.source.doc_id for edge in imported.edges)


def test_type_five_fixture_cannot_create_remediation_edge() -> None:
    """A Type-5 synthetic known-issue row does not become vendor-remediation."""
    payload = json.loads((ROOT / "cvrf_v3_synthetic.json").read_text(encoding="utf-8"))
    case = next(item for item in payload["documents"] if item["scenario"] == "type5-known-issue")
    imported = import_doc(case["document"])
    assert not any(edge.relation == "vendor-remediation" for edge in imported.edges)


def test_unknown_remediation_type_is_not_confirmed_as_a_kb_fix() -> None:
    """An unknown synthetic remediation type cannot be promoted to a confirmed remediation."""
    payload = json.loads((ROOT / "cvrf_v3_synthetic.json").read_text(encoding="utf-8"))
    case = next(item for item in payload["documents"] if item["scenario"] == "unknown-remediation-type")
    imported = import_doc(case["document"])
    assert not any(edge.relation == "vendor-remediation" for edge in imported.edges)
