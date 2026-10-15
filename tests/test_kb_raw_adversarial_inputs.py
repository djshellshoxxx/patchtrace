"""Boundary checks for committed raw synthetic parser attacks."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kbc_k1_support import import_doc, json_bytes
from patchtrace.kbcorrelation.sources.cvrf import SourceError, parse_cvrf

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"
pytestmark = pytest.mark.usefixtures("no_sockets")


def raw_cases() -> dict[str, dict[str, str]]:
    payload = json.loads((ROOT / "raw_adversarial_inputs.json").read_text(encoding="utf-8"))
    return {item["scenario"]: item for item in payload["cases"]}


@pytest.mark.parametrize(
    "scenario",
    [
        "duplicate-json-key",
        "non-finite-number",
        "oversized-document-text",
        "deep-nesting",
        "xml-doctype-entity",
    ],
    ids=["duplicate-key", "nan", "oversized-text", "deep-nesting", "xml-entity"],
)
def test_structurally_hostile_raw_inputs_are_rejected(scenario: str) -> None:
    """Malformed JSON, oversized content, deep nesting and XML entities fail at the parser boundary."""
    with pytest.raises(SourceError):
        parse_cvrf(raw_cases()[scenario]["raw"].encode("utf-8"))


def test_unknown_product_id_does_not_become_a_wildcard_edge() -> None:
    """A source row naming an absent product cannot create a product-agnostic remediation."""
    raw = raw_cases()["unknown-product-id"]["raw"]
    imported = import_doc(json.loads(raw))
    assert not imported.edges


def test_non_ascii_kb_lookalike_does_not_become_a_remediation() -> None:
    """A visually similar non-ASCII KB suffix does not normalize as a numeric KB identifier."""
    raw = raw_cases()["confusable-kb"]["raw"]
    imported = import_doc(json.loads(raw))
    assert not any(edge.relation == "vendor-remediation" for edge in imported.edges)


def test_advisory_text_is_not_followed_as_a_network_request() -> None:
    """A URL in synthetic title text is data only; parser execution uses local bytes."""
    raw = raw_cases()["url-hostile-advisory-text"]["raw"]
    parsed = parse_cvrf(raw.encode("utf-8"))
    assert parsed.release_id == "2099-Jan"
