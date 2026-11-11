"""Structural checks for synthetic update lineage and many-to-many relationships."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"


def test_relationship_fixture_has_product_scoped_many_to_many_edges() -> None:
    data = json.loads((ROOT / "update_relationships_synthetic.json").read_text(encoding="utf-8"))
    edges = data["edges"]
    assert len({edge["cve"] for edge in edges}) >= 3
    assert len({edge["product_id"] for edge in edges}) >= 3
    assert len({edge["update_id"] for edge in edges}) >= 2
    assert all(edge["relation"] == "synthetic-remediation" for edge in edges)


def test_cumulative_and_checkpoint_relationships_are_explicit() -> None:
    data = json.loads((ROOT / "update_relationships_synthetic.json").read_text(encoding="utf-8"))
    updates = {row["update_id"]: row for row in data["updates"]}
    assert updates["SYN-UPDATE-010"]["class"] == "cumulative"
    assert updates["SYN-UPDATE-011"]["class"] == "checkpoint"
    assert updates["SYN-UPDATE-012"]["supersedes"] == ["SYN-UPDATE-011"]
    assert updates["SYN-UPDATE-011"]["prerequisites"] == ["SYN-UPDATE-010"]


def test_supersedence_chain_preserves_a_branch() -> None:
    data = json.loads((ROOT / "update_relationships_synthetic.json").read_text(encoding="utf-8"))
    updates = data["updates"]
    assert any("SYN-UPDATE-010" in row["supersedes"] for row in updates)
    assert any(row["update_id"] == "SYN-UPDATE-013" for row in updates)
