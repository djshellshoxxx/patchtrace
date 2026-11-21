"""Strict saved all-pages pull-request JSON admission; no external services."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "branch_inventory.py"
spec = importlib.util.spec_from_file_location("branch_inventory_strict_pr_json", TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("duplicate-top", '[{"number":1,"number":2}]'),
        ("duplicate-head", '[{"head":{"ref":"good","ref":"other"}}]'),
        ("duplicate-nested-repo", '[{"head":{"repo":{"full_name":"owner/repo","full_name":"evil/repo"}}}]'),
        ("nan", '[{"number":NaN}]'),
        ("infinity", '[{"number":Infinity}]'),
        ("negative-infinity", '[{"number":-Infinity}]'),
    ],
)
def test_saved_pr_json_refuses_ambiguous_or_nonfinite_metadata(tmp_path, name, raw):
    source = tmp_path / f"{name}.json"
    source.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="invalid pull-request metadata") as caught:
        tool.read_json(source)
    assert "owner/repo" not in str(caught.value)
    assert "evil/repo" not in str(caught.value)


def test_saved_pr_json_accepts_valid_nested_unicode_and_preserves_data(tmp_path):
    data = [{"number": 42, "state": "open", "head": {"ref": "review/évidence", "sha": "a" * 40,
              "repo": {"full_name": "owner/repo"}}, "base": {"sha": "b" * 40}}]
    path = tmp_path / "valid.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert tool.read_json(path) == data


def test_invalid_saved_pr_json_preserves_previous_inventory_output(tmp_path, capsys):
    pulls = tmp_path / "pulls.json"
    pulls.write_text('[{"number":1,"number":2}]', encoding="utf-8")
    snapshot = tmp_path / "refs.tsv"
    snapshot.write_text("branch\ttip_sha\n", encoding="utf-8")
    previous = tmp_path / "inventory.tsv"
    previous.write_bytes(b"previous verified inventory\n")
    with pytest.raises(SystemExit) as caught:
        tool.main(["--repo", str(tmp_path), "--main", "a" * 40, "--candidate", "b" * 40,
                   "--pulls-json", str(pulls), "--refs-tsv", str(snapshot), "--output", str(previous)])
    assert caught.value.code == 2
    assert "invalid pull-request metadata" in capsys.readouterr().err
    assert previous.read_bytes() == b"previous verified inventory\n"


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("invalid-json", "{"),
        ("deeply-nested", "[" * 10000 + "{}" + "]" * 10000),
    ],
)
def test_saved_pr_json_rejects_malformed_or_excessively_nested_documents(tmp_path, name, raw):
    source = tmp_path / f"{name}.json"
    source.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="invalid pull-request metadata JSON"):
        tool.read_json(source)
