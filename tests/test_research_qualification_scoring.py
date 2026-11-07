from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import scoring as SC  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402


def c(i, fn="f", **exp):
    return {"id": i, "layer": "L2", "stratum": "s", "project": "p" + i, "source_url": "https://x.org/a",
            "licence": "MIT", "older": {"ref": "a"}, "newer": {"ref": "b"},
            "expected": exp or {"function": fn}, "facts": "unverified", "holdout": False}


M = {"schema": "rq-case-manifest/1", "cases": [c("a"), c("b"), c("n", no_change=True), c("z")]}


def test_ranks_hits_misses_and_blocked():
    r = SC.score_run(M, {"a": ["x", "f"], "b": ["1", "2", "3", "4", "5", "f"], "n": [], "z": None})
    assert (r["hits"], r["misses"], r["blocked"], r["scored"]) == (2, 1, 1, 3)
    assert r["rows"][0]["rank"] == 2 and r["rows"][1]["rank"] == 6
    assert SC.score_run(M, {"b": ["1", "2", "3", "4", "5", "f"]}, k=6)["hits"] == 1


def test_accepted_alternative_name_counts_as_hit():
    alt = {"cases": [c("r", function="FindObject", accept=["FindStreamObject"])], "schema": "x"}
    r = SC.score_run(alt, {"r": ["g", "FindStreamObject"]})
    assert r["hits"] == 1 and r["rows"][0]["rank"] == 2
    assert SC.score_run(alt, {"r": ["FindObject", "FindStreamObject"]})["rows"][0]["rank"] == 1


def test_false_positive_and_unrun_never_counts_as_hit():
    r = SC.score_run(M, {"n": ["g"]})
    assert r["false_positives"] == 1 and r["hits"] == 0 and r["blocked"] == 3


def test_bound_uses_scored_only_and_none_when_nothing_scored():
    assert SC.score_run(M, {})["lower_bound"] is None
    ok = {"cases": [c(str(i)) for i in range(29)], "schema": "x"}
    assert SC.score_run(ok, {str(i): ["f"] for i in range(29)})["lower_bound"] == 0.902


def test_hostile_inputs():
    with pytest.raises(ValueError):
        SC.score_run(M, {"nope": []})
    with pytest.raises(ValueError):
        SC.score_run(M, {"a": "f"})
    with pytest.raises(ValueError):
        SC.score_run(M, {"a": [1]})
    with pytest.raises(ValueError):
        SC.score_case(M["cases"][0], [], k=0)


def test_cli(tmp_path):
    m, r = tmp_path / "m.json", tmp_path / "r.json"
    m.write_text(json.dumps(M))
    r.write_text(json.dumps({"a": ["f"], "b": ["f"], "n": [], "z": ["f"]}))
    assert main(["score", str(m), str(r)]) == 0
    r.write_text(json.dumps({"a": ["q"]}))
    assert main(["score", str(m), str(r)]) == 1
    r.write_text("[]")
    assert main(["score", str(m), str(r)]) == 2
