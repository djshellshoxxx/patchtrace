from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.research_qualification import parity as PY  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402


def c(i, fn="f", **exp):
    return {
        "id": i,
        "layer": "L2",
        "stratum": "s",
        "project": "p" + i,
        "source_url": "https://x.org/a",
        "licence": "MIT",
        "older": {"ref": "a"},
        "newer": {"ref": "b"},
        "expected": exp or {"function": fn},
        "facts": "unverified",
        "holdout": False,
    }


M = {"schema": "rq-case-manifest/1", "cases": [c("a"), c("b"), c("n", no_change=True), c("z")]}


def row(res, cid):
    return next(r for r in res["rows"] if r["id"] == cid)


def test_identical_outcomes_are_not_a_disagreement():
    a = {"a": ["f", "x"], "b": ["x", "y"], "n": [], "z": ["q"]}
    res = PY.compare_runs(M, a, dict(a))
    assert res["identical"] is True and res["disagreements"] == []
    assert res["outcomes"]["both-hit"] == 2 and res["outcomes"]["both-miss"] == 2  # a and n hit; b and z miss
    assert row(res, "a")["overlap_at_k"] == 2 and row(res, "a")["jaccard_at_k"] == 1.0


def test_a_only_hit_is_a_disagreement():
    res = PY.compare_runs(M, {"a": ["f"], "b": ["x"]}, {"a": ["x"], "b": ["x"]})
    assert row(res, "a")["outcome"] == "a-only"
    assert res["disagreements"] == ["a"] and res["identical"] is False


def test_b_only_hit_is_a_disagreement():
    res = PY.compare_runs(M, {"a": ["x"]}, {"a": ["f"]})
    assert row(res, "a")["outcome"] == "b-only"
    assert res["disagreements"] == ["a"]


def test_ranks_and_topk_overlap_use_score_case_semantics():
    cands_a = ["1", "2", "3", "4", "5", "f"]  # rank 6 is outside k=5: a miss
    cands_b = ["f", "2", "9", "8", "7"]
    res = PY.compare_runs(M, {"a": cands_a}, {"a": cands_b})
    r = row(res, "a")
    assert r["outcome"] == "b-only" and r["a"]["rank"] == 6 and r["b"]["rank"] == 1
    assert r["overlap_at_k"] == 1 and r["jaccard_at_k"] == round(1 / 9, 3)


def test_no_change_case_is_hit_only_when_both_report_nothing():
    res = PY.compare_runs(M, {"n": []}, {"n": []})
    assert row(res, "n")["outcome"] == "both-hit"
    res = PY.compare_runs(M, {"n": ["g"]}, {"n": []})
    assert row(res, "n")["outcome"] == "b-only" and row(res, "n")["a"]["verdict"] == "FALSE_POSITIVE"


def test_null_is_blocked_never_a_hit_and_not_compared():
    res = PY.compare_runs(M, {"a": None, "b": ["f"]}, {"a": ["f"], "b": ["f"]})
    r = row(res, "a")
    assert r["outcome"] == "blocked" and r["overlap_at_k"] is None and r["jaccard_at_k"] is None
    assert res["blocked"] == 3 and res["compared"] == 1 and res["disagreements"] == []  # only "b" is compared


def test_missing_case_counts_as_blocked():
    res = PY.compare_runs(M, {}, {"a": ["f"]})
    assert res["compared"] == 0 and res["blocked"] == 4 and res["identical"] is False


def test_rows_are_sorted_by_case_id_and_output_is_deterministic():
    shuffled = dict(M, cases=list(reversed(M["cases"])))
    a = {"a": ["f"], "b": ["x"], "z": ["f"]}
    res = PY.compare_runs(shuffled, a, {"a": ["x"], "b": ["f"], "z": ["f"]})
    assert [r["id"] for r in res["rows"]] == ["a", "b", "n", "z"]
    assert res["disagreements"] == ["a", "b"]
    assert json.dumps(res, sort_keys=True) == json.dumps(
        PY.compare_runs(shuffled, a, {"a": ["x"], "b": ["f"], "z": ["f"]}), sort_keys=True
    )


def test_unknown_case_ids_raise():
    with pytest.raises(ValueError, match="not in the manifest"):
        PY.compare_runs(M, {"nope": []}, {})
    with pytest.raises(ValueError, match="not in the manifest"):
        PY.compare_runs(M, {}, {"nope": []})


def test_hostile_inputs_and_k():
    with pytest.raises(ValueError):
        PY.compare_runs(M, {"a": "f"}, {})
    with pytest.raises(ValueError):
        PY.compare_runs(M, [], {})
    with pytest.raises(ValueError):
        PY.compare_runs(M, {}, {}, k=0)


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.delenv("RQ_ALLOWED_DIRS", raising=False)
    return {
        "m": _write(tmp_path, "m.json", M),
        "same_a": _write(tmp_path, "sa.json", {"a": ["f"], "n": []}),
        "same_b": _write(tmp_path, "sb.json", {"a": ["f"], "n": []}),
        "diff_b": _write(tmp_path, "db.json", {"a": ["x"], "n": []}),
        "blocked": _write(tmp_path, "bl.json", {"a": None}),
        "list": _write(tmp_path, "li.json", ["f"]),
    }


def test_cli_exit_0_on_identical(files, capsys):
    assert main(["parity", files["m"], files["same_a"], files["same_b"]]) == 0
    assert json.loads(capsys.readouterr().out)["identical"] is True


def test_cli_exit_1_on_disagreement(files, capsys):
    assert main(["parity", files["m"], files["same_a"], files["diff_b"]]) == 1
    assert json.loads(capsys.readouterr().out)["disagreements"] == ["a"]


def test_cli_exit_2_when_nothing_comparable(files, capsys):
    assert main(["parity", files["m"], files["blocked"], files["same_b"]]) == 2


def test_cli_exit_2_on_usage_and_bad_input(files, tmp_path, capsys):
    assert main(["parity", files["m"], files["list"], files["same_b"]]) == 2
    assert main(["parity", files["m"], str(tmp_path / "missing.json"), files["same_b"]]) == 2
    bad_k = ["parity", files["m"], files["same_a"], files["same_b"], "--k", "0"]
    assert main(bad_k) == 2


def test_cli_refuses_paths_outside_allowed_roots(files, monkeypatch, capsys):
    monkeypatch.delenv("RQ_ALLOWED_DIRS", raising=False)
    assert main(["parity", "/etc/hostname", files["same_a"], files["same_b"]]) == 2
    assert main(["parity", files["m"], "/etc/hostname", files["same_b"]]) == 2
    assert main(["parity", files["m"], files["same_a"], "/etc/hostname"]) == 2


def test_cli_subprocess_exit_code(files):
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.research_qualification",
            "parity",
            files["m"],
            files["same_a"],
            files["diff_b"],
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1 and json.loads(r.stdout)["outcomes"]["b-only"] == 0
