"""Tests for sample_size, call_model and fixture_pairs (RQ-01b, RQ-03a, sample-size table)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.research_qualification import call_model as CM  # noqa: E402
from tools.research_qualification import fixture_pairs as FP  # noqa: E402
from tools.research_qualification import sample_size as SS  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402

needs_toolchain = pytest.mark.skipif(not FP.elf_toolchain_available(), reason="needs a Linux-targeting gcc and nm (ELF fixtures)")


def test_sample_size_golden():
    assert SS.min_cases(0.90, 0) == 29
    assert SS.min_cases(0.90, 1) == 46
    assert SS.min_cases(0.90, 2) == 61
    assert SS.min_cases(0.80, 0) == 14
    assert round(SS.lower_bound(15, 15), 3) == 0.819
    assert round(SS.lower_bound(49, 50), 3) == 0.909


def test_sample_size_monotonic_and_hostile():
    assert SS.lower_bound(29, 29) > SS.lower_bound(28, 29) > SS.lower_bound(27, 29)
    for bad in [(-1, 5), (6, 5), (0, 0)]:
        with pytest.raises(ValueError):
            SS.lower_bound(*bad)
    for t in (0, 1, -0.5, 1.5):
        with pytest.raises(ValueError):
            SS.min_cases(t)
    with pytest.raises(ValueError):
        SS.min_cases(0.999, 0, limit=10)


def test_call_model_analytic_and_simulation_agree():
    p = CM.Params(pairs=300, old_functions=40, new_functions=40)
    sim = CM.simulate(p)
    assert sim["decisions_identical"] is True
    assert sim["baseline_calls"] == sim["expected_baseline"]
    assert sim["cached_calls"] == sim["expected_cached"]
    assert sim["cached_calls"] < sim["baseline_calls"]


def test_call_model_amplification_scales_with_pairs_and_marks_unverified():
    a = CM.analytic(CM.Params(1000, 100, 100))
    b = CM.analytic(CM.Params(4000, 100, 100))
    assert b["amplification"] > a["amplification"] * 3.5
    assert CM.UNVERIFIED in a["unverified"]
    assert "estimated_baseline_seconds" not in a
    t = CM.analytic(CM.Params(1000, 100, 100), us_per_call=10)
    assert "not measured" in t["time_basis"]
    assert all(r["amplification"] > 1 for r in CM.sensitivity(CM.Params(1000, 100, 100)))


@pytest.mark.parametrize("args", [(0, 1, 1), (1, 0, 1), (5, 1, 1), (-1, 3, 3)])
def test_call_model_rejects_bad_params(args):
    with pytest.raises(ValueError):
        CM.analytic(CM.Params(*args))


def test_call_model_zero_traversals():
    out = CM.analytic(CM.Params(10, 5, 5, traversals=0))
    assert out["cached_predicate_evaluations"] == 0


def _truth():
    f = lambda base: [{"name": n, "addr": base + 16 * i, "size": 8} for i, n in enumerate(FP.FUNCTIONS)]  # noqa: E731
    return {"older": {"functions": f(0x1000)}, "newer": {"functions": f(0x2000)},
            "expected": {"matched": [[n, n] for n in FP.FUNCTIONS]}}


def _good():
    return [{"old": 0x1000 + 16 * i, "new": 0x2000 + 16 * i} for i in range(len(FP.FUNCTIONS))]


def test_score_perfect():
    r = FP.score_matches(_truth(), _good())
    assert r["passed"] and r["correct"] == 6 and r["omitted"] == 0


def test_score_false_match_and_omission():
    m = _good()
    m[0]["new"], m[1]["new"] = m[1]["new"], m[0]["new"]
    r = FP.score_matches(_truth(), m)
    assert not r["passed"] and r["false_matches"] == 2 and r["omitted"] == 2
    r = FP.score_matches(_truth(), _good()[:4])
    assert not r["passed"] and r["omitted"] == 2 and r["false_matches"] == 0


def test_score_inverted_and_unknown():
    swapped = [{"old": m["new"], "new": m["old"]} for m in _good()]
    r = FP.score_matches(_truth(), swapped)
    assert r["orientation_inverted"] and not r["passed"]
    r = FP.score_matches(_truth(), _good() + [{"old": 1, "new": 2}])
    assert r["unknown_entries"] == 1 and not r["passed"]


def test_score_empty_is_not_a_pass():
    r = FP.score_matches(_truth(), [])
    assert not r["passed"] and r["omitted"] == 6


@pytest.mark.parametrize("bad", [None, "x", [1], [{"old": 1}], [{"old": "1", "new": 2}], [{"old": True, "new": 2.5}]])
def test_score_rejects_malformed(bad):
    with pytest.raises(ValueError):
        FP.score_matches(_truth(), bad)


@needs_toolchain
@pytest.mark.parametrize("case", list(FP.CASES))
def test_fixture_cases_truth_and_reproducible(case, tmp_path):
    truth = FP.build_case(case, tmp_path)
    assert FP.verify_truth(case, truth, tmp_path) == []
    assert FP.check_reproducible(case, tmp_path, truth)
    assert truth["older"]["sha256"] != truth["newer"]["sha256"] or case == "identical"


@needs_toolchain
def test_material_fix_changes_only_the_mutated_function(tmp_path):
    t = FP.build_case("material-fix", tmp_path)
    old, new = tmp_path / "material-fix/old/old.so", tmp_path / "material-fix/new/new.so"
    of = {f["name"]: f for f in t["older"]["functions"]}
    nf = {f["name"]: f for f in t["newer"]["functions"]}
    diff = [n for n in FP.FUNCTIONS if FP.function_bytes(old, of[n]) != FP.function_bytes(new, nf[n])]
    assert diff == [FP.MUTATED]


@needs_toolchain
def test_verify_truth_catches_a_false_claim(tmp_path):
    t = FP.build_case("material-fix", tmp_path)
    t["expected"]["changed"] = []
    assert any("declared unchanged" in p for p in FP.verify_truth("material-fix", t, tmp_path))


def test_function_bytes_rejects_non_elf(tmp_path):
    p = tmp_path / "x.so"
    p.write_bytes(b"MZ" + b"\0" * 100)
    with pytest.raises(FP.FixtureError):
        FP.function_bytes(p, {"name": "f", "addr": 0, "size": 1})


def test_cli_samplesize_and_callmodel_and_score(tmp_path, capsys):
    assert main(["samplesize", "--target", "0.9", "--max-errors", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["min_independent_cases"] == 46
    assert main(["samplesize", "--target", "2"]) == 2
    capsys.readouterr()
    assert main(["callmodel", "--pairs", "1000", "--old", "100", "--new", "100", "--simulate"]) == 0
    assert main(["callmodel", "--pairs", "0", "--old", "1", "--new", "1"]) == 2
    t, m = tmp_path / "t.json", tmp_path / "m.json"
    t.write_text(json.dumps(_truth()))
    m.write_text(json.dumps(_good()))
    assert main(["fixtures", "score", "--truth", str(t), "--matches", str(m)]) == 0
    m.write_text("[]")
    assert main(["fixtures", "score", "--truth", str(t), "--matches", str(m)]) == 1
    assert main(["fixtures", "score", "--truth", str(t), "--matches", str(tmp_path / "none")]) == 2


@needs_toolchain
def test_cli_fixtures_build(tmp_path, capsys):
    assert main(["fixtures", "build", "--out", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"


def test_non_elf_toolchain_is_blocked_not_failed(monkeypatch, tmp_path):
    class R:
        stdout = "x86_64-w64-mingw32\n"
    monkeypatch.setattr(FP.subprocess, "run", lambda *a, **k: R())
    monkeypatch.setattr(FP, "_tool", lambda name: name)
    with pytest.raises(FP.FixtureError, match="not an ELF target"):
        FP.build_case("identical", tmp_path)
    assert FP.elf_toolchain_available() is False
    assert main(["fixtures", "build", "--out", str(tmp_path / "b")]) == 2
