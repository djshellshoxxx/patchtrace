from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import cases as CS  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402

SHA = "a" * 64


def case(i="c1", **kw):
    c = {"id": i, "layer": "L2", "stratum": "msvc-own-build", "project": "proj-" + i, "source_url": "https://example.org/x",
         "licence": "MIT", "older": {"ref": "v1"}, "newer": {"ref": "v2"}, "expected": {"function": "parse"},
         "facts": "unverified", "holdout": False}
    c.update(kw)
    return c


def manifest(*cs):
    return {"schema": CS.SCHEMA, "cases": list(cs)}


def test_valid_manifest_summary_counts_projects_not_cases():
    m = manifest(case("a", project="p"), case("b", project="p"), case("c", project="q", holdout=True))
    s = CS.validate_manifest(m)["layers"]["L2"]
    assert s["cases"] == 3 and s["independent_projects"] == 2 and s["holdout"] == 1 and s["unverified"] == 3
    assert s["best_case_lower_bound_if_no_errors"] < 0.8


@pytest.mark.parametrize("mut", [
    lambda c: c.update(layer="L9"), lambda c: c.update(id="../x"), lambda c: c.update(source_url="http://x"),
    lambda c: c.update(extra=1), lambda c: c.update(holdout="yes"), lambda c: c.update(licence=""),
    lambda c: c["older"].update(sha256="XYZ"), lambda c: c.update(expected={}),
    lambda c: c.update(expected={"function": "f", "no_change": True}),
    lambda c: c.update(facts="verified"),
])
def test_bad_cases_rejected(mut):
    c = copy.deepcopy(case())
    mut(c)
    with pytest.raises(ValueError):
        CS.validate_manifest(manifest(c))


def test_verified_with_hashes_ok_and_no_change_case():
    ok = case(facts="verified", older={"ref": "a", "sha256": SHA}, newer={"ref": "b", "sha256": SHA})
    CS.validate_manifest(manifest(ok, case("n", expected={"no_change": True})))


def test_duplicate_ids_and_bad_manifest():
    with pytest.raises(ValueError):
        CS.validate_manifest(manifest(case("a"), case("a", project="z")))
    for bad in (None, [], {"schema": "x", "cases": []}, {"schema": CS.SCHEMA, "cases": "no"}):
        with pytest.raises(ValueError):
            CS.validate_manifest(bad)


def test_freeze_detects_edits_but_not_order():
    a, b = case("a"), case("b")
    sha = CS.canonical_hash(manifest(a, b))
    CS.check_frozen(manifest(b, a), sha)
    edited = copy.deepcopy(b)
    edited["expected"]["function"] = "other"
    with pytest.raises(ValueError):
        CS.check_frozen(manifest(a, edited), sha)
    with pytest.raises(ValueError):
        CS.check_frozen(manifest(a, b), "nothex")


def test_cli(tmp_path, capsys):
    f = tmp_path / "m.json"
    m = manifest(case("a"))
    f.write_text(json.dumps(m))
    assert main(["cases", str(f)]) == 0
    sha = json.loads(capsys.readouterr().out)["manifest_sha256"]
    assert main(["cases", str(f), "--frozen-sha", sha]) == 0
    assert main(["cases", str(f), "--frozen-sha", "0" * 64]) == 1
    f.write_text("{}")
    assert main(["cases", str(f)]) == 2
    assert main(["cases", str(tmp_path / "none.json")]) == 2
