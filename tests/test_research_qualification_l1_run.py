"""L1 advisory-join runner (`l1-run`): mechanics only, on a synthetic manifest and the synthetic CVRF month.

Every input here is a hand-written fixture (`tests/fixtures/kbcorrelation/`, CVE-2099-*, KB5099*), so nothing in this
file is live evidence and no accuracy figure follows from it.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.research_qualification import l1_check as L1  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "kbcorrelation"
# The fixture's client product has no Windows generation in its name, so the product derives no file-index key for
# it. Renaming it (as tests/test_kbc_acquire_cli.py does) gives the scope the key the synthetic records use.
WIN11 = "Windows 11 Version 24H2 for x64-based Systems"
PASS_ID, EDGE_ID, MONTH_ID, UNVERIFIED_ID = "l1-a-pass", "l1-b-missing-edge", "l1-c-absent-month", "l1-d-unverified"


def case(cid, **kw):
    c = {"id": cid, "month": "2099-Feb", "cve": "CVE-2099-20001", "kb": "KB5099001", "product": WIN11,
         "expected_files": ["exampledrv.sys"], "oracle_urls": ["https://example.invalid/synthetic"],
         "stratum": "baseline-driver", "facts": "verified", "notes": "synthetic"}
    c.update(kw)
    return c


def four_cases():
    return [case(PASS_ID),
            case(EDGE_ID, cve="CVE-2099-20002"),  # the month lists this CVE under KB5099002 (server) only
            case(MONTH_ID, month="2099-Mar"),
            case(UNVERIFIED_ID, cve="CVE-2099-20003", facts="unverified")]  # would FAIL if it were ever asked


def write_manifest(tmp_path, cases, name="manifest.json"):
    m = {"schema": L1.SCHEMA, "cases": sorted(cases, key=lambda c: c["id"])}
    path = tmp_path / name
    path.write_text(json.dumps(m, indent=1), encoding="utf-8", newline="\n")
    return path, L1.manifest_hash(m)


@pytest.fixture
def months(tmp_path):
    d = tmp_path / "months"
    d.mkdir()
    raw = (FX / "cvrf-2099-Feb.json").read_bytes()
    assert b"Example OS 24H2 x64" in raw
    (d / "2099-Feb.json").write_bytes(raw.replace(b"Example OS 24H2 x64", WIN11.encode("ascii")))
    return d


@pytest.fixture
def winbindex(tmp_path):
    d = tmp_path / "winbindex"
    d.mkdir()
    for name in ("exampledrv.sys.json", "examplenet.sys.json"):
        shutil.copyfile(FX / "winbindex" / name, d / name)
    return d


def run(tmp_path, months, cases, *extra, out="receipt.json", frozen=True, evidence="synthetic"):
    manifest, sha = write_manifest(tmp_path, cases)
    target = tmp_path / out
    argv = ["l1-run", str(manifest), "--months", str(months), "--out", str(target), *extra]
    if frozen:
        argv += ["--frozen-sha", sha]
    if evidence:
        argv += ["--evidence-class", evidence]
    code = main(argv)
    return code, json.loads(target.read_text(encoding="utf-8")) if target.exists() else None


def rows_of(receipt):
    return {r["id"]: r for r in receipt["cases"]}


def test_pass_fail_blocked_and_unverified_excluded(tmp_path, months, monkeypatch):
    from tools.research_qualification import l1_run as L1R
    asked = []
    real = L1R.ProductJoin.search
    monkeypatch.setattr(L1R.ProductJoin, "search", lambda self, cve, month: asked.append(cve) or real(self, cve, month))
    code, rec = run(tmp_path, months, four_cases())
    assert code == 1 and rec["status"] == "FAIL" and rec["schema"] == "rq-l1-run/1" and rec["layer"] == "L1"
    rows = rows_of(rec)
    assert set(rows) == {PASS_ID, EDGE_ID, MONTH_ID}
    assert rows[PASS_ID]["outcome"] == "PASS"
    assert rows[PASS_ID]["checks"] == {"edge": "pass", "scope": "pass", "file": "not-asked"}
    assert rows[EDGE_ID]["outcome"] == "FAIL" and rows[EDGE_ID]["checks"]["edge"] == "fail"
    assert "KB5099001" in rows[EDGE_ID]["reason"] and rows[EDGE_ID]["observed"]["kbs"] == ["KB5099002"]
    assert rows[MONTH_ID]["outcome"] == "BLOCKED" and "2099-Mar" in rows[MONTH_ID]["reason"]
    assert rows[MONTH_ID]["checks"] == {"edge": "not-asked", "scope": "not-asked", "file": "not-asked"}
    # The unverified case is listed, never asked and in no count.
    assert rec["excluded"] == [{"id": UNVERIFIED_ID, "reason": "facts: unverified", "stratum": "baseline-driver"}]
    assert "CVE-2099-20003" not in asked and sorted(asked) == ["CVE-2099-20001"] * 2 + ["CVE-2099-20002"]
    counts = rec["counts"]
    assert (counts["cases"], counts["excluded_unverified"], counts["asked"]) == (4, 1, 3)
    assert (counts["PASS"], counts["FAIL"], counts["BLOCKED"], counts["scored"]) == (1, 1, 1, 2)
    assert counts["checks"]["edge"] == {"asked": 2, "passed": 1}
    assert counts["by_stratum"] == {"baseline-driver": {"PASS": 1, "FAIL": 1, "BLOCKED": 1, "excluded": 1}}


def test_synthetic_receipt_states_its_limits_and_carries_no_bound(tmp_path, months):
    code, rec = run(tmp_path, months, [case(PASS_ID)])
    assert code == 0 and rec["status"] == "PASS"
    assert rec["evidence_class"] == "synthetic" and rec["bound"] is None
    assert any("no accuracy" in line for line in rec["limits"])
    assert rec["manifest"]["sha256"] == rec["manifest"]["frozen_sha256"]
    assert [m["release_id"] for m in rec["inputs"]["months"]] == ["2099-Feb"]
    assert rec["inputs"]["months"][0]["file"] == "2099-Feb.json" and len(rec["inputs"]["months"][0]["sha256"]) == 64


def test_receipt_bytes_are_deterministic_and_carry_no_local_path(tmp_path, months, winbindex):
    extra = ["--winbindex", str(winbindex), "--winbindex-date", "2099-02-12"]
    assert run(tmp_path, months, four_cases(), *extra, out="a.json")[0] == 1
    assert run(tmp_path, months, four_cases(), *extra, out="b.json")[0] == 1
    a, b = (tmp_path / "a.json").read_bytes(), (tmp_path / "b.json").read_bytes()
    assert a == b and a.endswith(b"\n") and b"\r" not in a
    assert str(tmp_path).encode() not in a and tmp_path.name.encode() not in a


@pytest.mark.parametrize("frozen_args", [[], ["--frozen-sha", "0" * 64], ["--frozen-sha", "not-a-hash"]],
                         ids=["absent", "wrong", "malformed"])
def test_unfrozen_manifest_is_refused_for_a_scored_run(tmp_path, months, frozen_args, monkeypatch, capsys):
    from tools.research_qualification import l1_run as L1R
    monkeypatch.setattr(L1R.ProductJoin, "__init__", lambda *a, **k: pytest.fail("the join must not be asked"))
    code, rec = run(tmp_path, months, four_cases(), *frozen_args, frozen=False)
    assert code == 2 and rec is None
    assert "frozen" in capsys.readouterr().err


def test_dry_run_lists_what_would_be_asked_without_running(tmp_path, monkeypatch, capsys):
    from tools.research_qualification import l1_run as L1R
    monkeypatch.setattr(L1R.ProductJoin, "__init__", lambda *a, **k: pytest.fail("a dry run asks nothing"))
    manifest, _ = write_manifest(tmp_path, four_cases())
    assert main(["l1-run", str(manifest), "--dry-run"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["dry_run"] is True and plan["frozen"] == "not-given"
    assert [a["id"] for a in plan["would_ask"]] == [PASS_ID, EDGE_ID, MONTH_ID]
    assert plan["would_ask"][0] == {"id": PASS_ID, "search": "CVE-2099-20001", "month": "2099-Feb",
                                    "expect_kb": "KB5099001", "expect_product": WIN11, "files": ["exampledrv.sys"]}
    assert [e["id"] for e in plan["excluded"]] == [UNVERIFIED_ID]
    assert list(tmp_path.glob("*receipt*")) == []


def test_dry_run_of_the_committed_corpus_excludes_every_unverified_case(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    corpus = json.loads(L1.DEFAULT_PATH.read_text(encoding="utf-8"))["cases"]
    assert main(["l1-run", str(L1.DEFAULT_PATH), "--dry-run"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert [e["id"] for e in plan["excluded"]] == [c["id"] for c in corpus if c["facts"] == "unverified"]
    assert [a["id"] for a in plan["would_ask"]] == [c["id"] for c in corpus if c["facts"] == "verified"]
    assert plan["excluded"] and plan["would_ask"]


def test_paths_outside_the_allowed_roots_are_refused(tmp_path, months, monkeypatch):
    monkeypatch.delenv("RQ_ALLOWED_DIRS", raising=False)
    manifest, sha = write_manifest(tmp_path, [case(PASS_ID)])
    tail = ["--frozen-sha", sha, "--evidence-class", "synthetic"]
    out = str(tmp_path / "receipt.json")
    assert main(["l1-run", "/etc/passwd", "--months", str(months), "--out", out, *tail]) == 2
    assert main(["l1-run", str(manifest), "--months", "/etc", "--out", out, *tail]) == 2
    assert main(["l1-run", str(manifest), "--months", str(months), "--out", "/etc/rq-l1.json", *tail]) == 2
    assert main(["l1-run", str(manifest), "--months", str(months), "--out", out, *tail,
                 "--winbindex", "/etc", "--winbindex-date", "2099-02-12"]) == 2
    assert main(["l1-run", "/etc/passwd", "--dry-run"]) == 2
    assert not Path(out).exists()


def test_evidence_class_is_never_guessed(tmp_path, months, capsys):
    code, rec = run(tmp_path, months, [case(PASS_ID)], evidence=None)
    assert code == 2 and rec is None and "--evidence-class" in capsys.readouterr().err


def test_an_existing_receipt_is_never_overwritten(tmp_path, months, capsys):
    (tmp_path / "receipt.json").write_text("prior result", encoding="utf-8")
    manifest, sha = write_manifest(tmp_path, [case(PASS_ID)])
    assert main(["l1-run", str(manifest), "--months", str(months), "--out", str(tmp_path / "receipt.json"),
                 "--frozen-sha", sha, "--evidence-class", "synthetic"]) == 2
    assert (tmp_path / "receipt.json").read_text(encoding="utf-8") == "prior result"
    assert "exists" in capsys.readouterr().err


def test_blocked_cases_block_the_run_but_are_not_misses(tmp_path, months):
    code, rec = run(tmp_path, months, [case(PASS_ID), case(MONTH_ID, month="2099-Mar")])
    assert code == 2 and rec["status"] == "BLOCKED"
    assert (rec["counts"]["PASS"], rec["counts"]["FAIL"], rec["counts"]["BLOCKED"]) == (1, 0, 1)
    assert rec["counts"]["scored"] == 1


def test_product_scope_and_no_kb_expectations(tmp_path, months):
    cases = [case("l1-a-scope", kb="KB5099002"),  # KB5099002 is the server row of this CVE, not the client product
             case("l1-b-nokb-ok", cve="CVE-2099-20003", kb="", stratum="no-kb", expected_files=[]),  # mention only
             case("l1-c-nokb-bad", kb="", stratum="no-kb", expected_files=[])]
    code, rec = run(tmp_path, months, cases)
    rows = rows_of(rec)
    assert code == 1
    assert rows["l1-a-scope"]["checks"] == {"edge": "pass", "scope": "fail", "file": "not-asked"}
    assert rows["l1-a-scope"]["outcome"] == "FAIL" and "Example Server 2099 x64" in rows["l1-a-scope"]["observed"]["products"]
    assert rows["l1-b-nokb-ok"]["outcome"] == "PASS" and rows["l1-b-nokb-ok"]["checks"]["scope"] == "not-asked"
    assert rows["l1-c-nokb-bad"]["outcome"] == "FAIL" and "KB5099001" in rows["l1-c-nokb-bad"]["reason"]


def test_file_leg_with_a_supplied_file_index(tmp_path, months, winbindex):
    cases = [case("l1-a-changed"),
             case("l1-b-unchanged", expected_files=["examplenet.sys"]),  # listed under the KB, last changed earlier
             case("l1-c-norecord", expected_files=["absent.sys"]),
             case("l1-d-badname", expected_files=["example.tsp"])]  # the product's file index refuses this extension
    code, rec = run(tmp_path, months, cases, "--winbindex", str(winbindex), "--winbindex-date", "2099-02-12")
    rows = rows_of(rec)
    assert code == 1
    assert rows["l1-a-changed"]["outcome"] == "PASS" and rows["l1-a-changed"]["checks"]["file"] == "pass"
    assert rows["l1-a-changed"]["files"] == [{"name": "exampledrv.sys", "result": "pass", "changed_in_kb": "yes",
                                              "candidates": 1, "detail": ""}]
    assert rows["l1-b-unchanged"]["outcome"] == "FAIL" and rows["l1-b-unchanged"]["checks"]["file"] == "fail"
    assert rows["l1-b-unchanged"]["files"][0]["changed_in_kb"] == "no"
    assert "KB5097000" in rows["l1-b-unchanged"]["files"][0]["detail"]
    assert rows["l1-c-norecord"]["outcome"] == "BLOCKED" and rows["l1-c-norecord"]["checks"]["file"] == "blocked"
    assert rows["l1-d-badname"]["outcome"] == "FAIL" and rows["l1-d-badname"]["checks"]["file"] == "fail"
    assert rec["counts"]["checks"]["file"] == {"asked": 3, "passed": 1, "blocked": 1}
    assert [r["name"] for r in rec["inputs"]["winbindex"]["records"]] == ["exampledrv.sys", "examplenet.sys"]
    assert rec["inputs"]["winbindex"]["data_date"] == "2099-02-12"


def test_winbindex_needs_an_explicit_data_date(tmp_path, months, winbindex, capsys):
    code, rec = run(tmp_path, months, [case(PASS_ID)], "--winbindex", str(winbindex))
    assert code == 2 and rec is None and "--winbindex-date" in capsys.readouterr().err


def test_a_rejected_month_file_is_recorded_and_blocks_only_its_cases(tmp_path, months):
    shutil.copyfile(FX / "cvrf-2099-Feb-duplicate-key.json", months / "2099-Mar.json")
    code, rec = run(tmp_path, months, [case(PASS_ID), case(MONTH_ID, month="2099-Mar")])
    rows = rows_of(rec)
    assert code == 2 and rows[PASS_ID]["outcome"] == "PASS" and rows[MONTH_ID]["outcome"] == "BLOCKED"
    rejected = [m for m in rec["inputs"]["months"] if m["status"] == "rejected"]
    assert [m["file"] for m in rejected] == ["2099-Mar.json"] and rejected[0]["reason"]


def test_invalid_manifest_is_a_usage_error(tmp_path, months, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": L1.SCHEMA, "cases": [case("l1-b"), case("l1-a")]}), encoding="utf-8")
    assert main(["l1-run", str(bad), "--dry-run"]) == 2
    assert "sorted" in capsys.readouterr().err


def test_bound_counts_independent_products_and_only_for_live_evidence():
    from tools.research_qualification import l1_run as L1R
    from tools.research_qualification.sample_size import lower_bound
    rows = [{"product": "A", "outcome": "PASS"}, {"product": "A", "outcome": "FAIL"},
            {"product": "B", "outcome": "PASS"}, {"product": "B", "outcome": "PASS"},
            {"product": "C", "outcome": "BLOCKED"}]
    assert L1R.product_bound(rows, "synthetic") is None
    bound = L1R.product_bound(rows, "live")
    assert (bound["unit"], bound["n"], bound["correct"]) == ("product", 2, 1)  # A has a miss; C was never scored
    assert bound["lower_bound"] == round(lower_bound(1, 2), 3)
    assert L1R.product_bound([{"product": "C", "outcome": "BLOCKED"}], "live")["lower_bound"] is None


def test_scope_is_matched_by_the_products_own_identity_when_names_merge(tmp_path, months):
    # Two advisory names that the product maps to one scope: the scope shows the smaller name, so the expected name
    # is found through the product's own scope identity, and a different release still fails.
    path = months / "2099-Feb.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["product_tree"].append({"architecture": "amd64", "family": "windows-client", "product_id": "PT-CLIENT-ALT",
                                "name": "Microsoft " + WIN11})
    path.write_text(json.dumps(doc, indent=1), encoding="utf-8", newline="\n")
    cases = [case("l1-a-merged"), case("l1-b-other-release", product=WIN11.replace("24H2", "23H2"))]
    code, rec = run(tmp_path, months, cases)
    rows = rows_of(rec)
    assert code == 1
    assert rows["l1-a-merged"]["observed"]["products"] == ["Example OS 24H2 ARM64", "Microsoft " + WIN11]
    assert rows["l1-a-merged"]["outcome"] == "PASS" and rows["l1-a-merged"]["observed"]["scope_match"] == "scope-id"
    assert rows["l1-b-other-release"]["checks"] == {"edge": "pass", "scope": "fail", "file": "not-asked"}


def test_a_join_that_raises_leaves_the_case_blocked_not_failed(tmp_path, months, monkeypatch):
    from tools.research_qualification import l1_run as L1R

    def boom(self, cve, month):
        raise RuntimeError("synthetic crash with /home/someone/private in its text")

    monkeypatch.setattr(L1R.ProductJoin, "search", boom)
    code, rec = run(tmp_path, months, [case(PASS_ID)])
    row = rows_of(rec)[PASS_ID]
    assert code == 2 and row["outcome"] == "BLOCKED" and "RuntimeError" in row["reason"]
    assert "someone" not in json.dumps(rec)  # exception text is not copied into a receipt


@pytest.mark.parametrize("text", ['{"schema": "rq-l1-manifest/1", "cases": [], "cases": []}',
                                  '{"schema": "rq-l1-manifest/1", "cases": [], "x": NaN}'],
                         ids=["duplicate-key", "nan"])
def test_manifest_must_be_strict_json(tmp_path, text, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(text, encoding="utf-8")
    assert main(["l1-run", str(bad), "--dry-run"]) == 2
    assert "strict JSON" in capsys.readouterr().err


def test_write_receipt_creates_exclusively(tmp_path):
    from tools.research_qualification import l1_run as L1R
    target = tmp_path / "sub" / "receipt.json"
    L1R.write_receipt({"b": 1, "a": "é"}, target)
    assert target.read_bytes() == b'{\n  "a": "\\u00e9",\n  "b": 1\n}\n'
    with pytest.raises(L1R.RunBlocked, match="never overwritten"):
        L1R.write_receipt({"a": 2}, target)
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": "é", "b": 1}


def test_months_must_be_a_directory(tmp_path, capsys):
    not_a_dir = tmp_path / "months.json"
    not_a_dir.write_text("{}", encoding="utf-8")
    code, rec = run(tmp_path, not_a_dir, [case(PASS_ID)])
    assert code == 2 and rec is None and "--months is not a directory" in capsys.readouterr().err


def test_a_patchtrace_from_another_checkout_is_not_scored(tmp_path, months, monkeypatch, capsys):
    # The receipt describes this checkout, so a join imported from somewhere else must not be scored under its name.
    from tools.research_qualification import l1_run as L1R
    other = tmp_path / "other-checkout"
    (other / "src" / "patchtrace").mkdir(parents=True)
    monkeypatch.setattr(L1R, "REPO", other)
    code, rec = run(tmp_path, months, [case(PASS_ID)])
    assert code == 2 and rec is None and "PYTHONPATH" in capsys.readouterr().err
