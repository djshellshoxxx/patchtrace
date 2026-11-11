from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import receipt as R  # noqa: E402
from tools.research_qualification import scorerun as SR  # noqa: E402

SHA_A, SHA_B = "a" * 64, "b" * 64


def case(cid, fn="Target", facts="verified", holdout=False, layer="L3", **exp):
    return {
        "id": cid, "layer": layer, "stratum": "s", "project": "p" + cid, "source_url": "https://x.org/a",
        "licence": "MIT", "older": {"ref": "a.sys", "sha256": SHA_A}, "newer": {"ref": "a.sys", "sha256": SHA_B},
        "expected": exp or {"function": fn}, "facts": facts, "holdout": holdout,
    }


def pair(cid, status="found", sha_new=SHA_B):
    return {"id": cid, "status": status,
            "older": {"status": "found", "path": f"{cid}/older/a.sys", "sha256": SHA_A},
            "newer": {"status": "found", "path": f"{cid}/newer/a.sys", "sha256": sha_new}}


def ghidriff_json(*names):
    mod = [{"old": {"name": n, "fullname": n}, "new": {"name": n}, "diff_type": ["code"], "ratio": 0.1 + i / 100}
           for i, n in enumerate(names)]
    return json.dumps({"functions": {"modified": mod, "added": [], "deleted": []}})


def put_report(reports, cid, text, status=None):
    d = reports / cid
    d.mkdir(parents=True)
    (d / "x.ghidriff.json").write_text(text, encoding="utf-8")
    if status is not None:
        (d / SR.STATUS_FILE).write_text(json.dumps(status), encoding="utf-8")


@pytest.fixture
def cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(cases, pairs, reports, k=5):
    m = {"schema": "rq-case-manifest/1", "cases": cases}
    return SR.score_all({p["id"]: p for p in pairs}, m, reports, k, "ghidriff")


def verdicts(res):
    return {r["id"]: (r["verdict"], r["reason"]) for r in res["rows"]}


def test_pass_fail_and_rank(cwd):
    put_report(cwd / "r", "hit", ghidriff_json("Other", "Target"))
    put_report(cwd / "r", "miss", ghidriff_json("Other"))
    res = run([case("hit"), case("miss")], [pair("hit"), pair("miss")], cwd / "r")
    assert verdicts(res) == {"hit": ("PASS", "hit"), "miss": ("FAIL", "miss")}
    assert res["rows"][0]["rank"] == 2
    assert SR.exit_for(res) == 1


def test_k_boundary(cwd):
    put_report(cwd / "r", "c", ghidriff_json("A", "Target"))
    assert verdicts(run([case("c")], [pair("c")], cwd / "r", k=1))["c"][0] == "FAIL"
    assert verdicts(run([case("c")], [pair("c")], cwd / "r", k=2))["c"][0] == "PASS"


def test_no_change_false_positive(cwd):
    put_report(cwd / "r", "n", ghidriff_json("Something"))
    res = run([case("n", no_change=True)], [pair("n")], cwd / "r")
    assert verdicts(res)["n"] == ("FAIL", "false_positive")


def test_unverified_blocked_even_with_report(cwd):
    put_report(cwd / "r", "u", ghidriff_json("Target"))
    c = case("u", facts="unverified")
    res = run([c], [pair("u")], cwd / "r")
    assert verdicts(res)["u"] == ("BLOCKED", "unverified")
    assert res["development"]["scored"] == 0 and SR.exit_for(res) == 2


def test_missing_pair_and_report_are_blocked_not_misses(cwd):
    (cwd / "r").mkdir()
    put_report(cwd / "r", "ok", ghidriff_json("Target"))
    cs = [case("ok"), case("nopair"), case("noreport"), case("miss2")]
    res = run(cs, [pair("ok"), pair("noreport"), pair("miss2", status="missing")], cwd / "r")
    v = verdicts(res)
    assert v["nopair"] == ("BLOCKED", "missing_pair")
    assert v["miss2"] == ("BLOCKED", "missing_pair")
    assert v["noreport"] == ("BLOCKED", "missing_report")
    d = res["development"]
    assert (d["scored"], d["pass"], d["fail"], d["blocked"]) == (1, 1, 0, 3)
    assert SR.exit_for(res) == 0


def test_tool_failure_timeout_and_bad_status(cwd):
    put_report(cwd / "r", "t", ghidriff_json("Target"), {"rc": 124, "timed_out": True})
    put_report(cwd / "r", "f", ghidriff_json("Target"), {"rc": 1, "timed_out": False})
    put_report(cwd / "r", "b", ghidriff_json("Target"), {"rc": "x"})
    put_report(cwd / "r", "g", ghidriff_json("Target"), {"rc": 0, "timed_out": False})
    res = run([case(i) for i in "tfbg"], [pair(i) for i in "tfbg"], cwd / "r")
    assert verdicts(res) == {"t": ("BLOCKED", "timeout"), "f": ("BLOCKED", "tool_failed"),
                             "b": ("BLOCKED", "bad_run_status"), "g": ("PASS", "hit")}


def test_unparseable_and_ambiguous_report_blocked(cwd):
    put_report(cwd / "r", "bad", "{not json")
    put_report(cwd / "r", "two", ghidriff_json("Target"))
    (cwd / "r" / "two" / "y.ghidriff.json").write_text(ghidriff_json("Target"), encoding="utf-8")
    res = run([case("bad"), case("two")], [pair("bad"), pair("two")], cwd / "r")
    assert verdicts(res)["bad"][1] == "unparseable_report"
    assert verdicts(res)["two"] == ("BLOCKED", "ambiguous_report")


def test_sha_mismatch_and_non_l3_blocked(cwd):
    put_report(cwd / "r", "s", ghidriff_json("Target"))
    put_report(cwd / "r", "l", ghidriff_json("Target"))
    res = run([case("s"), case("l", layer="L2")], [pair("s", sha_new="c" * 64), pair("l")], cwd / "r")
    assert verdicts(res)["s"] == ("BLOCKED", "sha_mismatch")
    assert verdicts(res)["l"] == ("BLOCKED", "layer_not_l3")


def test_holdout_reported_separately(cwd):
    put_report(cwd / "r", "d", ghidriff_json("Target"))
    put_report(cwd / "r", "h", ghidriff_json("Nope"))
    res = run([case("d"), case("h", holdout=True)], [pair("d"), pair("h")], cwd / "r")
    assert (res["development"]["pass"], res["development"]["fail"]) == (1, 0)
    assert (res["holdout"]["pass"], res["holdout"]["fail"]) == (0, 1)
    assert SR.exit_for(res) == 1


def test_symlinked_report_ignored(cwd):
    d = cwd / "r" / "s"
    d.mkdir(parents=True)
    real = cwd / "real.ghidriff.json"
    real.write_text(ghidriff_json("Target"), encoding="utf-8")
    (d / "x.ghidriff.json").symlink_to(real)
    res = run([case("s")], [pair("s")], cwd / "r")
    assert verdicts(res)["s"] == ("BLOCKED", "missing_report")


def test_plan_only_found_verified_l3(cwd):
    cs = [case("a"), case("u", facts="unverified"), case("m"), case("l", layer="L2")]
    ps = {p["id"]: p for p in [pair("a"), pair("u"), pair("m", status="missing"), pair("l")]}
    out = SR.plan(ps, {"schema": "rq-case-manifest/1", "cases": cs})
    assert out == {"include": [{"id": "a", "older": "a/older/a.sys", "newer": "a/newer/a.sys"}], "count": 1}


def test_plan_rejects_unsafe_paths():
    p = pair("a")
    p["older"]["path"] = "../../etc/passwd"
    assert SR.pair_problem(case("a"), p) == "missing_pair"


def write(path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")


def setup_files(cwd, cases, pairs):
    write(cwd / "cases.json", {"schema": "rq-case-manifest/1", "cases": cases})
    write(cwd / "pm.json", {"schema": SR.PAIR_SCHEMA, "cases": pairs})


def test_cli_exit_codes_and_receipt(cwd, capsys):
    put_report(cwd / "r", "a", ghidriff_json("Target"))
    setup_files(cwd, [case("a")], [pair("a")])
    args = ["score", "--pair-manifest", "pm.json", "--cases", "cases.json", "--reports", "r", "--out", "o"]
    assert SR.main(args) == 0
    receipts = [p for p in (cwd / "o").glob("rq-diffscore-*.json")]
    assert len(receipts) == 1
    rec = R.load_receipt(receipts[0])
    assert rec["result"]["status"] == "PASS" and rec["result"]["counters"]["blocked"] == 0
    assert (cwd / "o" / SR.RESULTS_FILE).is_file()
    assert SR.main(args) == 2  # refuses to overwrite prior results
    capsys.readouterr()


def test_cli_all_blocked_is_2_and_receipt_blocked(cwd):
    (cwd / "r").mkdir()
    setup_files(cwd, [case("a")], [pair("a", status="missing")])
    assert SR.main(["score", "--pair-manifest", "pm.json", "--cases", "cases.json", "--reports", "r",
                    "--out", "o"]) == 2
    rec = R.load_receipt(next((cwd / "o").glob("rq-diffscore-*.json")))
    assert rec["result"]["status"] == "BLOCKED" and rec["result"]["blocked_reasons"]


def test_cli_fail_is_1(cwd):
    put_report(cwd / "r", "a", ghidriff_json("Nope"))
    setup_files(cwd, [case("a")], [pair("a")])
    assert SR.main(["score", "--pair-manifest", "pm.json", "--cases", "cases.json", "--reports", "r",
                    "--out", "o"]) == 1


def test_cli_confinement_and_usage(cwd, tmp_path_factory, capsys):
    outside = tmp_path_factory.mktemp("x")
    setup_files(cwd, [case("a")], [pair("a")])
    # tmp is an allowed root, so use a path outside every root
    assert SR.main(["score", "--pair-manifest", "/etc/hostname", "--cases", "cases.json", "--reports", "r",
                    "--out", "o"]) == 2
    assert "outside" in capsys.readouterr().err
    assert SR.main(["plan", "--pair-manifest", "pm.json", "--cases", "cases.json", "--out", "/etc/m.json"]) == 2
    assert SR.main([]) == 2
    assert SR.main(["score", "--pair-manifest", "pm.json", "--cases", "cases.json", "--reports", "r",
                    "--out", "o", "--k", "0"]) == 2
    assert SR.main(["score", "--pair-manifest", "pm.json", "--cases", "cases.json", "--reports", "r",
                    "--out", "o", "--engine", "nope"]) == 2
    assert outside.exists()


def test_cli_bad_schema_is_2(cwd):
    write(cwd / "pm.json", {"schema": "wrong", "cases": []})
    write(cwd / "cases.json", {"schema": "rq-case-manifest/1", "cases": []})
    assert SR.main(["plan", "--pair-manifest", "pm.json", "--cases", "cases.json"]) == 2


def test_cli_plan_prints_matrix(cwd, capsys):
    setup_files(cwd, [case("a")], [pair("a")])
    assert SR.main(["plan", "--pair-manifest", "pm.json", "--cases", "cases.json", "--out", "m.json"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 1
    assert json.loads((cwd / "m.json").read_text())["include"][0]["id"] == "a"
