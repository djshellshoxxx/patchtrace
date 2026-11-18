from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import l1_check as L1  # noqa: E402


def case(i="l1-2024-08-cve-2024-38196-kb5041571", **kw):
    c = {"id": i, "month": "2024-Aug", "cve": "CVE-2024-38196", "kb": "KB5041571",
         "product": "Windows 11 Version 24H2 for x64-based Systems", "expected_files": ["clfs.sys"],
         "oracle_urls": ["https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Aug"],
         "stratum": "baseline-driver", "facts": "verified", "notes": "n"}
    c.update(kw)
    return c


def manifest(*cs):
    return {"schema": L1.SCHEMA, "cases": list(cs)}


def test_valid_manifest_summary():
    s = L1.check_manifest(manifest(case(), case("l1-b", stratum="no-kb", kb="", expected_files=[])))
    assert s["cases"] == 2 and s["strata"] == {"baseline-driver": 1, "no-kb": 1} and len(s["manifest_sha256"]) == 64


@pytest.mark.parametrize("bad", [
    {"facts": "maybe"}, {"stratum": "other"}, {"cve": "CVE-24-1"}, {"kb": "5041571"}, {"month": "2024-08"},
    {"expected_files": ["b.sys", "a.sys"]}, {"expected_files": ["C:\\x.sys"]}, {"oracle_urls": ["http://x.org/a"]},
    {"oracle_urls": ["https://x.org/a", "https://x.org/a"]}, {"product": " "}, {"notes": ""}, {"surprise": 1},
    {"expected_files": []}, {"products_for_kb": ["Other product"]},
])
def test_bad_case_rejected(bad):
    with pytest.raises(ValueError):
        L1.check_manifest(manifest(case(**bad)))


def test_verified_needs_oracle_url():
    with pytest.raises(ValueError, match="oracle URL"):
        L1.check_manifest(manifest(case(oracle_urls=[])))
    assert L1.check_manifest(manifest(case(oracle_urls=[], facts="unverified")))["facts"] == {"unverified": 1}


def test_duplicate_and_unsorted_ids_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        L1.check_manifest(manifest(case(), case()))
    with pytest.raises(ValueError, match="sorted"):
        L1.check_manifest(manifest(case("l1-b"), case("l1-a")))


def test_no_kb_and_no_file_strata_rules():
    with pytest.raises(ValueError, match="no-kb"):
        L1.check_manifest(manifest(case(stratum="no-kb", expected_files=[])))
    with pytest.raises(ValueError, match="empty expected_files"):
        L1.check_manifest(manifest(case(stratum="non-windows-kb")))


def test_wrong_schema_rejected():
    with pytest.raises(ValueError):
        L1.check_manifest({"schema": "x", "cases": []})


def test_hash_is_stable_and_key_order_independent():
    a = manifest(case())
    b = copy.deepcopy(a)
    b["cases"][0] = dict(reversed(list(b["cases"][0].items())))
    assert L1.manifest_hash(a) == L1.manifest_hash(b)
    b["cases"][0]["notes"] = "changed"
    assert L1.manifest_hash(a) != L1.manifest_hash(b)


def test_committed_manifest_is_valid(capsys):
    m = json.loads(L1.DEFAULT_PATH.read_text(encoding="utf-8"))
    assert L1.check_manifest(m)["cases"] >= 60
    assert L1.main([]) == 0
    assert '"manifest_sha256"' in capsys.readouterr().out


def test_cli_reports_failure(tmp_path, capsys):
    p = tmp_path / "m.json"
    p.write_text(json.dumps(manifest(case(), case())), encoding="utf-8")
    assert L1.main([str(p)]) == 1
    assert "duplicate" in capsys.readouterr().err


def test_cli_refuses_a_path_outside_the_allowed_roots(monkeypatch, capsys):
    # Every file argument goes through pathguard.confine: /etc/passwd is refused before it is opened.
    monkeypatch.delenv("RQ_ALLOWED_DIRS", raising=False)
    assert L1.main(["/etc/passwd"]) == 2
    assert "outside the working directory" in capsys.readouterr().err
