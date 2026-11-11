"""RQ-00 receipt contract: valid/invalid fixtures, hostile content, immutability, rerun comparison."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import receipt as R  # noqa: E402

H = "a" * 64


def good(**kw):
    base = dict(
        experiment_id="rq00-smoke", scenario_id="synthetic-1", tool_name="unit", status="PASS", exit_code=0,
        stop_reason="completed", patchtrace_sha="b" * 40, executable_sha256=H, older_sha256=H, newer_sha256="c" * 64,
        validations_run=["process_exit_zero"], result_hashes={"out": H}, counters={"functions": 3},
        observed={"started_utc": "2026-11-07T01:00:00.000000Z", "ended_utc": "2026-11-07T01:00:02.500000Z",
                  "duration_s": 2.5},
        artifacts=[{"path": "out/x.json", "sha256": H, "bytes": 10}],
    )
    base.update(kw)
    return R.build_receipt(**base)


def test_valid_receipt_has_no_problems():
    assert R.validate_receipt(good()) == []


@pytest.mark.parametrize("mutate,needle", [
    (lambda r: r["result"].update(status="SUCCESS"), "status"),
    (lambda r: r["result"].update(exit_code=1), "PASS requires result.exit_code"),
    (lambda r: r["result"].update(validations_run=[]), "validations_run"),
    (lambda r: r["result"].update(status="BLOCKED", blocked_reasons=[], exit_code=None), "BLOCKED requires"),
    (lambda r: r["result"].update(status="FAIL", stop_reason=""), "stop_reason"),
    (lambda r: r.update(extra=1), "unknown top-level"),
    (lambda r: r["tool"].update(executable_sha256="XYZ"), "64-char hex"),
    (lambda r: r["tool"].update(executable_sha256=None), "result.unverified"),
    (lambda r: r["artifacts"][0].update(path="../escape"), "relative POSIX"),
    (lambda r: r["artifacts"][0].update(path="/abs/x"), "relative POSIX"),
    (lambda r: r["artifacts"][0].update(path="a\\b"), "relative POSIX"),
    (lambda r: r["observed"].update(ended_utc="2026-11-07T00:59:00.000000Z"), "precedes"),
    (lambda r: r["observed"].update(started_utc="yesterday"), "ISO-8601"),
    (lambda r: r["observed"].update(duration_s=-1), "non-negative"),
    (lambda r: r["result"]["counters"].update(bad=True), "integers"),
    (lambda r: r.update(review={"reviewer": "x"}), "review"),
    (lambda r: r.update(experiment_id="../bad"), "experiment_id"),
])
def test_invalid_receipts_are_rejected(mutate, needle):
    r = good()
    mutate(r)
    assert any(needle in p for p in R.validate_receipt(r)), R.validate_receipt(r)


def test_null_hash_is_accepted_only_when_declared_unverified():
    r = good(executable_sha256=None, unverified=["tool.executable_sha256"])
    assert R.validate_receipt(r) == []


@pytest.mark.parametrize("text", [
    "/home/sheldon/work/x.bin", "/Users/sheldon/x", "C:\\Users\\sheldon\\x.pdb", "/root/.ssh/id",
    "ghp_" + "A" * 36, "github_pat_" + "B" * 40, "-----BEGIN RSA PRIVATE KEY-----", "AKIA" + "Z" * 16,
])
def test_paths_and_secrets_never_appear(text):
    r = good(stop_reason=text)
    assert any("absolute or home path" in p or "secret-like" in p for p in R.validate_receipt(r))


def test_urls_are_not_mistaken_for_paths():
    r = good(upstream_url="https://github.com/google/bindiff/tree/main/home/x")
    assert R.validate_receipt(r) == []


def test_write_is_atomic_and_immutable(tmp_path):
    r = good()
    p = R.write_receipt(r, tmp_path)
    assert json.loads(p.read_text())["experiment_id"] == "rq00-smoke"
    assert not [f for f in tmp_path.iterdir() if f.name.startswith(".receipt-")]
    with pytest.raises(R.ReceiptError, match="overwrite"):
        R.write_receipt(r, tmp_path)
    assert R.load_receipt(p) == r


def test_invalid_receipt_is_never_written(tmp_path):
    r = good()
    r["result"]["status"] = "NOPE"
    with pytest.raises(R.ReceiptError):
        R.write_receipt(r, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_load_rejects_nan_and_garbage(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"a": NaN}')
    with pytest.raises(R.ReceiptError):
        R.load_receipt(p)
    p.write_text("[]")
    with pytest.raises(R.ReceiptError):
        R.load_receipt(p)


def test_rerun_comparison_ignores_observed_but_catches_deterministic_drift():
    a, b = good(), good()
    b["observed"]["duration_s"] = 99.0
    b["runtime"]["python"] = "0.0.0"
    assert R.compare_receipts(a, b) == []
    assert R.deterministic_digest(a) == R.deterministic_digest(b)
    c = copy.deepcopy(a)
    c["result"]["result_hashes"]["out"] = "d" * 64
    c["result"]["counters"]["functions"] = 4
    assert R.compare_receipts(a, c) == ["result.counters.functions", "result.result_hashes.out"]


def test_env_fingerprint_never_stores_values_and_is_stable():
    env = {"A": "secret-value", "B": "2"}
    fp = R.env_fingerprint(["A", "B"], env)
    assert "secret-value" not in fp and fp == R.env_fingerprint(["B", "A"], env)
    assert fp != R.env_fingerprint(["A", "B"], {"A": "other", "B": "2"})


def test_sha256_file_matches_known_vector(tmp_path):
    p = tmp_path / "abc"
    p.write_bytes(b"abc")
    assert R.sha256_file(p) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
