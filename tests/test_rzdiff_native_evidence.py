"""Evidence-runner tests use synthetic output, NOT native acceptance."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.rzdiff.native_evidence import run, validate

ROOT = Path(__file__).resolve().parents[1]


def matrix(stock=False):
    rows = []
    for a, b in ((1, 1), (1, 2), (2, 1), (2, 2), (1, 0), (0, 1), (2, 0), (0, 2)):
        for overlap in range(2):
            for left, right in ((a, b), (b, a)):
                errors = int(stock and left == 1)
                rows.append(f"{left}:{right} overlap={overlap} errors={errors}")
    return "\n".join(rows) + "\n"


@pytest.mark.parametrize("variant,code", [("stock", 1), ("corrected", 0)])
def test_complete_control(variant, code):
    validate(variant, code, matrix(variant == "stock"))


@pytest.mark.parametrize("code", [-11, 2, 127, 0])
def test_crash_or_wrong_exit_is_not_red_control(code):
    with pytest.raises(ValueError):
        validate("stock", code, matrix(True))


@pytest.mark.parametrize("variant,code", [("stock", 1), ("corrected", 0)])
@pytest.mark.parametrize("mutate", [
    lambda s: "",
    lambda s: "\n".join(s.splitlines()[:-1]),
    lambda s: s + s.splitlines()[0] + "\n",
    lambda s: s.replace("overlap=0", "overlap=2", 1),
    lambda s: s.replace("errors=0", "errors=-1", 1),
    lambda s: s.replace("2:2 overlap=0 errors=0", "2:2 overlap=0 errors=1", 1),
])
def test_invalid_matrix_refused(variant, code, mutate):
    with pytest.raises(ValueError):
        validate(variant, code, mutate(matrix(variant == "stock")))


def test_green_stock_and_singleton_regression_refused():
    with pytest.raises(ValueError):
        validate("stock", 1, matrix())
    with pytest.raises(ValueError):
        validate("corrected", 0, matrix(True))


def test_unknown_variant_refused():
    with pytest.raises(ValueError):
        validate("unverified", 0, matrix())


@pytest.mark.parametrize("code", [0, 1])
def test_keeps_raw_evidence_on_failure(tmp_path, monkeypatch, code):
    fake = tmp_path / "fake"
    fake.write_bytes(b"test double, not a native executable")
    def execute(*args, **kwargs):
        return subprocess.CompletedProcess(args, code, b"incomplete\n", b"diagnostic\n")
    monkeypatch.setattr(subprocess, "run", execute)
    out = tmp_path / "evidence"
    assert not run("corrected", fake, out)
    receipt = json.loads((out / "native-result.json").read_text())
    assert receipt["accepted"] is False
    assert receipt["returncode"] == code
    assert len(receipt["executable_sha256"]) == 64
    assert (out / "native-matrix.log").read_bytes() == b"incomplete\n"
    assert (out / "native-stderr.log").read_bytes() == b"diagnostic\n"


def test_timeout_retains_partial_output(tmp_path, monkeypatch):
    fake = tmp_path / "fake"
    fake.write_bytes(b"double")
    def execute(*args, **kwargs):
        raise subprocess.TimeoutExpired(args, 1, output=b"partial", stderr=b"timed out")
    monkeypatch.setattr(subprocess, "run", execute)
    assert not run("stock", fake, tmp_path / "evidence", timeout=1)
    receipt = json.loads((tmp_path / "evidence/native-result.json").read_text())
    assert receipt["accepted"] is False
    assert receipt["returncode"] is None
    assert receipt["error"] == "native control timed out"
    assert (tmp_path / "evidence/native-matrix.log").read_bytes() == b"partial"


def test_cli_missing_executable_is_failure_with_receipt(tmp_path):
    out = tmp_path / "evidence"
    result = subprocess.run([
        sys.executable, str(ROOT / "tools/rzdiff/native_evidence.py"),
        "--variant", "stock", "--executable", str(tmp_path / "absent"),
        "--output", str(out),
    ], capture_output=True, text=True, check=False)
    assert result.returncode == 1
    receipt = json.loads((out / "native-result.json").read_text())
    assert receipt["accepted"] is False
    assert receipt["returncode"] is None


def test_one_green_duplicate_cannot_hide_in_stock_red_set():
    raw = matrix(True).replace("1:1 overlap=0 errors=1", "1:1 overlap=0 errors=0", 1)
    with pytest.raises(ValueError):
        validate("stock", 1, raw)
