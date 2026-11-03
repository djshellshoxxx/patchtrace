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


def test_native_coverage_oracle_rejects_contradictory_unmatched(tmp_path):
    """Compile the actual oracle with list doubles, not native Rizin evidence."""
    import shutil

    compiler = shutil.which("cc")
    if not compiler:
        pytest.skip("helper-only oracle regression requires a C compiler")
    source = (ROOT / "tools/rzdiff/native_control.c").read_text()
    start = source.index("static bool covered(")
    end = source.index("static int check(", start)
    oracle = source[start:end]
    prelude = r"""
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
typedef struct RzListIter { void *val; struct RzListIter *next; } RzListIter;
typedef struct { RzListIter *head; } RzList;
typedef struct { int id; } RzAnalysisFunction;
typedef struct { void *pair_a; void *pair_b; } RzAnalysisMatchPair;
#define rz_list_foreach(l, it, p) for ((it) = (l)->head; (it) && ((p) = (it)->val, 1); (it) = (it)->next)
static bool owned(RzList *list, const void *ptr) {
    for (RzListIter *it = list->head; it; it = it->next) if (it->val == ptr) return true;
    return false;
}
"""
    # owned() is supplied because the old oracle used it; the corrected oracle
    # can still use it for membership, without hiding duplicate unmatched rows.
    harness = r"""
int main(void) {
    RzAnalysisFunction a = {1}, b = {2}, c = {3};
    RzAnalysisMatchPair ab = {&a, &b}, ac = {&a, &c};
    RzListIter ia = {&a, NULL}, ib = {&b, NULL}, ic = {&c, NULL};
    RzListIter mab = {&ab, NULL}, mac = {&ac, NULL};
    RzListIter ua = {&a, NULL}, ua2 = {&a, NULL};
    RzList input = {&ia}, right = {&ib}, matches = {&mab};
    RzList unmatched = {&ua}, empty = {NULL};
    int errors = 0;
    // A function cannot be both matched and unmatched.
    if (covered(&input, &unmatched, &matches, true)) errors++;
    // Duplicate unmatched rows cannot account for one input twice.
    ua.next = &ua2;
    if (covered(&input, &unmatched, &empty, true)) errors++;
    ua.next = NULL;
    if (!covered(&input, &unmatched, &empty, true)) errors++;
    if (!covered(&input, &empty, &matches, true)) errors++;
    if (covered(&input, &empty, &empty, true)) errors++;
    // Singleton's legitimate all-candidate matches must remain supported.
    mab.next = &mac; ib.next = &ic;
    if (!covered(&input, &empty, &matches, true)) errors++;
    if (!covered(&right, &empty, &matches, false)) errors++;
    // Retain a simple pointer-membership control too.
    if (!owned(&input, &a) || owned(&input, &b)) errors++;
    printf("coverage-oracle failures=%d\n", errors);
    return errors ? 1 : 0;
}
"""
    cfile = tmp_path / "coverage.c"
    cfile.write_text(prelude + oracle + harness)
    executable = tmp_path / "coverage"
    subprocess.run([compiler, "-std=c99", "-Wall", "-Wextra", "-Werror",
                    str(cfile), "-o", str(executable)], check=True)
    result = subprocess.run([str(executable)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
