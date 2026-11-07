"""CLI behavior and exit codes for tools.research_qualification."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def cli(*args, cwd=ROOT):
    return subprocess.run([PY, "-m", "tools.research_qualification", *args], cwd=cwd, capture_output=True, text=True,
                          timeout=120, check=False)


def test_selftest_passes_and_writes_valid_receipts(tmp_path):
    r = cli("selftest", "--out", str(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["selftest"] == "PASS"
    files = [str(p) for p in tmp_path.rglob("*.json")]
    assert len(files) == 2 and cli("receipt", "validate", *files).returncode == 0
    assert cli("receipt", "compare", *files).returncode == 0  # deterministic fields agree across reruns


def test_perf_plan_executes_nothing(tmp_path):
    marker = tmp_path / "ran"
    r = cli("perf", "plan", "--out", str(tmp_path), "--", PY, "-c", f"open({str(marker)!r},'w')")
    assert r.returncode == 0 and not marker.exists() and json.loads(r.stdout)["executes"] is False


def test_perf_run_exit_codes_map_status(tmp_path):
    ok = cli("perf", "run", "--out", str(tmp_path), "--timeout", "20", "--", PY, "-c", "print(1)")
    assert ok.returncode == 0 and json.loads(ok.stdout)["status"] == "PASS"
    bad = cli("perf", "run", "--out", str(tmp_path), "--scenario", "bad", "--", PY, "-c", "raise SystemExit(4)")
    assert bad.returncode == 1 and json.loads(bad.stdout)["status"] == "FAIL"
    blocked = cli("perf", "run", "--out", str(tmp_path), "--scenario", "blk", "--", "no-such-binary-xyz")
    assert blocked.returncode == 2 and json.loads(blocked.stdout)["status"] == "BLOCKED"


def test_perf_without_command_is_a_usage_error(tmp_path):
    r = cli("perf", "run", "--out", str(tmp_path))
    assert r.returncode == 2 and "argv" in r.stderr and not list(tmp_path.glob("*.json"))


def test_stages_reads_a_log_and_validate_flags_garbage(tmp_path):
    log = tmp_path / "g.log"
    log.write_text("10:00:00.000 a\n10:00:05.500 Sorting functions\n10:10:00.000 esym\n")
    r = cli("stages", str(log), "--top", "1")
    assert r.returncode == 0 and json.loads(r.stdout)["quiet_intervals"][0]["gap_ms"] == 594_500
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert cli("receipt", "validate", str(bad)).returncode == 1


def test_paths_outside_allowed_roots_are_refused(tmp_path, monkeypatch):
    from tools.research_qualification import pathguard as PG
    from tools.research_qualification.__main__ import main
    monkeypatch.delenv("RQ_ALLOWED_DIRS", raising=False)
    assert main(["cases", "/etc/passwd"]) == 2
    assert main(["stages", "/etc/passwd"]) == 2
    assert main(["score", "/etc/passwd", "/etc/hostname"]) == 2
    assert main(["fixtures", "build", "--out", "/etc/rq"]) == 2
    f = tmp_path / "ok.json"
    f.write_text("{}")
    assert PG.confine(f) == f.resolve()
    with pytest.raises(PG.PathGuardError):
        PG.confine(tmp_path / ".." / ".." / ".." / ".." / "etc" / "passwd")
    with pytest.raises(PG.PathGuardError):
        PG.confine("")
    monkeypatch.setenv("RQ_ALLOWED_DIRS", "/etc")
    assert PG.confine("/etc/hostname")
