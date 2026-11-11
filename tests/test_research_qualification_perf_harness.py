"""RQ-01 perf harness against real short-lived child processes (python -c). No Ghidra, no network, no target
binaries. Verifies caps, cleanup of the whole process tree, env allowlist, typed BLOCKED/CANCELLED/FAIL states."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import perf_harness as P  # noqa: E402
from tools.research_qualification import receipt as R  # noqa: E402

PY = sys.executable


def go(tmp_path, code, **kw):
    kw.setdefault("timeout_s", 20)
    kw.setdefault("scenario_id", "t")
    return P.run([PY, "-c", code], experiment_id="rq01", out_dir=str(tmp_path), **kw)


def test_success_receipt_is_valid_and_records_process_evidence(tmp_path):
    rec, path = go(tmp_path, "print('Sorting functions'); print('12 entries')")
    assert rec["result"]["status"] == "PASS" and rec["result"]["exit_code"] == 0
    assert R.validate_receipt(rec) == [] and R.load_receipt(path) == rec
    assert "process_exit_zero" in rec["result"]["validations_run"]
    assert "exact_output_equivalence_not_checked" in rec["result"]["unverified"]
    assert rec["observed"]["log_stages"]["stage_marker_lines_without_timestamp"] == 1  # untimestamped output
    assert rec["artifacts"][0]["path"] == "rq01-t.log"
    assert R.sha256_file(tmp_path / "rq01-t.log") == rec["artifacts"][0]["sha256"]


def test_nonzero_exit_is_fail_not_pass(tmp_path):
    rec, _ = go(tmp_path, "import sys; sys.exit(3)")
    assert (rec["result"]["status"], rec["result"]["exit_code"]) == ("FAIL", 3)
    assert "process_exit_zero" not in rec["result"]["validations_run"]


def test_missing_executable_is_blocked_with_reason(tmp_path):
    rec, _ = P.run(["definitely-not-a-real-binary-xyz"], experiment_id="rq01", scenario_id="b",
                   out_dir=str(tmp_path), timeout_s=5)
    assert rec["result"]["status"] == "BLOCKED" and rec["result"]["exit_code"] is None
    assert rec["result"]["blocked_reasons"] and "tool.executable_sha256" in rec["result"]["unverified"]
    assert R.validate_receipt(rec) == []


def test_timeout_kills_whole_process_tree(tmp_path):
    code = (
        "import subprocess,sys,time\n"
        "c=subprocess.Popen([sys.executable,'-c','import time\\nwhile True: time.sleep(1)'])\n"
        "print('child', c.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    t0 = time.monotonic()
    rec, _ = go(tmp_path, code, timeout_s=1.5, sample_interval_s=0.05)
    assert time.monotonic() - t0 < 15
    assert (rec["result"]["status"], rec["result"]["stop_reason"]) == ("FAIL", "timeout")
    if P.psutil is not None:
        assert "no_surviving_descendants" in rec["result"]["validations_run"]
        pid = int((tmp_path / "rq01-t.log").read_text().split()[1])
        assert not P.psutil.pid_exists(pid) or P.psutil.Process(pid).status() == P.psutil.STATUS_ZOMBIE


def test_cancel_event_stops_child_and_reports_cancelled(tmp_path):
    ev = threading.Event()
    threading.Timer(0.5, ev.set).start()
    rec, _ = go(tmp_path, "import time; time.sleep(60)", cancel=ev, timeout_s=60)
    assert rec["result"]["status"] == "CANCELLED" and rec["observed"]["duration_s"] < 15


def test_environment_is_allowlisted_and_values_are_not_recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("RQ_SECRET_TOKEN", "super-secret-value")
    rec, path = go(tmp_path, "import os; print('SEEN' if 'RQ_SECRET_TOKEN' in os.environ else 'CLEAN')")
    assert "CLEAN" in (tmp_path / "rq01-t.log").read_text()
    assert "super-secret-value" not in path.read_text()
    go(tmp_path, "import os; print(os.environ.get('RQ_X'))", scenario_id="e", extra_env={"RQ_X": "yes"})
    assert "yes" in (tmp_path / "rq01-e.log").read_text()


def test_log_is_capped_but_child_is_not_blocked(tmp_path):
    rec, _ = go(tmp_path, "print('x'*1000)\n" * 1 + "for _ in range(2000): print('y'*100)", max_log_bytes=5000)
    assert rec["result"]["status"] == "PASS" and rec["observed"]["log_truncated"] is True
    assert (tmp_path / "rq01-t.log").stat().st_size <= 5000
    assert rec["result"]["counters"]["log_bytes_seen"] > 5000


@pytest.mark.skipif(P.psutil is None, reason="psutil absent: harness reports cpu/rss as unverified instead")
def test_resource_peaks_are_measured(tmp_path):
    rec, _ = go(tmp_path, "b=bytearray(30_000_000)\nimport time; t=time.time()\nwhile time.time()-t<0.6: pass",
                sample_interval_s=0.05)
    assert rec["observed"]["rss_peak_bytes"] > 20_000_000 and rec["observed"]["cpu_seconds_lower_bound"] > 0.2


@pytest.mark.parametrize("argv,timeout", [([], 5), (["a", ""], 5), ("echo hi", 5), ([PY], 0), ([PY], 10**6), (["a\x00b"], 5)])
def test_hostile_arguments_are_refused_before_execution(tmp_path, argv, timeout):
    with pytest.raises(P.HarnessError):
        P.run(argv, experiment_id="rq01", scenario_id="h", out_dir=str(tmp_path), timeout_s=timeout)
    assert not list(tmp_path.glob("*.json"))


def test_plan_executes_nothing_and_names_only_env_names(tmp_path):
    marker = tmp_path / "ran"
    out = P.plan([PY, "-c", f"open({str(marker)!r},'w')"], timeout_s=5, out_dir=str(tmp_path),
                 env_allowlist=P.DEFAULT_ENV_ALLOWLIST)
    assert out["executes"] is False and not marker.exists()
    assert out["argv0"] == Path(PY).name and "-c" not in json.dumps(out)


def test_two_runs_have_matching_deterministic_view(tmp_path):
    a, _ = go(tmp_path / "a", "print('same')")
    b, _ = go(tmp_path / "b", "print('same')")
    assert R.compare_receipts(a, b) == [], R.compare_receipts(a, b)
    assert os.path.exists(tmp_path / "a" / "rq01-t.log")
