"""RQ-01: bounded process performance harness that emits an RQ-00 receipt.

Runs ONE operator-supplied argv (never a shell string, never model-suggested) with a wall-clock cap, an
allowlisted child environment, a capped log file, process-tree sampling (CPU time and RSS, via psutil when
installed) and tree-wide cleanup on timeout or cancel. `PASS` means the process exited 0 and was cleaned up; it is
process evidence, not proof that a comparison was correct. Nothing here changes Ghidriff or PatchTrace behavior.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from . import receipt as R
from .stage_parser import STAGE_MARKERS, parse_log_text

try:  # optional: sampling degrades to "unverified" without it
    import psutil
except ImportError:  # pragma: no cover - exercised only where psutil is absent
    psutil = None

DEFAULT_ENV_ALLOWLIST = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "JAVA_HOME", "GHIDRA_INSTALL_DIR")
_GRACE_S = 2.0


class HarnessError(ValueError):
    """Invalid harness arguments (refused before anything is executed)."""


def build_env(allowlist: tuple[str, ...], extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in allowlist if k in os.environ}
    env.update(extra or {})
    return env


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Terminate the child and all descendants. POSIX kills the child's own process group (it leads one)."""
    if os.name == "nt":  # pragma: no cover - Windows-only path
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        deadline = time.monotonic() + _GRACE_S
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                try:
                    os.killpg(proc.pid, 0)  # group still has members?
                except (ProcessLookupError, PermissionError):
                    return
            time.sleep(0.05)


class _Sampler(threading.Thread):
    """Samples the whole process tree. CPU time is a lower bound: exited children drop out of the sum.

    Every descendant ever seen is remembered with its creation time so cleanup can be verified AFTER the root
    exits (orphans are reparented, so asking the dead root for children would find nothing)."""

    def __init__(self, pid: int, interval_s: float) -> None:
        super().__init__(daemon=True)
        self.pid, self.interval_s = pid, interval_s
        self.stop = threading.Event()
        self.peak_rss = 0
        self.peak_procs = 0
        self.cpu_lower_bound_s = 0.0
        self.seen: dict[int, float] = {}

    def sample_once(self) -> None:
        if psutil is None:  # pragma: no cover
            return
        try:
            root = psutil.Process(self.pid)
            procs = [root, *root.children(recursive=True)]
        except psutil.Error:
            return
        rss, cpu = 0, 0.0
        for p in procs:
            try:
                rss += p.memory_info().rss
                t = p.cpu_times()
                cpu += t.user + t.system
                if p.pid != self.pid:
                    self.seen[p.pid] = p.create_time()
            except psutil.Error:
                continue
        self.peak_rss = max(self.peak_rss, rss)
        self.peak_procs = max(self.peak_procs, len(procs))
        self.cpu_lower_bound_s = max(self.cpu_lower_bound_s, cpu)

    def run(self) -> None:
        while not self.stop.is_set():
            self.sample_once()
            self.stop.wait(self.interval_s)

    def survivors(self) -> int:
        """Descendants seen earlier that are still alive (same creation time, not a zombie)."""
        alive = 0
        for pid, created in self.seen.items():
            try:
                p = psutil.Process(pid)
                if p.create_time() == created and p.status() != psutil.STATUS_ZOMBIE:
                    alive += 1
            except psutil.Error:
                continue
        return alive


class _LogPump(threading.Thread):
    """Drains child output to a capped log file and records when it last produced output."""

    def __init__(self, stream, log_path: Path, max_bytes: int) -> None:
        super().__init__(daemon=True)
        self.stream, self.log_path, self.max_bytes = stream, log_path, max_bytes
        self.last_output = time.monotonic()
        self.bytes_seen = 0
        self.truncated = False

    def run(self) -> None:
        written = 0
        with open(self.log_path, "wb") as f:
            for chunk in iter(lambda: self.stream.readline(), b""):
                self.last_output = time.monotonic()
                self.bytes_seen += len(chunk)
                if written + len(chunk) <= self.max_bytes:
                    f.write(chunk)
                    written += len(chunk)
                else:
                    self.truncated = True  # keep draining so the child never blocks on a full pipe


def plan(argv: list[str], *, timeout_s: float, out_dir: str, env_allowlist: tuple[str, ...]) -> dict[str, Any]:
    """Dry-run description: what would run, with which caps. Executes nothing."""
    _check_argv(argv, timeout_s)
    return {
        "argv0": Path(argv[0]).name,
        "argc": len(argv),
        "timeout_s": timeout_s,
        "out_dir": out_dir,
        "env_names_passed": sorted(k for k in env_allowlist if k in os.environ),
        "psutil_available": psutil is not None,
        "executes": False,
    }


def _check_argv(argv: Any, timeout_s: float) -> None:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise HarnessError("argv must be a non-empty list of non-empty strings (no shell strings)")
    if any("\x00" in a for a in argv):
        raise HarnessError("argv must not contain NUL")
    if not (0 < timeout_s <= 86_400):
        raise HarnessError("timeout_s must be in (0, 86400]")


def run(
    argv: list[str],
    *,
    experiment_id: str,
    scenario_id: str,
    out_dir: str,
    timeout_s: float,
    cwd: str | None = None,
    sample_interval_s: float = 0.25,
    max_log_bytes: int = 5_000_000,
    env_allowlist: tuple[str, ...] = DEFAULT_ENV_ALLOWLIST,
    extra_env: dict[str, str] | None = None,
    cancel: threading.Event | None = None,
    older_sha256: str | None = None,
    newer_sha256: str | None = None,
    tool_name: str = "perf_harness",
    write: bool = True,
) -> tuple[dict[str, Any], Path | None]:
    """Execute argv under the caps and return (receipt, receipt_path). Never raises for child failures."""
    _check_argv(argv, timeout_s)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    log_name = f"{experiment_id}-{scenario_id}.log"
    log_path = out / log_name
    env = build_env(env_allowlist, extra_env)
    started_utc, t0 = R.utc_now(), time.monotonic()
    cancel = cancel or threading.Event()
    options = {"argv0": Path(argv[0]).name, "argc": len(argv), "timeout_s": timeout_s, "max_log_bytes": max_log_bytes,
               "env_names": sorted(env)}
    unverified: list[str] = []
    blocked: list[str] = []
    status, stop_reason, exit_code = "FAIL", "unknown", None
    pump = sampler = None
    survivors = -1
    try:
        kwargs: dict[str, Any] = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL,
                                  "env": env, "cwd": cwd, "shell": False}
        if os.name == "nt":  # pragma: no cover
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(argv, **kwargs)  # noqa: S603 - argv list from the operator, shell=False
    except (FileNotFoundError, PermissionError, NotADirectoryError) as e:
        proc = None
        status, stop_reason = "BLOCKED", "executable could not be started"
        blocked.append(f"cannot start {Path(argv[0]).name}: {type(e).__name__}")
    if proc is not None:
        pump = _LogPump(proc.stdout, log_path, max_log_bytes)
        sampler = _Sampler(proc.pid, sample_interval_s)
        pump.start()
        sampler.start()
        deadline = t0 + timeout_s
        reason = None
        while True:
            if proc.poll() is not None:
                break
            if cancel.is_set():
                reason = "cancelled"
                break
            if time.monotonic() >= deadline:
                reason = "timeout"
                break
            time.sleep(0.02)
        if reason:
            sampler.sample_once()  # last look at the tree before it is torn down
            _kill_tree(proc)
        try:
            proc.wait(timeout=_GRACE_S * 2)
        except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL failed
            unverified.append("child_reaped")
        sampler.stop.set()
        pump.join(timeout=2.0)
        sampler.join(timeout=2.0)
        exit_code = proc.returncode
        survivors = sampler.survivors() if psutil is not None else -1
        if reason == "timeout":
            status, stop_reason = "FAIL", "timeout"
        elif reason == "cancelled":
            status, stop_reason = "CANCELLED", "cancelled by operator"
        elif exit_code == 0:
            status, stop_reason = "PASS", "process exited 0"
        else:
            status, stop_reason = "FAIL", f"process exited {exit_code}"
    ended_utc, elapsed = R.utc_now(), time.monotonic() - t0
    validations = []
    if proc is not None and status == "PASS":
        validations.append("process_exit_zero")
    if proc is not None and survivors == 0:
        validations.append("no_surviving_descendants")
    if psutil is None:
        unverified += ["cpu_time", "rss_peak", "descendant_cleanup"]
    elif survivors > 0:
        status, stop_reason = "FAIL", f"{survivors} descendant process(es) survived cleanup"
    unverified.append("exact_output_equivalence_not_checked")
    observed: dict[str, Any] = {"started_utc": started_utc, "ended_utc": ended_utc, "duration_s": round(elapsed, 3)}
    counters: dict[str, int] = {"timeout_s": int(timeout_s)}
    artifacts: list[dict[str, Any]] = []
    result_hashes: dict[str, str] = {}
    if proc is not None and pump is not None and sampler is not None:
        observed["last_output_age_s"] = round(max(0.0, time.monotonic() - pump.last_output), 3)
        observed["log_truncated"] = pump.truncated
        if psutil is not None:
            observed["rss_peak_bytes"] = sampler.peak_rss
            observed["process_count_peak"] = sampler.peak_procs
            observed["cpu_seconds_lower_bound"] = round(sampler.cpu_lower_bound_s, 3)
        counters["log_bytes_seen"] = pump.bytes_seen
        if log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="replace")
            observed["log_stages"] = parse_log_text(text, top_gaps=3)
            observed["stage_marker_names"] = [sid for sid, _ in STAGE_MARKERS]
            artifacts.append({"path": log_name, "sha256": R.sha256_file(log_path), "bytes": log_path.stat().st_size})
            result_hashes["log"] = artifacts[0]["sha256"]
    exe = shutil.which(argv[0], path=env.get("PATH")) if proc is not None else None
    exe_sha = R.sha256_file(exe) if exe and os.path.isfile(exe) else None
    if exe_sha is None:
        unverified.append("tool.executable_sha256")
    rec = R.build_receipt(
        experiment_id=experiment_id, scenario_id=scenario_id, tool_name=tool_name, status=status,
        exit_code=exit_code if status != "BLOCKED" else None, stop_reason=stop_reason,
        patchtrace_sha=R.git_head(Path(__file__).resolve().parents[2]), executable_sha256=exe_sha,
        older_sha256=older_sha256,
        newer_sha256=newer_sha256, options=options, env_fp=R.env_fingerprint(sorted(env), env),
        validations_run=validations, unverified=unverified,
        blocked_reasons=blocked, result_hashes=result_hashes, counters=counters, observed=observed,
        artifacts=artifacts,
    )
    path = R.write_receipt(rec, out) if write else None
    return rec, path
