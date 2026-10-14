# Process-supervision audit (BH-proc) - 2026-10-14

Scope: `src/patchtrace/jobs.py` (`run_process`, POSIX `killpg`, Windows Job Object + suspended `CreateProcessW`, spawn lock, `memory_limit_bytes`), `secondary/engine_env.py`, `secondary/scheduler.py`, `secondary/binexport_run.py` / `binexport_worker.py`, and `backend.py` child-environment building (read-only). Specs read: SPEC-28 (multi-engine orchestration), SPEC-10b (BinExport2 worker, memory cap).

Method: source reading, then about 35 attack ideas run on this Linux host (Python 3.13, uid 0; the project targets 3.12) with throw-away harnesses kept outside the repository. Windows-only branches were reasoned about, never guessed; they are listed under "Only Windows CI can verify". Fix rights were `jobs.py`, `engine_env.py`, `scheduler.py` and their tests; everything else is report-only.

Result after the fixes: `tests/test_jobs.py`, `tests/test_secondary_*.py`, `tests/test_engine_env.py`, `tests/test_binexport_isolation.py`, `tests/test_bindiff_run.py`, `tests/test_cli_secondary*.py`: 300 passed, 3 skipped (Windows-only). `ruff check src tests tools`: clean. Every fixed finding has a test that failed before the fix.

## Findings

| Id | Severity | Repro (Linux) | Status |
| --- | --- | --- | --- |
| PS-1 | Low-Med | Patch `Thread.start` to raise for the `patchtrace-log` reader: `run_process` raises but the child tree keeps running and its pipes stay open. Root cause: the `try/finally` began after `_posix_prlimit` and `reader.start()`. On Windows the Job handle is never closed (no `__del__`), so `KILL_ON_JOB_CLOSE` only fires at parent exit. | **Fixed** in `jobs.py` (the `finally` now covers everything after the spawn). Test `test_failure_between_spawn_and_supervision_still_kills_the_child`. |
| PS-2 | Low | `memory_limit_bytes=2**64`: `resource.prlimit` raises `OverflowError` (not `OSError`) after the child is running, so the handler that kills the child never runs; the child runs uncapped and unreaped. Values at or above `2**62` were accepted but are not caps. | **Fixed**: rejected before spawn (`MEMORY_LIMIT_CEILING`, `ValueError`); PS-1 also covers any other late exception. Test `test_memory_limit_outside_the_rlimit_range_is_rejected_before_spawn`. |
| PS-3 | Low | `timeout_seconds=float('nan')` passes `<= 0` and then never expires. `log_limit=10.5` raises `TypeError` in the reader thread (silently), the pipe stops draining and the child blocks until the full timeout. `log_limit=True` was accepted. Not reachable from today's CLI (`--timeout` is `type=int`, range-checked); API level. | **Fixed**: `not timeout > 0` and an integer check for both limits. Test `test_nan_timeout_and_non_integer_limits_are_rejected`. |
| PS-4 | Medium on Windows | `scheduler.work` wraps `TemporaryDirectory` cleanup inside the engine `try`. A cleanup error (Windows: scanner or lingering handle, WinError 32) replaces a finished `ok` run with `failed` / `PT-SECONDARY-RUN` / `OSError` class name (match set lost), and on the `cancelled`/`timeout`/`cached`/`failed` paths emits a second `finished` event. Reproduced with a real cleanup failure (workdir replaced by a file), no mock. | **Fixed**: `ignore_cleanup_errors=True` (same best-effort policy as `bindiff_run._remove_tree`). Test `test_workdir_cleanup_failure_does_not_discard_a_finished_run`. A true Windows sharing violation is still unverified. |
| PS-5 | Low-Med (environment) | If the process inherits `SIGCHLD=SIG_IGN` the kernel auto-reaps and `Popen` reports every status as 0: `exit(3)` -> 0, `SIGKILL` -> 0. The BinExport worker's exit 22 would read as success and become `worker_crash` instead of `worker_oom`; a crashed tool looks successful. | **Fixed (fail closed)**: `OSError('PT-BACKEND: SIGCHLD is ignored ...')` before spawn. Entry points (`cli.py`, UI; report-only) should restore `SIG_DFL` at start-up. Test `test_ignored_sigchld_fails_closed_instead_of_reporting_exit_zero`. |
| PS-6 | Medium (POSIX) | Harness: SIGKILL or SIGTERM to the parent while `run_process` supervises a child: the child tree survives. No SIGTERM/SIGHUP handler exists anywhere in `src/patchtrace`. Windows is covered by `KILL_ON_JOB_CLOSE`. A closed terminal (SIGHUP) or killed GUI leaves Ghidra's JVM running for minutes. | **Open, report-only** (needs `cli.py`/UI): install SIGTERM/SIGHUP handlers that set the shared `cancel` event (or raise `KeyboardInterrupt`) so the `finally` runs. `PR_SET_PDEATHSIG` is unsuitable: it fires when the spawning *thread* exits, and engines spawn from pool threads. |
| PS-7 | Low (design limit) | Grandchild that calls `setsid()` (daemon double-fork) survives cancel/timeout/normal exit; `run_process` additionally stalls about 5 s (reader join timeout, per reader) and leaves the reader thread and pipe fd until the daemon exits. A same-group grandchild holding the pipe is killed immediately (returns in 0.05 s). | **Open, documented**. Options: cgroup / child-subreaper, or kill the holders of the pipe found through `/proc/*/fd`. Rule for adapters below. |
| PS-8 | Low (theoretical) | `killpg(child.pid)` is also called after the leader was reaped (second sweep, and the final `finally` up to about 10 s later). If the group is empty and the pid recycled to another group leader (`pid_max` is 32768 here) an unrelated group could be signalled. Not reproducible deterministically. | **Open**. Design fix: observe exit with `waitid(P_PID, ..., WEXITED|WNOHANG|WNOWAIT)`, sweep while the zombie still pins the pid, then reap; or skip the `finally` sweep when already swept and reaped. |
| PS-9 | Low | `secondary/registry.py:68` `RzDiffAdapter.probe` discovers `rz-diff` with `shutil.which(..., path=job_env['PATH'])`, contrary to the "no PATH lookup" rule BinDiff follows. Safe today only because `Path(found).is_absolute()` rejects the relative result (on Windows, `shutil.which` consults the cwd first and returns `.\rz-diff.exe`). Adding `.resolve()` would execute a planted binary. | **Report-only**: require an explicit configured absolute path, or keep the absolute-path guard with a comment and test. |
| PS-10 | Low | `bindiff_run.py:219-221` maps every `OSError/ValueError/RuntimeError` from the runner, including the post-spawn `RuntimeError('terminated child did not exit')`, to `spawn-failed: Could not start BinDiff`. | **Report-only**. |
| PS-11 | Low | `accept_binexport(private_dir=<missing>)` raises a raw `FileNotFoundError` from `work.mkdir`, not the documented `SecondaryError`. FIFO, `/dev/zero`, `/dev/null`, directory and missing inputs are all rejected in 0.3-0.4 s with `PT-SECONDARY-INPUT` and leave nothing behind. | **Report-only** (`binexport_run.py`). |
| PS-12 | Medium (known, H7) | `backend._environment` with the default `restrict_env=False` hands the child the whole parent environment, credentials included; only `PYTHONPATH`/`PYTHONHOME` are removed (`LD_PRELOAD`, `JAVA_TOOL_OPTIONS`, `PYTHONSTARTUP` pass). The restricted path (`build_child_env`) is sound on read-through. | **Report-only**; already tracked as the H7 default-off decision. |
| PS-13 | Info | `ProcessResult.log_tail` is lossy text: invalid UTF-8 becomes U+FFFD and the tail cut can start mid code point. `RzDiffAdapter.run` re-encodes it, so `RawResult.stdout` and `output_sha256` hash re-encoded text, not the tool's bytes. | **Report-only**; add a bytes field to `ProcessResult` (spec first) before an adapter needs exact bytes. |
| PS-14 | Info | `engine_env`: `_RIZIN_ENV` matches exact case (a lower-case `rz_prefix` is dropped under `windows=True`; harmless because `os.environ` upper-cases on Windows). `_bindiff_env` with a relative `executable` yields `PATH=.:/usr/bin:/bin`; every production caller passes an absolute `cap.path`. | **Not fixed**: a flavour-aware absolute check would break `tests/test_engine_env.py`, which passes POSIX paths with `windows=True`. Do it together with that test. |

## Attack ideas tried (Linux)

| # | Idea | Outcome |
| --- | --- | --- |
| 1 | Grandchild survives kill (same group) on cancel / timeout / normal exit | Killed; existing tests plus a 40-process swarm all dead |
| 2 | Grandchild escapes with `setsid` | **Survives**, 5.4 s stall (PS-7) |
| 3 | Descendant holds stdout after the leader exits | Killed, returns in 0.05 s |
| 4 | Child closes stdout/stderr early, keeps running | Timeout fires normally |
| 5 | 300 MiB output without newline, 1 KiB tail | 0.2 s, tail bounded and correct |
| 6 | Invalid / truncated UTF-8 output | Replacement characters, no crash (PS-13) |
| 7 | Zombie reaping after ok, timeout and pre-cancelled runs | No zombie children of the parent |
| 8 | Cancel racing process start (50 runs, 0-60 ms) | No survivors |
| 9 | Timeout exactly at exit | `reason` set, status coherent; scheduler maps conservatively |
| 10 | SIGINT to parent mid-run | Group killed, `KeyboardInterrupt` propagates |
| 11 | SIGKILL / SIGTERM to parent | **Child tree survives** (PS-6) |
| 12 | Concurrent spawns inheriting each other's pipes (POSIX) | Isolated; a fast run is unaffected by a slow concurrent one |
| 13 | Very long argv (300 KiB arg, 4 MB total) | `OSError` (E2BIG), nothing spawned |
| 14 | Spaces, unicode, quotes, backslashes, empty and bidi args | Round-trip exactly (Windows quoting: Windows CI) |
| 15 | cwd that disappears | `FileNotFoundError`, nothing leaked |
| 16 | `memory_limit_bytes`: bool, 0, negative, float, str | `ValueError` |
| 17 | `memory_limit_bytes=2**64` | **Child orphaned** (PS-2) |
| 18 | 4 MiB cap, and 200 MiB cap vs 400 MiB allocation | Child fails at start / `MemoryError`; no hang |
| 19 | 12 concurrent `run_process` threads | Results independent |
| 20 | Partial result when killed | stdout and stderr tails kept |
| 21 | `check_output` raising | Child killed, exception propagates |
| 22 | stdin, new session, SIGSTOPped child, child SIGSEGV | EOF; own session; killed at timeout; -11 with `reason=None` |
| 23 | FD / thread leak over 31 mixed runs | None |
| 24 | Reader thread cannot start | **Child orphaned** (PS-1) |
| 25 | NaN timeout, float limit | **No deadline / undrained pipe** (PS-3) |
| 26 | `SIGCHLD` ignored | **All statuses 0** (PS-5) |
| 27 | Scheduler: cleanup failure after a finished run | **Result lost** (PS-4) |
| 28 | Scheduler: `on_outcome` raises with a slow second engine | Remaining engines cancelled in 0.1 s, exception propagates |
| 29 | Scheduler: `SystemExit` in a worker | Propagates after workers join |
| 30 | BinExport inputs: FIFO, `/dev/zero`, `/dev/null`, directory, missing, missing private dir | Rejected fast (PS-11 for the last) |
| 31 | `worker_env` and `engine_env` leak check | Secrets, `LD_PRELOAD`, `PYTHONSTARTUP` dropped (PS-14 notes) |

## Only Windows CI can verify

1. **Handle inheritance.** `CreateProcessW(bInheritHandles=TRUE)` without `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` passes every inheritable handle of the parent. `_WINDOWS_SPAWN_LOCK` only serialises `run_process`; a concurrent `subprocess` or `QProcess` spawn elsewhere can leak a pipe write end (symptom: a reader waits for the 5 s join timeout, not a hang). Test: spawn a `subprocess.Popen` while `run_process` runs.
2. **`.cmd` / `.bat` targets.** `CreateProcessW` runs `cmd.exe` implicitly and `subprocess.list2cmdline` does not escape `& | < > ^ %`; an `&` or `%` in a OneDrive path mis-parses. The `.cmd` fake executables run through this path.
3. **Environment block.** Sorted with a code-point sort (documentation asks for case-insensitive); names or values containing NUL or `=` are not rejected, and a NUL in an argument silently truncates the command line (POSIX and `_winapi` raise). Not exploitable with `os.environ` input; hardening.
4. **Memory cap.** `JOB_OBJECT_LIMIT_PROCESS_MEMORY` bounds committed bytes per process, while `memory_required` was measured under `RLIMIT_AS` (virtual). Over-limit behaviour and exit code are still U7; confirm `PeakProcessMemoryUsed` is tracked and that frozen `PatchTrace.exe` stays under the computed cap.
5. **`kill_tree()` raising** inside the `finally` would skip `child.close()` (handle leak, theoretical).
6. **cwd above `MAX_PATH`** for `CreateProcessW` `lpCurrentDirectory`.
7. **PS-4** against a genuine sharing violation, and the new portable tests (PS-1, PS-2, PS-3) on Windows. The SIGCHLD test is skipped on Windows.

## Hazards for new tool adapters (capa, FLOSS, DiE, Ghidra extractor)

1. Spawn only through `run_process` with an absolute path resolved once at probe time; never `shutil.which` at run time (PS-9).
2. The tool must not daemonize or `setsid` (PS-7). Keep Java launchers in the foreground group (no `-bg`, `nohup`, `start`).
3. Do not target `.bat` / `.cmd` launchers on Windows (item 2 above); use the `.exe` or a Python entry point.
4. Pass an integer `log_limit` of expected size + 1 and treat `len >= limit` as truncation: the buffer keeps the *tail*, so a truncated JSON starts mid-document. Use `separate_streams=True` for machine-readable stdout. Output is lossy text (PS-13).
5. `memory_limit_bytes` means virtual address space (`RLIMIT_AS`) on Linux and committed memory on Windows. Do not cap a JVM that way (it reserves large virtual ranges). Python workers should self-limit as the BinExport worker does; classify OOM by exit code plus stderr signature (Windows unmeasured).
6. Exit codes: negative = signal on POSIX, unsigned NTSTATUS on Windows. `reason` is authoritative; a cancelled or timed-out child's status is not a tool result. Never use `returncode < 0` alone.
7. Build environments only through `engine_env` allow-lists, with absolute directories in `PATH`; never `os.environ.copy()` (PS-12).
8. Close every handle a tool output is read through (SQLite `close()`, not just a `with`) before returning: the scheduler workdir is best-effort removed, but BinDiff-style adapters that delete their own directories will fail on Windows otherwise.
9. `check_output` runs on the supervising thread every 50 ms: keep it cheap, non-blocking and non-raising. Never read output written by a killed tool (a kill during the write phase yields a valid-looking database).
10. `run_process` blocks. Call it from a worker with the one shared `cancel` event; entry points must turn SIGTERM/SIGHUP into that cancel (PS-6). Parallelism stays at most 2.
11. Map `OSError`, `ValueError` and `RuntimeError('PT-BACKEND: ...')` from the runner to a failed outcome by class name; do not label post-spawn failures as spawn failures (PS-10).
