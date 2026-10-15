# CLI and persistence QA stress (QA-CLI, 2026-10-15)

Scope: every headless verb of `src/patchtrace/cli.py` and `cli_commands/` (help, bare, unknown option, error paths,
`--json` envelope), the project store (`persistence.py`: lock, snapshot, history, recovery, tamper refusal),
and enrichment ranking and project open at scale. Method: red/green tests under `tests/stress/` (new, no existing
file changed), scratch probes outside the repository, and the repository benchmark `tools/bench_enrichment.py`
for reference numbers. Base: `origin/main` at `21a005e`. Host: Linux 6.18, Python 3.13.16, one shared CPU
(numbers vary by about 2x between runs). Nothing ran on Windows; Windows-only behaviour is unverified.

Open PRs at audit time (REST `pulls?state=open`): #64 unified engine, #61 agent skills, #60 bundle validation,
#59 instance B wave, #43, #41, #40 (docs only). Checked by changed-file list: none of them touches `cli.py`,
`service.py`, `persistence.py`, `enrichment/` or `cli_commands/`. PR #59 adds `tests/stress/conftest.py` and
`tests/stress/test_fuzz_*.py`, so the integrator will see this directory shared; the QA-CLI files add no conftest and
use their own names. Check status of PR checks was not read (GraphQL is blocked for this session).

## Tests

| File | Tests | Result | What it covers |
|---|---|---|---|
| `tests/stress/test_cli_stress_verbs.py` | 133 | 128 pass, 5 xfail (strict) | 34 verb paths (incl. hidden `_worker`, `_binexport-worker`): `--help` exit 0 with usage; bare invocation of verbs with required arguments exit 2 (leaf verbs without required arguments are never run bare, because a bare `backend verify` or `intel-tools probe` would start a probe); unknown option exit 2; 16 error paths with exact contract codes; 8 `--json` runs with exactly one document; 5 real-process exit codes through `python -m patchtrace` |
| `tests/stress/test_cli_stress_paths.py` | 10 | 7 pass, 1 skip (root), 2 xfail (strict) | unicode and space names, shell metacharacters, a nested path over 200 characters, relative and trailing-separator paths, file-not-directory, a read-only stand-in (publish raises a read-only sqlite error), read-only directory (POSIX, non-root only) |
| `tests/stress/test_cli_stress_concurrency.py` | 4 | 4 pass | deterministic writer refusal while another process holds the lock (rank and flags, exit 2 with one document); 4 racing CLI processes leave the store consistent (invariants, not outcome counts); stale lock text does not block; parallel probes |
| `tests/stress/test_cli_stress_recovery.py` | 7 | 7 pass | real SIGKILL parked inside a save transaction (prior snapshot and history kept, lock released, rank works afterwards); SIGKILL during creation recycled by the next create; torn database (one third) and garbage database refused with `PT-` codes; payload bit flip, deleted snapshot row, future schema version refused with their contract codes |
| `tests/stress/test_cli_stress_perf.py` | 4 | 4 pass (recorded, not gated) | 10k-pair ranking cold and cache hit (ranking identical on hit); open of a 10k-match project; 100 open/close cycles (traced growth bound 1 MiB); descriptor count after 100 cycles |

Totals of the directory: 158 collected; 150 passed, 1 skipped, 7 xfailed; 22.9 s wall on a quiet host, 26 s to 47 s under load (approximately: perf 15 s,
verbs 4 s, paths 3 s, concurrency 2 s, recovery 1.5 s; the perf file is the one closest to the 30 s budget). `ruff
check tests/stress` clean. No fixed sleeps: waits are on a child's `PARKED` line, process exit, or a 60 s watchdog.
Helpers live in `tests/stress/cli_stress_support.py` (not collected).

Overlap: `tests/test_service_storage_audit.py` (BH-svc, 2026-10-14) already covers in-process interrupted creation,
truncated and tampered stores. The recovery file adds a real SIGKILL and the CLI-level document for the same
states; it does not duplicate the in-process tests.

## Measured numbers (recorded, not gated)

| Measurement | Value on this host | SPEC-07 objective | Note |
|---|---|---|---|
| Ranking 10k pairs / 100k lines, cold | 5.1 s to 6.7 s (test run 6.4 s; `tools/bench_enrichment.py` 6.19 s) | 10 s | met |
| Derived-cache hit, 10k pairs | 1.45 s (tool), 1.5 s to 3.0 s (tests) | 500 ms | **not met** (matches SPEC-07 "measured 3.1 s" and the hardening note) |
| Process peak RSS, 10k pairs | 547 MiB (tool), 557 MiB (test process) | 512 MiB | **exceeded in this run**; SPEC-07 text records 240 MiB. The figure is a process peak including the fixture build, so it is an upper bound; the spec text needs a fresh number |
| Project open, 10k matches (17 MB database) | 0.57 s to 0.67 s (1.2 s under load) | not specified | save of the same project 0.67 s |
| Project open, sample after 121 saves | 5 ms | not specified | history pruned to 101 rows (HISTORY_KEEP 100 plus the newest snapshot of each revision) |
| Memory growth over open/close cycles | 3.5 KiB traced (200-cycle probe) | not specified | gated at 1 MiB |
| Descriptors after 100 cycles | no growth | not specified | Linux only |
| `rank --help` wall time | 0.29 s | not specified | CLI start is Qt-free |
| 4 racing `rank` writers, 5 rounds (20 processes) | 12 exit 0, 8 exit 2 (lock held); no exit 3, no traceback, all stores consistent | single writer | refusal, not waiting: a racing writer gets exit 2 at once |

## Bugs

Each xfail is strict: the suite fails when the bug is fixed, so the marker must then be removed.

| ID | Severity | Repro | Expected | Test |
|---|---|---|---|---|
| QA-CLI-1 | Medium | `python -m patchtrace rank --json; echo $?` (no project). Also `correlate --json`, `acquire search --json`, `rank <p> --json --limit x`. Exit 2, stdout empty, the message only on stderr. | Exit 2 and exactly one `enrichment-cli/1` JSON document with `status: failed` | `test_cli_stress_verbs.py::test_json_mode_parse_failure_emits_one_document` (4 cases). Cause: `cli.main` builds the envelope only after a successful parse (`args` is still `None` on an argparse failure). A consumer that parses stdout gets nothing. |
| QA-CLI-2 | Low | `patchtrace correlate <project> --cve bad` (no `--fetch`). Exit 4 ("complete evidence, zero entries") with the warning `bad: no snapshot available`. | Exit 2: the CVE id is malformed (`CVE-YYYY-NNNN`). Validation exists only on the `--fetch` path. | `test_offline_correlate_rejects_malformed_cve_id` |
| QA-CLI-3 | Medium | `patchtrace cache verify --cache-dir <regular file> --json`. Exit 0, `status: complete`, `result.error: "_Unsafe"`, `ok: 0`, `corrupt: 0`. A check that verified nothing reports success. `cache status` returns the same `_Unsafe` with exit 0. | Exit 2 (invalid environment or configuration) | `test_cache_verify_on_a_file_reports_failure` |
| QA-CLI-4 | Low | `patchtrace rank <p> --cache-dir <regular file> --json --dry-run`. Exit 0; the run goes ahead without any cache; `warnings` lists only `stage contextual: unavailable`. | Exit 2, or a warning that names the cache directory | `test_rank_reports_an_unusable_cache_dir` |

Observations, not gated:

- **O-1 (Low, wording).** `--weights` with an out-of-range or non-integer value (`{"BND": 101}`, `1.5`, `true`)
  exits 2 correctly, but the message is raw multi-line pydantic output that echoes the input dict and the
  pydantic documentation URL. A single line would serve the contract better.
- **O-2 (Info).** Nothing was run without arguments: that starts the desktop by design. The probe
  `python -m patchtrace` with no display aborts with SIGABRT (Qt platform plugin), which is expected for the GUI.
- **O-3 (Info, drift).** SPEC-07 says the 10k-pair peak was measured at 240 MiB; this host measured 547 MiB in the
  repository tool. Both figures should be kept in the spec with host and date.
- **O-4 (Info, not verified).** The read-only directory test (`test_read_only_project_directory_for_dry_run_and_persisting_rank`)
  is skipped on this host because the session runs as root, and root bypasses permission bits. It runs only on a
  non-root CI runner. The read-only path is therefore covered by the deterministic stand-in only here.

## Not done (open gates)

- Windows: nothing was executed. The suite uses `pathlib`, text files with `newline='\n'` and explicit UTF-8, and POSIX
  checks only behind `skipif`. The long-path test skips on Windows when the path reaches 260 characters; the lock and
  kill tests use `Popen.kill` (SIGKILL on POSIX, TerminateProcess on Windows) and are unverified there.
- No stress run of the full suite (the integrator owns it). The stress directory was run alone.
- `docs/specs/enrichment.md` still says 240 MiB (O-3); not changed here, because specs change through their owner.
