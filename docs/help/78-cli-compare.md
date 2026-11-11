# `patchtrace compare`

Runs the primary analysis for the two files of one project: Ghidriff, driven by an external Python and a Ghidra installation that you name. It is the headless form of **Analysis > Run comparison** (F5). The result is saved in the project, and `rank`, `flags`, `unified`, `export` and the other verbs then work on it.

```
patchtrace compare PROJECT --python EXE --ghidra-dir DIR
                   [--timeout SECONDS] [--cache-dir DIR]
                   [--symbols off|local|online] [--symbol-dir DIR]... [--consent-online-symbols]
                   [--force] [--json]
```

| Flag | Meaning |
|---|---|
| `--python EXE` | Absolute path of the external Python that has `ghidriff` installed. Required. |
| `--ghidra-dir DIR` | Root of the Ghidra installation. Required. |
| `--timeout SECONDS` | Analysis timeout, 10 to 86400. Default 3600. |
| `--cache-dir DIR` | Raw-output cache. Default: no cache. |
| `--symbols`, `--symbol-dir`, `--consent-online-symbols` | Ghidra symbol mode, as for `series create --run`. `off` is the default. `online` lets Ghidra contact its symbol servers and needs `--consent-online-symbols`. |
| `--force` | Run again although the project already has a completed run. The earlier run and its raw result stay in the project. |

The runtime flags are the same as those of [`series create --run`](58-cli-series.md) and are passed to the backend in the same way.

What it never does: it does not execute the two files (the analysis is static), it does not prompt, and it makes no network request of its own. Only `--symbols online` with the consent flag lets Ghidra use the network.

**Evidence.** This verb is verified only with a fake backend in the build sandbox: a small script stands in for Ghidriff. Its behaviour with a real Ghidra and Ghidriff installation is UNVERIFIED. The examples below come from that fake backend, which is why the version reads `fake-test-only`.

## A first run

Create the project with [`patchtrace project create`](77-cli-project.md), then:

```
$ patchtrace compare cmp --python /opt/pt/venv/bin/python --ghidra-dir /opt/ghidra
compare: preflight: Checking copied input hashes and external analysis runtime
compare: analysis: Ghidriff is performing static analysis; detailed counts are unavailable
compare: analysis-stopped: Ghidriff process supervision ended.
compare: completed: Raw static analysis saved; normalization is ready
compared: run f342f595-a416-4f5d-85bd-132a798a3808 completed (ghidriff fake-test-only)
matches: 1 (modified 1); project revision 1
raw result preserved: runs/f342f595-a416-4f5d-85bd-132a798a3808/raw/json/a-b.ghidriff.json sha256 74ea2b886455fec921b5805c93da642f4a7f13ed67d059fdf7c314412aa3ca26
```

The `compare: ...` lines are progress on stderr. The last three lines are the result on stdout. With `--json` stdout carries one `enrichment-cli/1` document with `ran`, `forced`, `run_id`, `status`, `backend`, `backend_version`, `raw_path`, `raw_sha256`, `revision` and `matches`.

## A project that is already compared

A project that has a completed run is left alone. The command says so and exits 0:

```
$ patchtrace compare cmp --python /opt/pt/venv/bin/python --ghidra-dir /opt/ghidra
run f342f595-a416-4f5d-85bd-132a798a3808 is already completed for this pair; nothing was run.
Use --force to run the comparison again; the earlier run is kept.
```

The same holds for a project made from two identical files: it has an `identical` run and there is nothing to compare.

## A failed run

The run is recorded as failed, its output is kept, and earlier results are unchanged. The command exits 3:

```
$ patchtrace compare cmp --python /opt/pt/venv/bin/python --ghidra-dir /opt/ghidra --force
compare: preflight: Checking copied input hashes and external analysis runtime
compare: analysis: Ghidriff is performing static analysis; detailed counts are unavailable
compare: analysis-stopped: Ghidriff process supervision ended.
compare: failed: PT-BACKEND: ghidriff exited with code 7; inspect analysis.log
error: PT-BACKEND: ghidriff exited with code 7; inspect analysis.log
comparison failed: run 62ee3161-9711-40b5-bab3-bea6ebccf328 was recorded; earlier results are unchanged; its output is kept under runs/quarantine-62ee3161-9711-40b5-bab3-bea6ebccf328
```

Read `analysis.log` in that directory. `patchtrace project runs PROJECT` lists the failed run with its error. With `--json` the document has `status: failed` and the result holds `run_id`, `error`, `error_code` and `output_dir`. A failed run is not a result, so the next `compare` runs again without `--force`.

## Cancelling

Press Ctrl+C once. PatchTrace asks the backend to stop, records the run as cancelled and exits 5. A second Ctrl+C interrupts at once; that run is then not recorded.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Compared, or already compared (nothing was run). |
| 2 | A flag or the runtime is wrong: `--python` is not an absolute path to an existing Python, `--ghidra-dir` is not a Ghidra root, `--timeout` is out of range, `--symbols online` lacks consent, or the path is not a project. These are checked before the project is opened, so nothing is written. |
| 3 | The run failed (it is recorded), or the project is locked by the desktop or another process. The lock message names the lock file `.patchtrace.lock`; close the other program and retry. |
| 5 | Cancelled. |

Typical messages for exit 2: `PT-BACKEND: select the absolute path to an installed external Python executable`, `PT-BACKEND: Ghidra/application.properties is missing; select the installation root`, `--timeout must be between 10 and 86400 seconds`, `PT-SYMBOL-NETWORK-REFUSED: --symbols online requires --consent-online-symbols`.

Desktop equivalent: **Analysis > Run comparison** (F5), with the runtime chosen in **Setup**.

Sources: `src/patchtrace/compare_cli.py`, `src/patchtrace/cli_commands/compare.py`, `src/patchtrace/backend.py`, `docs/specs/cli-project-compare.md`.
