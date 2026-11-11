# Headless project lifecycle and single-pair comparison: `patchtrace project`, `patchtrace compare`

Status: built 2026-11-11 (slice CLI-A, finding F-D01). Spec number pending (integrator ask: `INDEX.md` and `REGISTRY.md` rows). Verified only with hermetic tests in the build sandbox: synthetic PE fixtures and a fake Ghidriff backend. Behaviour with a real Ghidra and Ghidriff runtime, and on native Windows, is UNVERIFIED by this slice.

Amends: SPEC-44 (`cli-umbrella.md`) section 7 recorded `project` as "not in the alpha". The owner's required CLI list supersedes that row; this file is the owner spec of both verbs. The umbrella text itself is edited by slice CLI-0 (integrator ask).

## 1. Purpose

Before this slice two local binaries could become an analysed project only in the desktop. `series create --run` needs 3 to 8 builds, `acquire fetch` needs the network, `kb import-pair` needs an investigation id, and nothing imported a Ghidriff JSON, listed the analysis runs or made a backup headlessly. These two verbs close that gap so the core workflow can be scripted: create (or import), compare, then every derived verb (`rank`, `flags`, `unified`, `export`, ...).

Code: `src/patchtrace/project_cli.py` and `src/patchtrace/compare_cli.py` (Qt-free dispatchers), `src/patchtrace/cli_commands/project.py` and `compare.py` (registry adapters, at most 25 lines). `cli.py`, `service.py`, `persistence.py` and `backend.py` are called, not changed.

## 2. Rules common to every leaf

- Envelope `enrichment-cli/1` through `cli._emit`. With `--json` stdout carries exactly one JSON document; diagnostics and progress go to stderr. `command` is `project <leaf>` or `compare`, also in the failure envelope.
- Exit codes: 0 success; 2 invalid arguments, input or environment (the analyst must correct something); 3 runtime or storage failure, including a project that is locked; 4 legitimate no result (`project runs` on a project without runs); 5 cancelled.
- Never done: no input file or project artifact is executed, loaded or modified; no network request is made by these verbs themselves (`compare --symbols online --consent-online-symbols` lets Ghidra contact its symbol servers, exactly as `series create --run` does); nothing is read from stdin and nothing prompts. Confirmation is a flag.
- Untrusted text (file names, project names, backend error text) is shown in text mode with control and bidirectional characters escaped and bounded to 300 characters per field. JSON carries the stored value.
- Lock: every leaf that opens a project takes the project's advisory lock file `.patchtrace.lock`. When the desktop or another process holds it the leaf exits 3 with the service's `PT-STORAGE: project is locked by another writer or lock is inaccessible` followed by the lock file name and what to do. Any other reason the project cannot be opened (missing directory or database, damaged snapshot, changed artifact) exits 2 with the service's message.
- Read-only leaves (`project info`, `project runs`) open the store directly and load the snapshot with `recover_interrupted=False`, without the legacy raw cleanup. They change no byte in the project directory except the lock file, which every opener rewrites with its holder record. This is stricter than `ProjectService.open(maintenance=False)`, which would still rewrite a stored `queued` or `running` run as failed.
- No Qt import on any path.

## 3. `patchtrace project`

### 3.1 `project create --older FILE --newer FILE --project DIR [--name NAME] [--json]`

Wraps `ProjectService.create`. Both files are copied into `DIR/artifacts/<sha256>.bin`, hash-verified and statically validated as PE32+ AMD64; `DIR/project.sqlite3` holds the first snapshot. `--name` defaults to the service default (`Untitled comparison`).

- Refusals (exit 2): `project directory already contains a project` when `DIR/project.sqlite3` exists (the wording and code of `acquire fetch --project`); `the project directory must be absent or empty` for any other non-empty directory (the desktop's rule, `persistence.creation_directory_available`); every refusal the service raises, with its message (`PT-INPUT: ...` for a missing, unreadable, non-PE or non-AMD64 file, `PT-STORAGE: ...` when the directory cannot be created).
- Rollback: when the second input is refused, the copy of the first input, the `artifacts` directory and the database are removed by the service. The directory itself may remain holding only `.patchtrace.lock`; the service never unlinks a lock inode (unlinking would let two later writers lock different files). A retry into the same directory works.
- Identical inputs are not refused: the service records an `identical` run and the result says `identical: true`.
- Result: `project` (absolute directory), `project_id`, `name`, `revision`, `identical`, `artifacts` (older first; each `side`, `name`, `size`, `sha256`).
- Text: one line per artifact (`older: NAME SHA256 (SIZE bytes)`), `project: DIR (id ID)`, and a closing line that the inputs were copied and verified, not executed or modified.

### 3.2 `project sample --project DIR [--json]`

Wraps `ProjectService.sample`: the synthetic walkthrough project (authored PE fixtures, authored Ghidriff-shaped result, authored finding; no engine and no model is run). For scripted smoke tests and first trials. Same directory refusals and result fields as `create`, plus `sample: true`, `run_id` and `matches` (`total`, `by_category`).

### 3.3 `project info PROJECT [--json]`

Read-only summary. Result:

- `project`: `id`, `name`, `created`, `revision`, `schema_version` (snapshot contract), `database_version` (SQLite `user_version`), `sample`.
- `artifacts`: older first; `side`, `name`, `size`, `sha256`, `format`, `architecture`. `orientation`: `{older: sha256, newer: sha256}`.
- `runs`: `total`, `by_status` (every status of the contract, zero included), `latest_completed` (id of the newest `completed` run, the default of `--run` elsewhere, or null).
- `matches`: `total`, `by_category`, `by_review` (every value of the contract, zero included), `manual`.
- `findings`: `total`, `interpretations`, `by_review`, `stale`.
- `annotations`: per kind (`note`, `bookmark`, `match-override`, `validation`) `total` and `stale`. An active manual correction is a `match-override` that is not stale.
- `derived`: enrichment entries stored in the project database, per kind `entries` and `stale` (the stored flag); `{}` when none exist. The table is read, never created.

Exit 0. Text: a fixed block of lines in this order (project, contract, older, newer, runs, matches, findings, annotations, derived results).

### 3.4 `project runs PROJECT [--json]`

Every recorded analysis run, newest record first, including failed, cancelled, identical and quarantined runs. Per run: `id`, `status`, `backend`, `backend_version`, `created`, `tools` (the tool versions the backend recorded in the run settings: `ghidra_version`, `python_version`, `pyghidra_version`, `java_runtime_version`; absent keys are omitted), `error`, `error_code` (the leading `PT-...` code of `error`, or null), `raw_path` and `raw_sha256` (the preserved raw result, relative to the project, or null), `output_dir` (`runs/<id>` or `runs/quarantine-<id>` when that directory exists, else null), `quarantined`, `current` (true for `latest_completed`). The result also carries `latest_completed`.

The v1 run contract stores one timestamp per run (`created`: when the run record was made, which for a backend run is when the backend returned). Separate start and end times are not recorded and are not invented.

Exit 0 with at least one run; exit 4 (`status: complete`, empty `runs`) for a project without runs. Text: one row per run (`*` marks the current run), followed by an indented `error:` line where one is recorded.

### 3.5 `project import-json PROJECT FILE [--json]`

Wraps `ProjectService.prepare_import` and `apply_import`: imports an existing Ghidriff JSON result for exactly this pair. Strict JSON parsing, the 100 MiB bound, the input-hash identity check and normalization are the service's. The raw bytes are preserved under `runs/<id>/raw/result.ghidriff.json` and the run is recorded as `completed`, backend `ghidriff-import`.

- Exit 2 (bad input, project unchanged): `PT-SCHEMA: ...` and `PT-INPUT: ...` refusals (unreadable or malformed file, duplicate keys, a result for another pair, an unsupported shape) and a record that violates the function contract.
- Exit 3 (storage failure): `PT-STORAGE: ...` refusals and operating-system errors while the raw copy is staged or the snapshot is committed. A prepared import that is not applied is discarded (also on Ctrl+C), so no staged raw copy and no empty `runs` directory stays behind.
- Result: `run_id`, `backend`, `revision`, `raw_path`, `raw_sha256`, `matches` (`total`, `by_category`).

Importing invalidates like any new analysis: the revision rises and stored interpretations, findings and annotations are marked stale.

### 3.6 `project backup PROJECT --out DIR [--json]`

Wraps `ProjectService.backup`: a complete new copy (SQLite online backup plus `artifacts`, `runs`, `exports`, `kb`, `intelligence`). `DIR` must not exist and must be outside the project (exit 2, `PT-STORAGE: backup destination must be new and outside project`); nothing is ever overwritten. The service does not re-read the copy, so the CLI does: it opens the backup read-only (integrity check, snapshot hash, artifact and raw-output hashes) and compares project id, revision and snapshot with the source. Result: `backup` (absolute directory), `project_id`, `revision`, `verified: true`. A copy that fails this check exits 3, names the directory and leaves it in place for inspection. Other service failures exit 3.

### 3.7 `project swap PROJECT --confirm [--json]`

Wraps `ProjectService.swap_orientation`. Without `--confirm` it exits 2 (`PT-CLI-CONFIRM`) and explains the effect; it never prompts. Effect, as the service implements it: the older and the newer artifact exchange sides; every match is mirrored (`added` and `removed` swap, `split` and `merged` swap); the project revision rises by one; every interpretation context, every finding and every annotation (notes, bookmarks, manual-correction records) is marked stale. Analysis runs, preserved raw results and derived results in the database are not touched; whether a derived result is still current is decided by its own reader. Result: `revision`, `artifacts`, `matches` (`total`, `by_category`), `invalidated` (`interpretations`, `findings`, `annotations`: the records this swap marked stale).

## 4. `patchtrace compare PROJECT`

`compare PROJECT --python EXE --ghidra-dir DIR [--timeout SECONDS] [--cache-dir DIR] [--symbols off|local|online] [--symbol-dir DIR]... [--consent-online-symbols] [--force] [--json]`

Runs the primary Ghidriff analysis for the project's pair through the path the desktop and `series create --run` use: `backend.run_comparison`, then `ProjectService.prepare_analysis` and `apply_import`; a result the service rejects goes through `backend.quarantine_failed_run`; a failed, cancelled or identical run is recorded with `record_terminal_run`. `cli._run_pair` is not called because it cannot force a new run and returns neither the run nor the cancellation; the flow is replicated and a test runs both on the same fake backend and compares the recorded runs. `BackendConfig` is built from the same flags in the same way as `series create --run` (also pinned by a test), so the runtime flags mean the same on both verbs.

- Preflight, before the project is opened or anything is written (exit 2): `--python` and `--ghidra-dir` are required; `--timeout` must be 10..86400 (default 3600); the symbol flag rules of SPEC-53 (`PT-SYMBOL-NETWORK-REFUSED`, `PT-SYMBOL-MODE`); every `PT-BACKEND: ...` configuration error of the backend (not an absolute existing Python, not a Ghidra root, ...).
- No-op: a project that already has a `completed` or `identical` run is left alone (the reuse rule of `series create --run`): exit 0, result `ran: false`, `forced: false`, `run_id` and `status` of that run, `revision`, `matches`, and a line that says so. `--force` runs again; the earlier run and its raw result stay in the project.
- Success: exit 0, `status: complete`, `ran: true`; result `run_id`, `status` (`completed` or `identical`), `backend`, `backend_version`, `raw_path`, `raw_sha256`, `revision`, `forced`, `matches` (`total`, `by_category`).
- Failure: the terminal run is recorded as `failed` and its output is kept under `runs/quarantine-<id>`; exit 3, envelope `status: failed`, result `ran`, `forced`, `run_id`, `status`, `error`, `error_code`, `output_dir`; the error is also printed as `error: ...` on stderr. The envelope carries the result rather than a top-level `error`, so a script gets the run id. Earlier results are preserved, and a failed run is not a result: the next `compare` runs again without `--force`.
- Cancellation: exit 5, envelope `status: cancelled`, a `cancelled` run is recorded, result as for a failure. While the comparison runs, the first Ctrl+C sets the cancel event (so the backend stops its child and the run is recorded) and restores the previous handler; a second Ctrl+C interrupts as everywhere else in the CLI (exit 5; that run is then not recorded and its partial output stays under `runs/quarantine-<id>`). Where no handler can be installed (not the main thread) the first Ctrl+C already behaves like the second.
- Progress: stage events on stderr as `compare: <stage>: <message>`, through `CliBackendProgress` (bounded, never from inside child supervision).

After a successful compare, `rank PROJECT` and the other derived verbs work on the project.

## 5. Tests and evidence class

`tests/test_project_cli.py` and `tests/test_compare_cli.py` drive `patchtrace.cli.main` in process (plus one subprocess smoke through `python -m patchtrace`). Inputs are the synthetic PE fixture `sample.synthetic_pe`; the backend is the fake Ghidriff of `tests/test_jobs.py` and `tests/test_nway_series.py`. Evidence class: synthetic and mocked. None of it is live evidence for Ghidra, Ghidriff, Windows file locking or a frozen build.
