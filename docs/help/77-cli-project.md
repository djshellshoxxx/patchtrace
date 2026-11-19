# `patchtrace project`

Creates, inspects and maintains a comparison project without the desktop. Use it to turn two local PE files into a project from a script, to import a Ghidriff JSON result you already have, to list the analysis runs of a project and to make a backup.

```
patchtrace project create --older FILE --newer FILE --project DIR [--name NAME]
patchtrace project sample --project DIR
patchtrace project info PROJECT
patchtrace project runs PROJECT
patchtrace project import-json PROJECT FILE
patchtrace project backup PROJECT --out DIR
patchtrace project swap PROJECT --confirm
```

Every action takes `--json`, which prints exactly one `enrichment-cli/1` document on stdout. The `command` field is `project <action>`.

What it never does: it does not execute, load or change an input file, it makes no network request, and it never prompts. A confirmation is a flag.

The examples below were produced with the repository's synthetic PE fixtures (1024-byte authored files). No analysis engine ran.

## create

Copies both files into the new project directory, verifies their SHA-256 and checks statically that each is a 64-bit (AMD64) PE file.

```
$ patchtrace project create --older in/afd_old.sys --newer in/afd_new.sys --name afd-kb5099777 --project case
older: afd_old.sys dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215 (1024 bytes)
newer: afd_new.sys 4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168 (1024 bytes)
project: /work/case (id 355b4ee3-90ec-4c39-894a-4af97c83e32c)
Inputs were copied and hash-verified; they were not executed or modified.
```

- The directory must be absent or empty. A directory that already holds a project is refused with `project directory already contains a project`; any other content with `the project directory must be absent or empty`. Both exit 2.
- A file that is missing, unreadable, not a PE file or not AMD64 is refused with the reason, for example `error: PT-INPUT: missing DOS MZ header` (exit 2). The copy of the other file is removed again. The directory may stay behind holding only the lock file `.patchtrace.lock`; you can reuse it.
- Two identical files are accepted. The project then records an `identical` run and there is nothing to compare.
- Without `--name` the project is called `Untitled comparison`.

Next step: [`patchtrace compare`](78-cli-compare.md) runs the analysis, or `import-json` (below) loads a result you already have.

## sample

Creates the synthetic sample project: authored fixtures, an authored result with four matches and one authored finding. No engine and no model runs. It is meant for scripted smoke tests and first trials.

```
$ patchtrace project sample --project demo
older: older_sample.dll dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215 (1024 bytes)
newer: newer_sample.dll 4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168 (1024 bytes)
project: /work/demo (id a7122593-3719-410f-a0fc-22672366bd77)
Synthetic sample: authored fixtures and an authored result with 4 matches; no engine and no model was run.
Inputs were copied and hash-verified; they were not executed or modified.
```

## info

A read-only summary. It changes nothing in the project directory except the lock file, which every program that opens a project rewrites.

```
$ patchtrace project info case
project: afd-kb5099777 (id 355b4ee3-90ec-4c39-894a-4af97c83e32c; revision 1)
contract: snapshot schema 1, database version 1; created 2026-11-11T01:30:02.749539+00:00; synthetic sample: no
older: afd_old.sys dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215 (1024 bytes), PE x86-64
newer: afd_new.sys 4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168 (1024 bytes), PE x86-64
runs: 1 (completed 1); latest completed: e9fb6030-344c-42b4-81b1-38fe8cc30f69
matches: 2 (modified 1, added 1); review: unreviewed 2; manual 0
findings: 0 in 0 interpretation(s); stale 0
annotations: notes 0, bookmarks 0, manual corrections 0, validation records 0; stale 0
derived results: none stored
```

`latest completed` is the run that `rank`, `flags` and `correlate` use when you give no `--run`. `derived results` lists the enrichment entries stored in the project database by kind (for example `ranking 1 (0 stale)`). With `--json` every count is present, zero included.

## runs

Lists every recorded analysis run, newest first: completed, failed, cancelled and identical runs. `*` marks the latest completed run. The last column is the preserved raw result, or the directory that keeps the output of a failed run.

```
$ patchtrace project runs cmp
  run                                   status     backend           version         recorded                          result
* e8de1073-2b5a-4b63-8a53-d44bfe0cef16  completed  ghidriff          fake-test-only  2026-11-11T01:34:12.217906+00:00  runs/e8de1073-2b5a-4b63-8a53-d44bfe0cef16/raw/json/a-b.ghidriff.json
  62ee3161-9711-40b5-bab3-bea6ebccf328  failed     ghidriff          fake-test-only  2026-11-11T01:34:12.105650+00:00  runs/quarantine-62ee3161-9711-40b5-bab3-bea6ebccf328
    error: PT-BACKEND: ghidriff exited with code 7; inspect analysis.log
  f342f595-a416-4f5d-85bd-132a798a3808  completed  ghidriff          fake-test-only  2026-11-11T01:34:12.006225+00:00  runs/f342f595-a416-4f5d-85bd-132a798a3808/raw/json/a-b.ghidriff.json
```

(The version `fake-test-only` shows that this listing comes from the test backend, not from Ghidriff.)

With `--json` each run also carries `error_code`, `raw_sha256`, `quarantined`, `current` and `tools` (the Ghidra, Python, pyghidra and Java versions the backend recorded). A project stores one time per run: when the run was recorded. Start and end times are not stored, so none are shown. A project without runs prints `No analysis runs recorded.` and exits 4.

## import-json

Imports a Ghidriff JSON result for exactly this pair. PatchTrace parses it strictly, checks that the input hashes inside the result are the hashes of this project's two files, keeps the file's exact bytes under `runs/<id>/raw/` and records a completed run.

```
$ patchtrace project import-json case result.ghidriff.json
imported run e9fb6030-344c-42b4-81b1-38fe8cc30f69 (ghidriff-import); project revision 1
matches: 2 (modified 1, added 1)
raw result preserved: runs/e9fb6030-344c-42b4-81b1-38fe8cc30f69/raw/result.ghidriff.json sha256 0d697ebd56c75c426f605e55faa5caac7890ead0fcfdef6a679b4a771bd3ca08
```

A refused file exits 2 and leaves the project unchanged. Examples: `PT-SCHEMA: newer diff input hash does not match this project` (a result for another pair), `PT-SCHEMA: analysis output is unreadable or malformed UTF-8 JSON`, `PT-SCHEMA: duplicate JSON key old_meta`. A storage failure exits 3. An import raises the project revision and marks earlier interpretations, findings and annotations stale, as a new analysis does.

## backup

Writes a complete copy of the project to a new directory, then opens the copy and checks it: database integrity, snapshot hash, the hashes of both files and of every preserved raw result, and that the copy holds the same snapshot as the source.

```
$ patchtrace project backup case --out backups/case-1
backup: /work/backups/case-1
verified: the copy was re-opened (database integrity, snapshot hash, artifact and raw-result hashes) and holds revision 1 of project 355b4ee3-90ec-4c39-894a-4af97c83e32c
```

The destination must not exist and must be outside the project (exit 2 otherwise). Nothing is overwritten. If the copy does not pass the check, the command exits 3, names the directory and leaves it for inspection.

## swap

Exchanges the older and the newer side. Without `--confirm` nothing happens and the command explains the effect:

```
$ patchtrace project swap case
error: PT-CLI-CONFIRM: `project swap` changes the project: the older and the newer artifact exchange sides, every match is mirrored (added <-> removed, split <-> merged), the project revision rises by one and every interpretation, finding and annotation (notes, bookmarks, manual-correction records) is marked stale; analysis runs and preserved raw results are kept. Re-run with --confirm to do it.
$ patchtrace project swap case --confirm
older and newer exchanged:
older: afd_new.sys 4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168 (1024 bytes)
newer: afd_old.sys dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215 (1024 bytes)
project revision 2; 2 matches mirrored; marked stale: 0 interpretation(s), 0 finding(s), 0 annotation(s)
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done. |
| 2 | Something to correct: a flag, an input file, a path that is not a project, a directory that is not free, a missing `--confirm`. |
| 3 | A runtime or storage failure, or the project is locked. |
| 4 | `runs` only: the project has no analysis run. |
| 5 | Cancelled (Ctrl+C). |

A project that is open in the desktop or in another `patchtrace` process is locked. The command then exits 3 with `PT-STORAGE: project is locked by another writer or lock is inaccessible` and names the lock file `.patchtrace.lock`. Close the other program and retry. Do not delete the lock file. See [Troubleshooting](52-troubleshooting.md).

Evidence: these actions are tested with synthetic fixtures in the build sandbox. Native Windows behaviour is not verified by those tests.

Desktop equivalent: **Project > New**, **Sample**, **Import JSON**, **Back up project…** and **Swap orientation**. The desktop has no single list of runs; `project runs` is the way to read run ids for `--run`.

Sources: `src/patchtrace/project_cli.py`, `src/patchtrace/cli_commands/project.py`, `src/patchtrace/service.py`, `docs/specs/cli-project-compare.md`.
