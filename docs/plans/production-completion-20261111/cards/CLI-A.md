# Slice card CLI-A - headless project lifecycle and single-pair comparison: `patchtrace project` and `patchtrace compare` (F-D01, severity high)

Evidence and designs: `jq '.actionable_now[] | select(.id=="F-T07" or .id=="F-T08")' docs/status/inventory/F.json`,
`jq '.features[] | select(.id=="F-F03" or .id=="F-F04" or .id=="F-F15" or .id=="F-F18")' docs/status/inventory/F.json`,
`jq '.features[].defects[]? | select(.id=="F-D01")' docs/status/inventory/F.json`, parity matrix docs/status/gui-cli-parity-matrix.md rows 1-5, 24, 26 and section 3.
Constraints the analyst verified (binding): src/patchtrace/cli.py is exactly at its seam budget and cli.COMMANDS must not
change - do NOT edit cli.py; a new verb is a file src/patchtrace/cli_commands/<verb>.py exporting COMMAND (an adapter of
at most 25 lines, stdlib + this package only at module level, feature imported lazily inside build/run) over a Qt-free
dispatcher module; tests/test_help_docs.py requires a help page titled exactly `# `patchtrace <verb>`` and linked from
docs/help/README.md for every verb. Read src/patchtrace/cli_commands/__init__.py, _support.py, inspect.py and one
dispatcher (src/patchtrace/pe_overview/cli.py) before writing anything. Envelope enrichment-cli/1 through `emit`; exit
codes 0 ok, 2 usage/environment (raise CliError), 3 runtime failure, 4 no result, 5 cancelled; --json emits exactly one
JSON document on stdout; never prompt; no Qt import on any path (there is an import-cleanliness test pattern in
tests/test_cli_registry.py - extend it to the new modules).

## Today
Turning two local binaries into an analysed project is impossible without the desktop: no project-create verb, no
Ghidriff-JSON import verb, no single-pair comparison verb (`cli._run_pair`, cli.py about lines 651-676, is reachable
only from `series create --run` with 3 to 8 builds), no run listing, no backup.

## Spec first: docs/specs/cli-project-compare.md (new)
Write the contract before the code: purpose, each leaf with flags, result fields of the JSON envelope, text output
shape, exit codes per failure, what is written to disk, what is never done (no target execution, no network, no prompt),
and the evidence class of the tests (hermetic fake backend - never live evidence). Then build exactly that.

## `patchtrace project` leaves (src/patchtrace/project_cli.py + cli_commands/project.py)
- `project create --older FILE --newer FILE --name NAME --project DIR`: wraps ProjectService.create (service.py:81).
  DIR must not already hold a project (follow the wording and exit code `acquire fetch --project` uses for the same
  condition). Reports the two SHA-256 values, sizes and the project id. Input files are never executed and never
  modified. Every refusal the service raises (not a supported PE, unreadable file, identical files if the service
  refuses them) is exit 2 with the service's message; a partially created directory must not be left behind (the service
  has a rollback - test it through the CLI with a failing second input).
- `project info PROJECT`: read-only summary - name, contract/schema version, the two artifacts (role, original name,
  size, SHA-256), orientation, counts of matches by category and by review status, findings, notes, manual corrections,
  which derived results exist, and the latest completed run id. Must not write anything: open with
  `ProjectService.open(root, maintenance=False)` (check what maintenance does) and prove with a test that the project
  directory tree is byte-identical before and after (hash every file).
- `project runs PROJECT`: every recorded analysis run, newest first: run id, status (including failed, cancelled and
  quarantined runs), backend and tool versions as recorded, start/end time, error code and message if any, the raw
  result path relative to the project. This is the "historical run retrieval" requirement; text table and --json.
- `project import-json PROJECT FILE`: wraps ProjectService.prepare_import / apply_import (service.py:153, 251) - import
  an existing Ghidriff JSON result. Strict JSON and ownership validation are the service's job; map its typed errors to
  exit 2 (bad input) or 3 (storage failure) and leave the project unchanged on refusal (test: tree hash identical).
- `project backup PROJECT --out DIR`: wraps ProjectService.backup (service.py:138); report the backup path and that it
  was verified if the service verifies it.
- `project swap PROJECT --confirm`: wraps ProjectService.swap_orientation (service.py:426). Without --confirm exit 2 and
  explain what a swap does (older and newer are exchanged; stored derived results are invalidated - read the service to
  state exactly what is invalidated). Never prompt.
- `project sample --project DIR`: wraps ProjectService.sample (service.py:116): the synthetic sample project, for
  scripted smoke tests and first-run trials.
A project that is open in the desktop (or locked by another process) must give a clear exit-3 message naming the lock,
never a traceback: find how the lock refusal surfaces and test it by holding the project open in the test process.

## `patchtrace compare PROJECT` (src/patchtrace/compare_cli.py + cli_commands/compare.py)
Run the primary analysis for the project's pair. Reuse the exact flow `series create --run` uses for one pair
(cli._run_pair: backend.run_comparison, ProjectService.prepare_analysis / apply_import, quarantine_failed_run,
record_terminal_run) and the same flags for the runtime (--python, --ghidra-dir, timeout and the others
`patchtrace series create --help` lists for --run). Import and call the existing helper if its signature fits (one source
of truth; importing from patchtrace.cli is fine, editing it is not); if it does not fit, replicate the flow in
compare_cli.py and pin the equivalence with a test that runs both paths on the same fake backend and compares the
recorded run. backend.py belongs to another session: call it, never edit it, and build BackendConfig the same way the
series path does so new optional fields do not break this verb.
Behaviour: a project that already has a completed run is a no-op exit 0 that says so, unless `--force` asks for a new
run; a backend failure records the terminal run (quarantined raw output is kept) and exits 3 with the recorded error
code; cancellation (the cancel Event) exits 5 and records a cancelled run; missing or invalid runtime paths exit 2
before anything is written. After a successful compare, `patchtrace rank PROJECT` must work on the same project (test
it end to end with the hermetic fake Ghidriff the series tests use - find it in tests/test_nway_series.py and reuse the
fixture; do not write a second fake).
State in the spec and the help page: verified only with a fake backend in the build sandbox; live behaviour with a real
Ghidra is UNVERIFIED by this slice.

## Help pages (new files only; numbers assigned by the orchestrator)
docs/help/77-cli-project.md and docs/help/78-cli-compare.md, each titled as tests/test_help_docs.py requires, plus one
index line each in docs/help/README.md directly after the `inspect` line (76). Write for an analyst: what it does, a
worked example per leaf with real output copied from your test run, exit codes, what it never does.

## Tests (red first; tests/test_project_cli.py and tests/test_compare_cli.py, new)
Drive `patchtrace.cli.main([...])` in process as the existing CLI tests do, with tiny synthetic PE fixtures the repo
already has (find the helpers other CLI tests use: `grep -rn "def .*pe\|make_pe\|tiny_pe" tests/*.py | head`). Cover
every leaf: success (text and --json: assert the envelope contract and fields), each refusal with its exit code, tree
unchanged on refusal and for read-only leaves, lock refusal, no-Qt import, and one subprocess smoke
(`python -m patchtrace project sample ...` then `project info`) to prove the installed entry point works.

## Owned files
src/patchtrace/project_cli.py (new), src/patchtrace/compare_cli.py (new), src/patchtrace/cli_commands/project.py (new),
src/patchtrace/cli_commands/compare.py (new), docs/specs/cli-project-compare.md (new), docs/help/77-cli-project.md (new),
docs/help/78-cli-compare.md (new), docs/help/README.md (two added index lines only), tests/test_project_cli.py (new),
tests/test_compare_cli.py (new), tests/test_cli_registry.py (only if a verb list or count there must grow - say which
line).
NOT yours: src/patchtrace/cli.py, service.py, persistence.py, backend.py, docs/cli-reference.md (a later slice generates
it), docs/specs/cli-umbrella.md (slice CLI-0), tools/frozen_smoke.py (frozen: if the frozen build needs the new modules
listed, put the exact line under "Integrator asks").
If you find a real defect in ProjectService while wrapping it, do not patch service.py: write a failing test marked
xfail(strict=True, raises=...) with the defect described, and report it.
