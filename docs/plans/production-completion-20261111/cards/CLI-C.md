# Slice card CLI-C - configuration, health and offline-runtime verbs: `patchtrace profile`, `patchtrace doctor`, `patchtrace runtime`

Evidence and designs: `jq '.actionable_now[] | select(.id=="F-T09" or .id=="F-T12" or .id=="F-T13")' docs/status/inventory/F.json`,
`jq '.features[] | select(.id=="F-F12" or .id=="F-F17")' docs/status/inventory/F.json`, parity matrix docs/status/gui-cli-parity-matrix.md rows 17, 18 and section 3 (configuration
management, diagnostics, health checks). Read the binding CLI constraints at the top of docs/plans/production-completion-20261111/cards/CLI-A.md - they apply
here unchanged.

## Spec first: docs/specs/cli-profile-doctor-runtime.md (new) covering the three verbs; amend the status/CLI lines of
docs/specs/enrichment.md (profiles) and docs/specs/offline-backend-installer.md (install from the CLI) with one dated
sentence each that points to the new file.

## `patchtrace profile` - analysis profiles can be used by name today but not managed headless
Wrap enrichment.profiles.ProfileStore list/get/save/delete, load_file, profile_digest and default_profiles_dir
(src/patchtrace/enrichment/profiles.py about lines 89-222; check whether importing that module pulls in Qt - if it does,
the CLI must not import it at module level and you must find the Qt-free part; say what you found).
Leaves: `profile list`, `profile show NAME|FILE`, `profile validate FILE`, `profile save FILE [--name NAME] [--force]`,
`profile delete NAME --confirm`, all with `--profiles-dir DIR` (default: the desktop's directory) so tests never touch
the real one. A profile file is untrusted input: strict validation through the existing model, typed exit 2 on refusal.

## `patchtrace doctor` - one machine-readable health report
Wrap patchtrace.__version__, optional_deps.summary_line (and its structured form), cli_commands.discover() failures,
runtime_discovery.check_bundle (fast; starts no process) and runtime_discovery.discover_local_runtimes
(runtime_discovery.py about lines 75 and 243), Python and platform facts, and whether the per-user state/work
directories are writable. It starts NO process and touches no network (assert both in tests by patching subprocess and
socket to fail if used). Result: a list of checks, each {id, status: ok | warning | problem | not-applicable, detail,
remedy}; text output one line per check; exit 0 when no check is a problem, 4 when at least one is (document the choice
against the contract; warnings never change the exit code). `--json` is the machine-readable diagnostics the directive
asks for. Do not call backend.diagnose and do not edit backend.py or backend_cli.py (another session's lane, PR #280):
doctor reports the facts that need no process and tells the user to run `patchtrace backend diagnose` for the rest.

## `patchtrace runtime` - the offline backend archive
`runtime inspect-zip FILE [--sha256 HEX]` wraps offline_bundle.inspect_offline_bundle (offline_bundle.py about line
279): report what the archive contains and every refusal with its code; read-only. `runtime install-zip FILE --sha256
HEX --confirm [--work-dir DIR]` wraps install_offline_bundle (about line 369): the digest is REQUIRED for install
(integrity only - say that it does not prove who published the archive, as the backend CLI already words it), no
install without --confirm, typed exit codes, and nothing is left behind on refusal (assert the target directory tree).
Another slice is hardening offline_bundle.py in parallel: call its public functions only and do not edit the file.
Use the synthetic bundle builders the existing tests use (tests/test_offline_bundle.py) - never a real runtime.

## Help pages (new files; numbers assigned by the orchestrator)
docs/help/81-cli-profile.md, docs/help/82-cli-doctor.md, docs/help/83-cli-runtime.md, plus one index line each in
docs/help/README.md after the last CLI line. tests/test_help_docs.py also requires the troubleshooting page to name
every bundle and offline-install error code: you add no new code, so that page (owned by another session) stays as is -
if the test demands a change there, stop and report it.

## Tests (red first): tests/test_profile_cli.py, tests/test_doctor_cli.py, tests/test_runtime_cli.py (new)
Every leaf: success in text and --json, each refusal with its exit code, nothing written by read-only leaves (tree
hash), no process and no socket in doctor, no-Qt import for all three modules, one subprocess smoke of
`python -m patchtrace doctor --json`.

## Owned files
src/patchtrace/enrichment/profile_cli.py, src/patchtrace/doctor_cli.py, src/patchtrace/runtime_cli.py,
src/patchtrace/cli_commands/profile.py, doctor.py, runtime.py (all new), docs/specs/cli-profile-doctor-runtime.md (new),
docs/specs/enrichment.md and docs/specs/offline-backend-installer.md (one dated sentence each),
docs/help/81-cli-profile.md, 82-cli-doctor.md, 83-cli-runtime.md (new), docs/help/README.md (three added index lines),
the three new test files.
NOT yours: src/patchtrace/cli.py, backend.py, backend_cli.py, offline_bundle.py, runtime_discovery.py,
enrichment/profiles.py (wrap, do not edit; report gaps), optional_deps.py.
