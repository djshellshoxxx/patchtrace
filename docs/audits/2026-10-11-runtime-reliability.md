# PatchTrace runtime reliability audit — 2026-10-11

Scope: `main` following the Ghidra dot-prefix correction, pinned Ghidriff CLI source at `4f5d895fcbb1eacd65efd81145922c15bb7e741d`, Windows release workflow, and current tests. This is a source/CI audit, not a claim that all real-world binaries or installations have been exercised.

## Findings and priorities

| Priority | Area | Evidence from code or CI | Consequence and recommended treatment |
| --- | --- | --- | --- |
| P0 addressed by this PR | Ghidra project/GZF location | `backend.run_comparison` previously supplied only `--output-path`; Ghidriff's `__main__` defaults `--project-location` and `--gzfs-path` underneath that path | Ghidra lock-heavy databases and multi-GB caches end up under potentially OneDrive-synced case directories. Use a private per-run OS temp workspace via explicit upstream CLI arguments and delete on exit, retaining raw JSON/logs in case. Regression coverage covers both outcomes. |
| P1 pending | Offline semantics | `backend.run_comparison` omits upstream `--no-symbols`; observed Windows log actually queries Microsoft and other public symbol servers | Disconnected sites can incur retries/delays; confidential analysis may trigger outbound PDB lookups. Add explicit `offline/no_symbols` backend option (and UI/CLI state), local symbol cache control, and isolated no-network test. Do not claim `--no-symbols` alone sandboxes all Ghidra network paths. |
| P1 pending | Dependency compatibility | `_config_errors` checks only file presence; `_probe_backend` checks package metadata/version string, not complete Ghidra/Java/pyghidra startup | "Diagnose" can pass with incompatible Java/Ghidra or a partially broken backend. Add a diagnostic split (present/verified/unsupported); optionally run a tiny bundled synthetic live fixture as user-invoked deep check. Persist version tuple and observed result separately from guesses. |
| P1 pending | Path-length inflation | Ghidriff `__main__` names both the Ghidra project and output files with `<older_filename>-<newer_filename>`. PatchTrace artifacts use 64-hex SHA names | On deep Windows profiles/OneDrive paths, Ghidra projects and result files grow much longer than `--output-path`. Consider per-run short validated alias *copies* (`older.bin` / `newer.bin`) or an upstream-safe naming option, with post-run SHA verification; avoid writable hardlinks to immutable artifacts. Current 240-character output-path preflight is a conservative heuristic, not proof all generated paths fit. |
| P1 pending | Storage use | Ghidriff creates GZFs, project databases and symbol files; case backup copies `runs` and its entire tree | Cases grow rapidly, backups/sync become slow or fail. New scratch isolation removes Ghidra projects/GZF caches from normally completed runs; design a separate opt-in persisted symbol cache and bounded retention policy. Preserve raw comparison JSON and analysis.log by default. |
| P1 pending | Setup UX | `SetupDialog` requires manual Ghidra root plus external Python and indirectly Java; README requires Python, Git, JDK, Ghidra and pip | Build a modular runtime discovery/provisioning wizard and portable offline backend pack, then configure the existing `BackendConfig` automatically. Keep manual paths for advanced users. |
| P2 pending | Troubleshooting precision | `run_comparison` reports generic nonzero exit status, leaving the analyst to inspect `analysis.log`; 2 MiB tail may omit the first fault | Add categorized error hints from sanitized log tail, versions, disk, Java path and parseable diagnosis JSON without modifying Ghidriff internals. Keep original log and return code. |
| P2 pending | Configuration hygiene | GUI stores paths in `QSettings`, catches bad setup only when analysis runs | Validate settings before save; migrate toward a schema-versioned non-secret JSON profile shared by CLI and GUI, not credentials or target paths in public logs. |
| P2 pending | Real-world QA | The official live fixture validates one modified exported bounds-check function; existing synthetic and mock tests cover broad program invariants | Add tests for `.sys` inputs, OneDrive cases, offline network denial, long/Unicode paths, multi-version Ghidriff compatibility and system failures (disk full, interrupted analysis, insufficient RAM). |

## Repair shipped in this audit PR

The project stays the trust boundary: original inputs are immutable SHA-256-addressed copies; output JSON and diagnostic logs remain attached to the same run; completed results are not overwritten. The subprocess gets a unique temporary Ghidra project/GZF workspace outside the case directory, with upstream `--project-location` and `--gzfs-path` flags. No path or DB contract changes are made. On success and ordinary failure, scratch files are removed after the contained process exits; abrupt power loss can leave ordinary OS temporary files for normal system cleanup.

## Regression and release gates

1. Tests must fail on previous code when the fake backend requires independent `--project-location` and `--gzfs-path`.
2. New tests must pass on Linux and Windows: workspace isolated from the case, no dot-prefixed path parts, scratch cleanup on success and exit-code failure, raw JSON/log preservation.
3. `python -m ruff check src tests tools` and the full offscreen Qt test suite must pass.
4. Native Windows Ghidriff fixture must complete, normalize and expose the known bounds-check change.
5. Windows PyInstaller build and frozen desktop smoke check must succeed.
6. A real Windows user case under OneDrive remains pending even if GitHub CI passes.

## Modular setup proposal (separate, nonoverlapping workstream)

Keep the stable pipeline: UI or CLI -> application service -> backend runtime resolver -> supervised Ghidriff adapter -> normalization -> project storage. Do not move interpreter discovery, downloads, version installation or application-specific settings into the domain models or Qt widgets.

Introduce independent, testable packages:

- `runtime_discovery.py`: `discover(env, search_roots) -> list[Candidate]`; enumerate configured paths, well-known per-user locations and trusted installed toolchains without running targets or scripts. No network.
- `runtime_manifest.py`: versioned runtime manifest with exact Python/JDK/Ghidra/Ghidriff/pyghidra versions, archive SHA-256 digests, upstream sources and license notices; platform/architecture constraints.
- `runtime_validation.py`: `validate(candidate, level='metadata'|'smoke') -> RuntimeStatus`. Status must distinguish missing, unsupported, installed and live-verified; never mislabel a metadata probe as a complete test.
- `runtime_provisioning.py`: `plan(manifest, destination, mode='offline'|'download') -> InstallPlan`, `apply(plan, cancel, events) -> InstalledRuntime`; user-initiated only, download pin/verify before unpack, stage privately, atomically promote, never elevate silently, never run downloaded `exe` as part of extraction, rollback failed stages.
- `runtime_settings.py`: `load/save/migrate` for a versioned non-secret JSON config shared by GUI and CLI; user environment overrides explicit, deterministic precedence (CLI > active GUI profile > discovered defaults). Any API credentials remain session-only.
- `backend.py`: consume resolved, immutable `BackendConfig` and bounded process runner; never depend on Qt or installation tooling.

UI goal: on first analysis display `Backend ready` and allow **Compare**, or show a single guided **Use existing installation / Set up automatically / Import offline bundle** choice. A backend can live in `%LOCALAPPDATA%\\PatchTrace\\runtimes\\<version>`; no administrator rights or manual `pip` command needed. Keep a light GUI-only package plus an optional larger, explicitly licensed offline full-runtime ZIP; install from archive/USB with no network. Never assume frozen PyInstaller Python is a pip-manageable environment. Do not auto-update binaries or overwrite analyst projects. Preserve an advanced manual setup and portable CLI mode.

Supply-chain and QA requirements: manifests and downloaded dependencies pinned/checksummed; archive traversal/symlink protections; deterministic version compatibility; optional remote download always disclosed; system prerequisites reported concretely; cancellation and rollback; concurrent install lock; idempotent setup; ZIP path lengths and antivirus/locked-file failures tested. Bundling GPL Ghidriff and JDK/Ghidra imposes license/notice obligations to examine before distribution. No network request when the user selects offline mode.

### Coordination with other contributors

Reserve this audit PR for Ghidra scratch isolation and CI acceptance. Have other feature work avoid edits to `src/patchtrace/backend.py`, `tests/test_jobs.py` and the native acceptance workflow until this PR merges. Follow-on runtime wizard/CLI work should start from updated `main`, own separate feature modules and interfaces, use tests, and merge independently after the Windows/native CI gates pass.
