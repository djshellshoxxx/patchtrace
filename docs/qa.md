# QA and audit record

## Current evidence
2026-10-11: source inspection of pinned upstream revisions completed. Linux Qt offscreen desktop self-test starts and displays the synthetic project. Integrated Linux QA: 91 tests passed, 2 Windows-only tests skipped; Ruff and Qt offscreen desktop self-test passed. Domain, transport, worker, schema and UI tests are included. Synthetic fixtures and mocked providers verify wiring and validation, not real matching accuracy or model interpretation correctness.

## Repaired audit defects
- Ghidra rejected `runs/.quarantine-<uuid>/raw` with `Path element starting with '.' is not permitted`. Active and normalization-failed run directories now use `quarantine-<uuid>`. Preflight validates every resolved output ancestor, with an actionable error for dot-prefixed names and excessively long Windows output paths. The fake backend reproduces this exact rejection; native Ghidriff confirmation on Windows and clean-user reinstall remain release checks.
- Artifact storage could escape project roots: pure models and disk paths now reject traversal, absolute/drive paths and symlinks.
- Same-run evidence could be cited against the wrong function match: exact match/function and explicit neighbor associations are enforced.
- Repeated content-addressed contexts could conflict with global uniqueness: identical context/evidence can be shared; conflicting identities rejected.
- Backend module imports could be shadowed by project-local modules: configured trusted runtime cwd and removal of PYTHONPATH/PYTHONHOME.
- Windows process descendants require containment before running: suspended launch, Job Object assignment, kill-on-close then resume; failure terminates suspended child.
- Identical analysis result and failed runs needed separate transactional persistence rather than treating a directory as completed JSON.
- SQLite connections must remain on their creating thread; background project creation closes its connection before GUI reopens.
- Split/merged code view line offsets must map exact evidence lines rather than equal addresses/line numbers.
- Dynamic imported labels use plain text rather than automatic rich text.
- Large import parsing/normalization moved behind prepare/apply worker seam; atomic project changes on GUI thread.
- Ghidra/Python/pyghidra versions and dependency diagnostics are recorded, with unverified Java compatibility visible.
- Missing persisted instruction arrays are displayed as unavailable, never fabricated assembly.

- Unchanged Windows inputs were incorrectly rejected because path and open-handle ctime semantics differ: compare each source consistently, with native ChangeTime protecting against hidden edits.
- Large repetitive code could spend excessive time in line matching: bounded strategies and a disclosed linear fallback now cap the expensive path.
- Failed normalization after native execution needed quarantine and a persisted failed attempt; late cancellation cannot promote output.
- Export preview and actual bytes needed identical option handling and deterministic rendering.
- Optional Qt image/input plugins pulled unused PDF and virtual-keyboard dependencies into the freeze: custom desktop plugin collection now prevents those imports, with an executable-component rejection gate and post-build ZIP inspection.
- Qt wheels lacked redistributed license texts: exact upstream notice sources are vendored; the builder refuses missing required notices and excluded WebEngine/PDF collection.

- Native Ghidra workspace isolation: new regression tests require Ghidriff to receive an external private `--project-location` and `--gzfs-path`, check cleanup on success/failure, and preserve case-owned JSON/logs. Temporary engine workspaces should not be inside synced project directories; new Windows native compatibility must be rerun after this change.

- Ghidriff symbol-server behavior is now opt-in via an explicit saved GUI setting. The backend passes `--no-symbols` by default and records the choice in run provenance. Tests exercise both modes and reject ambiguous types. A passing no-symbols CLI fixture is not proof of OS-enforced network isolation.

- Local runtime discovery is a separate, read-only stdlib module with bounded direct-child scanning and no process execution. Setup prefills only unique existing candidates and preserves analyst-selected paths. This reduces manual path navigation but does not install or validate the full runtime; automated fixture coverage is distinct from real Windows/OneDrive acceptance.

- Native backend failure classifier maps supported error signatures to fixed actionable guidance (JDK mismatch, missing Ghidriff, Ghidra path, heap/disk/permissions), preserving original exit code and sanitized log. Unknown signatures retain the generic inspect-analysis.log message. Regression tests assert no tokens from raw upstream output are echoed.

- Offline bundle importer: strict versioned manifest/ZIP inventory SHA-256 checks, Windows path/type checks, per-user atomic staging/lock with cancellation/rollback, no network or payload execution in the install path, dedicated child-only Java environment. Synthetic payload fixtures verify importer plumbing, not a functional relocatable Ghidriff distribution. Spec-06 full disconnected Windows bundle acceptance remains pending.

## 2026-10-12 delivery session

- Cached-PDB `FileExistsError` under `--no-symbols` (PR #9): root cause traced in pinned Ghidriff `setup_project()` (skips `setup_symbol_server` then calls `get_pdb(allow_remote=False)`, which consults the persisted SymbolServerService) and Ghidra 12.0.4 `ApplicationUtilities.getDefaultUserSettingsDir` (`application.settingsdir`, then `XDG_CONFIG_HOME` on every OS). Fix: per-run `XDG_CONFIG_HOME` in private scratch. Native Windows CI matrix: plain Ghidriff with a persisted store **reproduces** the failure; PatchTrace analysis **passes** with the persisted store (with and without PDBs at the embedded path) and clean. The user's clfs.sys pair and Ghidra 12.1.4 were not available; the fixture is the compiled bounds-check DLL. A CI fixture regression (MSVC `/DEBUG` implying `/INCREMENTAL` thunks) was fixed with `/INCREMENTAL:NO`.
- Linux x86-64 onedir package: CI smoke on Ubuntu 22.04/24.04 offscreen and Xvfb/xcb (initial failure: missing Qt xcb libraries on runners; full list now installed and documented). Frozen Linux binary runs `rank` end to end locally.
- Offline installer (PR #7) security review: 8 defects fixed with regression tests (non-normalized/system install roots, junctions, PT-CANCEL, cleanup masking, zlib errors, extended device names, POSIX replace race, plan contract). Real relocatable runtime payload and air-gapped Windows acceptance remain open.
- Phase 2 enrichment (SPEC-07, PatchTrace-authored; supplied handoff schema/examples absent): B1 detectors, B2 WIL, B3 CVE normalization/transport/contextual ranking, B4 cache, additive storage, pipeline, CLI, desktop and report wiring. Independent review found 6 defects, all fixed with reproducing tests: cancelled stages cached as empty results (scores later dropped to 0); non-default CLI profiles shown as the default in GUI/export; cache hits not revalidated against live ownership; file-loaded CVE snapshots trusted for feature IDs and stale snapshots unreported; non-object weights traceback; stale rows recording the live revision. Storage tests also caught non-atomic DDL in Python's legacy sqlite3 mode (fixed with explicit `BEGIN IMMEDIATE`). Benchmark found the WIL stage never hit the cache when empty (fixed).
- CVE endpoints probed live once by the B3 implementer (2026-10-12): NVD CVE API 2.0 and MSRC `sug/v2.0` per-CVE; fixtures are trimmed real responses for CVE-2024-38063. No live fetch runs in tests. Model/transport success does not validate CVE relevance.
- Benchmark (`tools/bench_enrichment.py`, synthetic 10,000 pairs / 110,000 lines, 4 vCPU Linux container, Python 3.12.3): cold pipeline 6.6 s and 240 MiB peak RSS in a fresh process (objectives 10 s / 512 MiB met on this machine); derived-cache hit 3.1 s, **objective 500 ms not met** (dominated by input hashing and ownership revalidation, which are required for correctness). UI responsiveness at this scale not measured. Windows timings not measured.

## Acceptance gates
- Windows unit/Qt suite: 93 passed; Ruff passed ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38126515355)). Frozen desktop smoke passed on the final curated package ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38127040440)). That run repeats 93 Windows passes and 91 Linux passes with 2 Windows-only skips.
- Real native Ghidriff known bounds-check DLL patch: passed ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38126512208)). Python 3.12.10, Ghidra 12.0.4, Temurin Java 25; pinned Ghidriff revision from research. Both MSVC-built DLLs were statically analyzed, never executed. One modified change record contains the expected check. This single fixture does not establish general matching accuracy.
- Live Ollama and remote provider paths: unverified; no configured model/credentials supplied. Mocked HTTP request/envelope/schema tests are present. Follow SPEC-03 acceptance procedures; successful transport does not validate model truth.
- Clean Windows interactive resize/keyboard/code/evidence test: pending actual package and user testing.
- Matching precision/recall, held-out real patch corpus and resource targets: unmeasured. No accuracy or speed benchmark claimed.
- Dependency archive audit: CI ZIP downloaded and inspected; SHA-256 matched, all listed files existed, 47 Core/GUI attribution pages and required notice texts were present; two Qt Network attribution pages were subsequently added for the linked Network DLL. Curated package: 46,370,158 bytes, 417 ZIP entries; SHA-256 `c5783e25146029a741a5450209638a15cf9f955e6e24582c04277325079e95b2`. Qt Core/Gui/Network/Widgets and Windows/offscreen/style/network/TLS plugins remain. No PDF/WebEngine/QML/Quick/virtual-keyboard executable components. Final release is rebuilt from the merged commit and has its own accompanying checksum.

## Practical limits
Provider cancellation is cooperative around network reads; an active read can wait until the 120-second timeout, and transmitted remote context cannot be recalled. Native decompiler crashes/timeouts preserve logs and quarantined output; process isolation is not an OS sandbox. Backend output contracts are pinned to inspected Ghidriff; unknown output fields fail clearly. Only static PE AMD64 is initially supported. Call graph visualization, runtime debugging, automatic reproduction, auto-download and additional formats are deferred. The synthetic sample is authored and explicitly labeled.
