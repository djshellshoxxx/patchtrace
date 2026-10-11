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

## Acceptance gates
- Windows unit/Qt suite: 93 passed; Ruff passed ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38126515355)). Frozen desktop smoke passed on the final curated package ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38127040440)). That run repeats 93 Windows passes and 91 Linux passes with 2 Windows-only skips.
- Real native Ghidriff known bounds-check DLL patch: passed ([run](https://github.com/djshellshoxxx/patchtrace/actions/runs/38126512208)). Python 3.12.10, Ghidra 12.0.4, Temurin Java 25; pinned Ghidriff revision from research. Both MSVC-built DLLs were statically analyzed, never executed. One modified change record contains the expected check. This single fixture does not establish general matching accuracy.
- Live Ollama and remote provider paths: unverified; no configured model/credentials supplied. Mocked HTTP request/envelope/schema tests are present. Follow SPEC-03 acceptance procedures; successful transport does not validate model truth.
- Clean Windows interactive resize/keyboard/code/evidence test: pending actual package and user testing.
- Matching precision/recall, held-out real patch corpus and resource targets: unmeasured. No accuracy or speed benchmark claimed.
- Dependency archive audit: CI ZIP downloaded and inspected; SHA-256 matched, all listed files existed, 47 Core/GUI attribution pages and required notice texts were present; two Qt Network attribution pages were subsequently added for the linked Network DLL. Curated package: 46,370,158 bytes, 417 ZIP entries; SHA-256 `c5783e25146029a741a5450209638a15cf9f955e6e24582c04277325079e95b2`. Qt Core/Gui/Network/Widgets and Windows/offscreen/style/network/TLS plugins remain. No PDF/WebEngine/QML/Quick/virtual-keyboard executable components. Final release is rebuilt from the merged commit and has its own accompanying checksum.

## Practical limits
Provider cancellation is cooperative around network reads; an active read can wait until the 120-second timeout, and transmitted remote context cannot be recalled. Native decompiler crashes/timeouts preserve logs and quarantined output; process isolation is not an OS sandbox. Backend output contracts are pinned to inspected Ghidriff; unknown output fields fail clearly. Only static PE AMD64 is initially supported. Call graph visualization, runtime debugging, automatic reproduction, auto-download and additional formats are deferred. The synthetic sample is authored and explicitly labeled.
