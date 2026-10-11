# QA and audit record

## Current evidence
2026-10-11: source inspection of pinned upstream revisions completed. Linux Qt offscreen desktop self-test starts and displays the synthetic project. Integrated Linux QA: 91 tests passed, 2 Windows-only tests skipped; Ruff and Qt offscreen desktop self-test passed. Domain, transport, worker, schema and UI tests are included. Synthetic fixtures and mocked providers verify wiring and validation, not real matching accuracy or model interpretation correctness.

## Repaired audit defects
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
- Qt wheels lacked redistributed license texts: exact upstream notice sources are vendored; the builder refuses missing required notices and excluded WebEngine/PDF collection.

## Acceptance gates
- Windows unit/Qt tests and frozen desktop smoke: pending Windows Actions execution.
- Real native Ghidriff known bounds-check DLL patch: pending dedicated Windows workflow.
- Live Ollama and remote provider paths: unverified; no configured model/credentials supplied. Mocked HTTP request/envelope/schema tests are present. Follow SPEC-03 acceptance procedures; successful transport does not validate model truth.
- Clean Windows interactive resize/keyboard/code/evidence test: pending actual package and user testing.
- Matching precision/recall, held-out real patch corpus and resource targets: unmeasured. No accuracy or speed benchmark claimed.
- Dependency archive/license audit: distribution script collects Python/Qt/Pydantic notices; actual ZIP must be inspected before release status is claimed.

## Practical limits
Provider cancellation is cooperative around network reads; an active read can wait until the 120-second timeout, and transmitted remote context cannot be recalled. Native decompiler crashes/timeouts preserve logs and quarantined output; process isolation is not an OS sandbox. Backend output contracts are pinned to inspected Ghidriff; unknown output fields fail clearly. Only static PE AMD64 is initially supported. Call graph visualization, runtime debugging, automatic reproduction, auto-download and additional formats are deferred. The synthetic sample is authored and explicitly labeled.
