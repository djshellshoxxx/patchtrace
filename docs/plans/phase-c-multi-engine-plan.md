# Phase C — multi-engine integration: detailed plan (2026-10-14)

Baseline (verified in code): Ghidriff is the primary engine. `.BinDiff` SQLite import, rz-diff runner/parser, reconciliation and an
uncalibrated evidence index exist in `src/patchtrace/secondary/` and the CLI (`secondary` commands). Not done: real BinDiff
execution, BinExport producer/validation (protobuf bindings not shipped), live rizin/BinDiff runs, GUI evidence panel,
parallel scheduling, calibration. Rules that never change: no averaging of engine confidences, conflicts are preserved
(`contested`), missing match = unknown (not a negative vote), no target binary is ever executed, nothing is uploaded.

## Work packages (each = one small PR; spec → red tests → code → focused tests → full gate → CI → merge)

### C0 Spec freeze (docs only, integration owner)  — size S
- New `docs/specs/multi-engine-orchestration.md`: `EngineRun` record {engine, version, argv digest, input SHA-256 pair, orientation, status, timings, stderr tail, output SHA-256}; engine registry/capability interface (`probe`, `run`, `parse` → `SecondaryMatchSet`); scheduler semantics (max parallel, per-engine timeout, cancel fan-out, failure isolation); cache key = engine + version + args + input hashes; persisted-schema additions (append-only, backward compatible); GUI contract (read-only view of stored reconciliation).
- Exit: reviewed spec, schema generation plan, no code.

### C1 Engine scheduler (pure module `secondary/scheduler.py`) — size M
- Thread-pool bounded by `max_parallel` (default 1; opt-in 2), shared `cancel` event, per-engine deadline, results collected as `EngineOutcome` (ok / failed / cancelled / unsupported). One engine failing never discards another's result. Uses `jobs.run_process(separate_streams=True)` so Windows Job Object containment is reused.
- Tests: fake executables (slow, crashing, noisy-stderr, huge-output), cancellation mid-run, timeout, parallel ordering determinism.

### C2 rz-diff live acceptance — size M (needs CI work)
- CI step installs a pinned rizin release (Linux + Windows), runs `rz-diff` on the repo fixture pair, asserts parsed matches > 0 and records version + SHA in `docs/qa.md`. Separate "live" workflow like `live-backend.yml`; never counted as mocked evidence.
- Decide via research: supported `rz-diff` flags on the pinned version (`-C -j -t functions` assumption must be re-verified), 0.9.x JSON schema drift.

### C3 BinExport2 support — size L (highest uncertainty)
- Step 1 decision record: vendor generated `binexport2_pb2.py` (Apache-2.0, notice) vs depend on `protobuf` runtime; PyInstaller size/licensing impact; pin google/binexport commit.
- Step 2 enable `validate_binexport` (structural checks already written) with real bindings; golden files produced by the real BinExport plugin.
- Step 3 producer: BinExport files come from Ghidra/IDA plugin (Java, Ghidra 11.0.3 per upstream README) — decide: accept user-supplied `.BinExport` only (recommended first), or drive a headless Ghidra script later (Phase E).

### C4 BinDiff execution — size L
- Runner for the `bindiff` CLI (`bindiff --output_format=bin,log a.BinExport b.BinExport`) in a private cwd, output limits, exit-code mapping, version probe; result goes through the existing `.BinDiff` importer (already validates untrusted SQLite read-only).
- Depends on C3 (inputs) and a licensed BinDiff install on the CI runner (license/distribution review first — BinDiff is Apache-2.0 since 8, but its Java/IDA integration dependencies vary; we only call the CLI).
- Live acceptance gated on availability; otherwise recorded as blocked, never skipped silently.

### C5 Reconciliation hardening — size M
- Fix audit finding: one stored set per engine (supersede on re-import) so `reconcile` cannot crash with duplicates; keep newest non-stale set.
- Alternative-match handling: when engines pair one endpoint to different counterparts, persist all alternatives with source labels; orientation checks on every import.

### C6 Evidence panel (GUI) — size L
- New dock in `ui.py` split into `ui_evidence.py` (keep `ui.py` growth in check): per-match table with columns Ghidriff / BinDiff / rz-diff (native scores shown with units, never combined), verdict badge (agree / contested / single-engine / unknown), alternatives list, provenance + limitations text, tooltips registered in `tooltips.py`, accessibility names.
- Read-only over stored reconciliation; engine runs launched from a Setup tab through the C1 scheduler on a worker with progress/cancel.
- Tests: offscreen Qt tests for each state (no engines, one engine, contested, failed engine, stale).

### C7 N-way Series window + per-hop ranking (SPEC-09) — size L
- Window over stored `series.json` chains; per-hop attention using the existing enrichment ranking for each pair; tolerate unreadable sibling projects (audit finding).

### C8 Native Windows acceptance — size M, partly manual
- Native CI on a real binary pair (3-build series), scheduler under Windows Job Objects, frozen-EXE smoke of the new dock. Manual: clean-profile GUI/DPI pass of the beta ZIP (cannot be automated here; tracked as an open gate).

### C9 Calibration (research track, parallel, no UI claims) — size XL
- Follow SPEC-27: ground-truth corpus of hand-labelled function pairs, family-level train/test split, isotonic/Platt calibration, abstention policy. Until a held-out result meets the pre-declared precision target, the UI shows ordinal labels only.

## Order and ownership
C0 → (C1, C2, C3-decision in parallel) → C5 → C4 → C6 → C7 → C8; C9 starts after C0 and never blocks a release.
File ownership: C1/C4/C5 `secondary/*`; C3 `secondary/binexport.py` + packaging; C6 `ui_evidence.py` + `tooltips.py` (single integration owner for `ui.py`); C2/C8 `.github/workflows/*`.
Model tiering: mid-tier for C1/C4/C5/C6/C7; low-cost for fixtures/docs/log triage; top-tier only for C3 decision if packaging/licensing blocks, and C9 methodology review.

## Gates per PR
Focused tests → `QT_QPA_PLATFORM=offscreen python -m pytest -q` → `ruff check src tests tools` → Linux + Windows CI → native Ghidriff matrix when backend/job code changes → merge → verify release artifact + checksum.

## Difficulty ranking (hardest first)
1. **C9 calibration** — needs a hand-verified ground-truth corpus (real Windows binary pairs, permitted to redistribute?), leakage-safe splits, and honest abstention; cannot be finished by coding alone.
2. **C3 BinExport2** — no magic number, protobuf runtime/packaging/licensing choice, and producing files needs the Ghidra/IDA BinExport plugin (Java, version-pinned); validating hostile input is subtle.
3. **C4 BinDiff execution** — external licensed/installed tool, CLI behaviour must be verified against a live install, output is an untrusted SQLite DB, CI availability uncertain.
4. **C6 evidence panel** — largest UI surface in an already 3,000-line `ui.py`; presenting incomparable scores and conflicts without implying probability is a design problem as much as an engineering one.
5. **C8 Windows acceptance** — real binary pairs, process containment, and a manual clean-profile pass that automation cannot replace.
6. **C1/C5/C2/C7** — well-bounded (reuse existing process runner, importer and N-way core); main risk is rz-diff version drift and CI runner installs.
