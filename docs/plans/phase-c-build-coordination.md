# Phase C hard-step build coordination (2026-10-14)

Four Opus-tier builders run in parallel isolated worktrees; the integration owner (main session) merges, resolves doc conflicts, runs the full gate and CI, and escalates **only** hard test failures / hard bugs to Fable. Specs are authoritative; this file only freezes cross-agent seams and file ownership.

| Step | Spec | Owns (create/edit) | Must NOT edit |
|---|---|---|---|
| C3 BinExport2 | `docs/specs/binexport2-support.md` | `secondary/binexport_*.py`, `secondary/binexport.py` (facade), `secondary/cli_binexport.py` (+ ≤8-line hook in `cli.py`), `jobs.py` (memory cap only, additive), `pyproject.toml` (protobuf pin), `tools/build_*.py` + PyInstaller hooks, `tests/test_binexport_*.py`, license notice | bindiff*, registry, ui*, calibration |
| C4 BinDiff exec | `docs/specs/bindiff-execution.md` | `secondary/bindiff_probe.py`, `bindiff_run.py`, `bindiff_inputs.py`, `secondary/cli_bindiff.py` (+ ≤8-line hook in `cli.py`), BinDiff adapter in `secondary/registry.py`, importer hardening in `secondary/bindiff.py`, `runtime_discovery.py` (bindiff path pre-fill), `.github/workflows/live-bindiff.yml`, tests | binexport_*, ui*, calibration, `jobs.py` |
| C6 evidence panel | `docs/specs/multi-engine-evidence-panel.md` | `secondary/evidence_view.py`, `secondary/evidence_panel_service.py` (pure), `ui_evidence.py`, `tooltips.py` (`evidence.*` ids only), ≤15-line seam in `ui.py`, `tests/test_evidence_*.py`, `tests/test_tooltips.py` adjustments the spec lists | secondary adapters, binexport*, bindiff*, calibration |
| C9 calibration | `docs/specs/calibration-corpus-and-model.md` | `src/patchtrace/calibration/*` (features, artifact, predict, ood, policy), `tools/calibration/*`, `pyproject.toml` (optional `calibration-dev` extra only), tests | ui*, secondary/* (read-only consumers) |

## Frozen seams
1. **C3 -> C4**: `AcceptedBinExport(snapshot_path: Path, summary: BinExportSummary)` and `accept_binexport(...)` exactly as in binexport2-support.md §4 (module `secondary/binexport_run.py`). C4 must not import C3 modules in code paths tests exercise: it depends on a local `Protocol` (`snapshot_path`, `summary.file_sha256`, `summary.executable_id`, `summary.id_binding`) defined in `bindiff_inputs.py`, so C4 merges and tests independently; integration swaps in the real type (no signature change).
2. **C4 -> SPEC-28 registry**: adapter implements the existing `EngineAdapter` shape in `secondary/registry.py` (probe/argv/run/parse); outcomes flow through `EngineRun`/`scheduler` unchanged. BinDiff adapter reports `unsupported` until the probe passes.
3. **C6 reads only**: stored `secondary/2` sets + `Reconciliation` rows (with `alternatives`, `alternative_rank`, `disagreement_kind`) + `EngineRun` records. Never combine/average native scores. Calibration display level comes from `calibration.policy.display_level()` if importable, else the constant `'ordinal'` (C9 provides it; C6 must work without C9 present: import guarded).
4. **C9 ships** in `src/` only: features, artifact loader (strict JSON, no pickle, degrades to "no model"), predict, ood, policy. Training/labels/metrics/report stay in `tools/calibration/`.
5. Persisted schemas are additive only; never rewrite `secondary/1`/`secondary/2` rows.

## Shared rules (all builders)
- Read AGENTS.md, your spec, `docs/plans/spec-decisions-20261014.md`, only relevant source ranges. Decisions in that file are made; do not re-open them.
- TDD: failing test first, small commits, typed interfaces, pure modules without Qt except `ui_evidence.py`, untrusted strings rendered as plain text.
- Gates before reporting: `QT_QPA_PLATFORM=offscreen timeout 900 python -m pytest -q` and `python -m ruff check src tests tools` clean; run the full suite twice for Qt-touching work. Never skip/disable a test.
- Commit on your worktree branch (trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Do NOT push, do not touch GitHub. At the end append one short block to `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` (keep-both merge friendly: append only, do not reflow existing lines).
- Report (<=12 lines): worktree path, branch, commits, exact test/ruff results, what is only CI/Windows/live verifiable, unfinished items, and any HARD failure or bug you could not resolve (name it precisely so it can be escalated).

## Merge order and integration
C9 and C6 are independent (merge as ready). C3 before C4 only for the final wiring commit (`bindiff_inputs` -> real `AcceptedBinExport`). Integration branch per batch; full gate; PR; CI green on Linux + Windows + native matrix; squash merge; verify the beta release and its notes.
