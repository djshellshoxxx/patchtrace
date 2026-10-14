# Unified diff engine (SPEC-31): delivery plan

Spec: `../specs/unified-engine/` (start at its README). Base observed: `main` = `cb25132` (2026-10-14). Before EVERY slice: re-read AGENTS.md and CLAUDE.md, check GitHub's current default-branch SHA, all open PRs and their checks, and the file-ownership table below; never reuse this snapshot as truth (parallel contributors). Every slice: spec amendment rows of `10-amendments.md` first -> red tests -> code -> focused tests -> `QT_QPA_PLATFORM=offscreen python -m pytest -q` -> `python -m ruff check src tests tools` -> schema drift check -> Linux + Windows CI -> merge promptly -> exact results and open gates in the PR, `docs/qa.md`, `tasks/todo.md`.

## 1. Slices (H3 refined: two prerequisites, S0 split)

| Slice | Scope (deliverable) | Depends on | Model tier (CLAUDE.md) | Effort | Token band | Acceptance gate (beyond the full gate) | Fallback if blocked |
|---|---|---|---|---|---|---|---|
| P1 | Windows spawn lock in `jobs._windows_process` (pipe write ends not inherited by concurrent spawns) | - | mid-tier (process semantics) | 0.5-1 d | 0.1-0.3 M | `test_concurrent_spawns_do_not_leak_pipe_handles` green on Windows CI (red first on Windows) | keep extraction sequential and `max_parallel` 1 (already defaults) |
| P2 | nway raw reader skips `EXTERNAL:`/unparsable keys with a count (A-05) | - | low-cost | 0.5 d | 0.05-0.15 M | `test_nway_raw_external_keys_are_skipped_not_fatal` | none needed (S0 has its own tolerant reader) |
| S0a | contracts, limits, keys, registry, store (pointer rows, sidecar dirs, retention), schemas, doc status lines (A-01, A-01b, A-03, A-04, A-08, A-09, A-10, A-11, A-14) | - | mid-tier | 2-3 d | 0.4-0.8 M | schema round trips, invalid examples (02 s8), `test_unified_rows_survive_enrichment_retention`, `test_old_reader_ignores_unified_kinds` | none (contract freeze is mandatory) |
| S0b | sources (Ghidriff, secondary, manual), addressing, fusion/arbiter, S0 facts (C4n, C5t, C6, C8) and verdicts, pipeline (S0 mode), worker, CLI `run/show/explain/status --no-extract` | S0a | mid-tier | 5-7 d | 1.0-1.8 M | 05/06 tests; G-U4 determinism on synthetic data; `test_unified_run_never_mutates_project_snapshot` | B-00 already is this slice |
| S1 | extraction: ghidra script, runner, ingest, features, MD index (BinDiff port + notices), pe_tables, IR reader, backend `retain_gzf` seam, build data file, `live-unified.yml` | S0a, P1 (for parallel spawns only) | mid-tier; top-tier only after 2 failed attempts on a pyghidra/Ghidra API or Job Object blocker | 6-9 d | 1.2-2.2 M | 03 s10 tests; live extraction on the CI fixture pair, Windows + Linux, `content_digest` equal across OSes, recorded in qa.md | B-01 (analyze-only), B-02 (rizin), B-03 (S0 only) |
| S2 | ladder MVP (P00-P15, propagation, groups), parity harness | S0a (S1 for live data; synthetic IR builder before that) | mid-tier | 8-12 d | 1.5-2.5 M | 04 s9 tests; G-U3 on the CI fixture + zlib pair; G-U5 at 10k/60k synthetic | B-04 (minimal ladder), B-05 (no propagation) |
| S3 | IR channels C0-C3/C5, operand classifier, alignment, COS-ADDR/COS-LAYOUT proofs; S3b optional on-demand decompile mode for review pairs | S1, S2 (synthetic before) | mid-tier; top-tier review only for a soundness question in a proof | 5-8 d | 1.0-1.8 M | G-U1 (X vs X, P0), G-U2 leakage = 0 on unit mutants | B-06 (masked-equal only), B-08 (no S3b) |
| S4 | read model, `ui_unified.py`, `ui.py` seam (<= 12 lines), dock tab hook, tooltips, accessibility, CLI `show` polish | S0b | mid-tier (capable, Qt) | 6-9 d | 1.2-2.0 M | 07 s11 tests; 20x Qt repeat without abort; data() call-count gates | B-10 (dock tab only), B-10b (CLI only) |
| S5 | residual: blocking, P16-P19, LAP | S2 | mid-tier | 4-6 d | 0.8-1.4 M | `test_blocking_never_builds_full_matrix`; G-U5 at 60k; precision of tier C reported | B-07 (skip residual) |
| S6 | Tier R recipes, A/A and mutation scripts, bench, `unified-corpus.yml`, gate report, `features/2` proposal text | S0a (recipes now), S3 (gates) | low-cost for recipes/fixtures/log triage, mid-tier for harness and statistics | 5-10 d + CI time | 0.8-1.6 M | G-U1..G-U8 report SHA in qa.md; U-05 decision | report gates as blocked/insufficient-data, flag stays off |
Totals: 42-66 developer-days, about 8-15 M tokens [inf]. Escalation to the highest tier is allowed only for a demonstrated hard blocker named in the slice row; never for retries of an underpowered approach (CLAUDE.md).

## 2. Dependency graph and parallelisation
```text
wave 0:  P1 || P2 || S0a                       (disjoint files)
wave 1:  S0b || S1 || S2* || S6-recipes        (*S2 on the synthetic IR builder against the frozen program-ir/1)
wave 2:  S3* || S4 || S5                        (*S3 on synthetic IR until S1 lands)
wave 3:  S6 gates -> U-05 (flag default) -> retire Evidence tab (U-04)
critical path: S0a -> S2 -> S3 -> S6 gates   (about 18-28 days; S1 runs beside S2)
```

## 3. Exclusive file ownership (a file has one owner per wave; shared files list their allowed edit size)

| Files | Owner | Notes |
|---|---|---|
| `src/patchtrace/jobs.py` | P1 | spawn lock only; no other change |
| `src/patchtrace/nway/graph.py`, `tests/test_nway_graph.py` | P2 | |
| `src/patchtrace/unified/{__init__,contracts,limits,keys,registry,store}.py`, `docs/schemas/unified/*`, `tests/test_unified_{contracts,keys,store}.py` | S0a | |
| `src/patchtrace/enrichment/storage.py` | S0a | `KINDS` additions + `backup_once` wrapper (<= 20 lines) |
| `tools/generate_schemas.py` | S0a | unified output dir only |
| `src/patchtrace/unified/{addressing,pipeline,worker,cli}.py`, `unified/sources/{ghidriff,secondary,manual}.py`, `unified/fusion/*`, `unified/facts/{pseudo,verdict}.py` | S0b | `facts/channels.py` created by S0b (S0 channels), extended by S3 |
| `src/patchtrace/cli.py` | S0b | `COMMANDS += ('unified',)` + dispatch (<= 6 lines) |
| `src/patchtrace/unified/extract/*`, `unified/ir/*`, `.github/workflows/live-unified.yml`, `third_party/notices/bindiff-v8/*` | S1 | |
| `src/patchtrace/backend.py` | S1 | `retain_gzf` field + move block (<= 25 lines) |
| `tools/build_windows.py`, `tools/build_linux.py`, `tools/frozen_smoke.py` | S1 | data file, required notice, smoke lines |
| `src/patchtrace/unified/ladder/{passes,engine,propagate,groups}.py`, `tools/unified/parity.py`, `tests/unified_ir_builder.py` | S2 | |
| `src/patchtrace/unified/facts/{align,operands}.py`, `facts/channels.py` (IR part) | S3 | |
| `src/patchtrace/unified/read_model.py`, `src/patchtrace/ui_unified.py` | S4 | |
| `src/patchtrace/ui.py` | S4 | seam <= 12 lines (07 s2); inspect open PRs touching `ui.py` first |
| `src/patchtrace/ui_evidence.py` | S4, coordinated with the C6 owner | tab hook <= 10 lines |
| `src/patchtrace/tooltips.py`, `tests/test_tooltips.py` | S4 | `unified.*` ids and roots only |
| `src/patchtrace/unified/ladder/{blocking,residual,assign}.py` | S5 | |
| `tools/unified/{corpus,mutations}/*`, `tools/unified/bench.py`, `.github/workflows/unified-corpus.yml` | S6 | |
| `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` | every slice | append-only blocks, keep-both merge friendly |

## 4. Packaging (Windows standalone alpha must keep building)
- New runtime dependencies: none (stdlib `sqlite3`, `gzip`, `zlib`, `hashlib.blake2b`, `array`, `json`). Optional dependencies: none. The external Python environment already needs pyghidra for Ghidriff; nothing new is installed there.
- PyInstaller: collect `patchtrace/unified/extract/ghidra_script.py` as a DATA file in both build scripts (the external interpreter needs source, not PYZ bytecode); add `third_party/notices/bindiff-v8` to the required notice list; no hidden imports, no hooks. Size impact < 1 MB [inf].
- Frozen worker: `[sys.executable, 'unified', '_worker', ...]` works because `__main__` dispatches every non-Qt first argument to the CLI (`__main__.py`); in development `[sys.executable, '-m', 'patchtrace', 'unified', '_worker', ...]` requires an installed package (`pip install -e .`), tests use `--in-process`.
- Frozen smoke (A-20): `PatchTrace.exe unified --help` exit 0, `unified _worker --self-check` exit 0, script data file present. Windows packaging runs on Windows only (AGENTS.md).

## 5. Feature flags and release behaviour
- GUI: QSettings `unified/enabled` (default False) gates the view switch's Unified side, the Run button and the dock tab; when False the UI is byte-for-byte today's (test `test_flag_off_ui_unchanged`).
- CLI: `patchtrace unified ...` is always available, labelled "experimental, derived, ordinal" in `--help` and in every JSON document (`warnings`).
- Backend: `retain_gzf` is set only by a unified run request, never by default.
- Releases: alpha builds ship with the flag off; release notes state "experimental; no accuracy claim; display is ordinal". The flag defaults on only after G-U1..G-U6 pass (U-05) with report SHAs in `docs/qa.md`. Never claim a GitHub Release succeeded when the token lacks permission (handoff B1); report build-green and publish-failed separately.

## 6. Open gates this plan cannot close by itself
Live extraction on Windows with Ghidra 12.0.4 (S1), BinDiff MD parity (blocked until `tools/bindiff_pin.json` has verified assets), Tier W anchors (local only, USER corpus), Windows GUI/DPI/screen-reader passes of the Unified view (manual, C8-style), the legal review of the BinDiff port (U-01).
