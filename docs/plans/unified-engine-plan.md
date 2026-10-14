# Unified diff engine (SPEC-31): delivery plan

Spec: `../specs/unified-engine/` (start at its README). Base observed: `main` = `cb25132` (2026-10-14). Before EVERY slice: re-read AGENTS.md and CLAUDE.md, check GitHub's current default-branch SHA, all open PRs and their checks, and the file-ownership table below; never reuse this snapshot as truth (parallel contributors). Every slice: spec amendment rows of `10-amendments.md` first -> red tests -> code -> focused tests -> `QT_QPA_PLATFORM=offscreen python -m pytest -q` -> `python -m ruff check src tests tools` -> schema drift check -> Linux + Windows CI -> merge promptly -> exact results and open gates in the PR, `docs/qa.md`, `tasks/todo.md`.

## 1. Slices (H3 refined: two prerequisites, S0 split)

| Slice | Scope (deliverable) | Depends on | Model tier (CLAUDE.md) | Effort | Token band | Acceptance gate (beyond the full gate) | Fallback if blocked |
|---|---|---|---|---|---|---|---|
| P1 | DONE (C3 merge): Windows spawn lock `_WINDOWS_SPAWN_LOCK` (jobs.py:14-17) | - | - | 0 | 0 | `test_concurrent_run_process_calls_do_not_cross_pipes_or_leak_threads` | - |
| P2 | DONE (ce108cd): nway raw reader skips `EXTERNAL:<hex>` entries, other unparsable addresses still fail | - | - | 0 | 0 | `test_raw_ghidra_external_locations_are_skipped_not_fatal` | - |
| P2b | count the skipped `EXTERNAL:` entries in the series limitations; SPEC-09 and SPEC-28 status lines (A-05, A-06) | - | low-cost | 0.25 d | 0.03-0.08 M | `test_nway_external_skips_are_counted` | silent skip stays (already safe) |
| S0a | contracts, limits, keys, registry, store (pointer rows, sidecar dirs, retention), schemas, doc status lines (A-01, A-01b, A-03, A-04, A-08, A-09, A-10, A-11, A-14) | - | mid-tier | 2-3 d | 0.4-0.8 M | schema round trips, invalid examples (02 s8), `test_unified_rows_survive_enrichment_retention`, `test_old_reader_ignores_unified_kinds` | none (contract freeze is mandatory) |
| S0b | sources (Ghidriff, secondary, manual), addressing (reusing C3 `detect_address_basis`), fusion/arbiter with evidence classes, S0 facts (C4n, C5t, C6, C8) and verdicts, pipeline (S0 mode), worker (C3 `worker_argv`, L-42 cap), CLI `run/show/explain/status --no-extract` | S0a | mid-tier | 5-7 d | 1.0-1.8 M | 05/06 tests; G-U4 determinism on synthetic data; `test_unified_run_never_mutates_project_snapshot`; `test_same_class_never_corroborates_across_components` | B-00 already is this slice |
| S1 | extraction: ghidra script (`gzf`/`analyze` modes, API calls verified in 03 s4), runner, ingest with operand typing and located address fields, features, MD index (BinDiff port + notices), pe_tables incl. EH signature, IR reader, backend `retain_gzf` seam, build data file, `live-unified.yml` | S0a | mid-tier; top-tier only after 2 failed attempts on a pyghidra/Ghidra API or Job Object blocker | 6-8 d | 1.1-2.0 M | 03 s10 tests; live extraction on the CI fixture pair, Windows + Linux, `content_digest` equal across OSes and between `gzf` and `analyze` modes of the same analysis, recorded in qa.md | B-01 (analyze-only), B-02 (rizin), B-03 (S0 only) |
| S2 | ladder MVP (P00-P15, propagation, groups), parity harness | S0a (S1 for live data; synthetic IR builder before that) | mid-tier | 8-12 d | 1.5-2.5 M | 04 s9 tests; G-U3 on the CI fixture + zlib pair; G-U5 at 10k/60k synthetic | B-04 (minimal ladder), B-05 (no propagation) |
| S3 | IR channels C0-C3/C5, operand classifier with target consistency, DATA-MAP/1, alignment, UNCH/COS-ADDR/COS-LAYOUT proofs with EH-EQ, MAT-ANCHOR; S3b on-demand decompile mode (extractor `decompile`, worker `refacts`) | S1, S2 (synthetic before) | mid-tier; top-tier review only for a soundness question in a proof (the review already found four, R-01..R-04) | 7-11 d | 1.4-2.4 M | G-U1 (X vs X, P0), G-U2 leakage = 0 on unit mutants including the review's new classes (08 s1) | B-06 (positional C2), B-08 (no S3b), B-21 (no region shift), B-22 (no EH-EQ) |
| S4 | read model, `ui_unified.py`, `ui.py` seam (<= 12 lines), dock tab hook, tooltips, accessibility, CLI `show` polish | S0b | mid-tier (capable, Qt) | 6-9 d | 1.2-2.0 M | 07 s11 tests; 20x Qt repeat without abort; data() call-count gates | B-10 (dock tab only), B-10b (CLI only) |
| S5 | residual: blocking, P16-P19, LAP | S2 | mid-tier | 4-6 d | 0.8-1.4 M | `test_blocking_never_builds_full_matrix`; G-U5 at 60k; precision of tier C reported | B-07 (skip residual) |
| S6 | Tier R recipes, A/A and mutation scripts, bench, `unified-corpus.yml`, gate report, `features/2` proposal text | S0a (recipes now), S3 (gates) | low-cost for recipes/fixtures/log triage, mid-tier for harness and statistics | 5-10 d + CI time | 0.8-1.6 M | G-U1..G-U8 report SHA in qa.md; U-05 decision | report gates as blocked/insufficient-data, flag stays off |
Totals: 43-67 developer-days, about 8-15 M tokens [inf] (review: P1/P2 removed, P2b +0.25 d, S3 +2-3 d for DATA-MAP, EH-EQ and S3b, S1 up to -1 d because the Ghidra API surface is now verified). Escalation to the highest tier is allowed only for a demonstrated hard blocker named in the slice row; never for retries of an underpowered approach (CLAUDE.md).

## 2. Dependency graph and parallelisation
```text
wave 0:  P2b || S0a                            (disjoint files; P1/P2 already merged)
wave 1:  S0b || S1 || S2* || S6-recipes        (*S2 on the synthetic IR builder against the frozen program-ir/1)
wave 2:  S3* || S4 || S5                        (*S3 on synthetic IR until S1 lands)
wave 3:  S6 gates -> U-05 (flag default) -> retire Evidence tab (U-04)
critical path: S0a -> S2 -> S3 -> S6 gates   (about 18-28 days; S1 runs beside S2)
```

## 3. Exclusive file ownership (a file has one owner per wave; shared files list their allowed edit size)

| Files | Owner | Notes |
|---|---|---|
| `src/patchtrace/jobs.py` | nobody | no SPEC-31 change (spawn lock already merged) |
| `src/patchtrace/nway/graph.py`, `tests/test_nway_graph.py` | P2b | count only |
| `src/patchtrace/unified/{__init__,contracts,limits,keys,registry,store}.py`, `docs/schemas/unified/*`, `tests/test_unified_{contracts,keys,store}.py` | S0a | |
| `src/patchtrace/enrichment/storage.py` | S0a | `KINDS` additions + `backup_once` wrapper (<= 20 lines) |
| `tools/generate_schemas.py` | S0a | unified output dir only |
| `src/patchtrace/unified/{addressing,pipeline,worker,cli}.py`, `unified/sources/{ghidriff,secondary,manual}.py`, `unified/fusion/*`, `unified/facts/{pseudo,verdict}.py` | S0b | `facts/channels.py` created by S0b (S0 channels), extended by S3 |
| `src/patchtrace/cli_commands/unified.py` | S0b | adapter file (<= 25 lines); a temporary `COMMANDS += ('unified',)` hook may merge first and move later (GUI plan 8.12) |
| `src/patchtrace/unified/extract/*`, `unified/ir/*`, `.github/workflows/live-unified.yml`, `third_party/notices/bindiff-v8/*` | S1 | |
| `src/patchtrace/backend.py` | S1 | `retain_gzf` field + move block (<= 25 lines) |
| `tools/build_windows.py`, `tools/build_linux.py`, `tools/frozen_smoke.py`, `tools/pyinstaller_hooks/hook-patchtrace.unified.extract.py` | S1 | data-file hook, required notice, smoke lines |
| `src/patchtrace/unified/ladder/{passes,engine,propagate,groups}.py`, `tools/unified/parity.py`, `tests/unified_ir_builder.py` | S2 | |
| `src/patchtrace/unified/facts/{align,operands,datamap}.py`, `facts/channels.py` (IR part), extractor `decompile` mode | S3 | |
| `src/patchtrace/unified/read_model.py`, `src/patchtrace/ui_unified.py` | S4 | |
| `src/patchtrace/ui.py` | S4 | seam <= 25 lines (07 s2); inspect open PRs touching `ui.py` first |
| `src/patchtrace/ui_evidence.py` | S4, coordinated with the C6 owner | tab hook <= 10 lines |
| `src/patchtrace/tooltips.py`, `tests/test_tooltips.py` | S4 | `unified.*` ids and roots only |
| `src/patchtrace/unified/ladder/{blocking,residual,assign}.py` | S5 | |
| `tools/unified/{corpus,mutations}/*`, `tools/unified/bench.py`, `.github/workflows/unified-corpus.yml` | S6 | |
| `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` | every slice | append-only blocks, keep-both merge friendly |

## 4. Packaging (Windows standalone alpha must keep building)
- New runtime dependencies: none (stdlib `sqlite3`, `gzip`, `zlib`, `hashlib.blake2b`, `array`, `json`). Optional dependencies: none. The external Python environment already needs pyghidra for Ghidriff; nothing new is installed there.
- PyInstaller: collect `patchtrace/unified/extract/ghidra_script.py` as a DATA file through one hook `tools/pyinstaller_hooks/hook-patchtrace.unified.extract.py` (`collect_data_files(..., include_py_files=True)`; the hooks dir is already passed by both build scripts, 03 s3); add `third_party/notices/bindiff-v8-<sha7>` to `BINEXPORT_NOTICES`-style lists of both builds (09 s3); no hidden imports. Size impact < 1 MB [inf].
- Frozen worker: `[sys.executable, 'unified', '_worker', ...]` works because `__main__` dispatches every non-Qt first argument to the CLI (`__main__.py:13-15`); in development C3's `worker_argv()` gives `[python, '-P', '-m', 'patchtrace', 'unified', '_worker', ...]` with `PYTHONPATH` set to the source tree by `worker_env`, so no `pip install -e .` is needed; tests may still use `--in-process`.
- Repository hygiene: `.gitattributes` lines for `tests/fixtures/unified/` (02 s7.6) land with the first fixture (S0a).
- Frozen smoke (A-20): `PatchTrace.exe unified --help` exit 0, `unified _worker --self-check` exit 0, script data file present. Windows packaging runs on Windows only (AGENTS.md).

## 5. Feature flags and release behaviour
- GUI: QSettings `unified/enabled` (default False) gates the view switch's Unified side, the Run button and the dock tab; when False the UI is byte-for-byte today's (test `test_flag_off_ui_unchanged`).
- CLI: `patchtrace unified ...` is always available, labelled "experimental, derived, ordinal" in `--help` and in every JSON document (`warnings`).
- Backend: `retain_gzf` is set only by a unified run request, never by default.
- Releases: alpha builds ship with the flag off; release notes state "experimental; no accuracy claim; display is ordinal". The flag defaults on only after G-U1..G-U6 pass (U-05) with report SHAs in `docs/qa.md`. Never claim a GitHub Release succeeded when the token lacks permission (handoff B1); report build-green and publish-failed separately.

## 6. Open gates this plan cannot close by itself
Live extraction on Windows with Ghidra 12.0.4 and a real Ghidriff-written GZF (S1; the review verified the API on Linux with clang/nasm PEs only), the FID library marker (03 s4 [unv]), BinDiff MD parity (blocked until `tools/bindiff_pin.json` has verified assets), Tier W anchors (local only, USER corpus), Windows GUI/DPI/screen-reader passes of the Unified view (manual, C8-style), the legal review of the BinDiff port (U-01) and the BinDiff `v8` commit SHA for PROVENANCE (09 s3).
