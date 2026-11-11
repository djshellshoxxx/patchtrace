# Ledger: production-completion session (2026-11-11)

Session `session_01KtKj8mF3j3dSBSESbfu5Zs`. Branches of this session all start with `claude/sleepy-fermi-`.
Baseline: `main` at `882d1ca0` (push run 42605088788 green). This file is this session's own ledger and progress
record; other sessions do not edit it. Nothing recorded here is live or native evidence unless a row says so.

## 1. Baseline measured in this sandbox

| Check | Result | Notes |
|---|---|---|
| Full suite, `python tools/run_test_suite.py --workers 3` (Linux container, Python 3.12.3, PySide6 6.12.0, offscreen) | 1 failed, 20,809 passed, 56 skipped, 8 xfailed in 480 s | The one failure is `tests/test_research_qualification_cli.py::test_paths_outside_allowed_roots_are_refused`. It fails only under pytest-xdist and passes alone (6 passed in 16 s). CI does not use xdist, so CI is not affected. |
| `python -m ruff check src tests tools` | clean | |
| Native tools (Ghidra, Rizin, BinDiff) | not available | The egress proxy returns 403 for other repositories' GitHub release pages. NVD, MSRC, Winbindex, CISA and FIRST hosts are unreachable. Native and live evidence can only come from the repository's GitHub Actions workflows. |

## 2. Lanes owned by other sessions today (not touched here)

Read from GitHub on 2026-11-11 between 00:40 and 00:55 UTC. Re-read before acting.

| Lane | Owner branch / PR | Files |
|---|---|---|
| Unified-engine soundness: #259 follow-up (swap orientation, IR-only one-sided functions, DATA-MAP vote, reversal asymmetry) | `claude/funny-feynman-d2m0b5` | `src/patchtrace/unified/{sources,ladder,fusion,facts}/**`, `unified/registry.py`, `unified/keys.py`, `docs/specs/unified-engine/**` |
| Unified live gates and native proof (#268, #174, #139 to #141) | `claude/live-proof-20261111`, `claude/live-harness-infra-20261111`, ledger on `claude/autonomous-finish-20261104` | `tools/unified/**`, `src/patchtrace/backend.py`, `.github/workflows/unified-live-gates.yml`, `tools/calibration/tier_r/**` |
| Open-PR consolidation ledger, wave 3 | #179 `claude/patchtrace-multi-worker-consolidate-24ct7v` | `docs/plans/ledger-consolidation-20261104.md`, `tools/dev/branch_inventory.py` |
| Release job naming and action pin | `claude/patchtrace-haiku-agent-motpbx` | `.github/workflows/qa-windows.yml` (release job), `tests/test_release_gate.py` |
| SPEC-53 backend diagnose launcher | #280 `claude/spec53-diagnose-launcher` | `backend.py` diagnose path, `tests/test_backend_cli.py` |
| Analyst accessibility (Codex, 2026-11-09) | `codex/analyst-accessibility-20261109` | `src/patchtrace/ui_export_v2.py`, `src/patchtrace/ui_inspection.py`, `docs/help/**` |
| Codespaces bootstrap | #279 `codex/codespaces-cs1-20261109` | `.devcontainer/**` |
| Rules and call-graph bug fixes (#105 RULE-2, RULE-6, RULE-7, CG-3) | `claude/bugfix-rules-cg-rest-20261111` | `src/patchtrace/rules/**`, `src/patchtrace/callgraph/**` |
| Instance B 12-hour check (older unmerged slices) | `claude/instance-b-features` | `callgraph/layout.py`, `callgraph/limits.py`, `intelligence/tools/capa.py`, `intelligence/tools/runner.py`, `search/saved.py` |
| Instance C: unified bench and parity fixes (UE-B-03, UE-B-07) | #283 `claude/instance-c-research` | `tools/unified/bench.py`, `tools/unified/parity.py` |
| R7 research prototypes | #282 `consolidate/research-r7-20261104` | `tools/research/r7/**` |

## 3. Slices this session is building (file claims)

Every slice has its own worktree and local branch `claude/sleepy-fermi-<name>`; slices are pushed grouped into a few
pull requests. A row is released when its state says `released`. Files not listed here are not being edited by this
session. All `src/patchtrace/unified/**`, `backend.py`, `tools/unified/**`, `rules/**`, `callgraph/**` and the files in
section 2 are left to their owners; findings that fall there are listed in section 5.

| Slice | What | Files being edited | State |
|---|---|---|---|
| SEC-A | TB-16: deep JSON fails typed, not with RecursionError (non-unified sites) | `reports.py`, `search/service.py`, `calibration/artifact.py`, `diaphora/provenance.py`, `raw_cleanup.py`, `backend_bundle.py` | built, in review |
| SEC-B | WP-03, SEC-9 residual, PE-4/5: storage-side sanitisers use `hostile_text.is_hostile` | `secondary/bindiff_probe.py`, `secondary/runs.py`, `kbcorrelation/products.py` (`clean_text`), `pe_overview/resources.py`, `codetext/intraline.py`, `hostile_text.py` | building |
| SEC-C | TB-12, TB-10, TB-15, TB-09/WP-09 | `ingestion.py`, `offline_bundle.py`, `jobs.py` | building |
| SEC-D | PE-2/PE-3 (Tier W copy), PE-6, PE-7, PE-8 | `tools/calibration/tier_w/pe_tables.py`, `pe_overview/imports_exports.py`, `pe_overview/exports_table.py`, `pe_overview/_common.py` | building |
| K1 | KBA-06, KBA-08, `kb leads` state text | `kbcorrelation/lineage.py`, `alias_catalog.py`, `products.py` (derive/keys), `leads.py` | building |
| K2 | KBA-07, report/2 export of the KB context | `report2/contracts.py`, `report2/adapters.py` | building |
| K3 | KB dock loader fails for every open project (KBB-01) | `kbcorrelation/panel_qt.py`, `cli_leads.py`, `wiring.py` | building |
| K4 | `kb index sync --help`, `kb products --all`, KEV state in `pilot leads` and `kb search` | `kbcorrelation/cli.py`, `cli_index.py`, `cli_pairs.py`, `service.py` (KEV edge state), `pilot/collect.py`, `pilot/cli.py` | building |
| K5 | L1 advisory-join runner over the candidate manifest (mechanics only, synthetic) | `tools/research_qualification/l1_run.py` (new), `__main__.py` (one subcommand) | building |
| NA-1 | rz-diff: refuse results whose side ownership is ambiguous (Rizin singleton swap); adapter fidelity | `secondary/rzdiff.py`, `secondary/contracts.py`, `secondary/registry.py`, `docs/specs/secondary-engine.md` | building |
| NA-2 | BinDiff importer row cap, typed post-exit failures, `import-bindiff` exit code | `secondary/bindiff.py`, `secondary/bindiff_run.py` | queued |
| NA-3 | Diaphora SQLite guard refuses views, triggers, virtual tables | `diaphora/sqlite_guard.py` | queued |
| CLI-0 | SPEC-44 brought up to main; decisions for the new verbs | `docs/specs/cli-umbrella.md` | building |
| CLI-A | New verbs `project` (create, info, runs, import-json, backup, swap, sample) and `compare` | new `project_cli.py`, `compare_cli.py`, `cli_commands/project.py`, `cli_commands/compare.py`, help pages 77-78 | building |
| CLI-B | New verbs `corrections` (list, export, import, undo) and `review`; contract `corrections-exchange/1` | new `corrections_cli.py`, `review_cli.py`, `cli_commands/corrections.py`, `cli_commands/review.py`, help pages 79-80 | building |
| CLI-C | New verbs `profile`, `doctor`, `runtime` | new `enrichment/profile_cli.py`, `doctor_cli.py`, `runtime_cli.py`, three `cli_commands/` adapters, help pages 81-83 | building |
| TR-A | Tests that cannot fail or skip silently; PyYAML declared for the 39 skipped workflow-contract tests; pytest strict config | `tests/**` named files, `pyproject.toml` (dev extra, pytest options) | queued (first commit done) |
| TR-B | Skip ledger tool, live-status honesty, base-ref triage, schema drift `--check` | `tools/run_test_suite.py`, `tools/check_live_status.py`, `tools/skip_ledger.py` (new), `tools/generate_schemas.py` | queued |
| GUI-A | Changed-row contrast in light themes, untrusted text at display, navigator debounce, worker failure, accessible names | `ui.py` (within the 12-line seam budget), `tooltips.py`, new `ui_names.py` | queued |
| GUI-B | Palette list, header tooltips, keyboard header sort, lane start failures, failed-panel rebuild, copy refusal | `gui/registry.py`, `gui/table_spec.py`, `gui/shortcuts.py`, `gui/qt/{palette,table,commands,tasks,host}.py` | queued |
| GUI-C | State announcements for the evidence and Search panels | `ui_evidence.py`, `search/qt_panel.py` | queued |
| INT-1 | Withdrawn advisory claims, untested CSAF validation listed, CVSS consistency warnings, redirect refusal | `intelligence/explain.py`, `intelligence/cli.py`, `intelligence/csaf/validate.py`, `intelligence/csaf/transport.py` | queued |
| INT-2 | Typed CVSS/time errors, ASCII-only CVE id contract, KEV provenance never downgrades | `enrichment/cve.py`, `enrichment/contracts.py`, `kev/store.py`, `kev/service.py` | queued |

## 4. Events

| Time (UTC) | Item | State | Evidence |
|---|---|---|---|
| 2026-11-11 00:40 | Discovery | done | `main` `882d1ca0`; 49 open PRs; 284 remote branches, of which 120 change nothing when merged into `main`, 27 merge cleanly with changes and 137 conflict (`git merge-tree --write-tree origin/main <branch>`) |
| 2026-11-11 00:52 | Baseline suite and Ruff | done | section 1 |
| 2026-11-11 00:53 | Inventory analysts (17, read-only) | running | results will land under `docs/status/` |
| 2026-11-11 01:04 to 01:20 | Inventory analysts | 9 of 17 returned (I1 security backlog, D patch correlation, E GUI, K testing and CI, B native adapters, F CLI and parity, C CVE intelligence, T1 tracker part 1) | results held for `docs/status/`; the other 8 were cut off by an account usage-credit limit and re-queued on other models |
| 2026-11-11 01:12 to 01:21 | Account usage-credit limit | recovered with a model fallback chain | interrupted workers left partial commits in their worktrees; each slice is resumed from them, nothing was pushed |
| 2026-11-11 01:22 | Slices in flight | see section 3 | no code pushed yet; first push follows the first reviewed slice |

## 5. Findings handed to other lanes (not fixed here)

| Finding | Where | Owner lane |
|---|---|---|
| TB-16 deep-JSON `RecursionError` sites | `unified/extract/runner.py` (277; audit also 252, 468), `unified/ir/reader.py:264`, `unified/pair_text.py`, `unified/pipeline.py:558`, `unified/sources/secondary.py:95`, `unified/sources/diaphora.py:105` | unified soundness lane |
| TB-16, SEC-10, java probe cwd | `backend.py` (341, 609, 675) | live-gate and SPEC-53 lanes |
| PE-2: relocation directory above one read is reported unreadable | `unified/ir/pe_tables.py` | unified soundness lane |
| `rules propose` always exits 2 because the `BACKEND` seam is never assigned (F-D07) | `rules/cli.py:77, 236-238`, `rules/live.py` | rules bug-fix lane |
| `rules show` prints nothing for an empty result (WP-10) | `rules/cli.py` | rules bug-fix lane |
| Copy of the Calls detail cut on a character, not a byte, boundary | `callgraph/panel_qt.py:704` | call-graph lanes |
| rz-diff refusal changes which stored match sets exist for singleton shapes; the unified engine consumes them | `secondary/rzdiff.py` (slice NA-1) | information for the unified soundness lane |
