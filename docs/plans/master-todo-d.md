# Master to-do list (instance D), by feature

Tags: [BUILD] code to write, [SPEC] a spec is missing or thin, [PLAN] needs a short plan, [BUG] a known defect, [AUDIT] bug and code audit, [QA] stress or acceptance, [OWNER] needs the owner, [EXT] external CI or Windows only. Cost: S tiny, M small, L medium, XL large. Order inside a category is the working order. Source of each item: ledgers A/B/C/D, `docs/audits/*`, `OUTSTANDING-specs-ledger.md`, worker reports.

## T. Tiny wins and loose ends (do first)
- T1 [BUG] S: PR #58 CI: confirm Linux/Windows green on the current head; fix any remaining red (rules engine Windows timeout test is not ours: check it on main).
- T2 [BUILD] S: tooltips.py: reword `action.series` / `series.window` wording done; add lost ids check (`evidence.retry/copy_error/open_engines` removed by design); verify `tests/test_tooltips.py` id floor.
- T3 [BUG] S: `ui.py` run.error on completed interpretation runs (done in F5) - verify in CI.
- T4 [BUG] S: VirtualTable header has no keyboard sort path: add a sort command to each panel (panels spec item).
- T5 [BUG] S: evidence StateView has no announcer wired (F9/GUI2 note): wire `ctx.announce`.
- T6 [PLAN] S: reconcile `UI_TRANSITIONAL_CEILING` (-65) and the `panels` budget in `test_gui_host_seam.py` after PR merges.
- T7 [BUG] S: CI repeat job: add `python tools/qt_gate.py --repeat 20` (Linux) / `--repeat 5` (Windows) job text from `docs/qa.md` [GUI-F5:host] to `.github/workflows` (A owns workflows: send as integrator ask or do in D's PR).
- T8 [BUG] S: F4 timing test (data-calls) flaked once under load: make the ceiling load-tolerant (`>=` style, no fixed sleeps).
- T9 [BUG] S: ghidriff `csrc.find_functions` skips code inside `extern "C" {` (LBL).
- T10 [BUG] S: `_java_version` timeout in `backend.py` (A's note) - bundle owner path.
- T11 [BUG] S: B-0 follow-ups (rapidfuzz/yara-x licences in `licenses/`, `dependency-versions.json`, `copy_metadata`, declare `shiboken6==6.12.0`).
- T12 [PLAN] S: tasks/todo.md duplicate lines (F8 in OUTSTANDING ledger): collapse in one tracker-only commit.
- T13 [BUG] S: stale statuses in `REGISTRY.md` (F2-F10 of OUTSTANDING ledger).
- T14 [OWNER] S: bundle pins: record `python-windows` and ghidriff tarball digests (verified by run 38661029764) - waits for owner permission.

- T15 [BUG] M: TaskRunner/Lane: dropping the last runner reference or a gc run on a worker thread frees Qt wrappers off the GUI thread and can segfault in Shiboken `runDeletionInMainThread` (about half the time in tests that drop the runner). Harden `gui/qt/tasks.py` (own the runner from the host until shutdown, no Qt objects in worker closures, deterministic teardown); add a red test.
- T16 [BUG] S: palette results are capped at 50, so the empty-query list loses entries as panels add commands (raise cap or group by panel).
- T17 [BUG] S: `ColumnSpec.tip_id` is not served by `VirtualTableModel.headerData`; then register `strings.col.*` tips.
- T18 [BUG] S: WB panels: reword `tooltip_data.ENTRIES['search.query']` ("safe" fails the claims sweep); `strings.cli.compute` should accept a store; strings delta carries changed rows only (All strings inventory shows no unchanged strings).
- T19 [PLAN] S: push the local worker branches that wait on B (KB panels 72605cd, WB panels a338d6a..6620230) to a D-owned branch only after B's branch merges; until then they exist only in this container (risk: container reclaim): export them as patches under `docs/plans/pending-patches/` if B's merge is delayed more than 6 hours.

## B. Offline bundle (essential)
- B1 [OWNER] pins permission (T14). B2 [BUILD] M: record pins, merge main, run full build both OS (dispatch `backend-bundle.yml`), fix what the first live run exposes (JPype/pyghidra headless on both OS), offline acceptance green (no network, read-only tree). B3 [BUILD] S: B9 docs (`docs/windows.md`, `docs/linux.md`, qa rows, SPEC-06 amendment). B4 [QA] M: bundle prerelease with sha256, size gates. B5 [BUG] M: CODEX-13/15 (C's PR). B6 [PLAN] S: JDK 21 vs 25 decision recorded (21.0.12.1 pinned).

## G. GUI framework F0-F9 (to spec)
- G1 [QA][EXT] M: Windows CI for PR #58, 20x repeat in CI; manual M19/M21/M22/M23 (DPI, NVDA, Narrator, high contrast) - blocked-external.
- G2 [BUG] M: legacy paths: remaining `ui.py` seam budget; `ui_inspection.py` still holds inspection thread in MainWindow (move to runner).
- G3 [BUILD] M: F7 follow-ups (QtSystemPrefs real OS change simulation, reduced motion on custom animations).
- G4 [BUILD] S: GraphCanvas minimap (optional), tighter 2000/8000 timing test vs plan 13-86 ms.
- G5 [BUG] S: StateView announcer, F2 Windows `time.sleep(0.001)` coarse clock, repaint-under-load bound flake.
- G6 [PLAN] S: default_visible policy for panels; `View` menu order; panel manifest check (`patchtrace panels check`) in CI.
- G7 [AUDIT] M: full audit of `gui/`, host, seam, wiring (Step 12).
- G8 [SPEC] S: update `docs/specs/gui-framework.md` and `ui.md` to reflect built behaviour (status lines, section 8 contracts).

## U. Unified engine
- U1 [PLAN] M: research notes `docs/research/ue-open-questions.md` (open decisions in `00-decisions.md`/`10-amendments.md`): list, research, decide.
- U2 [BUILD] L: S6b gates (A/A, mutation scripts, bench, workflow), live runs Windows+Linux in Actions.
- U3 [BUILD] M: S4 CLI polish; Explain fragment into build_context/ContextDialog (needs `ui.py`/`build_context` change).
- U4 [BUG] M: panel run path only tested with fakes: add a hermetic real-pipeline GUI test with a tiny fixture.
- U5 [BUG] S: `unified/columns` setting not persisted (spec 07).
- U6 [BUILD] S: IR text reader for rows without a Ghidriff match.
- U7 [AUDIT] L: audit `unified/` (the file `20261014-C-unified-s0a.md` covers S0a only).

## K. KB/CVE correlator and patch search
- K1 [BUILD] M: merge B's K1-K7 to main (B), then my K4b/K7 panels commit 72605cd (local branch, push after B).
- K2 [BUILD] L: K8 adapters (KEV, WB1, FAB, unified). K3 [BUILD] L: K9 perf and live probes. K4 [BUG] M: C-01 slow-drip fix in transport before K6/K7 live use. K5 [QA][EXT] L: live MSRC/Winbindex acquisition with consent, exact hosts. K6 [SPEC] S: confirm KB2 source facts against live responses. K7 [AUDIT] L: audit `kbcorrelation/`, `acquisition/`.

## L. Label training (pillar)
- L1 [PLAN] M: LBL remaining-slice dependency map from `LBL-integration-plan.md` section 9: LBL-02..05, 07, 08, 12, 13, 15, 16, 18..25 (state which are hard).
- L2 [BUILD] XL: implement in order; recipes from permissive sources only, planted mutations, A/A controls, CVE-fix cases; evaluation harness; shard runner; honest-scope policy.
- L3 [QA][EXT] XL: Tier R training run in Actions matrices (aggregate metrics only, never images, no Microsoft data); preregistration hash recorded; strong results required: report paired bootstrap CIs, power, A/A false-positive rate, no leakage; if results are weak, stop and ask the owner.
- L4 [BUG] S: csrc extern "C" (T9); `power.py` formulas flagged for review (review them).
- L5 [AUDIT] L: audit calibration + tools/calibration (leakage, label noise, honest scope).
- L6 [OWNER] Tier W local runs (Microsoft-derived data stays on the owner machine).

## W. WB1 search, WB2 call graph, WB3 strings
- W1 [BUILD] M each: WB1 S7 panel, S8-S10; WB2 G5/G6 panels, G8 (needs UE S1), G9; WB3 S7b panel, S8, S9. W2 [SPEC] S: panel specs (Q category) for search/graph/strings. W3 [AUDIT] M each.

## P. Patch intent (PIL)
- P1 [BUILD] M: D1 arm runner, case/advisory loader, CLI (needs L2 labels). P2 [QA][EXT] M: D2 first evaluation run, G-PIL gate needs about 30 held-out lineages. P3 [BUG] M: Leads panel deps on A: worker-safe `collect`, public `_overview`, KEV not-in-snapshot date, split `store.load`. P4 [BUILD] S: Import advisory button, Shift+Enter navigation. P5 [AUDIT] M.

## F. Anchor fabric
- F1 [BUILD] M each: builder slices after FAB-1/3/4/5 (now on main): re-check plan for FAB-6+. F2 [SPEC] S: FAB-integration-plan exists; update status. F3 [AUDIT] M.

## Q. Qt panels (about 14) - SPECS FIRST
- Q1 [SPEC] L: per-panel UI specs (use `docs/plans/chatgpt-panel-specs-prompt.md`); today only 35-93 lines of GUI sections per feature plan exist; WB2/WB3/WBQ are thinnest (35-37 lines).
- Q2 [BUILD] M each, in order: UE S4b (done), PIL C2 Leads (done), KB K4b/K7 (built, unmerged), CAP-6a/b, WB1 S7, KEV K3, DIE D5, WB2 G5/G6, WB3 S7b, YRX R6b, WBQ S6/S9 wiring (built, wiring open), build_env, guide (deferred).
- Q3 [BUG] S: each new panel adds its ids to `tests/test_tooltips.py` and `test_gui_host_seam.py` built set (F9 pattern): make the host test derive the built set from the manifest to stop editing frozen tests.
- Q4 [AUDIT] M each; accessibility sweep of the 54 controls without accessible names (SPEC-45).

## C. CAP, DIE, KEV, YARA-X, quick wins
- C1 [BUILD] M each: CAP-8..11 (live gates), DIE D7-D10, KEV K3 panel and K2/K6 remainder, YRX R6b/R7/R8, WBQ S3 (rich header = DIE D2), S5, S13. C2 [BUG] S: TA-1..TA-12 tool-adapter audit fixes, capa `memory_limit_bytes`, intel-tools pairs, diec live. C3 [AUDIT] per feature.

## S. Specs missing or stale (create or update)
- S1 [SPEC] panel specs (Q1). S2 [SPEC] SPEC-48 anchor fabric registry row. S3 [SPEC] SPEC-26 inspection slices (D2 PE version/Authenticode exists; check). S4 [SPEC] Windows release/signing policy exists (WIN-release-signing-policy.md): owner decisions pending (signing certificate). S5 [SPEC] report/export v2 (RPT2) built? check. S6 [SPEC] E-6 test/performance/beta plan exists: execute. S7 [SPEC] CLI exit-code decisions (SPEC-44 s8, owner decision). S8 [SPEC] settings doc drift (SPEC-43). S9 [SPEC] dropped specs decisions (qbindiff/radiff2/Diaphora) recorded.

## A. Audits and cross-cutting
- A1 [AUDIT] per feature in readiness order (`migration-readiness.md`): checklist in `docs/plans/e4-audit-and-qa-plan.md`. A2 [AUDIT] wiring: anchors, panel manifest, CLI registry, frozen-smoke imports, schema drift, licence notices. A3 [QA] Step 13 stress list. A4 [BUG] random audit findings RA-1..RA-10 closure check. A5 [AUDIT] security: consent/socket-denial tests (SPEC-42), keys never in settings/logs, hostile inputs, path traversal, subprocess argv.

## R. Release
- R1 [BUILD] M: Windows alpha prerelease (after merge sweep). R2 [OWNER] signing, Pages source, logo, Monero address. R3 [BUILD] S: beta notes. No final release without the owner.
- L7 [BUILD] S: add an additive `deltas` field (paired deltas with sd, minimum detectable delta, power, non-inferiority) to `tier-r-report/1` in `tools/calibration/tier_r/contracts.py`; `evaluate_full()` already returns them (LBL-11). Not produced yet: tier-precision and reliability curves; live Ghidriff run; first real BinDiff export-driven run.
- U8 [BUILD] M: provision `tools/bindiff_pin.json` (BinDiff v8 pinned with a verified digest) so G-U3 can leave `blocked`; until then O2 ("G-U1..G-U6 pass") cannot be met. G-U7 needs >= 30 B+B rows per class pair. First dispatch of `unified-live-gates.yml` is still to be done (about 240 Ghidriff runs for G-U2).
- Open from fix pass: SEC-3, Ghidriff half of SEC-1 and SEC-10 (backend.py, bundle-owned), SEC-8 (strict UTF-8 changes a pinned contract), ACQ-12/13, text output keeps newlines (forged row risk), PE-2/PE-3 not copied to unified/ir/pe_tables.py and tier_w, no per-project byte cap for BinExport snapshots.
- B7 [BUILD] M: apply `docs/research/ghidra-headless-large-pe.md` to the bundle builder after the first green full build: stronger Ghidra strip (Function ID databases, Jython, BSim, GhidraServer, Debug: 847 MB to 234 MB, identical output measured on Linux), jlink 26-module Java runtime (78 MB vs 346 MB), JDK stays 21 (25 unsupported for Ghidra 12.0.x), ghidriff must disable remote symbol servers (offline policy), add an external analysis timeout (no in-process one on the PyGhidra path). Heap for ntoskrnl-class PEs and Windows/MSVC determinism are unmeasured.
