# Master plan to finish PatchTrace (instance D, owner order 2026-10-15)

Owner order, in sequence: tiny wins and loose ends, then GUI F0-F9 to spec, then the unified engine (research notes in the repo), then a build, then KB (K8/K9, K4b/K7 panels, live acquisition), then label training (remaining LBL slices and the Tier R training run, a pillar), then WB1-WB3, then patch intent, then the anchor fabric, then all Qt panels (specs first), then merge everything and cut a Windows alpha, then CAP/DIE/KEV/YARA-X/quick wins, then audits of every feature and the GUI wiring, QA and stress, fixes, beta build. One feature at a time, cheapest capable model, agents only when needed. Check every 6 hours; stop and ask only for a major issue.

Companion files: `docs/plans/master-todo-d.md` (the categorized to-do list), `docs/plans/ledger-D.md` (state and evidence), `docs/plans/migration-readiness.md` (per-feature readiness table), `docs/plans/chatgpt-panel-specs-prompt.md` (prompt for the per-panel specs).

## 1. Inventory (state at 2026-10-15 ~01:30Z; main 0fb25d8, PR #58 open with the GUI framework)

Legend: DONE = built, merged to main, CI green. BUILT = built but not on main. OPEN = not built. AUDIT = needs bug and code audit.

| Area | DONE (on main) | BUILT, not on main | OPEN | Needs audit |
|---|---|---|---|---|
| Core app (project, ingestion, evidence, series, files, backend) | all alpha features | GUI migration of evidence, series, files docks (PR #58) | Windows desktop acceptance (DPI, NVDA, Narrator), SPEC-26 inspection slices | acquisition and transport audit C-01 (slow-drip), SPEC-07 500 ms cache objective |
| Offline bundle (zero download) | B1-B8 | pin_verify run 38661029764 verified two digests | record the two pins (blocked by classifier, owner decision), first full build both OS, offline acceptance, prerelease, B9 docs | CODEX-13/15 fixes in flight (C) |
| GUI framework | F0, F1, F1b | F2-F9 (PR #58: F2 runtime, F3 widgets, F4 table, F5 host and seam, F6a CodeDiffView, F6b GraphCanvas, F7 themes, F8 evidence, F9 series/files, follow-through TSV/M4/evidence on runner) | Windows 5x/20x gates, manual M19/M21/M22/M23, high-contrast and DPI checks | all of `gui/` and wiring |
| Qt panels (14) | none | unified S4b, Leads (PIL C2), WBQ S6/S9 views, KB K4b/K7 (local branch, needs B's K1-K7) | CAP-6a/b, DIE D5, KEV K3, YRX R6b, WB1 S7, WB2 G5/G6, WB3 S7b, guide (deferred), build_env | each panel |
| Unified engine (UE) | S0a, S0b, S1, S2 | S3, S4a, S5, S6a (PR #57, now main) and panel S4b | S6b gates, live runs on Windows and Linux, CLI polish, research notes for open questions | whole `unified/` |
| KB/CVE correlator + patch search | K0 | K1-K7 (B's branch, not on main), K4b/K7 panels | K8 (KEV/WB1/FAB/UE adapters), K9 (perf, live probes), live MSRC/Winbindex acquisition, KB slice merges | acquisition C-01 before K6/K7 |
| Label training (LBL) | LBL-00, 01/09/11, 06, 10, 14, 17, HARDEN | - | LBL-02..05, 07, 08, 12, 13, 15, 16, 18..25, Tier R training run, honest-scope artifact, extern "C" csrc fix | statistics and leakage (HARDEN done), power formulas |
| WB1 search / WB2 call graph / WB3 strings | - | B's branch slices (WB1 S0-S6/S8, WB2 G0-G5vm/G7pure, WB3 S0-S7a) | WB1 S7-S10, WB2 G8/G9 (needs unified S1), WB3 S7b-S9 | each |
| Patch intent (PIL) | A1, A2, A3, B1, B2, C1, T, K1, K2 | D1 core, D2 workflow, C2 read model + Leads dock (in PR #58) | D1 arm runner/loader/CLI (needs LBL M2/M5 labels), D2 first run, gate G-PIL data (about 30 held-out lineages) | whole `pilot/` |
| Anchor fabric (FAB) | FAB-0, FAB-2 | FAB-1/3/4/5 (PR #57, now main) | FAB builder slices | `fabric/` |
| CAP (capa) / DIE / KEV / YARA-X / WBQ | tools-core, KEV core, YRX R0-R5, WBQ S1/S2/S4/S7/S8/S10 | CAP-4/5/7, DIE D3/D4/D6 (B) | CAP-8..11, DIE D7-D10, KEV K3 panel, YRX R6b/R7/R8, WBQ S3/S5/S13 and UI wiring | each |
| GDE guide | - | local G1-G4 (C) | deferred by owner | n/a |
| Dropped specs | - | - | qbindiff, radiff2, Diaphora, SPEC-QB/RD/DA: see OUTSTANDING-specs-ledger.md (drop/keep decisions) | n/a |

## 2. Execution order (one feature at a time; each step ends with a gate, a ledger line and a push)

Step 0 (now): tiny wins and loose ends (section 3 of the to-do list, category T). Merge PR #58 after CI green. Keep current workers running. Bundle pins remain an open owner decision; the bundle build resumes the moment the pin edit is allowed.

Step 1 GUI to spec (F0-F9): finish PR #58 (CI green on Windows and Linux, `qt_gate` 20x in CI), close every open follow-up (to-do category G), cheap Sonnet or Haiku workers only; exit when `docs/plans/migration-readiness.md` GUI row is `ready` except the manual Windows gates.

Step 2 Unified engine: research notes in `docs/research/ue-*.md` (open questions in `unified-engine/00-decisions.md` and 10-amendments), S6b gates and live runs by CI workflow, CLI polish, UE audit; exit when UE row is `ready`.

Step 3 Build checkpoint: cut a prerelease (lite Windows zip and Linux tar.gz) once GUI + UE are on main.

Step 4 KB: merge B's K1-K7 (B), my K4b/K7 panels, then K8, K9, live acquisition (consented, exact-host, C-01 transport fix first). One slice at a time.

Step 5 Label training: remaining LBL slices in dependency order, then the Tier R training run on GitHub Actions matrices, then the honest-scope artifact. Quality bar: preregistered metrics, held-out lineages, no leakage, power adequate, results reported with intervals; fail loudly, never claim real-world accuracy from synthetic builds.

Step 6 WB1 S7-S10, WB2 G8/G9, WB3 S7b-S9 and their panels, one at a time.

Step 7 Patch intent: D1 completion (needs Step 5 labels), D2 first run, Leads panel polish.

Step 8 FAB builder slices.

Step 9 Qt panels: specs first (to-do category Q: the ChatGPT prompt produces them); build the remaining panels one at a time in the order in `program-e-execution-plan.md` 6.4.

Step 10 Merge sweep and Windows alpha: all branches merged (A, B, C, D), CI green, bundle alpha (zero-download) if the bundle pins and acceptance are done, otherwise lite alpha; publish as prerelease only.

Step 11 Finish CAP, DIE, KEV, YARA-X, quick wins.

Step 12 Audits: per feature in readiness order (audit file in `docs/audits/`, repro per finding, small fixes with a red test), then the GUI audit (host, seam, wiring, a11y, theme, threads, teardown), then cross-feature wiring audit (anchors, panel manifest, CLI registry, frozen-smoke imports, schema drift, licences).

Step 13 QA and stress: full suite Linux+Windows, `qt_gate` 20x, 10k/100k tables, large graph, large corpus runs in Actions, cancel/teardown stress, memory/handle leaks, offline acceptance, fuzz hostile inputs; fix bugs.

Step 14 Beta: version bump, release notes, SHA256SUMS, prerelease only (final release only with the owner's explicit say).

## 3. Cost rules
Haiku for mechanical work, Sonnet for builds, no Opus unless two Sonnet failures (and never at `allowed_warning`), never Fable. Focused tests while developing, CI for full gates, no repeated local full-suite runs (owner, via A). Workers are briefed by pointing at the plan card, reports at most 250 words.

## 4. Schedule
Every 6 hours (routine `Instance D 6h check`): read this plan and the to-do list, verify agents and CI, restart stalled work on the first incomplete step, record state in the ledger. Stop and ask the owner only for a major issue (open now: bundle pin edit permission).
