# Ledger C (Instance C: labels, specs, guide, audits)

| Item | State | Evidence |
|---|---|---|
| Routine (12h) | created 2026-10-14 | trigger "Instance C 12h check" |
| LBL-1 mutation operators (SPEC-32 s8) | launched 2026-10-14 (12 workers running) | |
| LBL-2 evaluator, manifest, annotate, CLI (s10-s12) | launched 2026-10-14 (12 workers running) | |
| LBL-3 catalogue recipes + releases/CVE cards (s3) | launched 2026-10-14 (12 workers running) | |
| LBL-4 shard runner + Actions matrix (s13) | launched 2026-10-14 (12 workers running) | |
| SPEC-A outstanding specs batch 1 | launched 2026-10-14 (12 workers running) | |
| SPEC-B E-6 plan + outstanding-specs ledger | launched 2026-10-14 (12 workers running) | |
| GDE research R1 (expert RE/patch-diff) | launched 2026-10-14 (12 workers running) | |
| GDE research R2 (teaching in-tool) | launched 2026-10-14 (12 workers running) | |
| AUD audits (K, T, S0a, G, acquisition) | launched (K, T, S0a, G+acq) | |

## Update 2026-10-14 (wave 2)
- Done, in PR #45 (docs only): audits K/T/S0a/G+acq, GDE R1/R2/spec, SPEC26D2/WIN/GHR/RPT2, E6 plan, OUTSTANDING ledger.
- LBL plan landed from A (fc4901d). Wave-1 LBL workers (1 mutations ~LBL-06, 2 evaluator/CLI ~LBL-01/09/11, 3 catalogue ~LBL-02-04, 4 shard/workflow ~LBL-14) overlap the plan layout: reconcile after they report, not cancel.
- Launched: GDE builder G1-G4, LBL-00 contract freeze, LBL-10 evalcore stats, LBL-17 shipped scope (all Sonnet; LBL-10 Opus only after two failed attempts).

## Update 2026-10-14 16:10Z (owner priority: offline bundle)
- A message: BUNDLE (zero-download full zip/tar.gz) is essential priority; finish in-flight workers, start no new LBL/spec/GDE/audit slices until A says "bundle done".
- Done locally (branch integ-c1, not pushed): LBL-00, LBL-2 evaluator/CLI, LBL-17, LBL-10, LBL-1 mutations, LBL-4 shard+workflow, GDE G1-G4 integrated; full suite 2 fails (schema examples, fixed) pending re-gate. Held until the bundle is done or capacity frees.
- PR #45 (docs) conflicted with main; merged main in, re-running CI; merge when green.
- LBL-3 resumed. BUNDLE planner launched.
