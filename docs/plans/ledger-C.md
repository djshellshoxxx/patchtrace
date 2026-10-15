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

## Update 2026-10-14 20:50Z
- BUNDLE PR #48 merged (fd6cdba). B10 step 1 done: pin_report_only run 38622292405 resolved digests on the runner: python-windows 4acbed6d...a3c3 (11133606 B), ghidriff tarball 4ade6ae0...0f92 (4498098 B). Recording them as TOFU pins was denied by the auto-mode classifier (supply-chain pin); awaiting owner decision (see report to A).
- A: hold lifted; GDE deferred (G1-G4 NOT merged); LBL PR now (LBL-00, evaluator/CLI, LBL-17 scope, LBL-10 stats, mutations, shard runner, 13-project catalogue).

## Update 2026-10-14 22:55Z
- PR #51 merged (d156a17): LBL-00/10/17, Tier R evaluator/CLI, mutations, shard runner + corpus-tier-r.yml (first CI run green), 13-project catalogue, verified-pins tooling (verify_backend_pins.py, pin_verify job). GDE G1-G4 NOT merged (deferred by owner).
- Docs PR next: SPEC-46/47/49/55, C9 preregistration v1 + licence register (SHA placeholder to compute), registry rows.
- Open: B10 (pin_verify run needs python.org signer identity; no TOFU), B9 docs/qa, first full bundle build + acceptance; LBL-HARDEN (A's request), Tier R training run, honest-scope artifact; csrc extern "C" fix; _java_version timeout in backend.py (A's note).

## Update 2026-10-15 (12h check)
- Merged: #65 (A recovered my CODEX-13/15 + owner JDK approval; #60 closed), #66 LBL-15 train/shift/TIER_R_CLAIM (eb09607), #73 Diaphora spec scheduler claim (0c4251d, docs; squash title carried a skip-CI marker by mistake, never again).
- Open: #74 Codex audit-2 follow-ups (CODEX-2/3/4/7/8/10/11/12; Windows QA green, Ubuntu QA failed once on tests/test_gui_host.py debounce timeout, re-run queued). Held locally: mbedtls v3.6.0/v3.6.1 pins + card (worker commit fbabcda, tier_r catalogue-check ok, 71 catalogue tests pass); push as its own PR after #74 merges. v3.6.1->v3.6.2 card skipped on purpose: CVE-2024-49195 is not reachable in the default recipe config (0 changed functions), would need a MBEDTLS_USE_PSA_CRYPTO variant.
- Ownership: D drives the remaining LBL slices (docs/plans/lbl-remaining-plan.md on claude/instance-d-gui) and the locked Tier R run (needs LBL-11 scoring, pre-lock audit, preregistration lock). R1 diagnostic dispatches ran green: 38679899059 and 38679901515 (per-recipe results not extracted).
- LBL-integration-plan.md (clever-clarke-s4nhi6, research) read: its scope matches what landed in #51/#55/#66 plus D's remaining plan; no conflicting contract found at skim depth (evalcore, 25 operators in 3 layers, TIER_R_CLAIM, tier-w-aggregate/1 guard). Full reconcile belongs with D's LBL-11 work.
- Still open for C: C9 preregistration SHA placeholder; _java_version timeout/retry (backend.py); csrc extern "C" (D's worker); CODEX-1/5/6/9/14 (action SHA pinning, pip hashes, corpus cache verify, linux full CLI smoke); GDE deferred.
