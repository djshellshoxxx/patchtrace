# LBL remaining plan: finishing label training (Tier R run to a defensible result)

Status: plan, 2026-10-15. Base: `origin/main` 21a005e. Open PRs seen: #64 (unified S6b gate evaluators, draft; touches `tools/unified/`, not `tools/calibration/`), #61 (agent skills, docs), #60 (bundle, draft), #59 (instance B features, draft), #43/#41/#40 (docs). None touches `tools/calibration/` or `src/patchtrace/calibration/`; re-check before every slice (CLAUDE.md).
Sources of record: `docs/specs/program-e/LBL-integration-plan.md` (cited as LBL s<N>), `docs/plans/c9-preregistration-v1.md` (PREREG s<N>, draft, NOT locked, SHA placeholder), `docs/plans/ledger-C.md`, `docs/plans/master-todo-d.md` category L (L1-L6), `docs/audits/20261014-C-label-training.md`, code read at 21a005e. `[inf]` = my inference or estimate, not measured. `[proposal]` = not in the plan or preregistration; needs sign-off before it binds anything.

Why this is the pillar: every other track (unified engine gates G-U1..G-U7, PIL G-PIL, channel value gates, the honest-scope ledger) takes its truth and its intervals from this corpus. A weak or leaky label run poisons them all. The deliverable is not a number for Windows files (LBL s7.8 forbids that); it is a reproducible, leak-free, preregistered Tier R result that either shows the pipeline works (G1) and engines/lead lists differ measurably on test builds, or says plainly that it does not.

## 1. State on main and the slice table

What exists (read in tree): `tools/calibration/` core (cv, threshold, lineage, ece_null, metrics, gates, fit, ood_fit, report, run_locked_test, guards, stats, bootstrap, agree, ablation, sample, synth); `evalcore/{rank,boot,power}.py` (hardened in #55); `tier_r/{cli,__main__,build,factory,fetch,toolchain,csrc,debuginfo,pe,labeler,bodyhash,annotate,manifest,evaluate,shard,contracts,schemas,report_schemas}.py`; `mutations/{operators,engine,labels,coverage,contracts}.py` with the original 16 operators; 13 recipes in `tier_r/catalogue/recipes.d` (brotli cJSON expat jansson libpng libyaml lua lz4 mbedtls miniz pcre2 zlib zstd) and 12 `releases.d`; `.github/workflows/corpus-tier-r.yml` (plan, shard matrix, merge; first run green on smoke only); shipped `src/patchtrace/calibration/{scope,ledger,context,artifact,policy,...}.py`; `tier_w/{catalogue,pairs,guard,msf,pe_tables,run_local,...}.py`.
Not in tree: `train.py`, `shift.py`, `ci_summary.py`, `evalcore/{protocols,identity,change,curves,descriptors,report}.py`, `evalcore/engines/*`, `mutations/{registry,locate,ir,opt_transforms}.py`, `tier_r/msvc.py`, `channels/`, any `EvidencePanel.set_scope`, any `evidence_scope` in `reports.py`, `cli_commands/calibration.py`, `tier_w/{fetch,symbols,labels,audit,runner,pipeline,aggregate,evaluate}.py`.
Caveat: "built" below means code and unit tests exist, not that the live CI path has been exercised. The only live evidence in the repo is the smoke run of `corpus-tier-r` and the zlib card (`docs/qa.md`). Verifying the other 12 recipes on a runner is run R1 (section 3), the first real unknown.

Size S/M/L/XL = my estimate of agent effort [inf]. Tier follows CLAUDE.md (statistics Opus only after a failed Sonnet attempt; mechanical Haiku). Compute: A = agent tokens only, R = Actions shards, O = owner.

| ID | state | deps | size | tier | exclusive files (new or changed) | gate | compute |
|---|---|---|---|---|---|---|---|
| 00 contracts freeze | built | - | - | - | `tier_r/{contracts,schemas}.py` | schema drift test (exists). Residual: confirm 9 new operator ids + `layer` + report fields are in the Literal (LBL s7.1/7.2); if not, one S additive patch before 06/11 | A |
| 01 CLI, factory loaders | built | 00 | - | - | `tier_r/{cli,__main__,factory,build}.py` | `test_cli_exit_codes`; BLOCKED listed not skipped | A |
| 02 tranche 1 | partial (miniz, lz4, cJSON, jansson present; libdeflate missing; brotli, zstd present but not in plan) | 01 | S | haiku | `recipes.d/libdeflate.json`, `releases.d/libdeflate.json`, tranche test | 3 consecutive pairs build, 0 `disagree` on declared functions, A/A byte-identical, qa.md row | R (R1) |
| 03 tranche 2 | partial (lua, libyaml, expat; stb missing) | 01 | S-M | sonnet (stb has no tags: commit pairs, TU wrapper) | `recipes.d/stb.json`, test | same | R |
| 04 tranche 3 | partial (pcre2, libpng, mbedtls; c-ares missing; libpng needs zlib dependency check) | 01 | S-M | sonnet | `recipes.d/c-ares.json`, test | same; Mbed TLS to reserve if it fails | R |
| 05 card audit | open | 02-04 | M | haiku | `corpus/catalog/*.json`, `tools/corpus_check.py --cve-list` | 0 cards with unexplained `disagree`; Windows-scoped CVEs annotated; 33 CVE ids re-checked against CVE List V5 | A (+R for `run_card`) |
| 06 mutations, source | partial (16 of 25 operators; no `registry/locate/cases/cli` split) | 00 | L | sonnet | `mutations/{registry,locate,ops_source,ops_cosmetic,cases,cli}.py`, goldens | every operator applies, compiles, deterministic, records site and rejections; masked-body acceptance; fallback: ship the 16 | A, R for compile smoke |
| 07 mutations, IR and opt | open | 06 | M | sonnet | `mutations/{ir,opt_transforms}.py` | per-layer tests; `opt` BLOCKED when absent. Independent second truth source: matters for label noise, see 4.5 | A, R |
| 08 A/A nuisance + MSVC | open (toolchain.py has msvc-free/mingw only) | 01 | M | sonnet | `tier_r/msvc.py`, `toolchain.py`, `build.py` hook, `factory.py` | Windows-only tests record `blocked` elsewhere; windows-2022 run records `cl` version | R (Windows) |
| 09 manifest, annotate | built | 00 | - | - | `tier_r/{manifest,annotate}.py` | round trip; `guards.audit_manifest` (added in #55) | A |
| 10 evalcore stats | built (hardened; B1/B2 power fixes) | 00 | - | - | `evalcore/{rank,boot,power}.py` | hand goldens, hypothesis tests exist | A |
| 11 evalcore scoring, adapters | partial (`tier_r/evaluate.py` 488 lines scores rz-diff, BinDiff import, Ghidriff JSON; no per-label tables, rank block, curves, descriptors, attention, report block, lineage bootstrap wiring) | 09, 10 | L | sonnet | `evalcore/{protocols,identity,change,curves,descriptors,report}.py`, `evalcore/engines/{rzdiff,ghidriff,bindiff,attention}.py`, `tier_r/evaluate.py` | synthetic engine outputs give exact metrics; byte-identical report twice; `test_report_never_pools_engines`; real rz-diff run on template suite | A, R |
| 12 unified adapter | open | 11; UE S0b/S2 (PR #64 is gate evaluators only) | S-M | sonnet | `evalcore/engines/unified.py`, `tests/fixtures/known_answer/unified/` | synthetic `unified-result/1` mapped per LBL s7.1; live run waits for UE | A |
| 13 channel packs | open | 06, 11, T track | M | sonnet | `channels/{strings,capabilities,environment,rules,leadlist}.py` | per-pack goldens; `rules` BLOCKED until YRX | A |
| 14 CI workflow + summary | partial (workflow exists; no `ci_summary.py`, no nightly full matrix, no Windows leg, no determinism job) | 01, 11 | M | sonnet | `.github/workflows/corpus-tier-r.yml`, `tools/calibration/ci_summary.py` | green Linux smoke < 10 min; never-silent status JSON; artifacts are labels/reports only | R |
| 15 train + shift + report | open (components exist, driver does not) | 09, 11 | M | sonnet | `tools/calibration/{train,shift}.py`, `report.py` (`TIER_R_CLAIM`) | end-to-end on template suite < 60 s; G1 evaluated; G0/G2/G3 `insufficient-data` | A |
| 16 preregistration lock | partial (draft exists; Q1/Q2 open; SHA not recorded; P-1/P-2 verify not built) | 15 | S | opus once (methodology), sonnet for P-1/P-2 | `docs/plans/c9-preregistration-v1.md`, `tools/calibration/prereg.py` [proposal] | owner sign-off O3 in `docs/qa.md`; SHA row `C9-PREREG-v1` | O |
| 17 shipped scope | built | 00 | - | - | `calibration/{scope,ledger,context}.py` | tests exist | A |
| 18 GUI scope line | open | 17; GUI F6-F8 now on main (#58) | M | sonnet | `ui_evidence.py` seam, `secondary/evidence_view.py`, `tooltips.py`, `tests/test_ui_calibration_scope.py` | offscreen tests of LBL s8.6, 20x repeat | A |
| 19 reports + `calibration status` | open | 17 | S | haiku | `reports.py`, `calibration/status.py`, `cli_commands/calibration.py` | report goldens; exit 4 then 0 | A |
| 20 Tier W fetch + transport | open | - | M | sonnet | `tier_w/fetch.py` etc. | self-made fixtures; live paths record blocked | A, O |
| 21 symbols (Ghidra exporter, `symbol-map/1`, llvm-pdbutil) | open | 20 | M | sonnet | `tier_w/symbols*.py` | fixture tests; live Ghidra test passed/failed/blocked | A, O |
| 22 labels, tags, audit | open | 21 | M | sonnet | `tier_w/{labels,audit}.py` | fixtures | A |
| 23 runner | open (`run_local.py` exists as a precursor) | 20-22 | M | sonnet | `tier_w/runner.py` | fixtures | A |
| 24 evaluate + aggregate | open | 11 | M | sonnet | `tier_w/{evaluate,aggregate}.py`, guard contract list | aggregate guard (cells n < 30 suppressed) | A |
| 25 `tier_w all` | open | 20-24 | M | sonnet | `tier_w/{pipeline,__main__}.py`, runbook | dry run on self-made fixtures; owner run separate | A, O |

Additions not in LBL s9 [proposal]: **LBL-26** audit of the finished pipeline before the lock (master-todo L5: leakage, label noise, honest scope; the 2026-10-14 audit covered the harness, not the corpus or the runner output), tier sonnet, M, read-only plus fixes; **LBL-27** the training run itself (master-todo L3), a QA task, not a code slice; **L4** `csrc` `extern "C"` fix (T9), S, haiku, file `tier_r/csrc.py`. The `power.py` review in L4 is done by the #55 audit (B1/B2); re-check only the unchanged parts.
Counts: 5 built (00, 01, 09, 10, 17), 7 partial (02, 03, 04, 06, 11, 14, 16), 14 open. Hard ones: 11 (statistics-adjacent scoring), 06 (location of C sites without false rejections), 08 (Windows compiler on a runner), 12 (depends on another track), 15/16 (methodology).

## 2. Critical path and one-at-a-time build order

Critical path: **R1 (does what we have build on a runner?) -> 11 -> 15 -> 26 -> 16 (lock) -> run R6**. Recipes (02-04) and operators (06) widen the corpus and can finish while 11 and 15 are built, but they must be done before the lock because the shift declaration and the stratified sample list are committed with it (PREREG 8.1). One worker at a time on `tools/calibration/` (files overlap: `evaluate.py`, `cli.py`, `factory.py`), per CLAUDE.md small mergeable slices:

1. **R1 diagnostic run (no code)**: dispatch `corpus-tier-r` subset `cards`, engines `rz-diff`, 4 shards. Output decides whether 02-04 are "built". Also dispatch `noise` to see A/A byte-identity on all 13 recipes. Stop and fix the first failing recipe before anything else.
2. L4 `csrc` fix (S, haiku).
3. 02 libdeflate, then 03 stb, then 04 c-ares (each S, one PR each; the build is the check).
4. **11** in three PRs: (a) protocols/identity/change/descriptors with synthetic goldens and the `synergy-1` fixture (LBL s5 numbers are the acceptance test); (b) rank + lineage bootstrap + paired deltas wired into `tier-r-report/1`, curves, coverage; (c) engine adapters rz-diff/ghidriff/bindiff/attention.
5. **15** `train.py`, `shift.py`, report claim, end to end on the template suite.
6. 06 remaining 9 operators (L; split in two PRs: comparison/index/branch family, then string/api/field/global/buf).
7. 07 IR + opt layers (independent second truth source).
8. 14 `ci_summary.py`, nightly, determinism job (run twice, compare `report_sha256`).
9. 05 card audit (haiku).
10. 08 MSVC leg (advisory, windows-2022). If it slips, PREREG Q2 default applies (gcc-vs-clang shift split).
11. 12 unified adapter when UE S0b/S2 land; otherwise the run reports `unified` as `blocked`, not absent.
12. **26 audit**, then **16 lock** (owner O3 sign-off), then **R5-R7** (section 3).
13. After the run: 13 channel packs, 18, 19, then 20-25 (Tier W) in order; none of these blocks the Tier R result.

Do not start 18/19 early: they ship UI text about a result that does not exist yet, and the status line stays "Order only" regardless (LBL s8.6).

## 3. Compute: Actions shards versus agent tokens

Limits (GitHub docs, retrieved 2026-10-15 via search; LBL s2 read the same files): job 6 h, run 35 d, matrix 256 jobs, free-plan concurrency 20 [docs.github.com/en/actions/reference/limits; .../usage-limits-billing-and-administration]. Whether this repository is public (16 GB RAM / 14 GB disk runners, free minutes) was not verified here; if private, minutes are billed, Windows more than Linux, and the owner must approve budget (open question Q7).
All runner-hour figures are `[inf]` estimates from the zlib pair evidence and typical tool costs; R1 and the first Ghidra shard replace them with measurements. Record measured values in `docs/qa.md` after each run.

| run | what | runs/jobs [inf] | runner-hours [inf] | when |
|---|---|---|---|---|
| R0 | smoke (template suite + zlib card), rz-diff | done | < 0.2 | exists |
| R1 | all 13 recipes x cards/release pairs (about 40 pairs), 2 toolchain profiles, rz-diff, plus A/A and noise | 4-8 shards | 6-10 | before LBL-11 |
| R2 | mutation farm: 25 operators x 13 recipe lineages x up to 20 mutants (LBL s7.7 cap), build + rz-diff | about 6,500 mutants, 32-64 shards | 40-60 (compile dominated) | after 06/07 |
| R3 | Ghidriff leg: release/CVE/control pairs (about 100) + deterministic 5 mutants per operator and lineage (LBL Q8): about 1,600 | 32-64 shards, each below the 6 h cap, one Ghidra JVM at a time | 90-160 (Ghidriff 2-5 min per pair) | after R2; dispatch only |
| R4 | MSVC `cl` leg on windows-2022 (one recipe set, A/A + noise + cards, no mutants first) | 4-8 shards | 8-15 Windows | advisory, after 08 |
| R5 | dev training run (`train run`, `shift`): stdlib/scikit-learn, grouped nested CV | 1 job | 1-2 | after 15 and R2-R3 |
| R6 | **locked-test look**: exactly once per preregistration SHA | 1 job | < 1 | after lock; single use (PREREG 8.3, 8.7) |
| R7 | determinism re-run from the manifest; report SHA must equal R5/R6 | 1 job | 1-2 | after R6 |
| nightly | smoke + noise on `ubuntu-24.04` (pin label, not `latest`: moves to 26.04 in Nov 2026, LBL s2) | 1-2 | 0.3/day | after 14 |
Total full cycle about 150-250 runner-hours, wall clock about 8-14 h at 20 concurrent jobs [inf]. Cache by recipe digest and image SHA so a re-run after a code fix does not rebuild.
Agent tokens (no runner): 00-01-09-10-17 done; 11, 15, 06, 07, 13, 18-19, 20-25 are code and tests written against synthetic fixtures; 05 and 26 are audits; 16 is one Opus pass. Agents never run the heavy matrices in their loop (worker-brief: no full suite, no background jobs); they dispatch the workflow and read `ci_summary`. Owner only: Tier W (Microsoft data never committed, never in CI, LBL s8.3).

## 4. Quality bar for the Tier R training run

Principle: every threshold below is copied from PREREG s5/s6 (frozen values) or LBL s6/s7 unless marked `[proposal]`. Nothing is tuned after the lock. Tier R can reach G1 only; G0, G2, G3 are `insufficient-data` by construction (needs Tier W families, audit, second annotator), and artifact display stays `none` (PREREG 6.5, 7; LBL 7.3).

### 4.1 What "strong" means numerically
Strong = all of (a)-(f) hold on the natural Tier R stratum, out-of-fold over all lineages, evaluated once, symbols hidden, with lineage-bootstrap 95% intervals (B = 2000):
- (a) auto-accept precision at the frozen tau, point >= 0.95, CI lower >= 0.90, CI width <= 0.10 (PREREG 6.3 H2, L1 column); LTT certified at delta 0.05 (PREREG s5). Report the L2 column (lower >= 0.93, width <= 0.06) too; G1 is computed with L2 (PREREG 6.5), so a G1 pass requires it.
- (b) coverage point >= 0.40, CI lower >= 0.30 (L1); >= 0.50 / 0.40 for L2 (H3).
- (c) Brier skill vs prevalence CI lower > 0; ECE excess over null <= 0.03, CI upper <= 0.05 (H1, L2); calibration slope CI contains 1, intercept CI contains 0.
- (d) FDR reduction at equal coverage versus the best of M0, M0b, M1, M2: paired-bootstrap CI lower > 0 (L1), and relative reduction >= 0.25 (L2) (H4).
- (e) every stratum/subtype/lineage family with weighted n >= 200: precision CI lower >= 0.85 (L1) / 0.88 (L2) (H5). Strata under 200 are `insufficient`, listed, and abstain (PREREG Q5).
- (f) shift: precision at the frozen tau on the declared shift lineages >= 0.90 (L2) -- reported, a miss is a documented blind spot, not a retry trigger (PREREG 2.3, 6.3).
Engine/lead-list claims (separate from the model): the lead-list variant "attention + channel" beats the best single source on hit@10 with paired lower bound > 0 (non-inferiority margin -0.02 for a detector to join the default profile, LBL s7.6), on `real-fix` and `planted` populations reported separately, never pooled (LBL s7.1).
Honest ceiling: even a perfect result licenses only the LBL s7.8 left column ("on test builds of open-source C ... built by clang/lld, mingw, and, if it ran, MSVC"). It never licenses a percent for Windows files.

### 4.2 Preregistered inputs (frozen at the lock commit)
Metrics, models M0, M0b, M1, M2, M3 (+M4 ablations; M5 excluded), CV (k_outer 5, k_inner 5, C grid {0.01, 0.1, 1, 10}, seed 1), calibrator rule, ECE (15 bins, 1,000 null sims), tau grid, LTT (delta 0.05, effective n), OOD rule, seeds (bootstrap 21, ECE null 31, ablation 41), salt `c9-v1` (PREREG s5). The lock needs: manifest verifies, shift declaration in the manifest, guideline `g1` final, sample list hashed, owner sign-off O3, no locked-test or shift label analysed (PREREG 8.1). The SHA is recorded in `docs/qa.md` row `C9-PREREG-v1` and in every report (`prereg_sha256`). Add before the lock: P-1 (recompute SHA) and P-2 (a repo test that the constants in `cv.py/threshold.py/gates.py/ece_null.py/metrics.py` equal the prereg table) -- both are open gaps in PREREG 8.5.

### 4.3 Held-out lineages and no leakage
- Unit of resampling and splitting = lineage (project/recipe), never a mutant or function. Roles by `u = sha256(lineage|c9-v1)[:8]/2^32`: dev < 0.60, locked < 0.85, shift else (PREREG 2.1). Mutants, A/A and noise pairs inherit the base lineage and both images (audit A3).
- Executable checks, all must be zero violations: `guards.audit_manifest` (no lineage, source project, PDB name, image hash on both sides of a split; time-inverted pairs; empty roles); `evidence_pairs` excludes A/A, noise, planted pairs from accuracy evidence; union over >= 15% masked-body overlap (steps 15/30/50%), hub identities (`hub_max_lineages = 3`, must be passed explicitly: code default is None, PREREG Q3) reported as `seen-body`; symbols hidden and no sibling `.pdb/.dbg` (`PT-KA-LEAK`); orientation checked (`PT-KA-ORIENT`); no standardisation, C, calibrator or OOD statistic fitted outside training folds.
- Cross-project vendoring (zstd/brotli/zlib/libpng, Lua/Mbed TLS bundles): add a corpus-level scan of shared function bodies across recipes before the lock; merge lineages on a hit, never split to rebalance (PREREG 2.4). [proposal for the scan; the merge rule is in the prereg]
- Rule authors, operator mapping and thresholds are fixed before anyone looks at locked or shift labels. A look at a locked label before the lock voids that role (new lineage set, v2).

### 4.4 Statistics: intervals, power, A/A
- Intervals: lineage cluster bootstrap, B 2,000 (500 in smoke), percentile, paired deltas on identical draws (`boot.py`, `rank.py`). Effective n is lineages (about 37 [LBL s6]), not mutants; below 30 lineages intervals are labelled `anti_conservative` and the headline cannot pass (PREREG s5; `MIN_GROUPS_HEADLINE`).
- Power (derived, not a claim): the normal-approximation paired design detects a mean per-lineage difference of about (1.96 + 0.84) * sd / sqrt(n) = 0.45 sd at n = 38, two-sided alpha 0.05, power 0.8 (`min_detectable_delta` / `lineages_needed_t`, Guenther correction, `evalcore/power.py`). Report, for each headline comparison, the observed sd of per-lineage deltas, the minimum detectable delta and the achieved power; "no difference" is never reported without it.
- Locked role arithmetic (PREREG Q1): 25% of about 38 is 9-10 lineages, below the 12 required for a locked-profile (`gates`). So a locked-form G1 is `insufficient-data` unless the corpus reaches about 48+ lineages (12 / 0.25). Default: G1 from out-of-fold predictions over all Tier R lineages, labelled synthetic. This is the main honesty limit on Tier R; more recipes (reserve seven, LBL s2) are the only fix [inf], and each adds 1 lineage.
- A/A false-positive rate: on `aa-rebuild` (byte-identical X-vs-X), `icf` toggle, timestamp/GUID/path nuisance builds, report per engine and per flag the false-lead rate. Gates: byte-identical X-vs-X must give 0 flagged material changes; a detector joins a default profile only with A/A false-lead rate <= 0.1% (LBL s7.6, itself a plan value not a measured one). Report the count with a one-sided Clopper-Pearson upper bound so "0 of n" is not read as "0" [proposal for the bound; method standard].
- Multiple comparisons: intersection-union gates and fixed-sequence LTT (audit B4, spec 19.9); ablation/channel tables are descriptive and say so. Do not add arms after the lock.

### 4.5 Label noise bounds
- Two-source rule: source diff AND masked body fact must agree; `check=disagree` is counted; declared functions must have 0 unexplained disagree (LBL s6; 02-04 gate).
- `ambiguous` and `indeterminate` rows are excluded from fitting, counted, and bounded as worst case (y = 0). Limit: indeterminate <= 0.05 per stratum, else the stratum is flagged and the headline carries the worst-case bound (PREREG s3, 6.1). Known issue: zlib v1.3 -> v1.3.1 shows 9 of 128 functions ambiguous = 7%, already above 5% [LBL s2 row 29]. Expect the release stratum to be flagged on the first run; this is a feature of the bound, not a bug to patch away. Report both the point result and the worst-case-bound result.
- Mutation truth: accepted only if the masked body of the target differs; rejected mutants stored (`Rejection`) and reported per operator; each operator reported separately with >= 20 mutants per class (G-U2) and `mutations/coverage.py` weakness-class accounting. Cosmetic operators must not change masked bodies (checked by the same rule). IR layer (07) is the independent cross-check of the C locator; report agreement rate between layers per operator as a direct estimate of source-layer label noise.
- Manual noise estimate [proposal]: a blind sample of 100 accepted labels (stratified: 50 mutants, 50 release/CVE pairs, drawn before the lock) reviewed by the owner with the existing terminal tool and hash-chained `AnnotationLog`; report the error rate with a Clopper-Pearson interval. Tier W's symbol-audit error <= 0.02 (PREREG 6.1) is a different instrument and stays owner-only.
- Selection bias: report attempted/completed/blocked/failed per engine and stratum; metrics over completed only; warning if completion < 90% (LBL s6). A Ghidra timeout (1,800 s) is a row in the report, not a silent drop.
- Planted versus real fixes: mutants are easier than real CVE fixes. `real-fix` (about 20 cards, 13 lineages [LBL s6]) and `planted` are reported separately; the `real-fix` population is too small for a gate by itself and is labelled descriptive.

### 4.6 Ablations (required, PREREG 6.3)
M4: leave-one-family-out for each non-G family; drop `D_ghidra`; drop `D_symbols` (incl. `P.symbols`). Shift ladder: grouped CV inside one toolchain, leave-one-toolchain-out (gcc/clang -> msvc, or gcc vs clang when MSVC did not run), leave-one-family-out; each rung with precision at frozen tau, coverage, ECE excess, OOD flag rate and lineage intervals; plus "forced" accuracy with OOD abstention off (LBL 7.3). Lead list: drop each detector one at a time (`STR`, `CAP`, `RULE`; `ENV` carries no weight). A family that does not improve H4 is removed from the profile, per the prereg.

### 4.7 Stop-and-ask thresholds (exact)
Stop the run, post the report as it is, and ask the owner (do not retune, retry under the same SHA, or relax a gate; PREREG 2.3, 8.7; master-todo L3) if ANY of:
1. G1 evaluates `fail` or any frozen gate in 4.1 (a)-(e) misses its L1 value on the dev out-of-fold result, or the locked look misses it. `insufficient-data` is reported as such and is also a stop-and-ask, never a pass.
2. Fewer than 30 lineages in the evaluated population (anti-conservative), or fewer than 12 in a locked role.
3. Any `audit_manifest` violation, any orientation or symbol-leak error, or a non-identical `report_sha256` on the determinism re-run (R7).
4. A/A: any flagged material change on byte-identical X-vs-X, or an A/A false-lead rate above 0.1% for a detector proposed for the default profile.
5. Indeterminate share above 0.05 in a stratum used in the headline, or engine completion below 90%.
6. The FDR-reduction or hit@10 paired CI includes zero or is negative against the best baseline (honest result: "no demonstrated benefit"; do not run more variants hunting for one).
7. Shift-rung precision below 0.90 (reported as a blind spot; asking whether to widen the corpus or to accept the limit).
8. Any operator class with fewer than 20 accepted mutants, or a source/IR label agreement markedly low [proposal: below 0.95]. The 0.95 is mine; the prereg gives no number for it.
Values in items 1-7 are quoted from PREREG s5/s6, LBL s6/s7.6; item 8's number is a proposal.

## 5. Risks and owner blockers

| risk | effect | handling |
|---|---|---|
| Too few lineages (about 37-38) for a locked G1 and for narrow intervals | `insufficient-data` is the likely honest outcome at first | add reserve recipes (libsodium, nghttp2, libssh2, minizip, libuv, libwebp, libarchive); each +1 lineage; stop and ask rather than lower the 12/30 minima |
| Synthetic mutants easier than real fixes; operator taxonomy circular with the C locator | inflated recall | IR layer cross-check (07), separate populations, `real-fix` reported alone |
| Percentile bootstrap undercovers with few clusters | intervals too narrow | see Q3: add a studentized cluster-bootstrap sensitivity row before lock |
| Toolchain drift (`ubuntu-latest` moves Nov 2026, VS 2026 image) | non-reproducible reports | pin `ubuntu-24.04` and `windows-2022`, record clang/gcc/`cl` in `BuildInfo.compiler_version`; cross-digest comparison refused |
| Ghidra cost and the 6 h job cap | partial coverage | shard by project, sample 5 mutants per operator/lineage, report coverage |
| Upstream licence or tag changes | recipe breaks | per-pin SPDX read at pin time; commit pairs where no tags (stb) |
| A synthetic pass misread as accuracy on Windows files | the central honesty risk | `TIER_R_CLAIM`, `scope_ids`, banned-phrase tests; artifact stays `experimental`, display `none` |
| Parallel contributors collide on `tools/calibration/` and workflow YAML | lost work | re-check SHA and PRs before each slice; one worker at a time; PR #64 is in `tools/unified/` only |
| Locked-look spent by a crash | one look lost | by design the receipt counts; run R5 and the audit (26) first, dry-run the locked path on the template suite with a throwaway SHA [proposal] |

Blocks on the owner: O3 sign-off on the targets and display rounding (needed for the lock commit); decision on PREREG Q1 (G1 split) and Q2 (shift when MSVC absent); shift-lineage family choice named in the lock commit; confirmation whether Actions minutes are free (public repo) or budgeted (Q7); O1 legal reading of symbol-server terms and approval of what, if anything, of the Tier W aggregate enters `docs/qa.md`; O2 second annotator (G3 cannot pass without it); the manual noise sample in 4.5 (about 2.5 h of owner review [inf at 1.5 min each]).
Tier W (owner machine only, local, Microsoft binaries/PDBs/Winbindex labels never committed and never in CI; `tier_w/guard.py` enforces): slices 20-25 are built by agents against self-made fixtures; the real run (`tier_w all`), the symbol-audit (cap 150), the Tier W shift rung, kernel/driver/usermode family choice (>= 6 families, G0) and any `windows-validated` ledger entry are owner steps. Until then: G0/G2/G3 stay `insufficient-data`, display stays ordinal. Tier W results enter the repository only as owner-pasted aggregates with cells n >= 30 (LBL s8.2).
Reported separately from automated evidence (CLAUDE.md): frozen-EXE load, NVDA/Narrator, DPI passes, first green MSVC run, first live Ghidra legs.

## 6. Open questions, with sources and answers where possible

Q1. G1 on which split (PREREG Q1)? Answer: PREREG default stands: out-of-fold over all Tier R lineages, labelled synthetic; locked form only with >= 12 lineages in the locked role (about 48 total at 25% [inf arithmetic]). Needs owner OK before lock.
Q2. Shift set if the MSVC leg does not run? Answer: PREREG default, gcc-vs-clang split declared in the lock commit; relabel rung 2. Owner OK.
Q3. Are percentile intervals adequate with about 38 clusters? Partly answered. Cluster-robust inference over-rejects with few clusters (5-30), and cluster bootstrap-t procedures with asymptotic refinement restore nominal size in Monte Carlo, whereas plain asymptotic methods do not (Cameron, Gelbach and Miller 2008, Rev. Econ. Stat. 90(3):414-427; https://www.nber.org/papers/t0344). That paper is about regression coefficients; for hit@k/precision ratios the analogue is a studentized cluster bootstrap, which is my inference [inf], not shown in the source. Recommendation [proposal]: keep percentile as the preregistered primary (PREREG Q4), add the studentized cluster bootstrap and a leave-one-lineage-out jackknife (also used in the pilot prereg s5) as preregistered sensitivity rows, and treat any headline where they disagree as a stop-and-ask. A small simulation on synthetic lineages (`synth.py`) to measure actual coverage of the percentile interval at n = 38 would settle it with our own data: open, cheap, agent task.
Q4. Is Learn-then-Test the right threshold selector for the precision target? Answer: yes by design: it frames risk control as multiple hypothesis testing with finite-sample guarantees and no assumption on the model (Angelopoulos, Bates, Candes, Jordan, Lei, arXiv:2110.01052, https://arxiv.org/abs/2110.01052v4). The search results did not confirm how fixed-sequence testing is used in the paper, so that detail is not verified here; `threshold.py` implements it and the repo audit B4 documents it. The LTT guarantee is over exchangeable calibration data; lineage clustering breaks exchangeability, which is why the repo uses an effective-n design effect (PREREG s5). Whether that correction is sufficient is open: simulate on synthetic clustered data (agent task, falls under LBL-26).
Q5. Runner limits and cost? Answered: 6 h per job, 256-job matrix, 35 d per run, 20 concurrent jobs on the free plan, extra jobs queue (https://docs.github.com/en/actions/reference/limits; https://docs.github.com/en/actions/reference/usage-limits-billing-and-administration). Not answered: public versus private status and Windows multiplier for this repository; owner to confirm.
Q6. Ghidriff on every mutant? Default (LBL Q8): Ghidriff on all release/CVE/control pairs and 5 mutants per operator/lineage; rz-diff on all. First measurement from R3 should replace the 2-5 min guess before more shards are planned.
Q7. Budget for about 150-250 runner-hours per full cycle [inf]: owner (O4).
Q8. Real CVE card count is about 20 in 13 lineages: is that enough to say anything on `real-fix`? Answer from the plan's own rule: no gate (needs 30 lineages); report descriptively with intervals and the label "anti-conservative". More recipes or Tier W are the only fixes.
Q9. Are brotli and zstd (present in catalogue, absent from LBL s2 note A) licence-checked? Unverified: read `docs/plans/calibration-licences.md` and the per-pin SPDX hash before they enter a lock. Quick task for 05.
Q10. CWE -> operator mapping is heuristic (audit residual); keep it for coverage accounting only, never as evidence.
Unverified here (hosts blocked or not checked): arxiv.org full text, REFuSe-Bench/BinKit citations in SPEC-28 s17 (unchecked per LBL s2), whether `libpng`/`zlib` bundle overlap triggers the 15% merge, the `delta_hat` of any real lineage (no data exist yet).
