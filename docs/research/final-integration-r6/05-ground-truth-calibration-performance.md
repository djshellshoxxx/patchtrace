# 05 — Ground-truth corpus, semantic accuracy, calibration and performance

**Sources:** R1 [#128](https://github.com/djshellshoxxx/patchtrace/pull/128) and `docs/research/ground-truth-corpus/`; R2 [#131](https://github.com/djshellshoxxx/patchtrace/pull/131), R3 [#129](https://github.com/djshellshoxxx/patchtrace/pull/129), R5 [#132](https://github.com/djshellshoxxx/patchtrace/pull/132); SPEC-31 `08-evaluation.md`, SPEC-27/28, `docs/plans/c9-preregistration-v1.md`, `tools/{unified,calibration}/`. **Current decision:** no accepted real-world unified accuracy report or production calibrated probability. Exact tests and data are prerequisites.

## 1. Four different truth questions

| Target | Label universe and output | Evidence required | Must not be substituted by |
|---|---|---|---|
| **T-A: L1 function correspondence** | Same source-level function (under the label standard), different, no counterpart, indeterminate; selected pair, alternative/contested | Independent source/PDB/function identity and linked PE labels, engines run with label symbols hidden | Matching function name, same RVA, a similarity score, or analyst guess |
| **T-B: L2 materiality** | Unchanged, benign representation difference, material semantic change, insufficient proof/unestablished | Source mutation with proved emitted binary effect, target-sensitive instruction/CFG/EH facts, independently checked input/witness | L1 correspondence certainty, equal CFG size, same decompiler pseudocode |
| **T-C: advisory applicability** | Exact affected/product/KB/build/source assertion; negative/unknown/contradictory | Official source ProductID/KB/CVE pointer and complete source revision/coverage | NVD broad CPE, shared KB title/month, binary filename |
| **T-D: causal CVE-to-function association** | Verified source-level fix lineage, candidate, supported, confounded, counterexample, unknown | Reproducible patch commit/source diff → emitted binary delta → independently reviewed security behavior and vendor applicability | “Function changed in the patched update,” KEV status, CVE text, L1/L2 scores, AI narrative |

Only **T-A** currently has a project calibration implementation targeting a numeric correctness probability. Do not reuse its output for T-B/C/D. `review` is a legitimate conservative T-B outcome, not a negative correctness label for L1 or a zero-probability CVE association.

## 2. R1 ground truth: exact observed pilot and admission limits

At R1 draft head `a02a1774a1617441072f4a8770348cc22038eeac`, an author-controlled source-built Windows-targeted PE/PDB fixture contained 21 functions/side and 22 authored source identities, with 16 authored material source edits surviving compilation, 3 unchanged and 1 cosmetic controls, and 2 one-sided cases. Four ambiguous identity names were excluded from strict scoring; 18 accepted strict cases included 16 paired rows (13 changed, 2 unchanged, 1 cosmetic) and 2 one-sided. These categories depend on R1 manifest/adjudication rules and are **not** a measured PatchTrace precision/recall result. R1 ran Linux clang/LLD targeting MSVC ABI, inspected PE/PDB metadata and source spans; independent human labels, actual Windows/MSVC compiler runs and live Ghidriff/unified end-to-end scoring were not completed for this pilot.

R1's engineering lesson is more important than a sample count: a correct function label needs independently established source identity, preserved compile/link history and a code-body/relocation audit. Two different functions can share names, masked bytes or identical source; one source function can inline, fold or split. Object relocation to another symbol can have the same instruction bytes. A before/after source edit can optimize away, so “edited source” does **not** automatically make a material binary change.

**Corpus admission record per image:** unique corpus/card/lineage ID; upstream project and immutable source commit; permitted licence and redistribution; compiler exact executable/version/target/flags; linker options including ICF, LTO, CFG, /GS and EH; build OS; source files and their SHA; output AMD64 PE hash/size; PDB GUID/age and provenance where available; build reproducibility outcome; source-level mutation and witness; original/redacted debug symbols stored local only; analyst-label confidence state. If any field needed for an independent truth claim is absent, label it `indeterminate` rather than guess.

**Pair record:** ordered SHA pair; source/build family, lineage and patch boundary; one-to-one, many-to-one/inlining, one-sided or contested labels; old/new RVAs and body digests; all relevant relocations and import/section references; model-hiding policy; answer scope; expected semantic class; explicit source witness or known “cannot prove difference” condition. Compare engine-produced function names with symbols-hidden runs, not the hidden label metadata.

## 3. Tier definitions, partitioning and leakage guards

- **Unit/synthetic:** hand-built IR, fake engine records and contrived compiled functions prove parser/proof logic. They cannot provide native correctness estimates.
- **Tier R:** reproducible public-source projects with pinned compiler recipes, adjacent releases and source truth: `tools/calibration/tier_r/`; existing `tools/unified/corpus/` (zlib, libpng, Lua, mbedTLS, other accepted recipe cards); A/A, compiler-nuisance and mutation suites. Build-only and parser acceptance are separate.
- **Tier W:** permitted **local-only** real Windows binaries and PDB/symbols with index hashes, GUID/age, human adjudication; `tools/calibration/tier_w/`. Must not be committed or uploaded. Windows system-code risk claims require this domain.
- **Locked challenge/shift:** untouched lineages/build families and atypical compiler/OS/architecture distributions selected before reading labels. No repeated looks, threshold changes or “test rescue” tuning.

Split by **source project/release lineage**, CVE family, reuse of identical body and upstream code graph, not by randomly shuffling functions or duplicate builds. Same source compiled under O0/O2/clang-cl/MSVC belongs to one lineage. Function names can change and binaries can share large static CRT fragments across distinct projects; detect body duplicates across roles. Keep A/A, nuisance and planted mutations **out of natural-sample headline performance**; report them as separate stress/negative controls.

Never let a source-derived PDB name leak into engines when evaluating correspondence. When labels use PDB, verify GUID/age, unique symbol mapping and code extent, then run Ghidriff/BinDiff/rz-diff **symbols hidden** and record this condition. Analyst labels require independent reviewers and adjudication; majority votes from the same derived source are not independence.

## 4. Restore genuine live acceptance before computing metrics

Current exact main live-gate [41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449) had successful fixture build for **273 pairs** including the 12 mutation classes, yet zero actual A/A/release outcomes and 27 failed jobs. This is a harness/backend blocker, not a low or high measured accuracy result.

**P0 harness experiment, one owner `tools/unified/live_pairs.py`:**
1. Re-run a single valid `X vs X` pair in isolated workspace with raw Ghidriff, Ghidra and JVM logs; explicitly distinguish valid `run.status='identical'` from unsuccessful/no run. Verify both file hashes and committed run artifacts before accepting an “identical” outcome.
2. Re-run one actual changed source pair (R1 strict known truth) and capture the original failed result before modifying status logic. Identify exact backend failure mode (tool executable, raw output parser, metadata, version, permission, timeout, environment or known Ghidriff bug) from real logs, not guesses.
3. Add regression `identical success yields nonzero labelled/coverage-bearing outcome` and `nonidentical failed backend remains FAILED with logs`. If the canonical outcome set intentionally omits unmodified rows, adapt evaluator to reconstruct function coverage from labelled IR inventory **without fabricating engine correspondence**.
4. Pin expected input SHA manifests and require every eligible labelled endpoint to be present, matched, contested or explicitly accounted for. Empty outcomes cannot yield passed metrics.
5. Solve Linux `libEGL.so.1` dependency in the integrity job as a runner/dependency issue, not by skipping Qt or modifying correctness assertions. Separate acceptance of the Linux and Windows subgates.
6. Rerun the exact dispatch on a new commit; preserve failed run and report SHA `6328006a60e94c51aec6e0cc182f84bb3dbc8bfdd76c32685d0e888e06204710`. All subjobs must contribute signed/hashed outcomes to a final gate aggregator. A workflow with `continue-on-error` may be green while release gate is `NOT READY`.

## 5. SPEC-31 G-U1–G-U8 exit matrix

| Gate | Contract / threshold | Required dataset and failure handling |
|---|---|---|
| **G-U1: A/A null** | Exact image vs itself: 100% unchanged, zero contested or one-sided. Rebuilt same-source P0: zero material and review ≤0.1% of eligible rows; P1 nuisance: zero material. Every labelled older/newer RVA accounted for | At least all P0/P1 variants present in manifest, not zero outcomes. Any missing RVAs, source digest mismatch or unrun class is insufficient/fail, never pass |
| **G-U2: material mutation recall** | **Zero material→unchanged/cosmetic** on planted changes. (Material or review) recall ≥95% per class with ≥20 eligible mutants (project proposal). Frame/trace-arg cases remain review | 12 classes include constant, branch, boundary, signedness, removed check, callee, struct offset, block, same-shape global, register index, swapped then/else, moved call, try-scope, frame. Record which cases still lack generator/runtime |
| **G-U3: L1 precision/parity** | Precision ≥99.5% matched truth, lineage-cluster lower bound ≥99.0%, ≥30 independent lineages for CI; zero truth-contradicted A/A tier A; BinDiff oracle MD parity ≥99.9% to 12 decimals on n_bb≥5 and ≥98% tier A/B agreement when installed | Real BinDiff oracle `tools/bindiff_pin.json` incomplete trust/provisioning can block gate. Insufficient lineages cannot be scored 100%. Ghidriff ExactBytes/SymbolsHash pairs on A/A must be matched or contested with reason |
| **G-U4: determinism/metamorphic** | Byte-identical manifest except allowed timestamp after repeated runs, input record permutations, Windows/Linux same image bytes; swap older/newer mirrors pair/one-sided status; 3-build cosmetic chain not incompatible material; cheap semantic delta cannot coexist with cosmetic pseudo-proof | Run at least two repetitions per case and correct mirrored source identities; exact output digests stored |
| **G-U5: performance** | Existing L-35 budgets on 10k, 60k, 250k function IR and real largest Tier R pair; actual Windows frozen run | Record wall time/peak RSS/phase breakdown/gui data access. No invented budget after measurements; do not substitute Linux timing for Windows |
| **G-U6: reduced false leads** | Material false leads ≥20% fewer than best available single legacy source with nondecreasing planted change recall (proposal) | Ghidriff, BinDiff and rz-diff baselines must be genuinely supplied or clearly unsupported. No success with all baselines missing |
| **G-U7: engine independence** | B+B class/component pair error rate ≤2× tier A rate with lineage CI; each evaluated class pair at least 30 real rows | Shared-source errors are dependent, not multiple independent votes; insufficient groups cannot satisfy gate |
| **G-U8: integrity/safety** | Original snapshot SHA unchanged; legacy readers; schema drift; audited zero network on offline unified analysis; hostile inputs; Qt tooltips/accessibility; **Windows frozen smoke** | CI checks alone are necessary not sufficient; specific frozen smoke missing from 41063115449 |

Use `tools/unified/{gates_u,evaluators,rowgates,live_pairs,parity,bench}.py` and ``g-u` sources exactly as implemented. The gate aggregator must preserve `pass`/`fail`/`blocked`/`insufficient-data` and honest denominator/count for each class. No flag default change until all required gates are unequivocally passed with exact-head evidence.

## 6. Semantic confusion matrix and false-benign priority

Truth rows `unchanged`, `benign-representation`, `material`, `unestablished` versus predicted `unchanged`/`cosmetic`/`material`/`review`/`unknown`. Keep *different* denominators:
- `false_benign = count(ground-truth material predicted unchanged or cosmetic) / number of eligible ground-truth material cases`.
- `false_material = count(ground-truth benign predicted material) / number of eligible benign cases`.
- `screening_detection = count(material predicted material or review) / eligible material`.
- `conclusive_material_precision = true-material predicted material / all eligible predicted material` (different from screening detection).
- `review_rate` and `unknown_rate` across all eligible pairs, stratified separately for modified/unchanged/build noise.

`review` is an appropriate safety-conservative response to insufficient proof but increases workload. Do **not** call every review a detected vulnerability or every review a true positive. Report row-wise confusion counts and denominators, per-class false-benign counts, unscored cases, confidence intervals clustered by independent source lineage, and cases where low label quality precludes an estimate. A zero observed false-benign count is an empirical sample outcome, not a universal guarantee. A single reproduced planted material→benign misclassification blocks R6 until fixed and rerun against the locked set.

Key negative controls: A/A same-image and rebuild; changed image base; relocation-only; linker order/ICF; same-size changed integer constant; comparator strict→inclusive; lost indirect call target; data reference to a different preexisting global; same bytes with changed relocated callee; then/else successor swap; EH protection table; /GS/CFG; source edit optimized away; LTO, inline, outline; tail calls; undetected source/PDB symbol collisions; untrusted producer.

## 7. R5 calibration: what is built versus what can be displayed

**Current code:** `src/patchtrace/calibration/{features,context,artifact,predict,ood,policy,ledger,scope}.py`; dev tools `tools/calibration/{corpus,lineage,guards,sample,label,cv,mathcore,fit,evaluate,bootstrap,threshold,ood_fit,shift,train,run_locked_test}.py`; feature profiles G, G+B, G+R, G+B+R. Pydantic/strict JSON + no dynamic pickle loaders, calibration map, OOD flags, source families, grouped CV and dev model fitting are code present. They do **not** certify numeric probabilities for Windows system binaries.

**Target A only:** correct 1:1 function correspondence. Current user-visible default should remain **ordinal L0**. Contested, one-sided, N:M, unsupported architecture/toolchain, expired ledger, untrusted bundle or OOD domain must abstain or require manual review regardless of score.

**Current specific trust issue:** `tools/calibration/fit.py::_reproduce_gates` forces `reproducibility_check`, `owner_signoff`, `frozen_exe_smoke` and `independence_caveat_shown` to `True` before gate reproduction. The “pass” is based on asserted conditions, not externally checked identity. Required implementation:
1. Add red tests for no sign-off, forged receipt, wrong report SHA/approved commit, missing frozen smoke, expired/duplicate receipt, wrong model/profile/domain and missing prereg lock.
2. Define an independently verified, digest-pinned `PromotionEvidence` receipt with signer/authority identity (where appropriate), exact prereg/labels/report/model/CI/Windows executable hashes, OS, test-run IDs and expiration. Do not accept a report's own claim of this evidence as a substitute.
3. Use explicit `not verified` by default, remove the hardcoded `True` assumption, and fail closed to L0 on any mismatch. The independent release process signs/records the approval, not the model-fitting process.
4. Make engine major/toolchain domain compatibility hard abstention until separately validated; soft drift alone may allow a misleading numeric result. Test nonfinite FeatureRow values, corrupted artifacts, bad predictor state, expired ledger and UI stale status.
5. Verify saved and reopened project never shows a previously valid numeric status after model expiry/revocation/engine version drift. Existing projects keep raw matches/notes and derived versioned predictions.

The [C9 preregistration](../../plans/c9-preregistration-v1.md) was still a **draft** with an unresolved committed lock SHA at the examined baseline. `run_locked_test.py` creates a “single-look” receipt only within its local output directory; running in another directory/host can evade it. Lock and externally attest dataset/receipt before consuming the reserved held-out labels. No changed threshold after locked result; a new protocol v2 may be necessary with the original report preserved.

## 8. C9 acceptance gates G0/G1/G2/G3 (thresholds are requirements, not measurements)

| Gate | Thresholds and population | Current evidence |
|---|---|---|
| **G0 admissible corpus** | ≥12,000 natural candidates, ≥3,000 locked natural candidates, ≥150 effective locked negatives; ≥40 independent lineages from ≥10 families, locked ≥12 lineages/≥5 families, Tier W ≥6 families including kernel/user DLL/driver, ≥2 toolchain profiles and separate shift lineage; independent annotator/symbol audits | No complete accepted Tier W population demonstrated; `INSUFFICIENT-DATA` |
| **G1 engineering pipeline** | Real Tier R source-built inputs pass data/feature/evaluation flow with native engine outputs | R1 pilot and basic tools exist, but the failed 41063115449 live-gate does not establish complete G1 |
| **G2 probability bands** | G0; per-profile ≥2,000 natural candidates, ≥100 effective negatives, ≥12 independent lineages, ≥30 bootstrap groups; point auto-accept precision ≥.95 (CI lower ≥.90, width ≤.10), coverage ≥.40 (CI lower ≥.30), positive Brier skill, FDR comparator benefit, OOD and ablation gates | No passed locked Tier W outcome or trusted external evidence; bands prohibited |
| **G3 numeric percentage** | G2; CI precision lower ≥.93 and width ≤.06, coverage ≥.50 (lower ≥.40), null-ECE excess ≤.03 and upper CI ≤.05, calibration slope/intercept, relative FDR reduction ≥.25, shift precision ≥.90; independent reviewer and signed reproducibility/frozen UI receipt | No evidence satisfying these conditions; numeric probability prohibited |

Use exact authoritative `tools/calibration/gates.py` and C9 contract for nuance. The thresholds above are **published protocol conditions**, not measured PatchTrace performance. If a profile lacks a native secondary tool or enough negative labels, it is `insufficient-data` and cannot be rescued by another profile's result.

## 9. Statistical experiment plan and reports

| Experiment | Fixture/algorithm | Output and exit |
|---|---|---|
| C-01 corpus truth | R1 source-built PE/PDB, double human review, real native engine | Image/pair manifest SHA, label g1, symbol-hiding audit, accepted/excluded counts |
| C-02 no leakage | Lineage graphs + repeated CRT, duplicate source, ICF/inline and renamed symbols | Split audit digest, no cross-dev/locked overlap |
| C-03 per-profile dev | Existing M0/M0b/M1/M2 baselines and profile G/G+B/G+R/G+B+R | Grouped CV Brier/log loss, AUC, risk/coverage, threshold, reliability bins, intervals |
| C-04 feature ablation | Remove G/B/R/S/P/X feature group, keep matched samples | Incremental benefit/error per lineage, dependence and missing-engine status |
| C-05 out-of-domain | Compiler/flags/OS/Ghidra/rz major shift, kernel vs user modules | Hard-abstain fraction, error recall, correct-abstain cost and risk |
| C-06 selective guarantee | Cluster-correlated simulation and trusted external review | Preregistered type-I error assumptions, false-certification rate; toy simulation not product accuracy |
| C-07 locked test | Frozen model/tau/prereg + trusted receipt, one look | Held-out metrics/report SHA, all G0/G2/G3 statuses; no re-fit |
| C-08 frozen package | Actual Windows portable + Setup and valid/invalid artifact | Ordinal fallback/expiry/OOD/signed evidence in UI; screenshot/reader logs and binary hashes |

**Metric reporting:** use TP/FP/FN on a pinned labelled universe, not guessed per function. Precision=TP/(TP+FP), recall=TP/(TP+FN). If denominator is zero record `undefined`. Weighted/natural sampling requires inclusion probabilities, risk/coverage needs denominators, CI needs lineages or cluster bootstrap. Report per OS/compiler/optimization/family/mutation category; show unknown/abstain and label disagreement separately. Never leak raw Tier W binary disassembly or symbols into public report.

## 10. Performance and resource plan

Instrument extraction (Ghidra headless and GZF reuse), IR ingest/SQLite, key pass, propagation, residual, fusion, L2 semantic facts, decompilation requests, native secondary runtime, index/search, GUI first paint/sort/filter and report export. For each, collect:
- exact OS/CPU/RAM/Python/Ghidra/JDK/executable versions and PE SHA pair;
- wall-clock p50/p95/p99 over repeated independent runs, peak resident memory and worker/JVM memory separately, CPU if available;
- input size, function/block/instruction/edge counts, matched/unmatched/contested counts, cache hit/miss, code text cap, cancellation and timed-out cases;
- UI event-loop response latency and `QAbstractItemModel.data` count on 10k/100k rows, virtualized vs eager; backup/migration time and largest project history;
- same SHA case cold/warm and repeated comparison, real MSVC x64 PE sizes, and actual Windows frozen runtime in addition to generated 10k/60k/250k IR.

Use existing `tools/unified/bench.py` and `docs/specs/unified-engine/02-data-model.md` L-35 targets; do not revise target after observing bad performance. R2's synthetic 100k results are a *baseline hypothesis*; G-U5 requires larger realistic data and Windows actual measurements. Investigate memory amplified by protobuf fallback and read-model eager scans before adding nonessential optimizers.

## 11. Runbook and evidence retention

```bash
python --version
python -m tools.calibration.tier_r toolchain
python -m tools.calibration.tier_r catalogue-check
python -m tools.calibration.tier_r build-card --help
python -m tools.calibration.tier_r aa --help
python -m tools.calibration.tier_r mutate --help
python -m tools.calibration.tier_r evaluate --help
python -m tools.calibration.train --help
python -m tools.calibration.prereg --file docs/plans/c9-preregistration-v1.md
python -m ruff check src tests tools
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

For actual approved native sample, `PATCHTRACE_CALIB_ROOT` points **outside git**; fetch/build/reference only pinned source with approved licences, keep unredistributable Windows files local, use symbols-hidden engine flags, choose data partition before labels and record real CLI output. The prereg digest command only computes a hash; it does **not** confer owner approval or globally lock the test.

Test result form: test-run ID, git SHA, timestamp and runner, image/label/manifest/prereg SHA, exact toolchain, command, exit, passed/failed/skipped/blocked, input/outcome count (must be nonzero for accuracy), confidence interval and scope, output artifact path/hash, limits/exclusions and next owner.

**R6 gate conclusion:** without nonzero Tier R native outcomes, independent Tier W labels and a passing locked report, no quantitative “% accurate” or numeric probability can be honestly advertised. Completing the framework code is necessary but insufficient.
