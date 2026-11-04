# R5 / 01 — Implementation inventory, integration map, and evidence gaps

**Reference checkout:** GitHub main a04f5a299a8d4afef023261e52e08d14678cf1e7, 2026-10-30.  
**Method:** read live modules, tests, checked-in QA, C9/SPEC-27/SPEC-28/SPEC-31 contracts and open PR descriptions. Source inspection establishes that a path exists or that a particular branch of logic is present; it does **not** establish statistically correct behavior on real Windows images.

## 1. Architecture and scope

The shipped calibration runtime is **src/patchtrace/calibration/**. Development-only training and evaluation is **tools/calibration/**. Tier R source-built tests and labels are **tools/calibration/tier_r/**; local-only Microsoft/Windows corpus work is **tools/calibration/tier_w/**. Source Ghidriff and secondary-engine evidence is reconciled by **src/patchtrace/secondary/** and the separate **src/patchtrace/unified/** L1/L2 engine. The UI reads ordinal status through **src/patchtrace/secondary/evidence_view.py** and **src/patchtrace/unified/read_model.py**.

The development pipeline maps raw engine records and independently established labels into named feature profiles, performs grouped CV and calibration, selects a policy threshold, assesses drift and writes a versioned *experimental* artifact and reproducible report. A separate promotion procedure is intended to verify the held-out results, domain and review gates before allowing probability bands or numbers. No validated production bundle was found in the inspected runtime.

Do **not** conflate the C9 candidate probability with SPEC-31 ordinal evidence tiers: Ghidriff ratio, BinDiff confidence, evidence strength, correspondence correctness, L2 classification confidence, OOD risk and review status are distinct variables.

## 2. Component-by-component inventory

| Component | Source of truth / contract | Inspected behavior | Current evidence and necessary check |
|---|---|---|---|
| Prediction target | SPEC-28 §§1–2; C9 prereg §1 | Only A = correct Ghidriff one-to-one source-level function match | Implemented target; no released Tier W probability performance |
| Feature schema | src/patchtrace/calibration/features.py; features/1 | G, B, R, S, P, X feature families; raw native scores and missing indicators; fixed profiles G, G+B, G+R, G+B+R | Synthetic tests/test_calibration_runtime.py; confirm production train/serve parity on pinned real outputs |
| Feature extraction | features.extract; secondary.reconcile | Contested, one-sided and non-comparable matches have no vector; alternative count and agreement features are explicit | Synthetic golden vector; validate Ghidriff match type/version and BinDiff parser on real runs |
| Toolchain context | calibration/context.py | DiE signature-certain toolchain; unknown falls back, PE machine mapped to arch | Unit/contract evidence; unknown/unrepresented toolchains need abstention checks |
| Evidence dependencies | features.family_dependencies; unified/fusion/components.py; SPEC-31 §05 | Shared D_ghidra/D_symbols/D_callgraph prevents engine votes being naively independent | Logical unit tests, but joint-error rate still needs G-U7 measurement |
| Strict artifact | calibration/artifact.py; patchtrace-calibration-model/1; JSON schema | Bounded strict JSON, duplicate-key/nonfinite rejection, SHA-256 digest, feature profile/knot/expiries/gate checks; no pickle or dynamic loaders | Tests synthetic. Hash verifies self-consistency, **not external authenticity** |
| Runtime inference | calibration/predict.py | Median imputation, standardisation, L2-logistic score, Platt/isotonic map, predicted A score, OOD flags, provenance | Unit tests. Direct nonfinite FeatureRow boundary merits defense-in-depth test |
| OOD check | calibration/ood.py | Mahalanobis/range/unseen categorical hard flags; engine version not in spec is **soft only** | Flag behavior coded; risk discrimination and shift coverage unmeasured on Tier W |
| Acceptance policy | calibration/policy.py | L0 ordinal by default; only eligible Windows Tier W domain with >=40 lineages and passing G0/G2/G3 may show bands/numeric. Contested -> manual; unsupported -> abstain | Unit test with manufactured artifacts; no live numeric acceptance |
| Validation ledger | calibration/ledger.py; validation-ledger/1 | Strict bounded/expiring digest-checked synthetic/windows entries, invalid -> unvalidated | Unit tests. Keep provenance and time-of-check explicit |
| Scope notices | calibration/scope.py | Scope limitations, synthetic/Windows states; uses ledger.live_entries() for expiration filtering | Prior SER-5 expired-entry audit must be re-evaluated against **current** implementation; do not treat old finding as live |
| Label contract | tools/calibration/contracts.py; LabelRecord.json | A same/different/no-counterpart/indeterminate, B/C/D null, annotator and provenance | Schema and synthetic checks; human independent agreement and real Tier W labels still needed |
| Corpus manifest | tools/calibration/corpus.py; CorpusManifest.json | Hashes and Tier W no-redistribution guard, manifest checks | No completed owner-machine Tier W corpus evidenced |
| Tier R source factory | tools/calibration/tier_r/{factory,toolchain,build,labeler,manifest,cli}.py | Versioned public-source cases, mutation/noise/A/A generation, COFF/PDB/DWARF supporting metadata | Built cases are not measured accuracy; R1 #128 owns admission and real-engine pilot |
| Tier W local sources | tools/calibration/tier_w/{catalogue,pairs,fetch,symbols,labels,audit,evaluate}.py | Windows source acquisition/identity and local-only PDB label machinery | Synthetic/self-built fixtures noted in docs/qa.md; real Microsoft binaries/PDB verification unproven in this run |
| Leakage checks | tools/calibration/{lineage,guards}.py | Deterministic lineage hashing; source project, file/PDB/image/identity split audit; hub handling and seen-body | Tool unit tests; missing complete manifest or cross-corpus dedup -> no G0 |
| Sampling | tools/calibration/{sample,label}.py | Natural/adversarial separation, logged inclusion probability and guideline g1 | Need independently hashed sample list **before** annotations; missing probabilities -> exclude headline |
| Model fitting | tools/calibration/{cv,mathcore,fit}.py | Pure Python regularized logistic, Platt, PAV, nested grouped CV, profile-specific columns; optional sklearn cross-check | Synthetic test evidence only; candidate comparison on native outputs needed |
| Validation metrics | tools/calibration/{metrics,evaluate,bootstrap,ece_null}.py | Weighted Brier/log loss, ECE and null estimate, AUC, risk–coverage, clustered bootstrap intervals | Synthetic arithmetic tests; empirical coverage, uncertainty and stratum samples unverified |
| Baselines | tools/calibration/baselines.py | Predefined M0/M0b/M1/M2 comparators, documented unavailable channels | Some comparators unavailable without relevant engine outputs; never infer superiority from missing values |
| Threshold selection | tools/calibration/threshold.py | Fixed tau and tau-low grids, design-effect effective n, LTT-style binomial tests | Code exists; finite-sample guarantee under sampled clustered/OOF data **not established** |
| OOD fitting | tools/calibration/{ood_fit,shift}.py | Held-out-fold OOD fit and a shift ladder | No real Windows shift benchmark; verify version/domain coverage checks |
| Preregistration | docs/plans/c9-preregistration-v1.md; tools/calibration/prereg.py | Document draft; SHA utility can compute/verify once recorded | **Lock not recorded in docs/qa.md**; status is not a completed preregistered run |
| Locked test | tools/calibration/run_locked_test.py | Exclusive create of local SHA-named receipt before evaluating; repeated look on same directory refused | Useful guard, not a globally verifiable single-look seal across machines |
| Artifact creation/promotion | tools/calibration/fit.py | Dev artifact status experimental; promote checks report self-digest and G0/G2/G3 with declared Tier W scope | External-owner sign-off/repro/frozen-EXE conditions currently assumed true by helper; investigate before promotion |
| User evidence UI | secondary/evidence_view.py, unified/read_model.py | Raw engine scores distinguished, ordinal display, missing/contested visible | Numeric target-A display not actually integrated; mock/synthetic panel tests are not analyst validation |
| Regression tests | tests/test_calibration_{math,metrics,cv,tools,runtime,scope,hardening}.py and Tier R/Tier W tests | Broad arithmetic/contract/error-path coverage; some native-tool tests conditional | Record exact current-head Linux/Windows executions before any merge |
| Project snapshot integrity | unified/store.py, pipeline.py and AGENTS.md | Derived immutable results required by architecture | Add matched numeric artifact/provenance lifecycle tests, including rollback after failed promotion |

**Status labels:** "implemented" in this table means code exists on inspected main, not that a target gate passes. Older task checkboxes may precede merged #124; refresh from code and PR-head diff before declaring work missing.

## 3. Gate and contract map

C9 target A is constrained by the following four statuses. Each gate is **pass**, **fail**, or **insufficient-data**; missing input is not a pass.

| Gate | Purpose | Minimum evidence |
|---|---|---|
| G0 | Dataset admissibility and independent label quality | >=12,000 natural candidates; >=3,000 locked-test natural; >=150 effective locked negatives; >=40 independent lineages from >=10 families; locked >=12 lineages, >=5 families; Tier W >=6 families including kernel, user-mode DLL and driver; >=2 toolchain profiles; shift lineage; annotator checks, low indeterminacy and symbol-audit error |
| G1 | Pipeline check on Tier R source-built data | Model/evaluation plumbing; **cannot** alone promote any display |
| G2 | Bands-level correctness | G0; per-profile dev >=2,000 natural, >=100 effective negatives and >=12 lineages; >=30 bootstrap groups; auto-accept precision >=.95 with CI lower >=.90 and width <=.10; coverage >=.40 with CI lower >=.30; positive Brier skill and comparator FDR improvements; certified tau, subgroup/OOD and ablation gates |
| G3 | Numeric correspondence estimates | G2; precision CI lower >=.93, width <=.06; coverage >=.50 with lower >=.40; ECE15 null-excess <=.03 and CI-upper <=.05; calibration slope/intercept intervals, relative FDR reduction >=.25; shift precision >=.90; external independent annotator and sign-off/repro/frozen-EXE/UI-disclosure evidence |

The values are **project-defined proposed acceptance standards**, not estimates of achieved accuracy. Inspect **tools/calibration/gates.py**, **docs/plans/c9-preregistration-v1.md §§5–8** for all flags and exact conditions; do not rely on this summary alone for a lock.

## 4. Ranked R5 audit findings and hypotheses

### R5-P0-01 — External evidence is not reproducibly verified during promotion

**Observed:** tools/calibration/fit.py::_reproduce_gates constructs a map that sets reproducibility_check, owner_signoff, frozen_exe_smoke and independence_caveat_shown to True before recomputing gates. The comment explicitly states that nonstatistical conditions are assumed true. The artifact loader checks declared G0/G2/G3 fields and report digests, but a digest alone does not verify a trusted runner or sign-off.

**Risk:** A syntactically valid report/domain claim can pass the promoter's **internal** status checks without cryptographically/operationally proving required external acceptance. Package-bundled artifact placement is separately controlled, so this is a promotion workflow assurance gap, not evidence of remote arbitrary code execution.

**Proposed fix:** Promote only from a sealed, versioned acceptance manifest containing independent named/dated reviews, exact locked report and prereg SHA, Tier W manifest digest, native CI job URLs/commit SHAs, validation ledger entries, pinned engine/toolchain versions, frozen EXE checksum and policy disclosure confirmation. The build job verifies all expected fields against trusted inputs; unsigned, missing, stale and contradictory attestations fail closed. Test forged pass flags, mismatched scope/report, missing external conditions, swapped artifacts and scope narrowing.

**Owner:** integration/security owner, after spec revision. **Evidence status:** source-confirmed implementation gap; no demonstration of improper release.

### R5-P0-02 — Engine-version OOD is only a soft flag

**Observed:** calibration/ood.py::ood_flags emits soft:engine-version when a runtime version is not in the artifact's OOD list. calibration/policy.py::decide only abstains on flags beginning hard:. The C9 text says a new engine major version invalidates its model.

**Risk:** A model could auto-accept a match outside the engine version set unless a separate domain gate not present in the observed policy path is enforced.

**Proposed fix:** Define per-profile exact/major version admissibility in the frozen domain contract. Missing/unknown/incompatible engine version must produce abstention/ordinal fallback until a documented compatibility analysis passes; do not silently change all soft alerts into hard alerts without version-compatibility tests. Red tests: exact pinned match, minor/major bump, missing metadata, unexpected BinExport producer, mixed G/B/R versions, unknown toolchain, invalidated cached result.

**Owner:** calibration runtime integrator. **Evidence status:** source-confirmed policy concern; end-to-end exploitability untested.

### R5-P0-03 — LTT-style certification under clustered dependence is a statistical assumption, not a proven guarantee

**Observed:** tools/calibration/threshold.py computes ICC/design-effect n_eff, then uses a binomial CDF on floor(n_eff) and rounded errors. The classical exact binomial test assumes independent Bernoulli observations; effective-sample substitutions need their own justification. Thresholds are chosen using OOF dev rows. tools/calibration/train.py documents that reported dev threshold precision is selected on those same OOF rows.

**Risk:** Calling a chosen tau "certified" may overstate the statistical guarantee under correlated functions, non-probability inclusion weights, repeated source lineages, prevalence shift or model-selection reuse.

**Proposed evaluation:** Simulate independent clusters and latent cluster effects under a known error null, varying cluster count, group size, ICC, weights and class imbalance. Measure empirical false certification over >=10,000 Monte Carlo trials per cell with prespecified seed and confidence interval. Compare current effective-n procedure with a *truly independent* lineage-held-out threshold calibration partition, cluster-level bound/conservative binomial-unit threshold and simple ordinal-only baseline. A formal theorem or measured conservative risk bound is required before describing finite-sample risk guarantees. This review does not assert current control is invalid for every population.

**Owner:** statistician + calibration integrator; protocol change may require prereg v2 if v1 locked.

### R5-P0-04 — Data and lock preconditions remain unfulfilled

**Observed:** docs/qa.md says no C9 prereg lock recorded; C9 draft has placeholder and owner decisions O1/O2/O3/O4. R1 #128 reports source-built but not successful full live acceptance; no Tier W locked test available.

**Risk:** Even flawless software cannot validate the probability until population, labels and holdout are independently established. **Stop:** Do not expose numeric probability; do not count an authored fixture, report schema or model object as a pass.

**Owner:** R1 dataset owner, calibration evaluation owner, product owner for local Windows and prereg sign-off.

### R5-P1-05 — Local locked-test lock is not a cross-machine single-look seal

**Observed:** run_locked_test.py stores locked-test-<sha>.lock under a caller-supplied local folder using exclusive create; the SHA is only syntax-checked, not compared to authoritative locked bytes inside this function. Fresh folders or hosts have separate receipts.

**Proposed fix:** Publish a repository-side, append-only signed/verified run record keyed by exact prereg SHA, dataset digests and commit; CI rejects second promotion result, even if someone reuses a new local directory. Preserve failed/aborted attempts. No raw Tier W data upload.

### R5-P1-06 — Train/serve and candidate support-set mismatch needs field-level proof

**Observed:** src feature extraction supports B confidence, algorithm flags and richer Ghidriff types; train.py's Tier R adapter explains that it may use only old/new RVA, changed flag and similarity, sets callee counts and match type flags to zero and drops constant columns. These are legitimate dev-time simplifications but narrow the validated population.

**Proposed fix:** On representative *real* source-derived engine output, serialize feature name/value/missing vector from training and runtime code and compare exact profile, version, origin and missingness. Reject if profile/domain features differ or count of missing families changes. Do not generalize results from a truncated feature population to richer live output.

### R5-P1-07 — Input-number defense and scope copy lifecycle

**Observed:** predict.impute and predict do not themselves reject every nonfinite value; features._num filters nonfinite values in the existing standard extractor. This is **defense in depth**, not a demonstrated reachable GUI fault. A historical audit cited expired scope-copy behavior; current scope.notice uses ledger.live_entries(), so rerun the historical test before accepting that earlier issue as live.

**Proposed fix:** Test direct malformed FeatureRow, infinity, NaN and huge exponent at the last inference boundary; fail closed before nonlinear math and OOD flags. Test expiry at both ledger and UI/render boundaries with a fixed clock and prove no old Windows-tested label leaks.

### R5-P1-08 — Artifact provenance authenticity and reproducibility limits

Artifact digest and schemas protect accidental/tampered content relative to their own digest, but anyone rewriting JSON can recompute the digest. Require release pipeline provenance and exact verified package checksum before a promoted file is treated as a trusted source. The artifact currently records created/expires, tools, selected model and feature schema; compare this against R5-required *training corpus digest*, partition digest, label digest, random seed, toolchain versions and immutable report set. If any is absent from the actual artifact, add a **versioned additive spec**; do not rely on a provenance note outside the artifact without binding it by digest.

## 5. Validation of prior work and PR ownership

- [#128](https://github.com/djshellshoxxx/patchtrace/pull/128) builds R1 dataset science: reuse its labels, code paths, provenance, failed-G-U observations and handoff; avoid changing its files without owner coordination.
- R2 corpus/matching benchmarking may be embedded in docs/research/calibration, phase-c and Tier R historical work; GitHub branch-name search for R2 is **not** evidence it is absent. Audit delivered R2 outputs before duplicating experiments.
- [#129](https://github.com/djshellshoxxx/patchtrace/pull/129) supplies R3 L2 semantics; its COS-PSEUDO/EH discrepancy and 10 static fixtures do not measure target-A correctness. Track L2-specific confidence as a **separate future calibration**.
- [#130](https://github.com/djshellshoxxx/patchtrace/pull/130) is R4 provenance graph; do not allow target-A probability to imply any CVE or causal patch confidence.
- [#126](https://github.com/djshellshoxxx/patchtrace/pull/126) owns shared docs/qa.md and tasks/todo.md reconciliations. Submit exact suggested text in this dossier; let coordinator apply without conflicting edits.
- [#78](https://github.com/djshellshoxxx/patchtrace/pull/78), [#79](https://github.com/djshellshoxxx/patchtrace/pull/79), [#82](https://github.com/djshellshoxxx/patchtrace/pull/82), [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) have historical calibration scope; confirm any unmerged hunk against current main before cherry-picking.

## 6. Concrete exit criteria for the inventory

An integrator may close this *inventory* deliverable after recording an exact refreshed SHA, changed-file diffs for relevant PRs, current-head test outcomes on Linux and Windows, existing model bundle contents, test corpus manifest size and provenance, current C9 lock status, data-independent external gates, and owner assignment for each P0. Until then the appropriate status is **implementation inventoried; real calibration claim not accepted**.
