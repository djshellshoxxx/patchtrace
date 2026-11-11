# C9 preregistration v1: frozen analysis configuration and lock procedure (LBL-16)

Status: draft, 2026-10-14 (P-1 and P-2 tooling built; section 8.5 iii still open). Owner: calibration integrator; product-owner sign-off on the targets (decision O3) is pending. Parent: `docs/specs/calibration-corpus-and-model.md` section 2 (protocol) and section 12 (go/no-go numbers), as amended by its section 18. Documents the frozen values in `tools/calibration/{cv,threshold,lineage,ece_null,metrics,gates,contracts,fit,run_locked_test}.py` and the artifact check in `src/patchtrace/calibration/artifact.py`. Modules named in section 2 (`train.py`, `shift.py`, `manifest.py`, `annotate.py`) are planned under slice LBL-15 and are not in the tree on 2026-10-14; the values here still bind them.

Freeze rule: the bytes of this file become final at the lock commit (section 8). After that the status line above is superseded by the lock record in `docs/qa.md`, and the file is not edited (any change is v2, section 8.6).

**LOCK SHA-256 PLACEHOLDER: the integrator computes it after the lock commit with the procedure in section 8.2 and records it in `docs/qa.md` (row `C9-PREREG-v1`). It is deliberately not written back into this file, because that would change the hashed bytes.**

## 1. Scope and non-goals

1.1 This file pre-registers one target, the candidate models, the frozen analysis configuration, the gates, the shift declaration, what synthetic results may claim, and the lock procedure.

1.2 Target (only this one): `A = 1` iff the older and newer endpoints of a Ghidriff `FunctionMatch` are the same source-level function, one-to-one. The unit is one candidate pair; many-to-many and unparsable matches are `not-comparable` and always abstain (SPEC section 1).

1.3 Non-goals: B (block/edge identity), C (patch mechanism) and D (root cause) are reserved as `null` in the label schema and are not analysed, calibrated or shown. P(vulnerability), security relevance and exploitability are out of scope. Any new target needs a new preregistration.

1.4 Invariants that this file does not weaken: engine scores are never averaged; `contested` is decided by `reconcile`/`evidence`, never by a model; missing match is unknown, not a negative vote; no target binary is executed; nothing is uploaded.

## 2. Data roles and declarations

2.1 Role assignment (spec 4.4): `u = int(sha256(lineage_id + "|" + salt)[:8], 16) / 2**32`, salt `c9-v1`. `u < 0.60` is `dev`, `u < 0.85` is `locked-test`, otherwise `shift-test` (`lineage.py` `ROLE_CUTS = (0.60, 0.85, 1.01)`). Roles are per lineage, never per row. The only override allowed is the shift declaration in 2.3, which must be made before any label is recorded.

2.2 Minimum content per role is in section 6.1 (G0) and section 6.2 (per profile).

2.3 Shift-test declaration (made before labelling; written into `calibration-corpus/1` `split.shift_test_lineages`, whose manifest SHA is recorded in the report):
- (a) Tier R: every lineage whose recipe uses the `msvc` toolchain profile (LBL 7.3), plus one family named in the lock commit. If the MSVC leg (LBL-08) does not run, the first part is empty and the replacement rule in section 9 Q2 applies.
- (b) Tier W (owner only, decision O4): one Windows servicing era and one non-MSVC toolchain set, as named by lineage id in the lock commit. Spec 2.1 gives these as examples; the concrete choice is the owner's.
- A lineage moved into or out of the shift set after any label has been recorded is a protocol violation and creates v2 (section 8.6).
- A shift-test failure is a documented blind spot. It is never a trigger for re-tuning or for a retry.

2.4 Grouping (spec 4.2, 18.10): lineages are the connected components of the union graph over binaries (same `file_name`; same source project for Tier R; at least 15 % overlap of relocation-masked body hashes; same PDB name). Union uses lineage edges only. If everything merges into one component, the overlap threshold is raised in the steps 15, 30, 50 % and the step is recorded; a component is never split to improve balance. Function-identity union: an identity present in more than `hub_max_lineages` lineages is a hub (shared CRT or static code) and is not a union edge; its candidates are reported as the `seen-body` stratum. Value: `hub_max_lineages = 3` [proposal; the code default is `None`, and LBL 7.3 marks 3 as [inf]].

2.5 No candidate from one Ghidriff run crosses folds. Every metric, CV fold, bootstrap resample and threshold resamples by group.

2.6 Labelling guard: the stratified sample list (spec 5.3) is generated and hashed before labelling starts. Locked-test and shift-test labels are not opened for analysis before the lock commit (section 8.1).

## 3. Strata, tiers and what each may count for

| Data | Role | May count toward | May not count toward |
|---|---|---|---|
| Tier R natural | dev | model selection, nested CV, calibrator, tau candidates, ablations, shift rungs 1-3, G1 pipeline check (see 9 Q1) | G2, G3, any display level, ledger `windows-validated` |
| Tier R natural | locked-test | one look for the synthetic H-criteria, only with at least 12 lineages in the role (otherwise `insufficient-data`) | any display level, G2, G3 |
| Tier R adversarial | any | stress table only (spec 2.2) | the headline numbers; pooling with natural |
| Tier W natural | dev | model selection and nested CV only | any claim |
| Tier W natural | locked-test | the only input to G2 and G3 numbers, and to the Tier W G0 minima | any output leaving the owner machine (O1); the aggregate is the only export |
| Shift-test (any tier) | shift | the shift rungs and the H-shift criterion (section 6.3) | tuning of any kind |
| `seen-body` (hub identities) | any | its own stratum table | the headline |
| `indeterminate` | excluded from fitting | counted; if above 5 % of a stratum, the stratum is flagged and the headline gets a worst-case bound with indeterminate read as y = 0 | silent dropping |
| `no-counterpart` | y = 0 | the positive/negative tables | a positive |
| B, C, D | null | nothing | any claim |

Engine scores: each engine's native score is used only as that engine's own feature or scorer. M0 uses the Ghidriff ratio, M0b the rz-diff raw-byte similarity (`R.similarity`), M2 the SPEC-27 index. No pooling across engines or channels; shared-origin evidence (`D_ghidra`) counts once.

## 4. Candidate models (complete; no additions after lock)

- M0: Ghidriff-only rule `ratio >= t`; `t` chosen in dev only.
- M0b: rz-diff raw-byte similarity threshold; defined only for profiles containing R.
- M1: Ghidriff-only L2 logistic regression (nested CV over the G columns).
- M2: the current SPEC-27 index (55/20/8/83) used as a scorer. It tests whether the placeholder has any ranking value.
- M3: multi-family L2 logistic regression per profile (`features/1`, 63 columns for G+B+R, bound 64).
- M4: ablations of M3: leave-one-family-out for each non-G family; drop `D_ghidra`; drop `D_symbols` (including `P.symbols`).
- M5 (gradient-boosted ranker) is excluded from v1. It is not part of this preregistration and cannot ship in a v1 artifact.

Profiles: G and G+R first; G+B and G+B+R once BinExport pairs exist (LBL 7.3). Each profile has its own gate results. The top-level gate is the worst status over profiles (`gates.combine`).

## 5. Frozen analysis configuration

| Parameter | Frozen value | Where it lives |
|---|---|---|
| Label mapping | y = 1 iff A = `same`; y = 0 for `different` and `no-counterpart`; `indeterminate` excluded and counted | spec 5.1, `contracts.LabelRecord.y` |
| Guideline | `g1` as committed in `tools/calibration/guidelines/g1.md` (version recorded in every report) | spec 5.1 |
| Outer CV | k = 5, grouped by identity group | `cv.CVConfig.k_outer` |
| Inner CV | k = 5 | `cv.CVConfig.k_inner` |
| C grid | {0.01, 0.1, 1, 10} | `cv.CVConfig.c_grid` |
| CV seed | 1 | `cv.CVConfig.seed` |
| Standardisation, C, calibrator, OOD statistics | fitted inside training folds only | spec 4.5 |
| Calibrator | Platt by default. Isotonic only if both classes have at least 1000 effective natural weight AND the cross-fitted lineage-clustered Brier gain of isotonic over Platt exceeds one standard error | `cv.choose_calibrator`, `cv.ISOTONIC_MIN_EFFECTIVE` |
| Calibrator data | natural out-of-fold rows only | spec 7.3, 8 |
| Weights | w = 1 / p_incl (sampling, spec 5.3) | spec 9.1 |
| ECE | 15 equal-width bins on [0, 1] | `metrics.ECE_BINS = 15` |
| ECE gate | excess = plug-in ECE minus the null-simulated ECE of a perfectly calibrated model (1000 simulations; null rho = residual lineage ICC, 0 when undefined) | `ece_null.NULL_SIMS = 1000`, `ece_null.RHO_UNDEFINED = 0.0`, spec 18.8 |
| Bootstrap | cluster (lineage) bootstrap, B = 2000, 95 % two-sided intervals; interval method [proposal: percentile, not stated in the spec] | `evaluate` `b_count=2000`, spec 9.2 |
| Seeds | bootstrap 21; ECE null 31; ablation 41; agreement (kappa CI) 11 | `evaluate.py`, `ece_null.py`, `ablation.py`, `agree.py` |
| Tau grid (strict to loose) | 0.999, 0.998, ..., 0.500 (step 0.001) | `threshold.TAU_GRID` |
| Tau-low grid | 0.001, ..., 0.500 | `threshold.TAU_LOW_GRID` |
| Precision target / alpha | 0.95 / 0.05 | `threshold.TARGET_PRECISION` |
| NPV target (tau-low) | 0.90 | `threshold.TARGET_NPV` |
| Learn-then-Test delta | 0.05; exact binomial test at n = floor(n_eff), k = ceil(risk x n_eff) | `threshold.DELTA`, spec 18.7 |
| Effective n | n_eff = Kish n / (1 + (m_bar - 1) x rho); rho = lineage ICC of the error indicator; rho undefined = 1.0 (conservative, for LTT only) | `threshold.RHO_UNDEFINED = 1.0` |
| LTT start | first grid point at which the accepted Kish n reaches 361 (true risk alpha/2 certified at 80 % power); a grid point that selects the same set as its predecessor is skipped; stop at the first non-rejection | spec 18.7, `threshold.ltt_start_n` |
| Locked-test tau | the frozen tau from the dev sequence, evaluated as a one-element sequence | spec 18.7 |
| OOD | flags fitted on outer-train lineages only; Mahalanobis test kept only if the lineage-bootstrap risk-ratio lower bound (flagged vs unflagged at 0.5) exceeds 1, otherwise range and unseen-level tests only (`ood_reduced=true`) | spec 18.11, `ood_fit.py` |
| Ablation reference coverage | 0.5, used only when no tau is certified | `fit.ABLATION_REFERENCE_COVERAGE = 0.5` |
| Display rounding (L2 only) | rounded down to 5 % | spec 12, 18.5 |
| Size limits | label doc 64 MiB / 200,000 functions; wrong-match list 5,000; report 64 MiB; engine deadline 1,800 s; mutants at most 20 per operator and lineage | spec 10 |
| Engine conditions | symbols hidden for all engine runs used for labels and features (`symbol_provenance = none`); orientation explicit (older, newer) and checked (`PT-KA-ORIENT`) | spec 5.2, LBL 7.3 |
| Engines | Ghidriff (symbols off), rz-diff, BinDiff only from supplied BinExport pairs | LBL 7.3 |

## 6. Gates and thresholds (frozen values)

6.1 G0 (dataset minimums, `gates.G0_MIN`): natural labelled candidates at least 12,000; locked-test natural at least 3,000 with at least 150 weighted-effective negatives; at least 40 lineages from at least 10 families; locked-test at least 12 lineages from at least 5 families; Tier W at least 6 families covering kernel, user-mode DLL and driver (`tier_w_kinds`); at least 2 toolchain profiles; at least 1 shift lineage. Inter-annotator: with a second annotator, kappa at least 0.80 and kappa CI lower at least 0.70; without one, test-retest kappa at least 0.80 (decision O2). Indeterminate rate at most 0.05. Symbol-audit error at most 0.02. Adversarial subtypes N1 to N11 each at least 30 items in dev. N12 is a positive hard case (spec 5.4) and is not a G0 minimum.

6.2 Per profile (`gates.PROFILE_MIN`): dev natural candidates at least 2,000; dev `y = 0` at least 100; dev lineages at least 12; `n_groups >= 30` for the bootstrap.

6.3 H-criteria (`gates.L1`, `gates.L2`; spec 12 table, with the amendments of 18.7 and 18.8). Evaluated on locked-test, natural stratum, weighted, cluster bootstrap B = 2000.

| Id | Criterion | L1 (G2) | L2 (G3) |
|---|---|---|---|
| H2 | auto-accept precision, point | >= 0.95 | >= 0.95 |
| H2 | precision CI lower | >= 0.90 | >= 0.93 |
| H2 | precision CI width | <= 0.10 | <= 0.06 |
| H2 | Learn-then-Test certified at frozen tau | required | required |
| H3 | coverage, point / CI lower | >= 0.40 / >= 0.30 | >= 0.50 / >= 0.40 |
| H1 | ECE excess over null, point / CI upper | not required | <= 0.03 / <= 0.05 |
| H1 | calibration slope CI contains 1; intercept CI contains 0 | not required | required |
| H1 | Brier skill vs prevalence, CI lower | > 0 | > 0 |
| H4 | FDR reduction at equal coverage vs best of M0, M0b, M1, M2 (paired bootstrap) | CI lower > 0 | CI lower > 0 and relative reduction >= 0.25 |
| H5 | each stratum/subtype/lineage family with weighted n >= 200: precision CI lower | >= 0.85 | >= 0.88 |
| shift | precision at frozen tau on the shift set | reported | >= 0.90, else numeric display restricted to the calibration domain with explicit text |
| OOD | flagged-subset error above unflagged (risk-ratio CI lower > 1), or hard flag reduced to range/unseen only | required | required |
| ablation | contribution of each non-G family reported; a family that does not improve H4 is removed from the profile | required | required |

6.4 Status values: `pass`, `fail`, `insufficient-data`. Insufficient data is never a pass and is treated as a failure for the gate that needs it. A missing input is `insufficient-data`.

6.5 G1 (pipeline on Tier R): the code evaluates G1 with the L2 thresholds (`gates.evaluate_gates(pipeline=...)`). Which Tier R split G1 uses is open (section 9 Q1). G1 is a pipeline-health result on synthetic data. It never changes `display_level()`, which needs G0 and G2 (or G0, G2 and G3) on a bundled artifact (spec 18.2).

6.6 G2 absorbs G0; G3 absorbs G2. G3 also requires: a confirmed second independent annotator (O2), a reproducibility check (stable report SHA on re-run from the manifest), owner sign-off recorded in `docs/qa.md`, a frozen-EXE smoke test that loads the artifact, and the independence caveat in the UI text for any profile whose engines share `D_ghidra`.

6.7 Expiry: an artifact expires 12 months after creation (at most 366 days) or on a new engine major version in its domain, and falls back to L0 until re-validated (spec 12, `artifact.py`).

## 7. What synthetic results may claim

7.1 Tier R and other synthetic results (generated worlds, open-source test builds) may support only the statements below. They may set a validation-ledger entry to `synthetic-validated` (with `tier-r` evidence and a report SHA). They never set `windows-validated`, never raise the display level, and never produce a numeric display.

| Licensed (with lineages, tool versions and tiers stated) | Not licensed |
|---|---|
| Engine behaviour on source-controlled changes in permissively licensed C code built by clang/lld, mingw gcc/clang and, when the Windows leg runs, MSVC `cl` (stripped x64 DLLs, O2, `/OPT:NOICF`): per-label pairing precision and recall, address-noise false-lead rate, planted-change recall per operator class | code built with whole-program or profile-guided optimisation, control-flow guard, ICF, hot/cold splitting, or C++ with WIL/STL; Windows function-size and call-graph distributions; servicing updates with hundreds of changed functions; any Windows system file |

7.2 Required wording (spec 18.* and LBL 7.8): "Tested on test builds of open-source libraries (N code sets, compilers, tool versions). Not tested on Windows system files." Forbidden in any output: "accurate", "validated for Windows", any percentage derived from synthetic data, "confirmed by two engines" where `D_ghidra` is shared.

7.3 `TIER_R_CLAIM` ("Measured on test builds of open-source code; says nothing about Windows system files") is written into every Tier R `calibration-report/1` with `dataset.tier = 'R'`.

## 8. Lock procedure

8.1 Preconditions for the lock commit: (a) the Tier R corpus manifest verifies (`corpus.py verify`) and the corpus guard passes; (b) the shift declaration of 2.3 is in the manifest and the manifest SHA is noted; (c) guideline `g1` is committed at its final version; (d) this file has its final bytes; (e) the owner's sign-off on the O3 targets is recorded in `docs/qa.md`; (f) the stratified sample list is committed with its hash (spec 5.3). No locked-test or shift-test label has been analysed.

8.2 Hash: after the lock commit `C`, compute the SHA-256 of the file bytes as stored in git, for example `git show C:docs/plans/c9-preregistration-v1.md | sha256sum` (lowercase hex). Check first that `.gitattributes` applies no end-of-line conversion to this path, so the bytes are LF. Record the value in `docs/qa.md` with the commit `C`, the date and the owner sign-off. The hash covers the placeholder line above as committed.

8.3 Use: `tools/calibration/run_locked_test.py` `run_locked_test(corpus_dir, prereg_sha, evaluate)`. The code checks the format only: `prereg_sha` must match `[0-9a-f]{64}` or `LockedTestError` is raised. It then creates `locked-test-<sha>.lock` in the corpus directory (`PATCHTRACE_CALIB_ROOT`, outside the repository) with exclusive create, before `evaluate()` runs. A second call with the same SHA raises `LockedTestError`. A crash during evaluation still leaves the receipt, so it counts as the one look.

8.4 Recording: the SHA goes into the report field `prereg_sha256` (`contracts.CalibrationReport`, `report.make_report`), which is covered by `report_sha256`. For a numeric artifact it goes into `evidence.preregistration_sha256`; `artifact.py` requires the field to be present for `numeric-ok`, but does not compare its value with any file.

8.5 Not checked by code today (gaps, not yet built): (i) that the recorded SHA equals the SHA of this file; (ii) that the section 5 and 6 values equal the constants in `cv.py`, `threshold.py`, `gates.py`, `ece_null.py` and `metrics.py`; (iii) that the section 2.3 lists equal the manifest. Proposed (not built): P-1, a dev command `prereg verify` that recomputes the SHA and compares it with the `docs/qa.md` row; P-2, a repository test that compares the named constants with this file. Both need their own slice and are integrator decisions.

8.6 Amendments: any change to a frozen value, role or declaration after any locked-test or shift-test look creates `docs/plans/c9-preregistration-v2.md` with a new SHA and a new lock. The v1 result stays in the report, with the change listed in the report's `amendments` field. Before the lock commit, ordinary edits are allowed; no lock exists yet.

8.7 A SHA with a receipt is spent. A second run for that SHA is refused by design. A failed or aborted run is reported as it happened and is not retried under the same SHA.

8.8 Tier W locked-test runs happen only on the owner's machine (O1). Their receipt and the aggregate are recorded in `docs/qa.md` as externally produced evidence, labelled as such.

8.9 Existing tests that cover this section: `tests/test_calibration_tools.py::test_locked_test_runs_once_per_preregistration` (single use per SHA); `tests/test_calibration_runtime.py` (artifact `numeric-ok` evidence checks). Gaps: 8.5 (i) to (iii) have no test.

## 9. Open questions (each has a recommended default; the default applies unless the owner decides otherwise)

- Q1 (conflict). Spec 4.4 and 12 evaluate G1 on locked-test data, while LBL 7.3 makes every Tier R lineage dev. Tier R has about 38 lineages, so a 25 % locked role would hold about 9 or 10, below the 12 that `gates` requires for a locked profile. Default [proposal]: G1 is computed once from out-of-fold predictions over all Tier R lineages under the nested CV of section 5, labelled synthetic. A Tier R locked-test look happens only if its role has at least 12 lineages; otherwise G1 is reported as `insufficient-data` for the locked form.
- Q2 (empty shift set). If the MSVC leg does not run, rule 2.3(a) is empty. Default [proposal]: the Tier R shift test uses one non-MSVC toolchain split (gcc against clang), declared in the lock commit, and the ladder rung 2 is labelled accordingly.
- Q3 `hub_max_lineages`. Default 3 [inf, from LBL 7.3]. The code default is `None`, so the value must be passed explicitly.
- Q4 Bootstrap interval method. Default [proposal]: percentile intervals at B = 2000. BCa is not used.
- Q5 Where the H5 filter "weighted n >= 200" is applied. `gates._level` takes `strata_min_lo` as an input and does not apply the filter itself. Default [proposal]: the evaluation step applies it; strata below 200 are `insufficient` and abstain by default (spec 12).
- Q6 H4 comparator. Spec 12 names M0 and M1; spec 18.9 adds M0b and M2. Default: the amended set (M0, M0b, M1, M2), as the code tests.
- Q7 ECE and LTT rho conventions differ on purpose: ECE null uses 0 when undefined (the strictest for the ECE null), LTT uses 1.0 (the most conservative design effect). Both are kept as in the code (spec 18.7, 18.8).
- Q8 Owner decisions still open: O1 (legal: Tier W labels and parameters), O2 (second annotator), O3 (targets and display rounding), O4 (budget, Tier W families, Tier W shift lineages). Until O2 is answered, G3 cannot pass (`gates.evaluate_gates` requires `second_annotator`).

## 10. Test and acceptance plan

- Automated, hermetic: the existing tests of section 8.9, plus the gate tests for G0, L1 and L2 boundaries (`gates` module) and the Learn-then-Test tests (`threshold` module). The P-1 and P-2 tests of section 8.5 are proposals.
- Not automated: the owner's sign-off, the Tier W locked-test run, the second-annotator agreement, the frozen-EXE smoke test. These are listed separately in `docs/qa.md` and never count as done by this file.
- A synthetic G1 pass is not an acceptance of the product claim. Acceptance of any display level requires the section 6 gates on real locked-test data and the owner's sign-off.

## Integrator asks

1. After the lock commit, compute the SHA as in section 8.2 and record it in `docs/qa.md` (row `C9-PREREG-v1`). Do not edit this file to add the value.
2. Add the row for this file to `docs/specs/REGISTRY.md` (not edited by this worker).
3. Confirm `.gitattributes` does not end-of-line-convert `docs/plans/c9-preregistration-v1.md`.
4. Decide P-1 and P-2 (section 8.5) and whether they become a slice.
5. Decide Q1 and Q2 before the lock commit; they change which data is locked.
6. Tick `tasks/todo.md` C9-0 and `docs/plans/hard-problems/calibration-plan.md` step 1 only after owner sign-off (O3).
