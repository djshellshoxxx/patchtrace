# LBL-26 pre-lock audit of the Tier R training pipeline

Date: 2026-10-15. Base: `86fde6a` (branch `claude/instance-d-gui`). Scope: `tools/calibration/**` against `docs/plans/lbl-remaining-plan.md` sections 4.1-4.7 and `docs/plans/c9-preregistration-v1.md` (draft, not locked). Read: `cv`, `threshold`, `lineage`, `gates`, `ece_null`, `metrics`, `stats`, `bootstrap`, `evaluate`, `ablation`, `baselines`, `fit`, `guards`, `label`, `sample`, `tier_r/{manifest,evaluate,labeler,bodyhash,annotate,shard}`, `evalcore/**`, `channels/**`, `mutations/{labels,coverage}`. Not read line by line: `mutations/{operators,ops_more,engine}`, `tier_r/{build,factory,csrc,debuginfo,pe,toolchain,msvc,fetch}`, `ood_fit`, `mathcore`, `tier_w/**`, `pilot/**`.

`train.py`, `shift.py`, `report.py` and `schemas.py` of instance C are not in this tree (`report.py` and `tier_r/schemas.py` exist but belong to C). Findings that need their code are tagged **for C**.

Severity: High = can make a gate or a headline wrong; Medium = anti-conservative or misleading, local fix; Low = hygiene or latent.

## Verified clean (no finding)

- Constants equal the preregistration (`tests/test_prereg_constants.py`, re-read by hand): k 5/5, C grid, seeds 1/21/31/41, 15 ECE bins, 1,000 null sims, tau grids, alpha/delta/NPV, `RHO_UNDEFINED` 1.0 (LTT) and 0.0 (ECE), salt `c9-v1`, role cuts, `G0_MIN`, `PROFILE_MIN`, `n_groups >= 30`.
- Standardisation, C, calibrator, OOD statistics and weight clip are fitted on training rows only (`cv.nested_cv`, `final_model`, `training_weights`); `_check_disjoint` guards every fold.
- Determinism: no clock, locale, `random` or `hash()` in the audited paths; every set is sorted before use; `det_uniform` is platform independent; JSON is canonical. `run_locked_test` reads the clock only for the receipt stamp.
- No averaging across engines or channels: `evalcore/report.py` is per engine, `build_blocks` raises on mixed populations, `channels/*` macro-average inside one pack only.
- Unknown is not a negative vote in `evalcore/identity.py` (abstained), `channels/*` (None is left out, not zeroed) and `ece_null`/`gates` (missing input is `insufficient-data`).
- `gates._level` needs `n_groups >= 30` and `dev_lineages >= 12`; `evalcore.boot.non_inferior` and `leadlist` refuse a claim when `anti_conservative`.

## Findings

| id | sev | file:line (at 86fde6a) | status |
|---|---|---|---|
| LBL26-01 | High | `tier_r/annotate.py:79` | fixed |
| LBL26-02 | High | `guards.py:117-160`, `lineage.py:161` | fixed (guard); wiring **for C** |
| LBL26-03 | Medium | `channels/leadlist.py:86,90` | fixed |
| LBL26-04 | Medium | `tier_r/manifest.py:71` | fixed |
| LBL26-05 | Medium | `fit.py:165` | fixed |
| LBL26-06 | Medium | `tier_r/evaluate.py:309`, `tier_r/shard.py:607` | fixed |
| LBL26-07 | Low | `tier_r/manifest.py:91` | fixed |
| LBL26-08 | Low | `guards.py:144-148` | fixed |
| D-01 .. D-12 | see below | | deferred |

### LBL26-01 (High) The natural stratum holds only positives

- Where: `tier_r/annotate.py:79` (`candidates`).
- Evidence: `sampling` was `natural` iff the candidate was a truth pair (`key in truth`), and `adversarial` for every other engine-proposed pair, whatever the pair's stratum. A truth pair is `answer = 'same'` by construction, so every natural row had y = 1 and every engine mistake (`different`, `no-counterpart`) was adversarial. The test `test_candidates_answers_are_constructed_from_truth` pinned this. The spec says the opposite (LBL-integration-plan line 114: natural = every engine candidate of release, CVE and control pairs; adversarial = mutation, noise, identity-negative suites). Consequences: precision at any tau is 1 by construction, the calibrator and `choose_tau` (natural rows only) see one class, `validate_rows` or the Platt fit fails or degenerates, the G0 minimum of 150 weighted-effective negatives can never be met, and truth pairs no engine proposed (no feature vector exists for them) were counted as natural candidates.
- Fix (done): `sampling_of`. Natural iff an engine proposed the pair and the document stratum is `release`, `cve` or `control`. Engine candidates of `mutation`, `noise`, `aa`, `authored` are adversarial. A truth pair no engine proposed, and every pair in a label-only run, is `adversarial` with stage `known-answer-truth`. Test: `tests/test_lbl26_audit_fixes.py` (`test_engine_candidates_take_the_stratum_of_their_pair`, `test_natural_stratum_contains_negatives_when_an_engine_proposed_them`, `test_truth_pair_no_engine_proposed_is_never_natural`); `test_tier_r_eval_corpus.py` expectation corrected.
- For C: a label-only `annotate` run now yields no natural rows (honest: `insufficient-data`). The training run must annotate with engine outputs. Existing `calibration-labels` files written before this fix carry the wrong `sampling` and must be regenerated (the log is unchanged, `sampling` is recomputed at consolidation).

### LBL26-02 (High) Function identities shared across roles are not audited

- Where: `guards.audit_manifest` checks project, PDB name and image hash across roles, never function-body identity; `lineage.shared_identities` is a helper no pipeline code calls. Roles are assigned per lineage (`lineage.assign_roles`) while `identity_groups` merges lineages that share a non-hub body. Two lineages merged for CV can sit in different roles, so a body seen in dev is in locked-test or shift-test. This is the leakage the plan (4.3) demands be zero.
- Fix (done): `guards.audit_identity_roles(cands, roles, hubs=...)` returns one violation per non-hub identity present in more than one role, and one per candidate whose lineage has no role (fail closed). Hubs are reported through `seen_body`, not as violations. Tests: `test_identity_shared_across_roles_is_a_violation`, `test_hub_identity_across_roles_is_reported_as_seen_body_not_a_violation`, `test_identity_audit_missing_role_fails_closed`.
- For C: call it in `train.py` after `identity_groups(..., hub_max_lineages=3)` with the hub set it returns, and stop on a non-empty result (plan 4.7 item 3). If it fires, merge the lineages' roles (assign the role per identity group), never split the group (PREREG 2.4).

### LBL26-03 (Medium) The A/A false-lead gate passes on a pool too small to show the rate

- Where: `channels/leadlist.py:86,90`. `aa_false_lead_rate` was `flagged/pool <= 0.001`. Zero flagged in 100 functions passed, although the exact one-sided 95 % upper bound of 0 in 100 is 3 %. Plan 4.4 asks for the Clopper-Pearson bound so "0 of n" is not read as "0".
- Fix (done): `stats.clopper_pearson_upper`; `_aa_condition` is `False` when the observed rate exceeds 0.1 %, `True` only when the upper bound is within 0.1 % (about 2,995 clean functions), otherwise `None` (verdict `inconclusive`). Tests: `test_clopper_pearson_upper_matches_closed_forms`, `test_aa_false_lead_gate_uses_an_upper_bound`; three leadlist tests updated to the new rule.

### LBL26-04 (Medium) The same image can belong to two lineages

- Where: `tier_r/manifest.py:71`. The guard against an image in two lineages keyed on `binary_id(project, sha256)`, which contains the project, so identical content built under two projects (or two lineage ids of one project) passed. `audit_manifest` catches it only when the two lineages happen to get different roles.
- Fix (done): `image_owner` keyed on the image hash; a second lineage raises `ManifestError`. Test: `test_manifest_rejects_the_same_image_under_two_projects`. The lineage rule itself stays "lineage = project" (no merge, no split).

### LBL26-05 (Medium) `dev_neg` counts weight, not rows

- Where: `fit.py:165`. `evaluation['dev_neg']` was the sum of inverse-inclusion weights of natural negatives. Ten negatives of weight 20 read as 200 and pass `PROFILE_MIN['dev_neg'] = 100`. The prereg asks for at least 100 negatives.
- Fix (done): `fit.dev_negatives` returns the Kish effective n of the natural negatives (equals the row count at equal weights). Test: `test_dev_negatives_use_the_effective_count`.

### LBL26-06 (Medium) Markdown reports print precision and recall without the honest-scope line

- Where: `tier_r/evaluate.py:309`, `tier_r/shard.py:607`. Both renderers print identity precision, recall and FP rate per stratum with no statement that these are test builds of open-source code. PREREG 7.2/7.3 require the claim in every Tier R report; `scope_ids` is only in the JSON.
- Fix (done): both reports start with a quoted `TIER_R_CLAIM` ("Measured on test builds of open-source code; says nothing about Windows system files."). JSON and `report_sha256` are unchanged. Test: `test_markdown_reports_carry_the_tier_r_claim`.

### LBL26-07 (Low) `SPLIT` constant shared by reference

- `tier_r/manifest.py:91`: `dict(SPLIT)` is shallow, so appending a shift lineage to one manifest mutated the module constant and every later manifest. Fixed with a copied list. Test: `test_manifest_split_declaration_is_not_shared_between_documents`.

### LBL26-08 (Low) `audit_manifest` was silent on too few lineages

- `guards.py:144-148`: only an empty role warned. A locked-test role with 9 lineages (about 25 % of 38, PREREG Q1) or a corpus under 30 lineages gave no signal. Added warnings (not violations, so tiny test corpora still load): locked-test under 12, total under 30. Test: `test_audit_warns_about_small_locked_role_and_anti_conservative_total`.

## For C (`train.py`, `shift.py`, `report.py`, `schemas.py`)

- C-1 Rows: `group` must be `IdentityGrouping.group_of`, never the lineage. Call `identity_groups(..., hub_max_lineages=3)` with the value passed explicitly (PREREG Q3; the code default is `None` and silently disables hubs). Run `guards.audit_identity_roles` (LBL26-02).
- C-2 Label mapping: y = 1 iff `same`; `different` and `no-counterpart` y = 0; `indeterminate` excluded and counted per stratum. Above 5 % in a stratum: flag the stratum and add the worst-case result with indeterminate read as y = 0 (PREREG s3; plan 4.5). Report point and bound side by side. `tier_r/evaluate.py` cannot do this itself (its `ignored_predictions` mixes ambiguous with unlabelled runtime functions), so the bound belongs in the row-level report.
- C-3 Only rows with `sampling.stratum == 'natural'` enter the calibrator, tau and every headline; adversarial rows stay in their own table.
- C-4 Imputation: `fit.medians`/`fit.impute` (currently unused) take medians over the rows they are given. If used before CV they are fitted outside the training folds. Fit them inside each outer-train part, or leave missing features to the family flags.
- C-5 G1 optimism: `choose_tau` is run on the same out-of-fold rows on which precision, coverage and their intervals at that tau are then reported (`fit.run_pipeline`, `evaluate.evaluate_profile`). The point estimate and CI lower bound are therefore selected-on-the-same-data; Learn-then-Test controls the family error, not this selection effect on the interval. Either select tau inside the outer folds and report the held-out outer-fold precision, or label G1's precision as dev-selected. PREREG Q1 makes this the only Tier R number, so decide before the lock.
- C-6 Stop-and-ask in code: fewer than 30 lineages in the evaluated population, fewer than 12 in a locked role, any `audit_manifest` violation, and a non-identical `report_sha256` on the determinism re-run (plan 4.7 items 2-3). `gates` enforce 30 and 12 only as inputs; nothing halts the run.
- C-7 Print `TIER_R_CLAIM` in the Tier R training report; G1 never changes `display_level()`; never show a Tier R percent as Windows accuracy.
- C-8 Bootstrap intervals drop resamples whose statistic is undefined (`bootstrap._interval`; `undefined` is reported but no gate reads it). Surface it, and refuse a headline interval if more than a few percent of resamples are undefined.

## Deferred (no fix in this slice)

| id | sev | where | note |
|---|---|---|---|
| D-01 | Medium | `fit.py` / `evaluate.py` | = C-5. Needs a design decision (nested tau), touches C's report. |
| D-02 | Medium | `channels/capabilities.py:66`, `rules.py:58`, `strings.py:49` | `no_violations`, `no_false_positives`, `aa_false_adds_zero` are True after one clean pair or image. Same class as LBL26-03, but no numeric limit exists in the plan to size the pool against. Needs an owner-set minimum or a bound. |
| D-03 | Medium | `bootstrap.py:34`, `evalcore/boot.py:46` | = C-8; also `gates._level` does not read `undefined`. |
| D-04 | Low | `tier_r/labeler.py:174` | A declared change that the evidence labels `ambiguous` gets `check = 'ok'` (counted as agreement). Plan 4.5 says "0 unexplained disagree"; an ambiguous row has a reason, so this is consistent but overstates verification. Changing the value set needs a contract change. |
| D-05 | Low | `tier_r/labeler.py:212`, `mutations/labels.py:63` | Plan 4.5 says cosmetic operators must not change masked bodies "by the same rule", but code and `test_cosmetic_never_induces_ambiguity` deliberately accept a cosmetic target whose masked body differs (inline-toggle, reorder-defs). Product decision: either narrow the cosmetic set or drop the plan sentence. Not changed. |
| D-06 | Low | `lineage.py:132` | `hub_max_lineages` default `None` (pinned by `test_prereg_constants.py` and PREREG Q3). Make it required after the lock decision. |
| D-07 | Low | `baselines.py:34-41` | M2 reads a missing `X.agree_B`/`X.agree_R` column as 0 (a negative vote); with both absent it is a constant and a weak baseline for H4. Profiles without B and R should omit M2, not zero it. |
| D-08 | Low | `tier_r/shard.py:485` | `_engine_status` reports `partial` when the states are `blocked` and `failed` with no completed run. |
| D-09 | Low | `tier_r/evaluate.py:103` | Duplicate predictions for one (old, new) keep the first in provider order; claimed order independent, but the `changed` flag of a duplicate could differ. `to_engine_pairs` does the same. |
| D-10 | Low | `evalcore/report.py:206` | `few-lineages` counts lineages over all strata; a stratum with 3 lineages still gets its own `anti_conservative` interval flag, so no number is unflagged, but the report-level scope id can read "enough". |
| D-11 | Low | `tier_r/bodyhash.py:53` | Immediates inside `[image_base, image_end)` are masked as `R`. Harmless at base 0x140000000, but a PE with a low base (0x10000000) can mask a real constant change into `address-only`, which downgrades to `ambiguous` (safe direction). |
| D-12 | Low | `tier_r/manifest.py:19`, PREREG 2.3 | `SPLIT.shift_test_lineages` is empty; the shift declaration (and PREREG Q2 fallback) must be written into the manifest before any label is analysed. The manifest builder cannot decide it. |

## Test and lint evidence

Focused: `tests/test_lbl26_audit_fixes.py` (21 tests, red before the fixes: import and assertion errors) plus the affected suites (`test_tier_r_eval_corpus/cli/report/metrics/shard`, `test_calib_channels_leadlist`, `test_calibration_cv/tools/metrics/runtime/scope`, `test_prereg_constants`, `test_evalcore_report`): 312 passed, 2 failed. The two failures exist on the base commit and are unrelated: `test_tier_r_eval_cli.py::test_evaluate_with_imports_scores_and_exits_0` and `test_tier_r_shard.py::test_workflow_structure_and_pins` (the latter asserts the workflow job list and trips over the advisory `msvc-advisory` job). `hypothesis` is not installed here, so `test_calibration_hardening.py` and `test_evalcore_stats.py` could not be collected. `ruff check tools/calibration` and the touched tests pass.
