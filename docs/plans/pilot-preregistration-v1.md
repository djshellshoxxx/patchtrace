# PIL-D1 evaluation preregistration v1 (patch-intent localization)

Status: preregistration, frozen by committing this file. Record its SHA-256 in every PIL-D1 report. Source: `docs/specs/program-e/PIL-integration-plan.md` section 9 (slice PIL-D1) and section 5; code under test: `src/patchtrace/pilot/` (contract `pilot/1`, `TIERS_VERSION = 1`, rule table `pilot-rules/1`). Statistics reuse `tools/calibration/bootstrap.py` and the single-use locked run of `tools/calibration/run_locked_test.py`.

Current state (checked on this branch): `tools/calibration/pilot/` does not exist yet. D1 needs PIL-B2 (the engine), LBL M2/M5 (known-answer CVE cases) and, for typed arms, SPEC-31 S3. This document fixes the protocol so the slice builds against it. Any change after the first look at locked-test data creates `v2`, and the v1 result stays in the report.

## 1. Question and unit
Does the patch-intent leads list (P-full) put the patch-bearing function earlier than the baselines a reviewer already has, without losing recall? Unit: one case = one older/newer pair plus one advisory (CVE) whose fix functions are known from source (`label_source` `fix-diff` or `source-diff`). Truth set per case = the declared patch-bearing functions (median case: 1). Orientation is explicit (older, newer); an orientation-swapped run is a negative control and is not scored. Lineage = project (`lineage.assign_roles`); metrics and resampling are by lineage.

## 2. Arms
Each arm runs twice, symbols hidden and symbols visible (locality, name-based evidence, exists only with names). Both are reported; the headline uses symbols hidden.

| Arm | Ordering |
|---|---|
| B0 | Ghidriff `modified` functions in attention order |
| B1 | unified-engine material changes plus review order (unified-engine spec 05 s2.6) |
| B2 | attention order plus B3 contextual reranking |
| P-adv | pilot with advisory-side channels only |
| P-code | pilot with code-side channels only |
| P-full | pilot with all channels (tier, then tie-aware order; no numbers) |
| LOCO | P-full minus one channel each (leave-one-channel-out ablation) |

The best baseline is the best of B0, B1, B2 per metric, chosen on `dev` only and frozen before the locked run.

## 3. Metrics
hit@1, hit@3, hit@5, hit@10 (any truth function in the top K); recall@K; false leads before the first hit (non-truth functions ranked above the first truth function); tie-aware worst-case rank (a tie block counts at its last position); abstention coverage (share of cases where P-full returns leads rather than `not-assessed`); runtime and peak memory. The median case has one patch-bearing function, so hit@1 and hit@3 are the headline descriptive metrics. Pilot tiers are ordinal and are never converted to probabilities; no calibrated-confidence claim is made.

## 4. Data roles and leakage
Roles come from `lineage.assign_roles` (about 60 percent dev, 25 locked-test, 15 shift-test, salt fixed in the corpus manifest). Dev: rule and configuration choices, best-baseline choice. Locked-test: one look. Advisory fixtures live in `tools/calibration/pilot/advisories/<CVE>.json`. Rule-table authors must not read locked-test cases. Mutated variants and A/A pairs inherit their base lineage so a function identity never crosses roles. No Microsoft binary, PDB or Winbindex-derived label enters the repository; Tier W cases, if any, stay local and are reported by hash.

## 5. Statistics
Lineage cluster bootstrap, B = 2000, `det_uniform`-seeded, two-sided 95 percent percentile intervals: resample lineages with replacement, recompute totals over cases, no refit. Paired differences use `paired_delta` on the same resamples. Secondary: leave-one-lineage-out jackknife (worst lineage, largest influence), per-arm, per-channel and per-symbols-condition tables. Fewer than 30 lineages in the evaluated role makes intervals anti-conservative and the gate cannot pass.

## 6. The pre-registered gate (G-PIL)
Evaluated once on locked-test, symbols hidden, P-full versus the best baseline:
1. the lower 95 percent bound of the relative reduction in total false leads before the first hit is at least 20 percent (totals over cases, resampled by lineage); and
2. the lower bound of the recall@10 difference (P-full minus baseline) is at least 0; and
3. at least 30 held-out lineages are available.

`pass` needs all three. Condition 1 or 2 failing with 3 met is `fail`. Condition 3 unmet is `insufficient-data` regardless of point estimates. The committed corpus has about 31 lineages (20 projects plus 11 authored suites) with about 8 locked, so the gate is expected to stay `insufficient-data` until LBL M1/M2 roughly quadruple the catalogue. `insufficient-data` is never reported as pass or fail and never as a claim of benefit.

## 7. Stopping and forbidden practice
- `run_locked_test` writes its receipt before evaluating and refuses a second run for this preregistration SHA; a crashed run still counts.
- No arm, metric, K, channel, rule or case may be added, dropped or re-tuned after the locked look. Cases are excluded only by rules written beforehand (build failure, truth function absent in both builds), and every exclusion is counted in the report.
- The shift-test result is reported separately; failure is a documented blind spot, not a retry trigger.
- A failed or insufficient gate leaves the Leads panel wording unchanged (ordinal leads, `strong` unreachable); the report states the blind spots.
- Fallback if inputs are partial: unit and ablation tables without a gate claim.

## 8. Outputs
Deterministic `report.json` (same inputs, byte-identical) and rendered `report.md`: preregistration SHA, corpus manifest SHA, tool git SHA, per-arm metric tables with intervals, ablation deltas, gate status with the three conditions, exclusions, blind spots. This is automated evidence only; owner-only checks are outside this protocol.
