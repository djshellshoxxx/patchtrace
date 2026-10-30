# R5 / 04 — Incorrect matches, OOD, confidence policy, artifacts and GUI

**Status:** engineering design and failure taxonomy based on inspected implementation, SPEC-27/28/31, R1/R3 progress and statistical literature. All issues lacking a red regression or measured natural sample are marked **audit candidates**. No new Windows measurements or calibrated probability claims.

## 1. Prioritized failure taxonomy

| Failure ID | Symptom and distinguishing fixture | Root cause to test | Expected behavior | Regression and measurement |
|---|---|---|---|---|
| FP-01 | High-scored wrong pair sharing function names | Truncated/public/static/duplicate name, import stub, thunk or alias collision | Contested/unknown or wrong after adjudication, not auto-accept | Two unique source functions with same symbol, + one nonunique version; count wrong accepted in name tier |
| FP-02 | High-scored wrong pair with identical masked bytes | Overbroad relocation/immediate mask erases changed address or referenced object | Require referent identity before any equality proof; review otherwise | Swap existing global and callee while preserving instruction shape/length |
| FP-03 | Wrong match in copied CRT/runtime/static library | Near-duplicate bodies treated as independent evidence or wrong lineage | One lineage/seen-body/excluded from primary headline | Two unrelated projects with identical vendored static object; leakage guard must witness |
| FP-04 | Wrong residual assignment despite high structural score | One-to-one greedy resolver swallows alternative conflict, missing candidate margin | Preserve alternatives and contest flag; no certainty boost by assignment | 2x2 candidate graph, equal high candidates, forced residual |
| FP-05 | Two "independent" engines agree incorrectly | Ghidriff and BinDiff share Ghidra export/algorithm/bytes | One dependency component; no vote-count probability | Same wrong pair from both Ghidra-based engines, plus truly independent byte-source negative control |
| FP-06 | Auto-match a function actually split/merged/inlined | Forced 1:1 despite N:M source relationship | Abstain or ambiguous with group evidence | Multi-function inline/split fixtures with independent source truth |
| FP-07 | Wrong mapping propagated from one hub call | Unverified callgraph neighbor used as unique anchor | No higher tier without disjoint evidence and zero conflicts | One wrong hub mapping and two conflicting callers |
| FP-08 | Small identical imports and compiler thunks pair across unrelated versions | Structural/size heuristics confuse generic generated functions | Subtype-aware lower tier or review | Multiple equal-size empty functions/exports/thunks |
| FP-09 | Match right, materiality wrong | L1 correctness incorrectly interpreted as L2 equivalence | Separate L2 review/material/unknown; preserve L1 | Changed guard, signed comparison, callee, EH, frame, CFG polarity |
| FP-10 | Missing counterpart marked "wrong" from absent secondary record | Missing engine is treated as a negative observation | No vote, no model answer for one-sided | Remove BinDiff input while retaining unchanged Ghidriff pair |
| FP-11 | Incorrect confidence under new engine major or BinExport producer | Score scales/feature mechanisms changed | Domain mismatch -> abstain/ordinal pending compatibility | Clone baseline with bumped version, malformed/missing version, IDA vs Ghidra producer |
| FP-12 | False "in-domain" on packed or obfuscated binary | Known compiler metadata but radically different code distribution | OOD review; never extrapolate accuracy | Control-flow flattening, huge basic block, stripped symbols, packer-signature fixture |
| FN-01 | Real match wrongly low-scored under optimization | Correct source function radically transformed | Lower-tier candidate/review rather than wrong | O0/O2/O3, inlining, LTO, mergefunc and hot/cold control |
| FN-02 | Correct source match rejected after relocation/layout | Byte similarity ignores address remapping | Resolve mapped targets before lowering evidence; maintain ambiguity | Same function rebuilt at new RVA with identical logical targets |
| FN-03 | Correct pair rejected because secondary engine absent | Family missingness imputed as evidence against pairing | Missing family flag, model profile fallback/abstain, not lower raw confidence | Remove secondary evidence with same ground truth |
| FN-04 | Correct pair rejected because toolchain unknown | Unsupported categorical group extrapolated or overpenalized | OOD state + analyst review; distinguish unknown from incorrect | Confirm source mapping but hide compiler identification |
| CAL-01 | Severe probability overconfidence on uncommon function group | Model trained on easy examples or duplicate symbols | Disabled numeric; subgroup analysis | Per-family error vs probability reliability |
| CAL-02 | Reliability change after engine update | Feature schema/version shift | Frozen canary, expiry, revalidation | Exactly version-pinned canary before/after |
| CAL-03 | False OOD hard flags | Tail distribution or Mahalanobis under heavy tails | Evaluate error enrichment and reduce OOD model if unsupported | Correct large functions; flag confusion/coverage |
| CAL-04 | Positive score for nonfinite input | Malformed direct FeatureRow bypasses earlier normalization | Fail closed at inference boundary | nan/inf/huge features, independent of extractor |
| CAL-05 | False promotion or mislabelled report | Self-declared gate passes assumed review conditions | Reject untrusted/missing external evidence | Forged report, swapped digest/owner state, missing frozen Windows smoke |
| CAL-06 | Prereg single-use violated across hosts | Only local path receipt, SHA not checked against trusted commit | External ledger and preserved failed attempt | Two directories with same prereg SHA, no second promotion |

For each reproducible case save: unique case ID, fixture source license/commit and SHA, allowed redistribution class, exact old/new PE and source identity, compiler/engine versions, expected correspondence and L2 class separately, candidate/alternative list, native score texts, evidence dependency graph, model/feature schema, flags, actual verdict, root cause, severity and before/after pair-level deltas. Never modify truth to make a model look better. Write a red regression first, then implement the smallest correction and demonstrate no new false negative on the other controls.

## 2. Explicit policy precedence

A new calibrated result is an additional **derived read model**. Its existence must never silently change the underlying unified match or overwrite the raw evidence.

Recommended fail-closed ordering:
1. Validate current project/snapshot identity, two binary SHA values, result revision and matching schema. A stale or mixed result shows ordinal/raw status only.
2. Inspect user manual correction state, N:M group type, one-sidedness, hard contest, and impossible mapping. A model never overrides manual ownership; contested and ambiguous remain analyst decisions.
3. Check a loaded, trusted, schema-valid, non-expired model for the exact evidence profile and source domain, with all required Tier W and review/CI gates. No model -> ordinal.
4. Enforce engine-version, producer, architecture, compiler/symbol regime, binary class and model-scope compatibility. Hard incompatibility -> abstain. Record missing evidence independently of zero-valued scores.
5. Compute validated feature vector and per-feature missingness; guard all finite numbers at inference boundary. If row profile or model feature names disagree, fail closed.
6. Evaluate validated OOD hard flags before threshold selection. A soft warning may accompany a usable within-domain result; incompatible engine major must not remain soft just because it is an unknown category.
7. Apply the frozen tau and tau_low **only for supported source population and accepted model status**; otherwise review. An ordinal tier alone does not warrant a numeric probability.
8. Expose only claim level permitted by artifact_display_level; no percentage derived from raw similarity, BinDiff native confidence, evidence tier or synthetic benchmark rate.
9. Store status, model digest, limits, independent source tool versions, flag list, proof/contest references and user review separately. Reruns add a derived record; never rewrite earlier immutable original snapshots.
10. Any failure to parse/read/verify model/report/snapshot reverts to ordinal without crashing the GUI, then records a minimal non-sensitive diagnostic.

The existing calibration.policy.decide already handles basic contested/non-comparable/hard-OOD precedence. New work must preserve this and fill domain-compatibility/promotion-proof gaps, **not replace the unified resolver**.

## 3. OOD detection — supported domain versus distributional anomaly

Two complementary questions must be answered:

**Applicability domain:** Was the model tested on this engine major, BinExport producer, arch, PE type, Windows family, symbol policy, optimization range and toolchain? If **no**, it cannot claim calibrated correctness even if feature Mahalanobis is small. This needs an exact domain gate, ideally checked before scoring.

**Statistical anomaly:** Within a declared supported population, is this feature vector unusually far from the calibration examples? Current implementation uses category-unseen/range and an optional Mahalanobis score. Heuristic OOD flags must be validated against actual match errors. A low OOD distance is **not** evidence of correct identity.

Code observation at checked baseline: calibration/ood.py labels unrecognized engine versions soft:engine-version; calibration/policy.py abstains only on hard flags. This is a policy boundary requiring an exact version regression. Do not automatically hard-block all patch versions unless the calibration-domain policy declares compatibility by tested semantic version range.

Proposed OOD test grid:

| Axis | In-domain candidate | Shift candidate | Expected default |
|---|---|---|---|
| Engine version | Exact model-trained Ghidriff/rz-diff/BinDiff version | Unknown major; absent version | Unknown: abstain/ordinal unless certified |
| Architecture | x64 PE within measured domain | ARM64, x86, ELF or malformed | Unsupported: no calibrated number |
| PE class | Measured user DLL/kernel/driver family | New family/unusual object kind | Only documented covered family may get calibrated claim |
| Compiler | Measured clang-cl/mingw/MSVC versions | New MSVC codegen/LTO/PGO | Review/shift, avoid extrapolation |
| Optimization | Recorded O-level and ICF policy | Link-time clone/ICF/hot-cold splitting | Check support, likely abstain |
| Function complexity | Covered body/CFG/size range | Giant or tiny thunks, heavily obfuscated | Flag/review |
| Feature availability | Existing G/B/R profile with valid source | Absent secondary, damaged BinExport, missing C6 | Explicit profile selection or abstain, no negative vote |
| Symbol policy | Symbols hidden when truth symbol-derived | Symbols visible or mixed | Out of training domain |
| Referent identity | Unique mapped call/global | Masked changed linked referent | Materiality review, pairing ambiguity |

Report each subgroup's unique lineages, weighted n, number of incorrect accepted, hard/soft flag counts, false-flag rate, risk after abstention and precision/coverage at **frozen** tau. Mahalanobis correction must be based on held-out error enrichment with a clustered CI; code already supports reducing to range/unseen if enrichment is unproven. Keep old version canary runs and model expiry in artifact evidence.

## 4. Promotion and artifact integrity contract

Current artifact contract patchtrace-calibration-model/1 is intentionally data-only; strict parse, no pickle, 512KiB cap, feature schema, self-digest, profile, model version, coefficients, OOD policy, domain, evidence, created/expires. A digest is an integrity check against accidental drift and a link between documents, **not** proof that the author was authorized or that a locked test passed.

The promotion builder should accept an **independent source of gate evidence**, not a mutable report with arbitrarily declared passing booleans. Proposed versioned promotion-attestation fields:
- Exact git commit, CI workflow run + job IDs and result + completion timestamp on each required platform.
- Prereg file SHA and immutable lock commit; byte-level config/constant equivalence check.
- Exact Tier W manifest and independent label digest; sampling/identity role manifest digest; eligible population definition, exclusions and cluster counts.
- Exact frozen locked-test report digest, independent receipt and a no-second-look record.
- Independent second-annotator/owner review records and date, scope/legal decision O1, version coverage, measured external validations and reviewer identity references without sensitive names in public reports.
- Reproducibility witness: re-run report SHA on the **same allowed dev inputs**; only one final-test look.
- Windows frozen EXE SHA, smoke job URL and toolchain/pin list.
- GUI disclosure test evidence, hard OOD policy review, package verification and declared model expiry.
- Final attestation digest/signature or trusted CI provenance from a protected release pipeline, with exact verification semantics specified before implementation.

Promotion must reject: fabricated gate status, stale report, wrong prereg commit, unmatched label/model SHA, omitted Windows family, downgraded gate, expired or incompatible engine version, missing independent reviewer and absent frozen-EXE smoke. For backwards compatibility, old unpromoted experimental models continue to load only at ordinal.

## 5. Explainability without false precision

UI copy must distinguish the following data concepts:

| View field | What it tells an analyst | What it must not imply |
|---|---|---|
| Raw similarity | Engine-specific source score with its unit and algorithm | Cross-engine comparable likelihood |
| Evidence strength | Named ordinal tier, match types and dependency grouping | Numeric percentage |
| Proposed pairing | L1 matched/tentative/candidate/contested/N:M status | Semantic equivalence |
| Materiality | L2 unchanged/cosmetic/material/review/unknown and reason/proof version | A vulnerability is present or patched |
| Calibration availability | Experimental, ordinal, bands or numeric + measured population | Every PE is in-domain |
| Estimated correspondence correctness | Only if G3 accepted on validated target-A domain, rounded down as policy | A KB/CVE was fixed or code is harmless |
| OOD | Hard unsupported, soft anomalous, untested compiler or new engine version | Correctness ranking |
| Analyst status | Accepted, rejected, corrected, unreviewed; timestamp | Retrospective model-generated truth |

Suggested analyst reading example (ordinal today):
- **Pair:** old RVA / new RVA, function names and source project IDs.
- **L1 evidence:** Ghidriff match type exact, BinDiff similarity native and algorithm, rz-diff bytes native; groups show shared Ghidra provenance.
- **Decision:** tentative, competing candidate exists; reviewer action needed.
- **L2:** material/review/unknown etc with verified proof name, not a probability.
- **Validation scope:** "No supported numeric calibration for this profile and build; confidence is ordinal." Use product wording already controlled by scope.py; do not place a decorative number alongside it.

Only if accepted later: separate read-only panel with model ID, supported input population and version, calibration date, number of independent lineages, exact outcome A, rounding rule (floor to 5% in C9), interval/limitations (if exposed), OOD flags and provenance receipt. A band label needs meaning validated by G2; never present confidence-bands as specific numeric probabilities. Avoid calibrated result influencing original pairing/semantic proof engine unless a separately reviewed and versioned decision-policy spec explicitly authorizes it.

**Design/accessibility:** native engine text remains in its source cell, untrusted names/citations sanitized and bounded; no trust cue depends on color alone. Contested remains top of unified view, COS-PSEUDO/1 is not silently hidden, and the user can open conflict evidence and the original raw engine result. Provide stable keyboard navigation and text statuses, offscreen Qt tests, screen-reader checks where available, and Windows frozen package QA.

## 6. Failure-driven tests

Place new tests next to the existing relevant owner modules after spec/ownership review. Proposed names below are **plans**, not tests executed here:

- tests/test_calibration_runtime.py — invalid FeatureRow finiteness, unknown engine major and fallback, misleading high p with contested/N:M.
- tests/test_calibration_scope.py — time-expired validation ledger, missing model, scope downgrade on old project session.
- tests/test_calibration_tools.py — forged promotion prerequisites, invalid pinned prereg digest, consumed local lock and report mismatch.
- tests/test_calibration_cv.py — cross-lineage shared source and fold parameter invariance; no post-test hyperparameter access.
- tests/test_calibration_metrics.py — paired grouped CI, undefined bootstrap statistic, heavy-weight/highly imbalanced bins.
- tests/test_tier_r_eval_engines.py — identical backend status, 0-outcome detector, nonzero expected candidate count and recorded tool unavailable state (coordinate R1 #128).
- tests/test_unified_fusion.py or current named fusion suite — Ghidra-origin duplicate agreement, same evidence class, changed global/callee, contested precedence (coordinate R3).
- GUI evidence/read-model suite — ordinal-only with missing/experimental model, numerical output only after accepted signed/attested G3, no stale probabilities after source or engine change.

Run narrow red tests, modify only owned runtime once a spec is approved, run green tests, full offscreen pytest, Ruff and current-head native tool acceptance. Preserve output digests and report the total pass/skip/blocked counts. A mocked test cannot substitute for real calibration or Windows acceptance.

## 7. Decision and remaining research

**Keep ordinal-only now.** The priority is not a sophisticated new calibrator, but trustworthy independent labels, a valid statistical test unit, hardened promotion conditions, explicit engine domain enforcement and reproducible subgroup/OOD evidence. Continue research into beta calibration, conformal abstention, hierarchical clustering and other models only after comparisons with the locked candidate set are predeclared and proven beneficial on dev/shift groups.

**R5 output status:** robust failure taxonomy and integration test design available; no failure counts or confidence performance invented. See [implementation handoff](05-engineering-handoff.md) for owners and next executable steps.
