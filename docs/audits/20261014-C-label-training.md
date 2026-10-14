# Audit C: label-training pipeline (tools/calibration, src/patchtrace/calibration)

Date 2026-10-14. Scope: lineage/split, bootstrap, calibration selection, gates, labelling, reports, evalcore. Synthetic data only; nothing here is a claim about real binaries. Tests live in `tests/test_calibration_hardening.py` unless noted. docs/plans/c9-preregistration-v1.md is not on main; skipped. Spec amendments: `calibration-corpus-and-model.md` section 19.

| # | Finding | Severity | Fixed by test |
|---|---|---|---|
| A1 | No check that a lineage, source project, PDB name or image hash is not on both sides of a split, or that pairs cross roles | High | test_source_project_on_both_sides..., test_same_image_pdb_name_and_lineage..., test_recorded_pair_role... |
| A2 | A/A, noise and mutation pairs entered the manifest as ordinary `cross-version`/`adjacent-patch` pairs with no marker, so evidence could not exclude them | High | test_aa_noise_and_mutation_pairs_are_excluded_from_evidence_pairs |
| A3 | Mutant/control lineage inheritance only held by construction | Medium | test_control_pairs_must_inherit_the_base_lineage |
| A4 | Time-inverted adjacent-patch pairs undetected; empty roles in tiny corpora silent | Low | test_time_inverted_..., test_tiny_corpus_warns_about_empty_roles |
| B1 | `power_for_delta(0, ...)` returned alpha/2 (one tail): type-I error mis-stated; one-sided power used abs(delta); no input validation; no primary source | High | test_two_sided_power_at_zero_effect..., test_power_inputs_are_validated, test_power_round_trip_and_monotonicity; test_evalcore_stats golden corrected |
| B2 | Normal approximation understates n for few lineages | Medium | test_t_correction_matches_guenther_and_is_never_smaller (`lineages_needed_t`, Guenther 1981) |
| B3 | Promotion trusted gate statuses and the domain tags; a forged domain plus forged gates promoted a synthetic report | High | test_promote_refuses_forged_gates..., updated test_built_artifact_loads_in_shipped_runtime... |
| B4 | Multiple comparisons undocumented | Low | Documented (spec 19.9): intersection-union gates, fixed-sequence LTT; no code change needed |
| B5 | Platt vs isotonic rule: deterministic, documented, penalises small n (>= 1000 effective per class, then one clustered SE); unchanged | Info | existing test_calibration_cv tests |
| B6 | Platt with no signal gave a non-monotone calibrator and an unhandled `ArtifactError` | Medium | test_tiny_and_imbalanced_corpora_never_pass_any_gate_and_stay_experimental |
| B7 | Percentile ECE CI is of the biased plug-in; gate uses excess over a null simulation; unchanged | Info | existing ece_null tests |
| C1 | Kappa could pass with 3 items or 1 lineage (spec 5.6 minimums unenforced) | High | test_kappa_cannot_pass_with_too_few_items_or_lineages, test_kappa_passes_at_the_spec_minimums..., test_subtypes_below_sixty... |
| C2 | An annotator could adjudicate their own disagreement | Medium | test_adjudication_by_a_blind_annotator_is_rejected |
| D1 | Duplicate row ids silently overwrote predictions | High | test_duplicate_row_ids_are_rejected... |
| D2 | NaN, zero weights, one class, empty input raised unrelated errors (Cholesky, CVError, ArtifactError) | Medium | test_unusable_rows_raise_row_error, test_empty_rows..., test_predictions_must_be_finite_probabilities |
| D3 | No planted-mutation coverage accounting per weakness class or hard negatives | Medium | test_every_semantic_operator_maps_to_a_weakness_class, test_coverage_reports_missing_and_thin_classes... |
| D4 | Tiny, imbalanced and shifted corpora: no gate can pass | Info | test_tiny_and_imbalanced_..., test_shifted_corpus_runs... |
| E1 | No order-independent manifest hash | Medium | test_canonical_manifest_hash_ignores_order_and_provenance_but_not_content |
| E2 | Seeded determinism of the whole pipeline | Info | test_pipeline_report_is_byte_identical_for_the_same_seed |
| F1 | `make_report(synthetic=False)` on a Tier R dataset produced a real-world claim | High | test_tier_r_dataset_can_never_produce_a_real_world_claim |
| F2 | Runtime honoured gate strings but not sample size: an artifact on < 40 lineages could raise the display level | High | test_display_level_floor_matches_the_g0_lineage_minimum, test_calibration_cv (display ordinal below 40) |
| F3 | Sample-size and ECE failures block the numeric gate | Info | test_ece_and_sample_size_failures_block_the_numeric_gate |
| G1 | No property tests for rank, bootstrap or splitters | Medium | hypothesis tests: midranks, hit@k, lineage bootstrap, paired delta, cluster partition and order independence, roles, identity groups, grouped_kfold |

## Residual (not fixed)
- Body-hash overlap uses min(|A|,|B|); one shared hub hash links tiny binaries (mitigated by threshold escalation and `identity_groups` hubs).
- Operator-to-CWE mapping is a heuristic; it is for coverage accounting only.
- Real-binary power cannot be assessed until Tier W exists.
