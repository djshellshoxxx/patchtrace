# R2: evidence fusion, function identity and false matches

Research date: 2026-10-30. Reconciled starting point: `a04f5a299a8d4afef023261e52e08d14678cf1e7`; worker branch `codex/r2-fusion-research-20261030`. This report covers the fusion/identity workstream, not the whole R2 acceptance decision. Source observations are against that baseline plus the narrow corrections recorded below. All experiments here use manufactured evidence records or existing synthetic fixtures. They establish implementation behavior, not native engine accuracy or real-world correspondence precision.

## Findings and implemented corrections

The current union-find/component design prevents a particularly dangerous mistake: Ghidriff plus BinDiff agreement is not treated as two independent votes. Tier-B acceptance also requires different evidence classes. Weak contradictory proposals remain visible, and missing/one-sided evidence does not become opposition. These rules should remain in place while representative error-correlation measurements are unavailable. [Local sources: registry, components and arbiter below.]

Five reproducible defects were corrected without changing thresholds, source precedence, accepted-pair rules, or persisted schemas:

1. **Serialized evidence depended on Python's hash seed.** `decide()` deduplicated complete atoms with `set()` but sorted on a key that omitted `native`. Eight otherwise identical atoms with different native ratio text produced four distinct orders under four hash seeds. Native fields now provide the final serialization tie-breaker. They do not contribute to edge strength or acceptance.
2. **The atom cap could erase the class that justified acceptance.** Seventy K1/B/E-BODY observations, one K1/B/E-DATA observation and one K2/B/E-BODY observation were accepted through D-32, but the 64 retained atoms were all E-BODY. Both support indexes consequently pointed at same-class atoms. The arbiter now reserves a complete component/class witness and points the corresponding support indexes at it before filling remaining audit space. The strongest opposing atom still has its reserved place.
3. **Manual groups were falsely explained as independent tier-B agreement.** Manual split/merged groups intentionally have no 1:1 component support. `reason_text()` previously interpreted that absence as the B+B branch. It now reads the explicit `manual-group:<kind>` marker and attributes split, merged and ambiguous groups to an analyst correction. Inferred ambiguous groups keep their ordinary abstention explanation.
4. **IR-only unmatched functions disappeared at the ladder adapter.** The ladder returned typed leftovers, but the adapter ignored them. It now emits one-sided W/E-UNKNOWN `pt-ladder` observations, resolving their RVA/name/kind through the verified ProgramIR. Their original reason and bounded hints survive. They produce older-only/newer-only rows or join another source's pair as nonopposing observations; they never assert added/removed. Invalid IDs or mismatched correspondence/reader RVAs fail closed.
5. **A custom atom cap could erase every opposing atom.** With two B acceptance witnesses, one opposing B atom and L-39=2, the arbiter constructed `contested` with `contest=None`. It now rejects a cap that cannot retain the required component representatives plus an opposing atom with `PT-UNIFIED-LIMIT` / `atoms-cap`, preserving the ordinary no-publication-on-failure behavior.

The initial red tests are committed separately: `04ed999` (four failures) and `232b984` (three failures, one passing control). Production corrections are `f31554b` and `4afd4ec`. They are small local checkpoints for the integration owner to cherry-pick, not evidence of publication to GitHub.

Follow-up checkpoints: `beabe63` adds leftover regressions (six observed red failures before the fix, plus a foreign-RVA rejection case); `7a1eab0` implements the adapter correction and spec clarification. `37875c7` records the insufficient-cap red regression; `b546d70` implements its classified failure. The integration owner updates the older existing test that explicitly expected residual-disabled leftovers to disappear.

**Cache integration requirement:** the changes affect persisted atom order/support indexes and unmatched-row coverage. Prior results must not be reused under the same identity. The integration owner identified that manifest `engine_version` is a literal `ude/1` and the store hardcodes that wire value, so changing it would require a persisted-contract amendment. The chosen compatible solution adds an explicit `match_policy: matching/2` version to the existing `compute.pass_tables_digest` payload, which feeds `config_digest` and the result key. ProgramIR keys, engine wire version and record contract versions remain unchanged. The integration owner owns that shared edit and its old/new identity regression. See [keys.py](../../../src/patchtrace/unified/keys.py), [compute.py](../../../src/patchtrace/unified/compute.py), and the [SPEC-31 amendment](../../specs/unified-engine/05-fusion-and-noise.md#14-invariants-and-what-fusion-never-does).

## Implementation inventory

Status terminology is scoped: “implemented and verified” means source inspection plus the portable tests executed here; it does not mean live tool acceptance.

| Component | Actual behavior / representation | Status and qualification |
|---|---|---|
| Registry and dependence graph | `Family.tags` records dependencies; `joining` controls union-find. `SourceSpec` separates display/native units from decisions. | Implemented and verified; independence remains a declared assumption, not an empirical result. |
| Component max-pooling | Strongest tier per component; source count and duplicate atom count never multiply support. | Implemented and verified. |
| Evidence-class gate | A B+B witness must differ in component and class; E-UNKNOWN cannot corroborate. | Implemented and verified; cap/witness defect corrected here. |
| Ghidriff adapter | Non-manual modified records plus preserved raw address relations become atoms; connected nonexclusive relations become ambiguous groups; strongest correlator selects tier/class. | Implemented and verified with synthetic records. Original correlator names are copied into bounded native text (which can truncate); only one class is structurally represented per edge. The preserved raw output remains authoritative. |
| BinDiff adapter | Algorithm name maps to tier/class; native scores are display only; alternatives become C atoms. Zero-basic-block stubs are demoted to C. | Implemented and verified with synthetic sets. `basicblocks=None` remains unidentifiable and can retain A; limitation reported. Do not claim every possible stub is recognized. |
| rz-diff adapter | Every proposal is W/E-BODY; shared newer endpoint is `non-exclusive`; version outside 0.9.x adds a limitation. | Implemented and verified. Additional `alternatives` are counted as unused rather than imported into unified rows. |
| Manual control | M 1:1 claims, one-sided declarations, or groups; overlapping manual claims fail. Manual claims precede engine groups and greedy choices. | Implemented and verified; group explanation corrected here. Manual group conflicts stay in atoms, without a structured `Contest` entry. |
| Engine group arbitration | Groups sharing endpoints merge; engine groups abstain as ambiguous; manual claims are applied first. | Implemented and verified. Groups are not proof of split/merge semantics. |
| Pair arbitration | Greedy maximum-tier, component-count, Ghidriff-presence, then RVA ordering; any alternative endpoint proposal contests a non-manual pair. | Implemented and verified; a deterministic displayed choice is not a global optimal-assignment claim. |
| Contest strength | Any opposing M/A/B atom makes the contest strong; otherwise weak. The base decision survives in `uncontested:<decision>`. | Implemented and verified. Weak opposition remains opposition; it is never silently erased. |
| Artifact/address identity | Whole source sets must match ordered artifact SHA-256s; per-set VA/RVA basis is normalized using each PE layout. Mixed/unknown basis is not comparable. External-space indexes are skipped. | Implemented and verified for covered fixtures. Legacy secondary reconciliation does exact address comparison with an explicit basis limitation; it is not the unified address-normalization layer. |
| Original comparison preservation | Unified computation takes snapshots and writes derived result parts/pointers; it does not rewrite primary matches or attention. | Implemented and verified by the existing pipeline tests executed here. |
| Result explanation | Persisted row holds atoms, source/step/class/tier/native/ref, support indexes, contest indexes, hints; manifest holds artifact pair and source refs. CLI `explain` returns row/facts plus detail text. | Partially implemented: useful machine-readable material exists, but several provenance/relationship gaps remain below. |
| Unknown sources | Unknown pattern-valid source IDs can be loaded and displayed generically. Computing with an unregistered source raises a typed internal adapter error. | Implemented and verified in existing tests. Safe reading is different from granting an unknown source voting authority. |
| Diaphora | Source/family registry entry and a separate `diaphora` subsystem exist; `compute_stage` invokes Ghidriff, secondary and manual adapters plus the ladder. | Unified adapter missing at this baseline; registry membership is not an operational integration. |
| Ladder leftovers | `sources.ladder.ladder_output()` now emits W/E-UNKNOWN one-sided observations with verified RVA/name/kind, original reason and bounded hints. | Implemented and verified by R2 adapter and compute/persistence regressions; malformed IDs or foreign RVAs fail closed. |
| Ladder duplicate/ICF/inline/outline groups | `Correspondence` preserves groups in memory; the adapter reduces groups to a count. | Partially implemented. Unified persisted results lose memberships/reasons; functions exclusively represented by these groups can still be absent from rows. |
| Semantic equivalence | Correspondence and materiality are different layers; L2 uses proof/channel rules and does not feed L1. | Implemented separation. General semantic equivalence, split/merge proof and overlapping containment persistence are not implemented. |

Audited source files: [registry](../../../src/patchtrace/unified/registry.py), [components](../../../src/patchtrace/unified/fusion/components.py), [arbiter](../../../src/patchtrace/unified/fusion/arbiter.py), [contracts](../../../src/patchtrace/unified/contracts.py), [sources](../../../src/patchtrace/unified/sources/), [read_text](../../../src/patchtrace/unified/read_text.py), [read_model](../../../src/patchtrace/unified/read_model.py), [secondary reconciliation](../../../src/patchtrace/secondary/reconcile.py), [ladder relation types](../../../src/patchtrace/unified/ladder/types.py), and [group detection](../../../src/patchtrace/unified/ladder/groups.py).

## Dependence, evidence quality and conflicts

The current registry produces three components:

| Component | Families | Consequence |
|---|---|---|
| K0 | F-MANUAL | An analyst decision is explicit control, not statistical corroboration. |
| K1 | F-BINDIFF, F-DIAPHORA, F-GHIDRIFF, F-PT-NAMES, F-PT-PE, F-PT-STRUCT | Shared symbols, call graphs or Ghidra-derived facts join these transitively. Several agreeing tools remain one component. |
| K2 | F-PT-BYTES, F-RZDIFF | Byte-derived dependence joins the in-house comparator and rz-diff. W rz-diff never satisfies a B corroboration requirement. |

Two components are still insufficient: Ghidriff ExactMnemonics and `pt-bytes` P08 both observe E-BODY. Their agreement stays tentative. Ghidriff string-reference evidence (E-DATA/K1) and a pdata-confirmed byte-family B atom (E-BODY/K2) can satisfy D-32. This is a policy assumption about sufficiently distinct errors, not a claim that the events are statistically independent. Shared compiler transformations, common templates, bad boundaries or identical code can affect both. The current registry cannot express conditional dependence by corpus stratum, extraction mode or individual evidence pair. That is a calibration research question; no quantitative probability should be attached now. [SPEC-31 D-10, D-11, D-32; registry and tests.]

Class labels are coarse. E-DATA includes string references and P14 constant sets, even though constants and mnemonics can both be derived from the same instruction bodies. The implemented D-32 rule also permits K2/E-DATA plus K1/E-BODY; the named A-IND-1 assumption in the specification is phrased more narrowly around K2/E-BODY plus another K1 class. G-U7 should enumerate every actually permitted class pair and identify the underlying key/producer, rather than treating “different class” as proof of independence. This is an explicit open research limit, not justification to silently retier existing passes.

Max-pooling is deliberately conservative but not a complete causal model. Every K1 feature is joined even when a particular pair was matched without symbols or call references. This may sacrifice recall. Splitting K1 on conjecture would risk false automatic acceptance. Retain the conservative graph until held-out lineage data can compare error co-occurrence for each proposed class/component split.

The upstream BinDiff concepts document supports maintaining the distinction between native metrics and actual correspondence certainty: its similarity concerns selected graph/instruction characteristics, and its confidence is derived from configured matching-algorithm qualities. It also warns that weak call-sequence steps can produce poor matches. Ghidra Version Tracking separately models associations and scored opinions, and accepting one association blocks conflicting endpoint assignments. Neither design provides a justification for treating several correlated tool outputs as calibrated posterior probabilities. [Primary sources U1–U3.]

For the requested disagreement example, use old A with Ghidriff A→B, BinDiff A→C, rz-diff A→B and A→C, and manual A→D. M selects A→D; Ghidriff/BinDiff/rz-diff proposals remain opposing atoms on that row, with a strong contest because A/B-tier opposition exists. B and C can remain newer-only with proposal-lost/partner-taken hints. Removing the manual claim yields a contested displayed pair ordered by the existing tier/component/source/RVA policy. Native rz-diff similarity never breaks that tie. A one-sided Ghidriff “removed A” observation is kept with `one-sided-by:ghidriff`, not converted into opposition.

Failures and unavailable engines are absence of a vote. A conflicting two-sided assignment is positive evidence for another edge, which creates a contest. Those are distinct states. The legacy `secondary.reconcile()` can label a primary one-sided observation versus a secondary pairing as disagreement; unified deliberately uses the D-14 absence rule instead. Do not accidentally substitute one model's verdict for the other.

L2 facts may still be computed for a contested displayed edge. They describe that shown pairing and cannot resolve the L1 contest. Even a strong unchanged/cosmetic proof is not permission to overwrite an analyst claim or suppress an alternative correspondence.

## False-match taxonomy and regression coverage

| Root cause | Concrete risk | Present safeguard / executable seam | Remaining limitation |
|---|---|---|---|
| Same size or instruction count | Unrelated wrappers share a cheap scalar feature. | Weak ladder passes stay C; BinDiff instruction count is C; `test_base_decisions_follow_the_best_evidence`. | Representative rates by compiler/optimization remain unmeasured here. |
| Identical library/template bodies | Many indistinguishable functions yield arbitrary 1:1 matches. | Ladder uniqueness gates; `test_duplicates_are_one_group_never_cross_multiplied`. | Group membership is not persisted through the unified ladder adapter. |
| ICF/COMDAT folding | Alias sets change cardinality between builds. | `test_icf_alias_group_not_added_removed`, mirror case and identical-fold-set tests. | A folded alias is not a separate executable function identity; source-symbol identity must remain separate. |
| Thunks/stubs | Empty/tiny bodies appear exact under strong engine algorithms. | Zero-block BinDiff rows demoted; `test_bindiff_stub_row_alone_is_never_matched`. | Legacy rows without block counts cannot be reliably identified. |
| Lossy instruction normalization | Constants, registers or operands disappear from an L1 key. | Tier/class gating and separate L2 operand facts; existing same-class and L2 tests. | An L1 correspondence is never a claim that the implementation is unchanged. |
| Repeated graph shapes | CFG/call-neighborhood twins have equal topology. | Uniqueness/drill-down; weak residual output remains C; repeated structures may be ambiguous. | Engine A tiers are trusted policy classifications; this audit does not independently re-prove upstream uniqueness. |
| Shared constants/strings | Common error messages or small constants resemble application identities. | Rarity gates in matching, all constants retained in L2; one component per shared origin. | Rarity is relative to the analyzed pair; compiler/runtime families need held-out strata. |
| Same feature counted twice | Ghidriff/BinDiff agree through shared Ghidra symbols; mnemonic hashes duplicated across K1/K2. | `test_two_ghidra_derived_sources_are_one_component`, `test_same_class_never_corroborates_across_components`. | Statistical independence remains unvalidated. |
| Duplicate evidence crowds out explanation | Many correlated observations consume the atom cap and erase the cross-class witness. | **Fixed R2:** `test_atom_cap_retains_the_cross_class_witness_of_an_accepted_match`, support-index and strong-contest variants. A custom cap too small for required evidence now fails explicitly. | Bounded output still omits lesser observations with an explicit count; original source outputs must remain accessible. |
| Nonexclusive engine proposals | Several old functions point to the same new function. | rz-diff nonexclusive flag; any conflicting endpoint remains contested; `test_weak_contest_still_contested`. | The label currently detects repeated newer endpoints; importing other engine cardinalities requires explicit adapter policy. |
| Hidden alternative assignment | An engine's runner-up corresponds to a primary row. | BinDiff C alternative atoms; secondary reconcile rank tests. | rz-diff alternative arrays are counted but unused; rank suffix may be truncated when a normalized step already uses all 64 characters. |
| VA/RVA or orientation error | Same numeric address names a different artifact/function, or a relocation is mistaken for absence. | Pair SHA check; whole-set basis refusal; `test_secondary_set_of_another_pair_is_refused_with_a_limitation_but_stays_an_input`, addressing tests. | SHA+RVA identifies a location within an artifact, not a verified source-level semantic identity. |
| External-space confusion | Ghidra external indexes mistaken for normal code addresses. | `test_external_keys_skipped_and_counted`; import keys handled by ladder P01. | External keys are not import names. |
| Boundary transformation | Inline/outline/split/merge forced into a unique edge. | Ladder containment hints; ambiguous engine groups; manual split/merge groups. | Automated split/merge proof and overlapping containment result records are missing. |
| Unmatched-function information loss | IR contains a function with no primary/secondary record, but a discarded ladder leftover produces no row. | **Fixed R2:** real ingested-IR adapter tests plus compute/write/deep-verify/read test; no added/removed semantics or negative vote. | Functions in omitted ladder groups remain a separate unresolved representation gap. |
| Analyst decision misattribution | A manual split/merge is described as independent engine agreement. | **Fixed R2:** three manual-group cases plus inferred-group control. | Analyst input can be mistaken; record the intervention, never relabel it as measured certainty. |
| Hash-order instability | Repeated identical inputs yield different audit content and indexes. | **Fixed R2:** four `PYTHONHASHSEED` child processes serialize identically. | Four Linux processes are not Windows/cross-version determinism acceptance. |
| Cap hides contradiction detail | Too many competing proposals exceed L-39. | Strongest opposing atom reserved; `atoms-omitted:<n>` explicit; capped witness/contest regression. | There is no structured omitted-by-source/class/endpoint summary; count alone cannot reconstruct every conflict. |

Existing tests are in [fusion tests](../../../tests/test_unified_fusion.py), [fusion properties](../../../tests/test_unified_fusion_properties.py), [source tests](../../../tests/test_unified_sources.py), [group tests](../../../tests/test_unified_ladder_groups.py), [addressing tests](../../../tests/test_unified_addressing.py), and [secondary reconcile tests](../../../tests/test_secondary_reconcile.py). New tests are [test_r2_fusion_regressions.py](../../../tests/test_r2_fusion_regressions.py). These are safeguards and repros, not measurements of the taxonomy's prevalence.

## Function identity and an explicit relation model

**Identity, relation shape, evidence strength and semantic change must remain separate.** Current canonical location identity is `(artifact_sha256, function_entry_rva)`. The ordered artifact pair and orientation supply context for each side. A run/IR identity records which extraction discovered that entry and extent. Names, function IDs and VA are properties or source-specific references; none should replace SHA+RVA. A different boundary inference at the same location should be traceable to its producing analysis, not silently treated as an independent corroborating identity.

The following is a research design for a future additive relation representation. It is not a new accepted import format or a schema migration implemented in this workstream.

| Relation shape | Member rule | Assertion and validation rule |
|---|---|---|
| Corresponds | Exactly one older and one newer function. | Exact byte/key evidence, structural similarity and probable correspondence are different evidence claims about the same topology. A matched relation does not establish semantic equivalence. |
| Ambiguous alternatives | One or more members on both sides; actual proposed edges listed separately. | Store the candidate edge set; never infer the Cartesian product from member sets. No individual alternative becomes accepted merely because it belongs to the group. |
| Split | One older, at least two newer functions. | An analyst or future evidence rule asserts that behavior from the older function is distributed across the newer set. Membership alone is not proof. Preserve covered/uncovered blocks or ranges and competing explanations. |
| Merged | At least two older, one newer function. | Reverse of split; record the contributing regions and unexplained residual code. |
| Inlined into | Older contained function points to a newer containing function/region. | The containing function can also have its own accepted 1:1 relation. Containment is nonexclusive on the container side. Block containment alone is an inline hypothesis, since code copying can look identical. |
| Outlined from | Older containing function/region points to a newer extracted function. | Reverse containment; allow the old container to remain in its own 1:1 correspondence. |
| Duplicate/ICF group | Member sets plus exact/normalized-body or alias evidence. | Represents indistinguishability or folding, not arbitrary pairwise identity. Symbol aliases are not separate function-entry identities. |
| Unmatched | One-sided observation/status, with search coverage and reason. | Does not assert addition or removal. Missing extraction, absent engine results, budget exhaustion and no unique evidence remain distinct reasons. |
| Added/removed claim | Source- or analyst-asserted one-sided claim with scope. | Preserve the original engine claim; do not derive it merely from lack of a correspondence. |

Every proposed relation should carry: immutable member identities, relation kind and direction, origin engine/run, original record reference plus source-output digest, exact evidence/feature references, ordinal evidence tier, explicit analyst intervention, candidate alternatives/conflicts, extraction coverage and unavailable evidence, and rule/config version. A derived relation ID should include its typed membership/edge set and artifact identities; a result identity should also include the producing run/config. A stable correspondence row ID may intentionally remain stable across reruns while the result ID changes.

Validation requirements follow from those meanings:

1. Resolve every member against the declared artifact/analysis; validate ordered orientation and RVA bounds. An unresolved entry is unavailable, never a fabricated function.
2. Validate relation-specific cardinality and region ownership. Sort unique members and exact edge lists canonically.
3. Apply endpoint exclusivity to accepted 1:1 correspondence assignments, not universally to containment. Otherwise an inlined helper would evict its host's legitimate correspondence.
4. Keep provenance scoped to the source record. A manual relation is an analyst assertion; engine confidence text retains its upstream unit.
5. Keep alternatives and disjoint hypotheses simultaneously reviewable. A split interpretation must not erase an ambiguous mapping or a code-copy explanation.
6. Require positive transformation evidence before promoting split/merge/inline/outline hypotheses. Missing callees or shared blocks alone are insufficient.
7. Keep semantic equivalence/change classification in L2 or a future explicitly scoped semantic layer. “Exact correspondence” must say what is exact: bytes, normalized instructions, symbols, labeled source identity or a formal semantic proof.

The current `UnifiedMatch` can represent nonempty member sets and atom cardinality, but lacks a typed relationship field, containment regions and overlap semantics. Manual group kinds survive in hints. Ghidriff groups preserve actual source edges as atoms. Ladder group memberships are lost at the adapter boundary; ordinary leftovers are now preserved. Reusing the exclusive group-claim path for inline containment would be incorrect because the container is already paired. A future contract amendment must address that explicitly; this work does not force those meanings into current fields.

The original unmatched adapter gap was directly reproduced without a tool or database: a `Correspondence` with no pairs/groups, `older_rva=(0x1000,)` and `older_only=(Leftover(0, 'no-unique-evidence'),)` passed to the original `ladder_output(corr, None, None)` yielded zero atoms, zero nodes and no limitations. The fixed adapter intentionally requires the real verified reader to resolve each leftover. New tests build both readers through the actual ingest pipeline and verify that unmatched functions on both sides survive compute and persisted-result verification. Ghidriff/secondary input is empty, so their survival cannot be attributed to another source.

## Machine-readable explanation coverage and gaps

The existing `unified explain` result is already a viable foundation: it returns the full row, facts, provenance summary and GUI detail text. GUI consumers can render source atoms and support/contest indexes without recomputing matching. L2 channels/proofs remain distinct from L1 decisions. Use the persisted records as the source of truth; do not reverse-engineer a decision from native numbers.

| Requested explanation | Current location | Gap / next bounded improvement |
|---|---|---|
| Which functions/artifacts | Row sides plus manifest artifact SHA-256s and Ghidriff run | CLI structured `provenance` omits artifact SHA/run even though detail text includes them; expose manifest fields additively. |
| Engines and original results | `Atom.source`, `ref`, `native`; manifest `SourceRef(entry_id,file_sha256,version)` | CLI provenance projection strips entry ID/hash; secondary run ID is not propagated into unified source refs. Original data exists elsewhere but is not self-contained in the explanation. |
| Evidence classes and independence | Atom class, support component labels; registry joins | Labels alone do not contain family members, joining tags or per-atom component mapping. An explanation needs the exact registry/config context, preferably a stored summary, to interpret historical labels safely. |
| Acceptance rule and witnesses | Source step, tier, decision/hints, support indexes | B+B indexes now preserve actual witness classes. No explicit `rule_id` distinguishes manual/A/B+B paths; templates infer it. |
| Opposing classes and endpoints | `Contest.against` indexes into full atoms | Manual groups and ambiguous groups retain attached conflicting atoms as extras without a typed opposition classification. |
| Rejected/retained alternatives | Losing edge atoms, alternative-rank step suffix, partner-taken/lost-to-group hints | No structured outcome/rejection reason per candidate; long step truncation can erase rank; rz-diff alternatives unused. |
| Analyst intervention | M atoms, manual source ref, `manual-group` hint | Human explanation corrected; a typed intervention field would be clearer than parsing hints in a future contract. |
| Unavailable evidence | Manifest limitations; read-model source states | No per-row source-availability matrix. “No record” and “engine failed” require run/manifest context. |
| Complete capped trail | Original source outputs plus `atoms-omitted:<n>` | Row is intentionally bounded; it cannot promise all opposing records. Add omitted-by-source/class counts or references without pretending the cap did not omit data. |
| Ladder chain and anchors | Native round/chain/first anchor/votes | `Correspondence.atoms()` truncates chain text and keeps only the first anchor; full anchor sets and drill-down provenance are not persisted. |

One pre-existing strict xfail remains: `test_same_class_support_lists_one_atom` expects E-BODY/K1 and E-BODY/K2 to produce one support item. Current support records one strongest observation per component, while the decision correctly stays tentative because classes match. This R2 correction does not redefine support as an independence count; it preserves correct B+B witnesses. The xfail should be resolved by an explicit support-contract decision, not by weakening the assertion or claiming it passed.

## Experiments, exact commands and limits

Runtime: existing Python environment at `/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python`; worktree source selected with `PYTHONPATH=src`. No target binary or native matching engine was executed in this workstream.

| Experiment | Before | After / interpretation |
|---|---|---|
| Eight native-only atom variants, hash seeds 0–3 | Four different serialized atom orders | One order across all four; decision stays matched. |
| 70 K1/E-BODY + K1/E-DATA + K2/E-BODY, cap 64 | Accepted row retains only E-BODY; supporting class witness absent | Retains E-DATA and E-BODY in distinct component support indexes; still matched; 8 omitted observations counted. |
| Same evidence plus a conflicting B BinDiff edge | Strong contest retained, but class witness lost | Strong contest and complete accepted-base witness both retained; decision remains contested. |
| Manual split, merged, ambiguous groups | Three incorrect/insufficient analyst explanations; inferred-group control passes | Three explicit analyst attributions; inferred-group explanation unchanged. |
| IR-only older/newer tiny functions, no other source records | Zero persisted rows | Two SHA/RVA-bound one-sided rows, W/E-UNKNOWN observations, no support/contest or change facts. |
| Partial unfinished leftovers | No observations | Original unfinished reason/hints preserved; partial/deadline limitation remains. |
| Two B witnesses plus one opposing B atom, custom cap 2 | Invalid `contested` row with no Contest | Classified `PT-UNIFIED-LIMIT` / `atoms-cap`; no incomplete row returned. |
| Focused original suite | 127 passed, 1 pre-existing xfailed; 5.23 s | With first four regressions: 131 passed, 1 xfailed; 5.37 s. |
| Expanded source/store/read model/CLI/pipeline suite after arbiter fix | Not rerun on baseline in this workstream | 619 passed, 1 xfailed; 23.01 s. |
| Final manual-group/fusion/read model/CLI/golden suite | Three new manual cases red before fix | 110 passed, 1 xfailed; 5.51 s. |
| Follow-up owned regressions before the insufficient-cap addition | Six leftover cases observed red before the fix | 15 passed; 1.61 s. |
| Follow-up fusion/source/group/wire suite with both corrections | — | 111 passed, 1 xfailed, 1 failed; 2.91 s. Sole failure is the pre-existing wire assertion that expected the unmatched gap function to disappear; its list indexing also assumes no newer-only rows. Integration owner owns that test update. |
| Same follow-up suite excluding the known obsolete wire assertion | — | 111 passed, 1 deselected, 1 xfailed; 2.78 s. This exclusion is diagnostic evidence, not a claim that the whole suite passes. |
| Ruff on owned production/test files | — | All checks passed. |

Commands (relative to this worktree):

```bash
PYTHONPATH=src /workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m pytest -q \
  tests/test_unified_fusion.py tests/test_unified_fusion_properties.py \
  tests/test_unified_sources.py tests/test_unified_read_model.py \
  tests/test_unified_fixture_fusion_properties.py

PYTHONPATH=src /workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m pytest -q \
  tests/test_r2_fusion_regressions.py

PYTHONPATH=src QT_QPA_PLATFORM=offscreen /workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m pytest -q \
  tests/test_r2_fusion_regressions.py tests/test_unified_fusion.py \
  tests/test_unified_fusion_properties.py tests/test_unified_fixture_fusion_properties.py \
  tests/test_unified_fixture_read_model_golden.py tests/test_unified_sources.py \
  tests/test_unified_registry.py tests/test_unified_addressing.py tests/test_unified_keys.py \
  tests/test_unified_contracts.py tests/test_unified_store.py tests/test_unified_read_model.py \
  tests/test_unified_audit_text.py tests/test_unified_cli.py tests/test_unified_cli_show.py \
  tests/test_unified_pipeline.py tests/test_unified_wire_compute.py tests/test_secondary_reconcile.py

PYTHONPATH=src /workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m pytest -q \
  tests/test_r2_fusion_regressions.py tests/test_unified_fusion.py \
  tests/test_unified_fusion_properties.py tests/test_unified_read_model.py \
  tests/test_unified_fixture_read_model_golden.py tests/test_unified_cli_show.py

/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m ruff check \
  src/patchtrace/unified/fusion/arbiter.py src/patchtrace/unified/read_text.py \
  src/patchtrace/unified/sources/ladder.py tests/test_r2_fusion_regressions.py
```

Follow-up focused command:

```bash
PYTHONPATH=src /workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -m pytest -q \
  tests/test_r2_fusion_regressions.py tests/test_unified_fusion.py \
  tests/test_unified_fusion_properties.py tests/test_unified_sources.py \
  tests/test_unified_wire_compute.py tests/test_unified_ladder_groups.py
```

Independent peer review of graph commit `d0216fd` found no correctness defect: preorder/subtree-end intervals implement the same dominator ancestry predicate as the prior parent walk; self loops, duplicate edges, unreachable nodes and invalid-entry behavior are preserved. Child enumeration is deterministic, and the work after immediate-dominator computation is linear in nodes plus edges. Existing assumptions that successor indexes are valid remain unchanged. This was source review of the commit and its independent vertex-removal oracle tests, not a claim of executing the graph benchmark in this workstream.

This report does not claim measured precision, recall, false-positive rate, calibrated confidence, a reduction in real false matches, native Ghidriff/BinDiff/rz-diff acceptance, Windows execution, or a full Linux suite pass. Those belong to integration/corpus/live gates. The implemented changes improve audit determinism and explanation completeness; they leave the accepted-edge policy unchanged. Representative R1/Tier R validation and held-out lineage correlation measurements remain open.

## Primary upstream references

Accessed 2026-10-30. These sources inform interpretation, not claims that their current upstream versions were executed locally.

- **U1.** Google BinDiff, [concepts and matching strategy](https://github.com/google/bindiff/blob/main/docs/concepts.md): unique signatures, drill-down, algorithm quality, native confidence/similarity semantics. Upstream moving branch; use the repository's pinned tool/version for live acceptance.
- **U2.** zynamics/Google, [BinDiff manual](https://www.zynamics.com/bindiff/manual/): native metric meanings, matching attributes, weak sequence matching, operand limitations.
- **U3.** NSA Ghidra, [Version Tracking introduction](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/Version_Tracking_Intro.html): associations, scored matches, user acceptance and endpoint conflicts. Ghidra's 1:1 association policy should not be mistaken for a general model of compiler split/merge/containment.
- **L1.** PatchTrace [SPEC-31 decisions](../../specs/unified-engine/00-decisions.md), [fusion and noise](../../specs/unified-engine/05-fusion-and-noise.md), and [adapter contracts](../../specs/unified-engine/06-adapters.md): binding D-02/D-03/D-08/D-10/D-11/D-12/D-14/D-17/D-23/D-29/D-32, including the distinction between current code and planned integrations.
