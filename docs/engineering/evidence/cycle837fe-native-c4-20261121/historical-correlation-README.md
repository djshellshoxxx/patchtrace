# Historical correlation scopes — independent follow-up

Reviewed target: **`d628749401f61d3653b5e066ff38245b938c5dcd`**, tree **`5d4f2d3beff122b352d0d62a15ea0800c578c0b9`**.

Four bounded historical scopes already survive in the current source. No missing implementation or new source blocker was established in these scopes. No product, test, specification, global-ledger or remote-ref edit was made. The maintained focused selection passed **134 distinct cases**, with zero failures, errors, skips or expected failures. This does not qualify an entire donor branch or any live provider/native engine.

The review first read AGENTS.md, the relevant module-index entries, SPEC-07 section 8, SPEC-31-B/C/E/G, the authoritative ledger, the previous 95FE semantic review, the cycle2 historical review, both 837FE disposition records and the acquisition-provenance peer review. The four selected scopes have no prior bounded donor disposition in those records. Selection used the existing captured 364-head technical inventory and the frozen 181-unmatched/16-patch-equivalent branch census: PR190 is in the patch-equivalent class; the other three are unmatched. Those census counts are unchanged.

## Dispositions

| Donor | Exact captured and live-verified head | Named scope | Disposition |
|---|---|---|---|
| `codex/kb-explicit-filename-selection-20261104` / PR190 | `761b6b885f00143597c74f0457b1165a144fbdd4` | Explicit analyst filename survives an identical advisory title hint and the result cap | DUPLICATE |
| `codex/pr110-kb-arch-scope-20261029` / PR122 | `40e02daf93c8e13a94b74f5b80d86c1680fea7ad` | Refuse file-index pairs when the selected product is not AMD64 | SUPERSEDED |
| `codex/msrc-reconcile-integration-20261102` / PR159 | `56374f867594dd923383c91ea71970cb7d24d173` | Source-bound advisory card fields and per-document CWE interpretation | SUPERSEDED |
| `feat/enrichment-cve` | `49bf245583d040a8b29d80daee8666d8c7f7b8d4` | Original pure provider normalization and contextual ranking | SUPERSEDED |

All four **whole branches remain PARTIALLY_REVIEWED**. No branch deletion, wholesale merge or census decrement follows from these scoped findings. `source-comparison.json` records donor trees, original PR base/diff paths, merge bases, unique nonmerge commit identities, blob/byte/AST hashes and the exact selected declarations. All four refs were independently fetched through the GitHub read API; `live-ref-records.json` retains the responses. Commit ancestry was used for provenance, not as the semantic verdict.

### PR190 — explicit filename selection

The implementation commit is the donor head itself. The selected behavior is retained: `_tier_priority` places selectable A/B/C/E hints before context-only D; `hints_for` selects tier E when the same basename came from an analyst and an advisory title, retains both reasons and the title source reference, and applies the cap only after selectable-first ordering. A title-only hint remains unselectable. `_hint` leaves change status unknown until subsequent index evidence exists. `_tier_priority`, `_hint`, `_title_names`, `hints_for` and `selectable` are AST-identical to the donor.

The entire original component regression file is byte-identical. The donor's CLI/reopen regression is also AST-identical: a title alone cannot choose a file; the explicit choice persists, becomes tier E, and reaches the existing pending-byte pair result. Later current changes add the separately specified `.tsp` suffix and correct the validation error wording; they do not replace the selection behavior.

Excluded: other component-discovery tiers, package inventory, live Winbindex availability, whole-branch historical documents and binary or vulnerability attribution. No duplicate port is needed.

### PR122 — architecture refusal

The minimal donor pair is `400cfe4a258d58d0a98f1afe8a198632b761f456` (regressions) and `40e02daf93c8e13a94b74f5b80d86c1680fea7ad` (implementation). The exact guard still refuses a selected non-AMD64 product before consulting its Winbindex timeline. The donor's three-way ARM64/x86/unknown parameterized control and real ARM64 product-name control are AST-identical.

Current `resolve` extends the guard: it separates the selected machine's timeline before change detection, target enumeration and predecessor choice. Other-machine rows do not become an AMD64 predecessor or a false same-file variant. A KB represented only by other machines returns explicit `ARCH` with unknown change status. Consequently, the older ARM64-side test now expects an empty resolution with an `ARCH` blocker instead of a grade-X proposed pair. The specification explicitly requires this earlier refusal. Direct pair proposals still check both machines. Later chronology, ambiguity and enumeration-budget work is retained rather than replaced with the shorter donor resolver.

Excluded: the donor's inherited GUI/profile, symbol-consent, acquisition parsing and help changes; full chronology correctness; native machine compatibility; complete Winbindex membership/provenance. No duplicate port is needed.

### PR159 — source-bound card fields

The minimal field-attribution implementation is `0cf22c9520da6d2841d27c0aa8136f36657aecc6`; the reviewed integration donor also contains saved-scope work. The complete `card_provenance.py`, intelligence lexicon and intelligence contracts retain the donor's exact Git blobs. `ContextBundle` and its validation, `IntelligenceRules.interpret`, `_merge_profiles`, and importer `_import_plain` are AST-identical. The loader still derives field references from accepted values in the actual source object; duplicate CVE rows and unavailable JSON locations do not acquire fabricated references. Each interpretation receives one document's actual source hash and field locations. Non-CSAF explicit CWEs retain `explicit-advisory-cwe`; ordinary CSAF keeps its distinct basis. Combining references does not increase evidential strength.

Current `build_bundle` retains that mechanism and adds the existing saved-scope boundary, source-scoped edge digest, product-only context handling and a fallback to another bindable source kind when preferred CVRF cannot provide JSON-located fields. Legacy bundles remain readable without inventing their missing field references. Additional importer revision/publisher metadata does not alter the card-fact extraction path.

Two historical regression fixtures deliberately changed `edge=False` to `edge=True`. This is explained by later commit `d03a7d4897ca0f09172aeb17f0ee57f8caab13eb`: two native same-month snapshots with unknown/tied revision order and conflicting applicability are now disputed. Giving both test contributors the same remediation preserves the test's intended field-consensus question. The separate card-only mixed-source regression remains AST-identical and still proves that a card never borrows another source's edge pointer; actual attach/reload/export retains raw bytes and exact field references. The current revision-conflict regressions also passed in this selection.

Excluded: all other PR159 saved-scope implementation, full advisory parsing/transport review, complete real MSRC coverage, native provider acceptance, raw Winbindex index/resolver membership, and L1/L2/L3 accuracy. No duplicate port is needed.

### Original enrichment CVE normalization and contextual ranking

The donor `49bf2455` introduced `enrichment/cve.py` and a separate network transport. This scope compares the pure normalization/ranking module and its original regression file only. All 23 original production declarations remain; 16 are AST-identical. Current code preserves provider-attributed facts, response-digest snapshot identity, deterministic context terms, bounded adjustments and the original base ranking. Later implementation adds strict surrogate/snapshot admission, ASCII-only IDs and CWE token boundaries, deterministic decimal handling, representable timestamps, per-provider latest-snapshot merging and partial status for stale input.

Contextual scoring is stricter than the donor: a name or product string alone contributes nothing without a change signal or qualifying transition; one edit group is credited only once across sibling CWEs. An agreed CWE may contribute while disputed values remain blocked. The original name-only score test changed to assert zero adjustment with `no-binary-evidence`, in line with current SPEC-07. This is an intentional conservative extension.

The original `test_conflicting_severity_never_merged` no longer exists under that name. Its retained-data assertion is covered by `test_nvd_primary_secondary_difference_is_not_a_conflict`, which keeps both scores/severities while refusing to call disagreements inside one provider a cross-provider conflict. Separate tests retain disjoint cross-provider conflicts and reject cross-version comparison. These are current SPEC-07/07h H12 semantics; restoring the old assertion would undo that correction. The remaining original test-source differences add Unicode-ID refusal and the stricter binary-evidence rule. All other original declarations remain AST-identical.

Excluded: donor `enrichment/intelligence.py` transport, inherited contracts/identity/ranking work, live MSRC/NVD compatibility, empirical CVE accuracy, probability calibration, complete transitive input provenance and all unrelated branch documents. No duplicate port is needed.

## Verification

A detached clean checkout at the exact reviewed target and a dedicated source-bound Python environment were used. `python -I` resolved `patchtrace` to that checkout. The command, selection, full log, JUnit, timing, exact source/tree and before/after cleanliness are in `focused.json`, `focused.log`, `focused.xml` and `test-receipts.json`.

The nine selectors cover the component file, explicit filename reopen journey, three architecture selectors, complete card-field and MSRC revision-review files, original enrichment-CVE tests and its existing audit regressions. **134 passed in 2.24 seconds** in pytest (2.697 seconds for the command), with 134 distinct JUnit identities and no failures/errors/skips/xfails. Counts are not added to the coordinator's or previous workers' overlapping selections.

The source comparison contains nine production-file and five test-file comparisons. Its declaration numbers include helpers and classes and are not executed-test counts. No source assertion was weakened and no new test was authored. This was a bounded regression run, not full-suite, native Windows, native engine, real provider or release acceptance.

## Evidence and next action

`historical-correlation-followup.zip` contains this report, structured dispositions, exact source comparisons and snapshots, live-ref receipts, focused test evidence, and the two reproducible review scripts. `manifest.json` authenticates every payload before archival; the external bundle receipt records the ZIP digest and member count. The private environment and complete detached checkout are deliberately excluded from the archive.

Record these four scope dispositions in the existing ledger/history without changing whole-branch census counts. Continue the excluded historical scopes and the already-open raw-input/index-membership, native/provider and L1/L2/L3 gates separately. Preserve every donor ref and the original source/test history. The active PR349 qualification remains owned by the coordinator.
