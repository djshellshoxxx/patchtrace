# Semantic branch disposition — batch 2 (2026-11-18)

**Result:** 20 additional original reconciliation tips received a scoped source comparison. Eighteen retain their examined focal behavior, including three with explicit helper-contract replacements. Two overlapping tips share one confirmed missing analyst explanation: an explicitly selected advisory file can be superseded without a selected-file warning. No product source was changed.

Comparison source: `3be3af166897fc2376dc64850edc66485273dea1`; tree `7ef690a25be236eb7c28e3ea92228dca348d2697`. The frozen inventory observation remains `2026-11-18T13:50:56.954Z`. Local fetched refs were observed at `2026-11-18T16:47:02.099935+00:00`; all 20 selected tips match that inventory. This is a current local integration baseline, not a claim that main or remote qualification changed.

## Scope, denominator and limits

The original mechanical set contains 131 `needs_reconciliation` tips. Batch 1 selected 20; this batch selects another 20, leaving **91 unselected original tips**. Broad residue within previously inspected tips remains open. The two partial rows here describe **one shared behavior**, not two features. No whole branch is closed, deleted or declared fully reconciled.

No completion percentage is assigned. Branch entries and test cases are not a denominator for implemented product requirements or native acceptance. The original mechanical inventory and its observation date remain unchanged.

The review uses actual patches, changed paths, symbol-level structure, source call sites, replacement ancestry and behavior controls. Neither branch names nor commit subjects establish equivalence. Source/test/tools files are unchanged in this branch.

Evidence: [complete machine-readable ledger](semantic-disposition-batch2.json), [QA receipt](../../qa/semantic-disposition-batch2-20261118.md), and [sealed raw archive](../../qa/semantic-disposition-batch2-20261118.zip). The JSON retains the exact 91 remaining names/tips for the next batch.

## Confirmed candidate: B2-C1 — explain a selected superseded source

The unchanged historical `test_kbc12_a_named_superseded_file_says_its_hit_is_not_counted` fails at the missing `NAMED_SUPERSEDED` warning. Its preceding assertions pass: the lookup remains `not_observed`, and the old hit is retained under `superseded`. Historical source is `3f0df14d9d68dfd9523afd7f9e97482f9d7907ff`, present in the two overlapping coordinator tips but absent from the current ancestry.

Five actual headless CLI commands use two authored revisions and explicit source-ID scopes. The older-source query returns exit 4, no trusted edge, and only a generic superseded warning in JSON. Plain output says the checked documents do not list the KB, even though the selected older document contains it. The active-source query returns its hit; unscoped cached lookup remains negative. No advisory freshness or applicability is inferred.

A separate bounded warning-only repair is proposed. It must preserve all status/edge/card withholding, current revision ambiguity and conflict precedence, product scope, native source IDs and limits. The current plain-text presenter emits `Outcome.text` without its warnings, so `_lookup/_warnings` alone does not make the explanation visible in actual CLI output. A minimal presentation amendment needs explicit ownership alongside those index methods. No such source change is included here.

## Exact tips and scoped dispositions

| ID | Branch / frozen historical PR | Exact tip | Disposition |
|---|---|---|---|
| B2-01 | `audit/enrichment` — no linked PR in frozen inventory | `cbc5b079ad2c8cdea4ec161b1afe9ac554b8ed39` | Focal behavior retained |
| B2-02 | `audit/integration` — #11 | `f6505928d8264343caa33f878deb253626752944` | Focal behavior retained |
| B2-03 | `claude/audit-beta` — no linked PR in frozen inventory | `c93ff945b9b523abe0b829247137105788a5ea27` | Focal behavior retained |
| B2-04 | `feat/enrichment-cache` — no linked PR in frozen inventory | `0368fd9b5453ab50166c08cf8dfc493e57b0ee52` | Focal behavior retained |
| B2-05 | `feat/enrichment-contracts` — #10 | `010d809d2581d3a8ed8208e83325ba29f91b2419` | Focal behavior retained |
| B2-06 | `feat/enrichment-signals` — no linked PR in frozen inventory | `e96441a1a90478d5b06e7b0d9b4320695a2018ed` | Focal behavior retained |
| B2-07 | `feat/enrichment-wil` — no linked PR in frozen inventory | `9a6999a0e644ef03670d10fc0b08524345c6c709` | Focal behavior retained |
| B2-08 | `feat/nway` — no linked PR in frozen inventory | `44d431788bcc55429a033049ed997fa33c92289b` | Focal behavior retained |
| B2-09 | `feat/phase2-finish` — #12 | `86afe3f6563b71e1fff5ed56a907f29c6703b96e` | Focal behavior retained |
| B2-10 | `feat/secondary` — no linked PR in frozen inventory | `b932ae1a1c8916aeac7be2d49ce27c24717f2846` | Focal behavior retained |
| B2-11 | `feature/evidence-reconciliation-confidence` — #16 | `ddda35f40b94c145b2a9a9b68509b4ddb76a090a` | Focal behavior retained |
| B2-12 | `codex/fix-pr110-ci-gates-20261029` — #114 | `c0d1c38aee74461969ff0a8b4d61179c3dbb9b0b` | Retained; explicit contract replacement |
| B2-13 | `codex/pr110-ci-repairs-20261029` — #115 | `bb42828d05b775c59b73a7bbd02c0113b9b9bb3b` | Retained; explicit contract replacement |
| B2-14 | `codex/pr110-qa-wbjson-diaphora-help-20261029` — #112 | `aba4c2001a6b093f7f8cdc8b0ac20ab074ed57b8` | Retained; explicit contract replacement |
| B2-15 | `feat/pe-overview` — #22 | `4b78a6d3c0015a5fd46d557cde6cc8f0a583795b` | Focal behavior retained |
| B2-16 | `claude/bugfix-rules-cg-20261029` — no linked PR in frozen inventory | `78d48cf80bf9a8c698e604dc1ce58e8aecedca45` | Focal behavior retained |
| B2-17 | `claude/bugfix-rules-cg-rest-20261111` — #285 | `67b2bc456c59a510b854b0cdd9e85ed29d00b17d` | Focal behavior retained |
| B2-18 | `claude/modest-hamilton-kz2gta` — #126 | `280bf05856eb60f4ddb0d58210616f65a3735816` | Partial: shared B2-C1 omission |
| B2-19 | `codex/coordinator-rule-repairs-20261031` — #146 | `798e11ef345ed7a7a65508a466eaf77ee85ef77c` | Partial: shared B2-C1 omission |
| B2-20 | `consolidate/rules-callgraph-20261104` — #181 | `7b3fcbaca88256971eafd55b8fb8fe9f44634a9e` | Focal behavior retained |

## Qualification and original failures

| Gate on the comparison source | Result | Meaning |
|---|---|---|
| 39 current replacement files | 955 passed; 2 skipped; 32.63 s | Current source, injected transport/synthetic inputs and offscreen UI |
| 4 additional audit boundary files | 139 passed; 15.31 s | Artifact bytes, representations, core project and MainWindow behavior |
| Original rule/callgraph file, unchanged | 15 passed; 0.81 s | Retained older fixes; overlaps current test scope |
| Original acquisition file, unchanged | 7 passed; 1 failed; 0.19 s | Failure is the obsolete direct helper-surrogate expectation; public entry validation is retained |
| Original KB file, unchanged | 28 passed; 2 failed; 0.45 s | One missing warning; one old fixture lacks current ambiguity/truncation fields |
| Initial selected-source control | 1 failed; 0.50 s | Same missing warning, retained separately; do not count twice |
| Actual headless CLI observation | 5 commands; exits 0, 4, 4, 0, 4 | Withholding preserved; active source positive; named-file explanation absent |

The two skipped tests are native Windows WinVerifyTrust and `msdelta.dll` controls. Native compatibility, package/manual acceptance, live providers, empirical accuracy and timing targets remain separate gates. No test total is converted into a completion percentage.

Original evidence is retained: the preflight caught one nonexistent selected test file before pytest ran; the corrected selection omits it. The first authored CLI harness used raw SHA-256 values instead of the importer’s domain-separated document IDs and therefore selected nonexistent scopes. Its script, failure and all outputs are preserved. The corrected harness uses `import_bytes(...).doc_id` and records every child exit. These harness failures are not described as product defects.

The original acquisition helper assertion is not silently changed: current `strict_json` checks document syntax while `parse` and `parse_rows` perform mandatory per-entry UTF-8/hash validation. The old KB prefix fixture is also unchanged in the replay; the production-shaped current test adds `ambiguous` and `truncated` fields and passes.

## Detailed behavior and selective-port decisions

### B2-01: `audit/enrichment`

**Focus:** The three enrichment audit commits: predicate/dereference and temporary-spill negatives, WIL noise filtering, partial provider success, snapshot selection and cache lease recovery.

**Historical behavior.** BND recognizes cast dereferences and else-if predicates; SIZE ignores a semantically equal spilled temporary. WIL ignores strings, comments and rename-only changes. Partial provider failure retains other responses; CWE disagreements suppress only disputed values. An in-process lease still protects entries when its lease file cannot be written, and interrupted prune staging can be reclaimed.

**Current replacement evidence.**

- enrichment/signals.py retains _indexed_uses, _size/_spilled_same and predicate recognition; current hardening adds structural NOT-APPLICABLE versus evidence LIMIT distinctions, cast normalization and non-noise edit filtering.
- enrichment/wil.py retains comment/literal blanking and shared B1 edit identities, caches changed hunks, and skips gate work when no Feature spelling exists.
- cve.select_latest is a deliberate replacement: it selects each provider's newest retained contribution and conservatively uses the oldest contributing retrieval time, so a newer partial fetch no longer erases another provider. contextual_rank preserves disputed-CWE withholding and now credits one edit group once.
- cache._HELD_LEASE_KEYS and reclaimable staging remain; atomic owner publication, quarantine accounting and strict bounded manifest validation strengthen the older paths.

**Replacement provenance:** `1223cdd5517c2d49423210a6c7a35b5946679a07`, `f689d33f506c8ce37e626712c042f8560523e02c`, `67e5a6c6919ee711c99d334ed58e3e91298c3038`, `ec40ea98da45844d2677e5704250848c867844ca`, `4e47b20fa034888eded7e064a2db114d998aba21`, `802b5b1bb5f5e64118256e75414b7ca74ad61fcc`.

**Current controls:** `tests/test_audit_enrichment.py`, `tests/test_enrichment_signals.py`, `tests/test_enrichment_wil.py`, `tests/test_enrichment_cve.py`, `tests/test_enrichment_intelligence.py`, `tests/test_enrichment_cache.py`.

**Qualification:** Current pure/injected transport and real temporary-cache regressions pass. No live MSRC/NVD, empirical detector accuracy or native Windows lease qualification is claimed.

**Decision:** No selective source port for the examined audit behaviors; preserve current provider-wise selection and later bounds.

**Residual limits:** Historical audit timing and provider compatibility are historical, not acceptance on this baseline.

### B2-02: `audit/integration`

**Focus:** The integrated audit's cancellation/publication, settings validation, report escaping, acquisition and ownership behavior.

**Historical behavior.** Cancelled ranking results must not publish partial profile rows. Persisted numeric settings have safe fallbacks. Markdown cells cannot introduce new rows. The integrated acquisition, runtime, provider, project and desktop audits retain previous good evidence and normalize failure envelopes.

**Current replacement evidence.**

- pipeline.publish still returns no entries for a cancelled PipelineResult and rechecks current guards for other results; current audit and GUI enrichment controls pass.
- Current ui.setting_int, Setup helpers and backend_config preserve bounded settings; reports._cell retains newline flattening and escaping. Runtime/provider/project audits pass against the current implementations.
- The early incomplete-database recycling design is superseded by the separately reviewed creation ownership repair already present at the comparison baseline. This row does not propose restoring an older public-path unlink flow.
- Acquisition contracts, quarantine, deadline/cancellation, and explicit transport consent remain; the six current acquisition test files run here are source/injected controls.

**Replacement provenance:** `1223cdd5517c2d49423210a6c7a35b5946679a07`, `f689d33f506c8ce37e626712c042f8560523e02c`, `67e5a6c6919ee711c99d334ed58e3e91298c3038`, `49851325357c66bef10ca04edf871e2f52965fd3`.

**Current controls:** `tests/test_audit_core.py`, `tests/test_audit_runtime.py`, `tests/test_audit_ai_reports.py`, `tests/test_audit_desktop.py`, `tests/test_audit_enrichment.py`, `tests/test_acquisition_cli.py`, `tests/test_acquisition_transport.py`, `tests/test_acquisition_quarantine.py`, `tests/test_acquisition_winbindex.py`, `tests/test_ui_enrichment.py`.

**Qualification:** Current retained-audit and acquisition controls pass. The synthetic native msdelta control is skipped on Linux. Root's creation and publication qualification remains a separate receipt, not duplicated credit.

**Decision:** No wholesale or selective port for the examined integrated audit behavior.

**Residual limits:** Old research documents, benchmark claims, full historical-tree behavior and native runtime cleanup are not requalified.

### B2-03: `claude/audit-beta`

**Focus:** The original multi-area audit repair, including analyst-facing error handling and byte/PE boundary correctness.

**Historical behavior.** Prevent annotation code leakage when code export is disabled; preserve code text in explicit exports while redacting secrets; validate artifact regular-file state and POSIX change time; bound PE reads to mapped spans; separate empty WIL filters from no filter; retain canonical run IDs, safe profile paths, transport deadlines and explicit desktop inspection failures.

**Current replacement evidence.**

- reports retains _Verbatim and _annotation behavior, diagnostics redacts whole authorization headers, and current audit report tests pass. Current persistence uses the shared strict JSON boundary.
- VerifiedArtifactReader retains nonblocking regular-file acquisition and held-file checks; the additional current artifact-bytes and representation files pass. The Windows in-place mutation limitation is not erased by these Linux results.
- The PE single-offset _u32 path was replaced by contiguous-span reads. Current headers/debug/import/export readers and file-wide entropy budget add stricter limits.
- pipeline._filter_text distinguishes None from the empty feature filter; profiles validates names. nway._Pair.one requires the surviving reverse relation to be the same match, preserving manual overrides.
- Current profile helpers live in ui_profiles.py and file overview is hosted by the panel framework. Their old absence from ui.py is a refactor, not a missing UI feature. Current core and MainWindow tests pass.
- Windows ZIP checksum sidecars still use explicit LF bytes; make_offline_bundle delegates to build_backend_bundle.package_payload, which retains that behavior. Packaging was inspected, not executed.

**Replacement provenance:** `49851325357c66bef10ca04edf871e2f52965fd3`, `f1d95e154738e8cfc99f91d6f2bc06615f7bf1b1`, `f676f1009747de1e5e65d3d11ea01264787f9f94`, `e4b2b2ef1b0039ce1ab06de5bce694289756b724`, `cda7fe8630a76ff321f9cbd114b4a69fe7d9a71a`, `3daf65420b770685920bc27346460b0df99527f5`, `ad87acdd0e65e044c5eefd07990aee53863f540f`.

**Current controls:** `tests/test_audit_ai_reports.py`, `tests/test_artifact_bytes.py`, `tests/test_representations.py`, `tests/test_core.py`, `tests/test_ui.py`, `tests/test_cli.py`, `tests/test_profiles.py`, `tests/test_nway_graph.py`, `tests/test_pe_overview.py`, `tests/test_secondary_rzdiff.py`.

**Qualification:** The selected audit controls and four additional boundary files pass on current Linux source. The Windows build/checksum source was traced only; no native package was produced.

**Decision:** No source port for the examined audit fixes; do not restore superseded monolithic UI helpers.

**Residual limits:** The old planning document, historical full-suite result, release packaging and live engine compatibility remain outside this scoped disposition.

### B2-04: `feat/enrichment-cache`

**Focus:** Directional derived/raw cache, lease and crash recovery, plus common ranking/identity prerequisites.

**Historical behavior.** Content-addressed, orientation-sensitive cache entries with runtime fingerprint eligibility, bounded payloads, lock/lease ownership, staging, corrupt-entry quarantine and explicit prune behavior.

**Current replacement evidence.**

- Current cache keeps the original stage/key and orientation identities, validates exact full names, and still refuses unknown or online runtime fingerprints. Local-symbol fingerprints require an exact staged-PDB digest.
- The early direct owner-file writes have current atomic publication replacements. Quarantined bytes count toward budget, corrupt or over-budget manifests fail before payload reads, and failed fdopen closes its descriptor.
- The enrichment contracts and package initializer are byte-identical for this source projection. score_signals remains structurally identical; status aggregation and lazy view construction are intentional later amendments.

**Replacement provenance:** `0d22e9cdd833528e7b355051613c9deceb929f52`, `ec40ea98da45844d2677e5704250848c867844ca`, `4e47b20fa034888eded7e064a2db114d998aba21`, `802b5b1bb5f5e64118256e75414b7ca74ad61fcc`.

**Current controls:** `tests/test_enrichment_cache.py`, `tests/test_enrichment_core.py`, `tests/test_raw_cache.py`.

**Qualification:** Current synthetic cache/crash/identity controls pass. No current native Windows PID/liveness or real engine cache-hit acceptance is inferred.

**Decision:** Retain current cache implementation; no old cache source port.

**Residual limits:** The historical cache performance target and native acceptance need their own evidence.

### B2-05: `feat/enrichment-contracts`

**Focus:** The phase-2 enrichment integration and review fixes, rather than its temporary CI diagnosis branches.

**Historical behavior.** Strict enrichment records, identity/ranking, B1/B2/B3 orchestration, owner-thread guarded publication, additive storage, profile-aware loads, headless rank/flags/correlate/cache commands, desktop ranking and export provenance.

**Current replacement evidence.**

- The original contracts.py and __init__.py projections are byte-identical. Current pipeline/store/CLI/UI code retains cancelled-stage nonpublication, cached-location ownership checks and explicit unavailable/partial statuses.
- Current stage identity adds algorithm-constant digests and profile/WIL filter identity; latest provider contexts merge conservatively. These replace earlier incomplete keys rather than omit functionality.
- Desktop profile helpers and inspection presentation have dedicated modules/panel controllers; obsolete inline helper names are not evidence of missing behavior.
- The Windows last-error/PID liveness declarations are retained in the current cache source. Temporary diagnostic workflow variants and NTFS timestamp test changes are historical qualification support, not unique product features.

**Replacement provenance:** `0d22e9cdd833528e7b355051613c9deceb929f52`, `1223cdd5517c2d49423210a6c7a35b5946679a07`, `f689d33f506c8ce37e626712c042f8560523e02c`, `67e5a6c6919ee711c99d334ed58e3e91298c3038`, `ec40ea98da45844d2677e5704250848c867844ca`, `4e47b20fa034888eded7e064a2db114d998aba21`, `802b5b1bb5f5e64118256e75414b7ca74ad61fcc`.

**Current controls:** `tests/test_enrichment_core.py`, `tests/test_enrichment_review_regressions.py`, `tests/test_enrichment_storage.py`, `tests/test_enrichment_cache.py`, `tests/test_cli.py`, `tests/test_ui_enrichment.py`.

**Qualification:** Current scoped contracts, pipeline, storage, headless CLI and offscreen UI regressions pass. Old benchmarks and Windows matrix outputs are not rerun here.

**Decision:** No selective product port; keep current hardening and schema compatibility.

**Residual limits:** The documented 500 ms derived-cache target is not established by these unit tests; no benchmark or Windows full-suite completion claim is added.

### B2-06: `feat/enrichment-signals`

**Focus:** B1 lexical change signals and shared edit-group identity.

**Historical behavior.** Deterministic BND/INT/OVF/VAL/ERR/SIZE/SCRUB signals require bounded change evidence and carry exact source locations; shared edit-group identities prevent duplicate credit with WIL.

**Current replacement evidence.**

- Current signals.py retains all detectors and shared edit_group_key; original identity/ranking prerequisites remain, with identical score_signals AST.
- Later code skips whitespace/comment/rename-only edits, distinguishes missing evidence from structurally inapplicable pairings, canonicalizes casts and size arguments, and bounds/caches token/hunk work.
- Lazy MatchView.hunks and semantic_ordinals replace eager alignment without changing the caller's pairing identity; validated navigation additionally checks live ownership and excerpt hashes.

**Replacement provenance:** `0d22e9cdd833528e7b355051613c9deceb929f52`, `1223cdd5517c2d49423210a6c7a35b5946679a07`, `f689d33f506c8ce37e626712c042f8560523e02c`, `67e5a6c6919ee711c99d334ed58e3e91298c3038`.

**Current controls:** `tests/test_enrichment_signals.py`, `tests/test_enrichment_core.py`, `tests/test_audit_enrichment.py`.

**Qualification:** Positive/negative authored detector cases and exact ranking arithmetic pass. These are lexical heuristic controls, not measured vulnerability detection accuracy.

**Decision:** No port; retain the newer noise and evidence guards.

**Residual limits:** Empirical detector accuracy and per-layer native data gates remain separate.

### B2-07: `feat/enrichment-wil`

**Focus:** WIL feature-site identification and bounded transition classification.

**Historical behavior.** Recognize Feature_<uint32> identifiers, preserve unknowns and feature zero, classify old/new gates, and create a ranking signal only when a changed hunk lies in a qualifying enclosed region.

**Current replacement evidence.**

- Current site recognition, source-location hashes and transition vocabulary remain. The shared B1 cleaner blanks comments and quoted literals, and normalized condition text suppresses temporary-renaming noise.
- Current _changed uses cached semantic_ordinals; _qualifying_hunk reuses the computed changed list and no-Feature/no-site paths skip unnecessary work.
- wil_signals now explicitly shares the full changed-hunk identity with B1; a WIL site is not counted as an independent edit merely because it came through another detector.

**Replacement provenance:** `0d22e9cdd833528e7b355051613c9deceb929f52`, `1223cdd5517c2d49423210a6c7a35b5946679a07`, `f689d33f506c8ce37e626712c042f8560523e02c`, `67e5a6c6919ee711c99d334ed58e3e91298c3038`.

**Current controls:** `tests/test_enrichment_wil.py`, `tests/test_enrichment_core.py`, `tests/test_audit_enrichment.py`.

**Qualification:** Current recognition, noise, filter and grouping controls pass; no real-binary accuracy or new runtime benchmark is claimed.

**Decision:** No source port.

**Residual limits:** Historical performance and native symbol-dependent recognition remain unqualified here.

### B2-08: `feat/nway`

**Focus:** N-way chain extraction from verified adjacent pair projects and untouched-function raw address matches.

**Historical behavior.** Explicit ordered 3–8 builds, manual-over-engine edges, one-to-one chain hops, shared-build address joins, source-owned raw unchanged matches, and direct first-to-last confirmation/contradiction without treating transitivity as fact.

**Current replacement evidence.**

- nway/contracts.py and __init__.py are byte-identical for this projection; graph.py retains raw-match chaining and address-first joins.
- Current _read_address_matches refuses malformed or repeated addresses, skips entire relations touching EXTERNAL import locations, and reports those omissions. _Pair.one checks the surviving reverse relation, preserving manual overrides.
- Current _node bounds names and accepts address-only nodes; direct splits containing the chain endpoint remain inferred rather than falsely contradicted.
- series.py opens projects with maintenance=False, labels unreadable/locked sibling discovery, preserves damaged series on explicitly requested replacement, and checks pair/run/revision staleness. These are current replacements for the simpler old persistence path.

**Replacement provenance:** `7eea00147d2c9c898725c973aa2854aabcdeff9a`, `cda7fe8630a76ff321f9cbd114b4a69fe7d9a71a`, `3daf65420b770685920bc27346460b0df99527f5`, `ad87acdd0e65e044c5eefd07990aee53863f540f`, `20a843348dc125346af346ec32c815c469c67283`.

**Current controls:** `tests/test_nway_graph.py`, `tests/test_nway_series.py`, `tests/test_profiles.py`, `tests/test_raw_cache.py`, `tests/test_ui_profiles.py`.

**Qualification:** Current synthetic chain, manual override, raw ownership, series storage and profile controls pass. No three-build native Windows journey is run.

**Decision:** No old graph/series port; retain current ownership and uncertainty behavior.

**Residual limits:** Native three-build series and end-user manual acceptance are still separate gates.

### B2-09: `feat/phase2-finish`

**Focus:** Profile-selected cache/symbol behavior and the historical native Windows cache acceptance workflow.

**Historical behavior.** The desktop/CLI selected profile supplies cache policy and symbol restrictions; copied raw cache hits still follow normal normalization/publication and are labelled. The tip adds a native Windows cache-hit acceptance job.

**Current replacement evidence.**

- Current profiles, backend fingerprinting, stage-keyed profile loads and raw-cache controls preserve the product behavior already identified in batch 1.
- Current ui_profiles and effective_profile_symbol_mode keep the Setup ceiling and explicit online consent. A profile cannot silently enable more symbols than Setup permits.
- The historical native CI addition is evidence infrastructure; it cannot substitute for a new Windows run of this source. It is not a unique missing analyst feature.

**Replacement provenance:** `20a843348dc125346af346ec32c815c469c67283`, `1223cdd5517c2d49423210a6c7a35b5946679a07`, `f689d33f506c8ce37e626712c042f8560523e02c`, `67e5a6c6919ee711c99d334ed58e3e91298c3038`, `f1a1c0b2fd6d48a07c4f655247818e8a9ed30371`, `7716e2b02feaa04e59dce302c1c6cacbe800634b`, `f0af3fe2b4bfd6a8413d6d3cec093238d34e9d93`.

**Current controls:** `tests/test_profiles.py`, `tests/test_raw_cache.py`, `tests/test_ui_profiles.py`, `tests/test_ui_symbol_local.py`.

**Qualification:** Current authored profile/raw-cache and offscreen GUI controls pass. Native acceptance from the old branch stays historical.

**Decision:** No product source port; leave the fresh native cache-hit gate with release qualification.

**Residual limits:** A current native Windows cache-hit run is not supplied by this batch.

### B2-10: `feat/secondary`

**Focus:** BinDiff import, BinExport validation, optional rz-diff execution interfaces and conservative reconciliation.

**Historical behavior.** Import source-bound secondary match sets, validate ordered artifact ownership, preserve native metrics without a combined confidence claim, and treat absent/not-comparable evidence separately from contradictory endpoints.

**Current replacement evidence.**

- Current secondary contracts, BinDiff reader and reconcile retain ownership, orientation and unavailable-versus-conflict behavior; alternatives are additive and do not overturn disagreement.
- binexport.py is now a compatibility facade. Its removed _fail/_has/_bound/_optional helpers have explicit replacements in binexport_limits/check/pipeline, with stricter upb wire validation and worker-isolated production acceptance. The legacy public check/validate functions still exist.
- rzdiff imports the shared strict JSON decoder, hashes exact captured bytes, rejects invalid UTF-8 and unproven singleton ownership, and separates diagnostics from stdout. The removed private JSON callbacks are superseded, not missing input validation.
- Reconciliation treats current Ghidriff one-to-many abstentions as not-comparable; it does not invent an endpoint pair for secondary corroboration.

**Replacement provenance:** `7eea00147d2c9c898725c973aa2854aabcdeff9a`, `9403d1dc92537cee4341db21b3b48cb4a5ac183f`, `6764acb5dc99e39c94655188a1548225c10ac656`, `29a4d3f3a76ac398fe53b9f47dd5d2fa7341cf99`, `cb25132b0ebd12abb2f15bdc60324b8d177bef25`.

**Current controls:** `tests/test_secondary_bindiff.py`, `tests/test_secondary_binexport.py`, `tests/test_secondary_reconcile.py`, `tests/test_secondary_rzdiff.py`.

**Qualification:** Current importer/parser and fake-child controls pass; no real BinDiff/rz-diff/Ghidra compatibility or target execution occurs in this review.

**Decision:** No wholesale secondary port; retain worker acceptance and source-ownership amendments.

**Residual limits:** Native compatibility and isolated producer research remain outside this branch disposition.

### B2-11: `feature/evidence-reconciliation-confidence`

**Focus:** Conservative per-match cross-engine evidence adjudication and CLI presentation.

**Historical behavior.** Contradicting endpoints override corroboration, absence remains unknown, and engine-native metrics remain separate. The CLI exposes the adjudication while labelling its ordinal triage aid as uncalibrated.

**Current replacement evidence.**

- The current assess_reports decision order is unchanged: conflict first, then actual support, otherwise incomparable or single engine. The function pre-indexes rows once instead of scanning per match.
- Alternative ranks and explanatory text were added without promoting alternative matches to agreement. Current evidence tests exercise contradiction precedence and missing-evidence cases.
- The actual CLI dispatch moved into secondary/cli_import.py and still calls assess_reports and prints each match verdict and the ordinal note. This is a source-backed relocation, not an inferred equivalent based on names.

**Replacement provenance:** `6764acb5dc99e39c94655188a1548225c10ac656`, `29a4d3f3a76ac398fe53b9f47dd5d2fa7341cf99`, `cb25132b0ebd12abb2f15bdc60324b8d177bef25`.

**Current controls:** `tests/test_secondary_evidence.py`, `tests/test_secondary_reconcile.py`, `tests/test_cli.py`.

**Qualification:** Current pure adjudication and CLI tests pass. No calibrated probability, blended accuracy or fresh native three-engine evidence is claimed.

**Decision:** No product source port.

**Residual limits:** The empirical calibration plan on the historical branch is a separate research gate, not an implemented probability model.

### B2-12: `codex/fix-pr110-ci-gates-20261029`

**Focus:** Winbindex per-entry Unicode isolation, local-symbol consent ceilings and Diaphora help linkage.

**Historical behavior.** One malformed Winbindex entry cannot discard valid siblings; symbol profiles may narrow Setup consent; optional Diaphora import and its evidence limits are documented.

**Current replacement evidence.**

- Current parse/parse_rows validate entry UTF-8 when computing each record digest, skip a malformed entry, and retain valid siblings. Current display-label cleaning additionally reports collisions without changing raw identity.
- The historical strict_json helper's default surrogate rejection and temporary allow_entry_surrogates keyword were replaced by syntax-only document decoding followed by mandatory per-entry validation. Production callers are parse and parse_rows; the retained historical helper assertion fails, while all seven other old acquisition controls pass.
- The old effective_backend_symbol_mode convenience wrapper is absent; MainWindow.backend_config calls current configured_symbol_mode and effective_profile_symbol_mode directly. Current fail-closed consent/local-profile tests pass.

**Replacement provenance:** `f1a1c0b2fd6d48a07c4f655247818e8a9ed30371`, `7716e2b02feaa04e59dce302c1c6cacbe800634b`, `f0af3fe2b4bfd6a8413d6d3cec093238d34e9d93`.

**Current controls:** `tests/test_acquisition_hostile_20261029.py`, `tests/test_acquisition_winbindex.py`, `tests/test_ui_symbol_local.py`.

**Qualification:** Current production parser/GUI tests and seven unchanged historical neighboring controls pass. One unchanged old internal-helper expectation fails because the selected contract changed; it is retained and not counted as a product regression.

**Decision:** No port of the obsolete helper keyword or UI convenience wrapper. Preserve per-entry sibling survival and explicit consent.

**Residual limits:** No network or real symbol acquisition is exercised; help text is documentation evidence only.

### B2-13: `codex/pr110-ci-repairs-20261029`

**Focus:** An alternate PR110 Unicode/symbol-policy repair branch.

**Historical behavior.** Reject malformed entry text without losing sibling builds; centralize effective profile mode and local directories; show optional Diaphora CLI limits.

**Current replacement evidence.**

- This branch shares the same current parser replacement as the other two PR110 repair tips; malformed-entry and sibling controls are present and passing.
- Current effective_profile_symbol_mode is structurally the retained ceiling function. The old profile_symbol_settings wrapper was inlined at MainWindow.backend_config with the same two validated mode steps and saved directories; no acquisition is triggered by reading settings.
- The branch's helper layout is different from PR114, so the disposition follows the actual ui_symbols.py and backend_config call sites rather than treating similarly named branches as automatically equivalent.

**Replacement provenance:** `f1a1c0b2fd6d48a07c4f655247818e8a9ed30371`, `7716e2b02feaa04e59dce302c1c6cacbe800634b`, `f0af3fe2b4bfd6a8413d6d3cec093238d34e9d93`.

**Current controls:** `tests/test_acquisition_winbindex.py`, `tests/test_acquisition_hostile_20261029.py`, `tests/test_ui_symbol_local.py`.

**Qualification:** Current parser and offscreen symbol-policy controls pass; no live symbol/network acceptance.

**Decision:** No selective source port.

**Residual limits:** The old PR is closed in the frozen observation; no current PR state or branch deletion decision is inferred.

### B2-14: `codex/pr110-qa-wbjson-diaphora-help-20261029`

**Focus:** The narrow strict-JSON/per-entry Unicode and Diaphora help variant.

**Historical behavior.** Normalize Unicode encoding failure as a typed provider error for whole-document callers while permitting entry-level rejection for Winbindex index parsers.

**Current replacement evidence.**

- Current strict_json retains duplicate-key, nonfinite-number, UTF-8 byte decoding and recursion refusals. Both production parser entry points hash each entry before model admission, skipping lone-surrogate entries.
- Current f1a1c0b2 replaces the optional per_entry_text_validation switch with that single mandatory production path; 7716e2b0 adds display-label cleaning/collision notices. No other production importer of this helper was found.
- Diaphora help is not evidence that the optional native engine has been acquired or qualified. The retained functionality is import/documentation, with current separate engine acceptance boundaries.

**Replacement provenance:** `f1a1c0b2fd6d48a07c4f655247818e8a9ed30371`, `7716e2b02feaa04e59dce302c1c6cacbe800634b`, `f0af3fe2b4bfd6a8413d6d3cec093238d34e9d93`.

**Current controls:** `tests/test_acquisition_hostile_20261029.py`, `tests/test_acquisition_winbindex.py`.

**Qualification:** Current entry validation passes; the old direct helper-surrogate expectation is an explicitly recorded replaced contract, not a silently discarded failure.

**Decision:** No old parser-switch port; preserve current mandatory entry validation.

**Residual limits:** No live Winbindex fetch, Diaphora run or provider freshness acceptance.

### B2-15: `feat/pe-overview`

**Focus:** The original bounded PE overview, mapping, comparison and optional Authenticode probe.

**Historical behavior.** Inspect verified artifact bytes read-only, map file-backed RVA ranges, show import/export/debug/section/entropy facts with warnings and unknowns, compare two files, and explicitly separate Windows trust probing.

**Current replacement evidence.**

- git cherry identifies the original change as patch-equivalent to an ancestor. Six original source paths are still byte-identical; changed paths were inspected rather than assumed equivalent from that patch result.
- Current readers replace single-offset reads with contiguous backed spans, recognize cap-exact complete imports, sanitize hostile display text, and share a file-wide entropy budget.
- Current compare_metadata adds version/manifest/signature structure with explicit provenance and no chain-evaluation claim. The original compare_overviews remains structurally unchanged; the removed _u32 helper is replaced by bounded _read_span.

**Replacement provenance:** `f1d95e154738e8cfc99f91d6f2bc06615f7bf1b1`, `f676f1009747de1e5e65d3d11ea01264787f9f94`, `e4b2b2ef1b0039ce1ab06de5bce694289756b724`, `49851325357c66bef10ca04edf871e2f52965fd3`.

**Current controls:** `tests/test_pe_overview.py`, `tests/test_pe_overview_map_compare.py`, `tests/test_artifact_bytes.py`.

**Qualification:** Current synthetic PE/map/byte controls pass; the native WinVerifyTrust case is skipped on Linux. The separately reviewed manifest DTD repair is not recounted as new work.

**Decision:** No selective port.

**Residual limits:** Windows trust/catalog behavior and representative native/manual inspection remain separate qualification.

### B2-16: `claude/bugfix-rules-cg-20261029`

**Focus:** All seven rule fixes and three callgraph fixes in the original round-2 audit patch.

**Historical behavior.** Identity-correct cached matrix rescoring; stable same-second analyst decision ordering; export basename refusal before writes; damaged sidecar JSON withholding; deep expectation refusal; regular-file and byte bounds; bounded diff work; graph path work/count suffix/export omissions.

**Current replacement evidence.**

- All 15 unchanged original regression cases pass against this baseline. Current matrix.rescored first uses target/version identity plus hashes, then accepts content fallback only when unambiguous, preserving distinct duplicate-content observations.
- Current _digest adds nonblocking POSIX handle acquisition and real byte bounds; store._inline uses strict JSON. Decision restamping and window.diff_opcodes cell-product cap are retained.
- The old _valid_basename private helper has a current equivalent refusal in rules/export.py before creating output, exercised by the unchanged old long-name test.
- Current reviewed callgraph cap and shared-budget/lazy CSR slices supersede the earlier partial fixes. Their source and original red/independent qualification are retained separately; this batch adds no new callgraph port.

**Replacement provenance:** `936435241a3ab9663a3fa67da4497a088f32f09c`, `9d66abb26a015f075235e0434744eab38f676f83`, `e2b31582abe3777e8a83b8126ed42bbeab028a0a`, `df0f1eb8e935bc4a0a491faf7ee91e74f437b845`, `4067914793fa1822e9829484302120b137b6fe82`, `36e14051a4d36f5c66df0186f037a4905b01bf05`.

**Current controls:** `tests/test_rules_cg_bugfixes_20261029.py`, `tests/test_rules_matrix.py`, `tests/test_rules_store.py`, `tests/test_rules_export.py`.

**Qualification:** Current rule suite and all 15 unchanged historical controls pass. These overlap in scope and are not additive accuracy or completion evidence.

**Decision:** No source port; the stronger current identity, read and query bounds must remain.

**Residual limits:** Native Windows FIFO/device behavior and live YARA-X rule usefulness are not established by these source tests.

### B2-17: `claude/bugfix-rules-cg-rest-20261111`

**Focus:** The later remaining-rule fixes and capped graph-export truth.

**Historical behavior.** Same-second rule decisions are ordered by actual instants, test-build hashing enforces the byte cap, diff middle-product work is bounded, and capped neighborhood exports are partial.

**Current replacement evidence.**

- rules/matrix.py, rules/store.py and rules/window.py are byte-identical to this tip; these include the actual FIFO-safe reader, decision tie behavior and diff cap.
- Only callgraph/export_json.py differs in the source projection. It retains the historical MoreMarker truncation guard and additionally carries current per-view limitations through the reviewed cap slice.
- Replacement ancestor 40679147 is the integrated PR285 repair. Current rule controls and original 15-case replay pass.

**Replacement provenance:** `936435241a3ab9663a3fa67da4497a088f32f09c`, `9d66abb26a015f075235e0434744eab38f676f83`, `e2b31582abe3777e8a83b8126ed42bbeab028a0a`, `df0f1eb8e935bc4a0a491faf7ee91e74f437b845`, `4067914793fa1822e9829484302120b137b6fe82`, `36e14051a4d36f5c66df0186f037a4905b01bf05`.

**Current controls:** `tests/test_rules_cg_bugfixes_20261029.py`, `tests/test_rules_matrix.py`, `tests/test_rules_store.py`.

**Qualification:** Exact source/patch and current regression evidence support the focal disposition; no fresh native/runtime acceptance.

**Decision:** No port.

**Residual limits:** Frozen PR285 merge metadata is historical and does not authorize branch deletion.

### B2-18: `claude/modest-hamilton-kz2gta`

**Focus:** The coordinator rule/cache fixes plus an overlapping KB selected-source warning.

**Historical behavior.** Preserve distinct cached rule observations despite duplicate rule text; reject replaced FIFO inputs without blocking; bound graph count/path work; explicitly warn when a named source file is a superseded revision whose hit is withheld.

**Current replacement evidence.**

- Rule export and graph label paths are byte-identical. Matrix/store and path differences are accounted for by current stronger identity/strict-JSON/read bounds and the independently reviewed shared-budget repair.
- The KB index's NAMED_SUPERSEDED warning from 3f0df14d is absent. The unchanged historical test reaches the warning assertion: status and superseded withholding are already correct, but the selected document ID is not explained.
- Five actual headless CLI calls confirm that the selected older file is checked, the hit is withheld, JSON has only a generic superseded warning, and plain CLI text says the checked documents do not list it. The active-file positive returns its hit; unscoped cached lookup does not require a named-file warning.
- The original 30-case KB file has 28 passes, the real missing-warning failure, and one obsolete SimpleNamespace fixture lacking current ambiguous/truncated fields. Current production-shape prefix controls pass. These failures are recorded separately.

**Replacement provenance:** `936435241a3ab9663a3fa67da4497a088f32f09c`, `9d66abb26a015f075235e0434744eab38f676f83`, `e2b31582abe3777e8a83b8126ed42bbeab028a0a`, `df0f1eb8e935bc4a0a491faf7ee91e74f437b845`, `4067914793fa1822e9829484302120b137b6fe82`, `36e14051a4d36f5c66df0186f037a4905b01bf05`, `3f0df14d9d68dfd9523afd7f9e97482f9d7907ff`.

**Current controls:** `tests/test_rules_matrix.py`, `tests/test_rules_store.py`, `tests/test_rules_export.py`, `tests/test_kbc_bugfixes_20261029.py`.

**Qualification:** Current replacements pass; original selected-source warning remains reproducibly red. No source fix is included in this documentation branch.

**Decision:** Candidate B2-C1: restore a bounded selected-superseded explanation in a separate warning-only slice. Preserve current status/withholding, revision ambiguity, conflict precedence and native source identities; account for the plain CLI presentation seam.

**Residual limits:** This tip cannot be wholly classified as incorporated because the warning is absent. It shares this omission with the coordinator tip; count one behavior, not two features.

### B2-19: `codex/coordinator-rule-repairs-20261031`

**Focus:** The nonmerge coordinator tip underlying the merged rule-repair branch.

**Historical behavior.** Identity-preserving cached rescoring and FIFO race refusal, plus selected-old-advisory warning and graph work/label bounds.

**Current replacement evidence.**

- This exact tip shares the selected rule and KB source with the overlapping modest-hamilton branch. The inventory retains their distinct heads/merge structure and identical affected blobs where applicable.
- Current rules preserve exact target/version identities for duplicate-content observations and reject ambiguous content fallback. Current sidecar parsing and byte bounds are stricter than this tip.
- The named-superseded warning is the same one confirmed missing by the unchanged historical test and actual CLI run. No current trusted lead or applicability decision changes in that reproducer.

**Replacement provenance:** `936435241a3ab9663a3fa67da4497a088f32f09c`, `9d66abb26a015f075235e0434744eab38f676f83`, `e2b31582abe3777e8a83b8126ed42bbeab028a0a`, `df0f1eb8e935bc4a0a491faf7ee91e74f437b845`, `4067914793fa1822e9829484302120b137b6fe82`, `36e14051a4d36f5c66df0186f037a4905b01bf05`, `3f0df14d9d68dfd9523afd7f9e97482f9d7907ff`.

**Current controls:** `tests/test_rules_matrix.py`, `tests/test_rules_store.py`, `tests/test_rules_export.py`, `tests/test_kbc_bugfixes_20261029.py`.

**Qualification:** Same pinned current gates and original controls as the overlapping row; they are shared evidence, not additional passing tests.

**Decision:** The same B2-C1 warning-only port candidate; do not cherry-pick the complete coordinator tip.

**Residual limits:** One unresolved behavior is shared with another selected branch. Larger current security/native gates remain separate.

### B2-20: `consolidate/rules-callgraph-20261104`

**Focus:** The staged rule/callgraph repair consolidation and platform-test compatibility support.

**Historical behavior.** Preserve cached rule observation identity, refuse unsafe export names/unreadable sidecars/nonregular targets, bound path successor work and label counts, support platforms without O_NONBLOCK, and stabilize a fully loaded unified-panel wait.

**Current replacement evidence.**

- Rule export and graph label paths are byte-identical. Current matrix/store additions are the subsequently integrated byte-budget, same-second decisions and strict sidecar parsing.
- The current os.open flags use getattr(os, O_NONBLOCK, 0), preserving the historical portability fallback while POSIX still acquires nonblocking. The no-O_NONBLOCK test is present in the current matrix suite.
- Current reviewed lazy CSR/shared traversal budget supersedes the old enumeration-only successor count. The historical UI wait change is a test-stability control, not an analyst feature requiring a source port.

**Replacement provenance:** `936435241a3ab9663a3fa67da4497a088f32f09c`, `9d66abb26a015f075235e0434744eab38f676f83`, `e2b31582abe3777e8a83b8126ed42bbeab028a0a`, `df0f1eb8e935bc4a0a491faf7ee91e74f437b845`, `4067914793fa1822e9829484302120b137b6fe82`, `36e14051a4d36f5c66df0186f037a4905b01bf05`.

**Current controls:** `tests/test_rules_matrix.py`, `tests/test_rules_store.py`, `tests/test_rules_export.py`, `tests/test_rules_cg_bugfixes_20261029.py`.

**Qualification:** Current rule and unchanged historical controls pass. The earlier unified-panel stability amendment was inspected, not requalified as a native/UI performance gate.

**Decision:** No source port.

**Residual limits:** This scoped disposition does not certify historical full integration or native Windows device behavior.

## Continuation

Finish B2-C1 only through a separately owned, reviewed follow-on. Continue the remaining 91 frozen tips and the broad checkpoint research residue. Previously accepted creation, cap-truth and shared-path-budget repairs remain documented in their own source-pinned receipts; their old batch-1 failures stay historical. Preserve all branch tips until root makes an explicit disposition or merge decision.
