# Semantic branch disposition — batch 1 (2026-11-18)

**Result:** 20 of the 131 mechanically classified reconciliation tips received a scoped semantic examination. Seventeen retain their focal behavior in the current implementation. Three broad, overlapping checkpoint tips remain partial and expose three concrete repair candidates plus two larger workflow/qualification gaps. This is not whole-branch closure.

Comparison source: `ac789497597fba3cb87696990d171a7a27024fca`; tree `48c7e368d9d2e12336b2f9b62a6eb49b670fab86`. The original inventory observation remains `2026-11-18T13:50:56.954Z`. The local fetched refs were captured at `2026-11-18T15:50:24.213720+00:00` and all 20 tips match the committed inventory. No live REST refresh, source edits, remote mutations, closures, merges or deletions were performed.

The source baseline includes the accepted CVRF/staleness/advisory-read stack. Raw alignment and saved/recent search are separate accepted follow-on trees, recorded below; their absence from this comparison baseline is not rediscovered as an omission.

## Review basis and limits

Each row combines exact tip/merge-base and changed-path evidence, actual source inspection, current replacement or missing-behavior proof, a test/qualification record, and a selective-port decision. File and AST equality support only the compared scope. A merged PR or a matching patch ID alone does not prove semantic equivalence. Current tests exercise current replacements; they do not qualify historical trees or live/native compatibility.

There are 111 original reconciliation tips outside this batch. The three broad tips inside this batch also retain unreviewed source residue. No completion percentage is reported: the denominator is branch entries, and the amount of unreviewed behavior within them is not known. The original inventory classifications and historical evidence are unchanged.

Evidence: [machine-readable ledger](semantic-disposition-batch1.json), [raw receipt archive](../../qa/semantic-disposition-batch1-20261118.zip), and [QA receipt](../../qa/semantic-disposition-batch1-20261118.md). The archive retains the full mechanical snapshot, source/test patches, AST comparisons, probes and original test logs/XML.

## Candidate repairs and unresolved workflows

### C1: Reject foreign schemas before recycling an incomplete project

**Status:** `confirmed_missing_refusal`. **Suggested scope:** narrow repair.

Real SQLite empty current-schema databases with a foreign view, trigger, or extra column are accepted and replaced by ProjectService.create. Three negative controls fail; ordinary empty current-schema retry is the passing positive.

Historical source: `c13d3257c88140c23fb585a8a59a4dce81e81928:src/patchtrace/project_retry.py::_database`. Current seam: `src/patchtrace/persistence.py::_abandoned_creation; ProjectStore.__init__`.

Preserve healthy incomplete retry; refuse/preserve foreign schema objects and columns, bound DB/VM work, retain lock and artifact preservation rules, and check cancellation. Do not port the entire historical publication/retry UI stack.

Retained evidence: `creation-schema-red.log`, `creation-schema-red.xml`, `test_incomplete_creation_refusal_review.py`.

### C2: Report capped callgraph views as partial and deduplicate focus inputs

**Status:** `confirmed_missing_behavior`. **Suggested scope:** narrow analyst-output repair.

The real cycle_hub view shows 64 of 66 neighbours, retains a MoreMarker, but has truncated=False. Two CLI format controls fail at neighbours returning exit 0/ok. Duplicate focus IDs can consume the root budget and hide another root. The below-cap duplicate-claims control passes.

Historical source: `c13d3257c88140c23fb585a8a59a4dce81e81928:src/patchtrace/callgraph/{query,export_json,dot,view_model,panel_qt}.py`. Current seam: `src/patchtrace/callgraph/query.py::neighbourhood`.

Propagate per-origin omission into conservative partial state/limits, CLI exit, JSON/DOT and desktop text. Preserve below-cap complete behavior and exact per-origin counts. The original failing assertions stop before later export assertions; export and UI acceptance must be executed after repair, not inferred from this red run.

Retained evidence: `callgraph-red.log`, `callgraph-red.xml`, `historical-controls/test_callgraph_cap_truth.py`.

### C3: Share the path-query work budget across prepasses and avoid whole-graph/row copies

**Status:** `confirmed_missing_behavior`. **Suggested scope:** bounded analyst-query repair.

A caller budget of 40 allows 202 adjacency examinations in the reverse-prepass control. The actual normalized 816-node hub query copies 200145 adjacency entries. find_paths rebuilds the complete CSR; an already-cancelled query still copies/reads 859 entries before refusal. The normal shortest/tie-order positive passes.

Historical source: `c13d3257c88140c23fb585a8a59a4dce81e81928:src/patchtrace/callgraph/{algo,csr,paths,limits}.py`. Current seam: `src/patchtrace/callgraph/paths.py::find_paths; algo.simple_paths`.

Bound actual adjacency examinations across shortest, reverse and enumeration phases; check cancellation before work and during scans; preserve shortest lexical order, the five-path/length caps, listed-membership and endpoint rules, and a completed shortest witness on later exhaustion. Independently review this algorithmic port.

Retained evidence: `callgraph-red.log`, `callgraph-red.xml`, `callgraph-budget-red.log`, `callgraph-budget-red.xml`, `historical-controls/test_callgraph_path_budget.py`.

### C4: Recover an updated synthetic F8 packaged journey

**Status:** `coverage_gap_confirmed_no_product_failure_claim`. **Suggested scope:** separate package-QA design.

The historical helper exercised offline advisory import, ambiguity/explicit scope, pair preview/create/adopt, fixture import/rank, candidates, export, Unicode paths, reopen and stale-reopen using the normal event loop. Current --self-test checks a sample window and panel construction. Separate current pytest journeys cover many components, but do not replace that packaged end-to-end journey.

Historical source: `c13d3257c88140c23fb585a8a59a4dce81e81928:src/patchtrace/gui/qt/kb_selftest.py`. Current seam: `src/patchtrace/__main__.py::main (--self-test)`.

Adapt the journey to current contracts and packaging in a separate reviewed slice. Keep synthetic labeling, no target/network execution, bounded event-loop cleanup, and real frozen Windows/Linux runs distinct from source offscreen tests.

Retained evidence: `candidate-lineage.json`.

### C5: Explicit bounded recovery of partially created projects

**Status:** `incomplete_workflow_requires_design`. **Suggested scope:** separate feature decision.

The historical workflow privately staged artifacts/snapshot and offered an explicit check-and-retry action with byte identity, entry/schema bounds and owner/revision checks. Current creation supports rollback and some backend incomplete retry, but the wizard admits only absent/empty/lock-only destinations. The larger explicit partial-artifact recovery action is not implemented.

Historical source: `c13d3257c88140c23fb585a8a59a4dce81e81928:src/patchtrace/{project_creation,project_retry,ui_new_project}.py`. Current seam: `src/patchtrace/service.py::ProjectService.create; ui.py creation wizard`.

First fix C1 without broad changes. Before any larger port, reconcile current owned publication helpers, UI seam caps, locks, identity checks, cancellation and late adoption policy. Do not describe the current busy-disabled wizard as a confirmed reachable project-switch race without a reproducer.

Retained evidence: `candidate-lineage.json`.

## Exact tips and scoped dispositions

“Retained” means the focal behavior described in its detailed entry below. “Partial” means unresolved selective work remains in a broad tip; all three share source ancestry.

| ID | Branch / historical PR | Exact tip | Focal disposition |
|---|---|---|---|
| B01 | `codex/autonomous-checkpoint-20261102-0945` (no associated PR in frozen inventory) | `d038ddea43182b8709afd447140dc74fded487c5` | Partial; C2, C3, C4, C5 |
| B02 | `codex/autonomous-checkpoint-20261102-1020` (no associated PR in frozen inventory) | `c13d3257c88140c23fb585a8a59a4dce81e81928` | Partial; C1, C2, C3, C4, C5 |
| B03 | `codex/essential-project-safety-20261031` (#148) | `c3868d8335a8f32f676905032dc1a6d0e9f22fd6` | Retained in current scope |
| B04 | `codex/msrc-mixed-format-revision-20261102` (#158) | `e1b79e048d3963d747bc9f07448b039a250180ed` | Retained in current scope |
| B05 | `codex/msrc-reconcile-integration-20261102` (#159) | `56374f867594dd923383c91ea71970cb7d24d173` | Partial; C1, C2, C3, C4, C5 |
| B06 | `codex/kb-explicit-filename-selection-20261104` (#190) | `761b6b885f00143597c74f0457b1165a144fbdd4` | Retained in current scope |
| B07 | `codex/pr110-kb-arch-scope-20261029` (#122) | `40e02daf93c8e13a94b74f5b80d86c1680fea7ad` | Retained in current scope |
| B08 | `codex/pr110-persistence-feedback-20261029` (#119) | `3e9cedb012b4c82da3b0e5f9bc977ecd7313b64c` | Retained in current scope |
| B09 | `codex/pr111-bounded-nav-into-integration-20261029` (#117) | `025300f8e169556f84b6a8cfed20413e0a26b019` | Retained in current scope |
| B10 | `codex/gui-bounded-ambiguous-candidates-20261029` (#111) | `3287cb3d36052bd6e44420f631ed033baf939d64` | Retained in current scope |
| B11 | `codex/analyst-accessibility-20261109` (no associated PR in frozen inventory) | `b90a2cd49fa4ba71050a378abc753fe8c90733fd` | Retained in current scope |
| B12 | `feat/acquisition` (no associated PR in frozen inventory) | `293362a2d8cee7d5cc373439436945888b3b805a` | Retained in current scope |
| B13 | `feat/acquisition-gui` (no associated PR in frozen inventory) | `7ae34d8fa26a6b6c8b7acf40f5c16d99643151ce` | Retained in current scope |
| B14 | `feat/phase3-batch` (#13) | `3581b520207b464b35a7baa39d188fb4f2a08cf1` | Retained in current scope |
| B15 | `feat/profiles` (no associated PR in frozen inventory) | `d21b5917a66041cb1ffa4f46931e551e55f3165a` | Retained in current scope |
| B16 | `feat/raw-cache` (no associated PR in frozen inventory) | `28bc476713fc9b77b876cfc8f5454760ea23d4e0` | Retained in current scope |
| B17 | `feat/enrichment-cve` (no associated PR in frozen inventory) | `49bf245583d040a8b29d80daee8666d8c7f7b8d4` | Retained in current scope |
| B18 | `claude/patchtrace-features` (#100) | `66e9adc50fb118c04e5e24eacd0c221ca483a130` | Retained in current scope |
| B19 | `claude/spec53-diagnose-launcher` (#280) | `a00fcc14ea11751ce5ca05271e2be32d06dd4535` | Retained in current scope |
| B20 | `claude/bugfix-search-pilot-20261111` (#288) | `d1f7d9aa64b28c8a8ca0a1065bb88e1e2f15b7f0` | Retained in current scope |

## Per-branch evidence and decisions

### B01: codex/autonomous-checkpoint-20261102-0945

**Assessed scope:** Project-safe export/adoption, owner-thread KB panel loading, frozen KB journey, creation staging, and bounded callgraph exploration in the broad checkpoint.

The export/adoption and KB snapshot behavior has current replacements. The checkpoint retains useful callgraph cap-truth and path-work fixes absent from the comparison baseline. Its private creation helper and full synthetic F8 self-test are absent as named paths; the creation strategy and packaged journey are not equivalent to current rollback and sample-only self-test. Research/native residue is still partial.

Exact tip is in the table above. Merge base with the comparison source: `25c9795bd9cd58bfad855f30594ee3a0c7584cec`. Divergence: 648 comparison-only / 38 tip-only commits. Of the changed production paths, 10 are byte-identical, 47 differ and 4 are absent by that path. These counts are mechanical evidence, not semantic scores.

- gui/qt/project_adoption.py is byte-identical; reports._check_destination and ProjectService.export_report have equal ASTs.
- Historical adapters/panel_snapshot.py is replaced by cli_leads.read_snapshot, KbSnapshot, SnapshotRows/SnapshotEngine and leads_from_snapshot; panel_qt reads on the owner thread, then computes on a worker.
- Historical callgraph/algo.py, query.py and paths.py are byte-identical across both selected checkpoints and #159, but differ from current. Extracted historical controls reproduce the missing behavior.
- raw_alignment_view.py and representations/alignment.py are byte-identical. Desktop raw wiring is separately accepted at raw-integration e6f9ea3fafa400d5585a2db17131efcac8791bcd.

**Current regression seams:** `tests/test_export_destination_guard.py`, `tests/test_gui_creation_retry.py`, `tests/test_audit116_create_rollback.py`, `tests/test_kb_investigation_service.py`, `tests/test_ui_kb_investigation.py`, `tests/test_gui_project_adoption.py`, `tests/test_kbc_snapshot.py`, `tests/test_ui_kb_panel.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** Selectively recover C2/C3 after independent review. Evaluate C4/C5 separately. Preserve the checkpoint and the unreviewed native/unified research deltas; no whole-branch merge.

**Remaining qualification:** Unified proof, calibration, CFG/literal matching and native engine differences were inventoried but not exhaustively semantically qualified in this batch. No current packaged F8 journey or native/Windows acceptance is claimed.

### B02: codex/autonomous-checkpoint-20261102-1020

**Assessed scope:** The previous checkpoint plus bounded, identity-aware incomplete-creation retry and its desktop adapter.

project_retry._database checks exact schema, limits and cancellation. Current persistence._abandoned_creation accepts a snapshot-less database with a foreign view, trigger or extra column and deletes/replaces it. Three real SQLite probes fail; ordinary empty-schema retry passes. The shared callgraph omissions from the earlier checkpoint also remain.

Exact tip is in the table above. Merge base with the comparison source: `25c9795bd9cd58bfad855f30594ee3a0c7584cec`. Divergence: 648 comparison-only / 39 tip-only commits. Of the changed production paths, 10 are byte-identical, 47 differ and 6 are absent by that path. These counts are mechanical evidence, not semantic scores.

- project_retry.py is absent from current; its blob is identical to #159. project_creation.py is identical in all three selected broad tips.
- Current ProjectService.create has rollback and exclusive-publication repairs. It does not implement the historical explicit bounded partial-artifact retry workflow, so the old helper is not a safe wholesale port.
- Current KB owner-thread snapshot and project adoption replacements are exercised by the two passing gates.

**Current regression seams:** `tests/test_gui_creation_retry.py`, `tests/test_audit116_create_rollback.py`, `tests/test_export_destination_guard.py`, `tests/test_gui_project_adoption.py`, `tests/test_kbc_snapshot.py`, `tests/test_ui_kb_panel.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** Prioritize C1 strict refusal while preserving healthy incomplete retry. Recover C2/C3 separately; retain C4/C5 and research residue as open scope.

**Remaining qualification:** Foreign schema refusal is confirmed missing; full bounded retry UX, filesystem identity/publication semantics and Windows behavior need a separately owned design/review. No blanket conclusion about the other 515 changed paths.

### B03: codex/essential-project-safety-20261031

**Assessed scope:** PR #148 project-safe legacy export, explicit offline KB investigation/pair preview, and transactional GUI adoption.

The focal safety and offline investigation behavior is retained. Current investigation adds online/current-project and candidate-index journeys; these are later extensions, not a reason to restore the older whole file.

Exact tip is in the table above. Merge base with the comparison source: `a04f5a299a8d4afef023261e52e08d14678cf1e7`. Divergence: 655 comparison-only / 1 tip-only commits. Of the changed production paths, 1 are byte-identical, 11 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- gui/qt/project_adoption.py is byte-identical. reports._check_destination and ProjectService.export_report are AST-identical to this tip.
- test_export_destination_guard.py and test_kb_investigation_service.py are byte-identical.
- Historical test_ui_kb_entry.py is no longer present. Current host adoption plus test_gui_project_adoption.py and the real dialog journey provide explicit replacement evidence.

**Current regression seams:** `tests/test_export_destination_guard.py`, `tests/test_kb_investigation_service.py`, `tests/test_ui_kb_investigation.py`, `tests/test_kb_candidate_journey_20261105.py`, `tests/test_gui_project_adoption.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No selective product port for the assessed #148 behavior. Keep later investigation features and current publication helpers. Preserve historical receipts without treating them as current approval.

**Remaining qualification:** The original full-suite/native/package claims are historical. Current evidence here is offline and offscreen. The exact missing entry test was inspected, but not asserted to be byte-equivalent to all replacement tests.

### B04: codex/msrc-mixed-format-revision-20261102

**Assessed scope:** PR #158 native/synthetic ambiguous MSRC revision conflict handling.

The mixed-format quarantine is retained and further scoped by active tracking groups and release month. Current comparison checks all active relevant documents once a native ambiguous group exists, so a synthetic snapshot cannot conceal disagreement or missing applicability fields.

Exact tip is in the table above. Merge base with the comparison source: `d03a7d4897ca0f09172aeb17f0ee57f8caab13eb`. Divergence: 633 comparison-only / 3 tip-only commits. Of the changed production paths, 0 are byte-identical, 1 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- ReverseIndex.lookup has the mixed-format comparison with improved revision/group ordering.
- Ancestor d99cd7712b76e9e42661ef0b268417d7ca322d3e incorporates synthetic revisions in conflicts.
- Current tests explicitly cover native+synthetic disagreement, missing fields, agreement/reload, and isolation from a different release month.

**Current regression seams:** `tests/test_kbc_msrc_review_findings.py`, `tests/test_kbc_card_field_provenance.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No port for the narrow conflict behavior; do not replace the newer index with the older implementation.

**Remaining qualification:** Live Microsoft format compatibility and upstream freshness are not inferred from synthetic fixtures.

### B05: codex/msrc-reconcile-integration-20261102

**Assessed scope:** PR #159 card field provenance and saved investigation scope, plus inherited broad checkpoint source.

Current field provenance and document-scoped lookups retain the focal MSRC/saved-scope behavior. Inherited project-retry and callgraph fixes are still missing; the three broad tips are one overlapping repair lineage, not three independent findings.

Exact tip is in the table above. Merge base with the comparison source: `0cf22c9520da6d2841d27c0aa8136f36657aecc6`. Divergence: 643 comparison-only / 42 tip-only commits. Of the changed production paths, 8 are byte-identical, 46 differ and 6 are absent by that path. These counts are mechanical evidence, not semantic scores.

- test_kbc_card_field_provenance.py and test_kbc_scope_retained.py exercise the current contract.
- project_retry.py, project_creation.py, callgraph/algo.py, query.py, paths.py and the two historical callgraph regression files match the 1020 checkpoint blobs.
- The current KB snapshot seam provides the former adapter behavior without reopening the held project.

**Current regression seams:** `tests/test_kbc_card_field_provenance.py`, `tests/test_kbc_scope_retained.py`, `tests/test_kbc_msrc_review_findings.py`, `tests/test_kbc_snapshot.py`, `tests/test_ui_kb_panel.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No port for focal MSRC provenance/scope. Carry C1-C5 by their shared lineage; keep unreviewed native/unified/calibration residue explicit.

**Remaining qualification:** The 481-path historical branch is only partially semantically disposed. Branch name and card tests do not prove all inherited behavior equivalent.

### B06: codex/kb-explicit-filename-selection-20261104

**Assessed scope:** PR #190 an explicit analyst filename surviving a conflicting advisory-title mention and candidate cap.

Selectable tiers outrank contextual D; an explicitly selected title collision remains tier E with both reasons and unknown changed-in-KB status. Current inventory/TSP extensions preserve this rule.

Exact tip is in the table above. Merge base with the comparison source: `5d504ff5c046bfb758623182b472976003632bba`. Divergence: 621 comparison-only / 1 tip-only commits. Of the changed production paths, 0 are byte-identical, 1 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- The single source commit is patch-equivalent. Ancestor 1dfd535d3ef9467091cee7daf05aecc53ecf108b applies the fix.
- test_kbc_components.py is byte-identical; the existing pairs-index reopen control covers persisted selection.

**Current regression seams:** `tests/test_kbc_components.py`, `tests/test_kbc_pairs_index.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No selective port for this behavior.

**Remaining qualification:** No claim that a selected filename proves applicability or that current inventory extensions were qualified by this one historical patch.

### B07: codex/pr110-kb-arch-scope-20261029

**Assessed scope:** PR #122 reject incompatible product architectures before Winbindex pair resolution, including inherited integration fixes.

The explicit supported-architecture guard remains. Later current repairs isolate mixed x64/WoW64 rows before predecessor/tie selection, preserving raw rows while preventing cross-architecture pairing.

Exact tip is in the table above. Merge base with the comparison source: `5ed624e91468c410f2cf738ed4e36c2be3e0201d`. Divergence: 681 comparison-only / 8 tip-only commits. Of the changed production paths, 0 are byte-identical, 4 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- resolver.py retains the SUPPORTED_ARCH guard and later per-row architecture selection.
- Ancestors b244369c296bceb13ce6e0d716f99e078d440f13 and 11e88b634af70a40f6860e0abb843b3f627ad5cc record architecture-isolated index lineage.
- Current acquisition Winbindex and symbol-profile controls cover the inherited focused seams.

**Current regression seams:** `tests/test_kbc_resolver.py`, `tests/test_kbc_resolver_architecture.py`, `tests/test_acquisition_winbindex.py`, `tests/test_ui_profiles.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No port for the architecture guard; preserve the stronger current lineage isolation.

**Remaining qualification:** Offline metadata and synthetic PE controls do not qualify live retrieval or native binaries.

### B08: codex/pr110-persistence-feedback-20261029

**Assessed scope:** PR #119 failed save/bookmark/review/note operations must preserve analyst drafts and avoid false success.

The helper and all four affected MainWindow actions retain the historical behavior.

Exact tip is in the table above. Merge base with the comparison source: `5ed624e91468c410f2cf738ed4e36c2be3e0201d`. Divergence: 681 comparison-only / 9 tip-only commits. Of the changed production paths, 1 are byte-identical, 3 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- ui_persistence.py is byte-identical.
- MainWindow.save_project, bookmark_evidence, review_finding and save_note are AST-identical.
- The current test_ui.py failed-save controls exercise all four actions.

**Current regression seams:** `tests/test_ui.py`, `tests/test_acquisition_winbindex.py`, `tests/test_ui_profiles.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No port for the persistence feedback scope.

**Remaining qualification:** This does not certify every unrelated edit in the branch parent or all native desktop behavior.

### B09: codex/pr111-bounded-nav-into-integration-20261029

**Assessed scope:** PR #117 the bounded ambiguous-navigation repair carried onto its integration parent.

The same limited candidate buffer is current; the inherited integration Winbindex/symbol seams have later tested replacements. This is the same navigation behavior as #111, not an additional feature.

Exact tip is in the table above. Merge base with the comparison source: `5ed624e91468c410f2cf738ed4e36c2be3e0201d`. Divergence: 681 comparison-only / 8 tip-only commits. Of the changed production paths, 1 are byte-identical, 3 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- gui/anchors.py is byte-identical to the tip.
- NavResult.ambiguous retains only MAX_CANDIDATES while counting the iterable; the original 100,000-item stream/memory controls are current.

**Current regression seams:** `tests/test_gui_core_anchors.py`, `tests/test_acquisition_winbindex.py`, `tests/test_ui_profiles.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No port for navigation; preserve the later integration fixes.

**Remaining qualification:** No claim about all non-source parent history or native UI acceptance.

### B10: codex/gui-bounded-ambiguous-candidates-20261029

**Assessed scope:** PR #111 bounded memory when an ambiguous anchor returns many navigation candidates.

The sole changed production file and its regression file are byte-identical to current.

Exact tip is in the table above. Merge base with the comparison source: `f4063c3cc7e0c9d02d972e798699ad206628a5f1`. Divergence: 1061 comparison-only / 3 tip-only commits. Of the changed production paths, 1 are byte-identical, 0 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- src/patchtrace/gui/anchors.py and tests/test_gui_core_anchors.py have matching Git blobs.
- The current stream, cap and memory assertions ran in the 50-file gate.

**Current regression seams:** `tests/test_gui_core_anchors.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No selective port. Retain the reference; merge history/patch IDs do not change the byte-equality finding.

**Remaining qualification:** The bounded list remains ambiguous; these tests do not validate semantic match correctness.

### B11: codex/analyst-accessibility-20261109

**Assessed scope:** Export keyboard/focus behavior and Files-pane announcements and accessibility controls.

Both changed production files are byte-identical. Current announcement tests have additional retry and project-path controls; no unique source omission was found in this scope.

Exact tip is in the table above. Merge base with the comparison source: `882d1ca0b4190bccddb6ce1f66b46c4db856703b`. Divergence: 226 comparison-only / 5 tip-only commits. Of the changed production paths, 2 are byte-identical, 0 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- ui_export_v2.py and ui_inspection.py match exactly; ui_export_v2/accessibility regression files match.
- Ancestor 45997cfc997b06996a982705e6cd60dc73a8fae1 carries the accessibility work.
- Current tooltip registry sweep and actual export/dialog/inspection tests ran.

**Current regression seams:** `tests/test_files_announcements.py`, `tests/test_ui_export_accessibility.py`, `tests/test_tooltips.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No source port; preserve historical timeouts as historical incomplete evidence.

**Remaining qualification:** Offscreen Qt is not native Windows keyboard, screen-reader or assistive-technology acceptance.

### B12: feat/acquisition

**Assessed scope:** Original acquisition contracts, transport, quarantine, Winbindex resolution, delta integration and CLI.

The original modules/APIs remain, with stronger URL/host consent, byte/deadline/hash limits, cancellation and publication/retention rules. The inherited audit foundation is represented by current audit tests; native/live behavior is not requalified.

Exact tip is in the table above. Merge base with the comparison source: `320a87700feb196835b1e45ac90a00bc0963db1d`. Divergence: 1134 comparison-only / 14 tip-only commits. Of the changed production paths, 1 are byte-identical, 20 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- No changed production path is missing. Original CLI/delta tests and fixtures are retained.
- Current acquisition.workflow is a Qt-free facade reused by the KB journey.
- Current quarantine keeps an already committed project if provenance/annotation publication fails; restoring older cleanup behavior would regress preservation.

**Current regression seams:** `tests/test_acquisition_cli.py`, `tests/test_acquisition_delta.py`, `tests/test_acquisition_quarantine.py`, `tests/test_acquisition_transport.py`, `tests/test_acquisition_winbindex.py`, `tests/test_gui_creation_retry.py`, `tests/test_audit_core.py`, `tests/test_audit_desktop.py`, `tests/test_audit_runtime.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No selective port for the focal acquisition workflow. Use existing current services for future work.

**Remaining qualification:** The Windows msdelta.dll execution control is skipped on this host. No live Microsoft acquisition, network credentials, delta execution or target execution occurred.

### B13: feat/acquisition-gui

**Assessed scope:** Desktop acquisition dialog, explicit pair selection, background acquisition and owner-thread adoption.

The dialog remains integrated in current MainWindow. The original test_ui_acquisition.py is byte-identical; current creation/retention fixes extend failure handling.

Exact tip is in the table above. Merge base with the comparison source: `20a843348dc125346af346ec32c815c469c67283`. Divergence: 1132 comparison-only / 1 tip-only commits. Of the changed production paths, 0 are byte-identical, 1 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- AcquisitionDialog still captures explicit older/newer choices and exact consent before worker acquisition.
- GUI-thread promote/adopt, busy state and error paths are covered by the current original tests.

**Current regression seams:** `tests/test_ui_acquisition.py`, `tests/test_gui_creation_retry.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No selective source port for this workflow.

**Remaining qualification:** No live download/native delta or manual Windows GUI acceptance is implied.

### B14: feat/phase3-batch

**Assessed scope:** PR #13 N-way series and unchanged-hop raw-address matches, acquisition GUI, and secondary engine import/reconciliation.

Current N-way preparation/computation/storage/staleness and secondary CLI/import APIs retain the focal feature set. The modern BinExport/secondary reader and native-producer ownership policies supersede the old implementations; temporary Windows CI diagnostics are not product omissions.

Exact tip is in the table above. Merge base with the comparison source: `20a843348dc125346af346ec32c815c469c67283`. Divergence: 1132 comparison-only / 42 tip-only commits. Of the changed production paths, 2 are byte-identical, 11 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- Historical functional commits include 70bdb28db2d8bf3260f5e510acb5ccc6609b5208 (N-way), 44d431788bcc55429a033049ed997fa33c92289b (unchanged-hop matching), b932ae1a1c8916aeac7be2d49ce27c24717f2846 (secondary engines), and 462ef7fa098caa0df8608a7ea28c07003904b92d (integration CLI).
- Current nway.series performs verified raw reading and corruption/staleness checks; secondary facades route to newer bounded readers instead of missing old helper names.

**Current regression seams:** `tests/test_nway_graph.py`, `tests/test_nway_series.py`, `tests/test_ui_acquisition.py`, `tests/test_cli_secondary.py`, `tests/test_secondary_reconcile.py`, `tests/test_secondary_bindiff.py`, `tests/test_secondary_binexport.py`, `tests/test_secondary_rzdiff.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No focal feature port. Preserve current conservative native Rizin/producer qualification boundaries.

**Remaining qualification:** Native BinDiff/BinExport/Rizin compatibility and Windows packaging are not exercised here. Broad inherited audit/profile/cache code is scoped by the other batch rows, not blanket certified.

### B15: feat/profiles

**Assessed scope:** Persistent named enrichment profiles, validation/digest and desktop selection; inherited acquisition/audit foundation.

The profile model/store/digest and UI behavior remain. Current code additionally validates profile names/paths and supports the reviewed local-symbol policy.

Exact tip is in the table above. Merge base with the comparison source: `320a87700feb196835b1e45ac90a00bc0963db1d`. Divergence: 1134 comparison-only / 25 tip-only commits. Of the changed production paths, 1 are byte-identical, 23 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- enrichment/profiles.py retains historical functions; differences add local symbol policy and strict ProfileStore._path validation.
- Current profile and UI-profile controls cover store roundtrip, selection and symbol policy.

**Current regression seams:** `tests/test_profiles.py`, `tests/test_ui_profiles.py`, `tests/test_acquisition_cli.py`, `tests/test_audit_enrichment.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No profile port; avoid reverting current path validation or local symbol policy.

**Remaining qualification:** No native engine/profile compatibility or all historical parent changes are certified by profile tests.

### B16: feat/raw-cache

**Assessed scope:** Ghidriff raw-output cache keyed by input/runtime identity, cache hit/miss/no-cache/refresh behavior.

The raw cache remains and is more conservative: runtime identity includes selected symbol mode and staged PDB digest; online/unknown version cases stay ineligible. This is not the separate unresolved capa cache.

Exact tip is in the table above. Merge base with the comparison source: `320a87700feb196835b1e45ac90a00bc0963db1d`. Divergence: 1134 comparison-only / 25 tip-only commits. Of the changed production paths, 1 are byte-identical, 22 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- backend._read_raw_cache is AST-identical; _open_raw_cache evolves the identity and eligibility checks.
- tests/test_raw_cache.py is byte-identical to the historical tip.
- Current profile UI retains cached-result labels and selected-symbol settings.

**Current regression seams:** `tests/test_raw_cache.py`, `tests/test_ui_profiles.py`, `tests/test_backend_symbol_local.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No port for raw Ghidriff caching. Retain current identity and staging rules.

**Remaining qualification:** Fake-engine cache mechanics are not a fresh Ghidra/Ghidriff/PDB/native run.

### B17: feat/enrichment-cve

**Assessed scope:** B3 CVE normalization, contextual reranking, exact consented MSRC/NVD request planning and provider transport.

The original normalization and transport APIs remain with stricter parsing, Unicode handling, deadline/pacing, partial-provider-failure and snapshot-selection controls. This is distinct from the separately reviewed CVRF-to-pilot bridge already present in the comparison baseline.

Exact tip is in the table above. Merge base with the comparison source: `615b9354fe8b5a8954d71f212ecf76f5a8d08c0e`. Divergence: 1138 comparison-only / 2 tip-only commits. Of the changed production paths, 2 are byte-identical, 5 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- enrichment/cve.py and enrichment/intelligence.py retain the original contracts and CLI correlate seam.
- Original fixtures/core tests are retained; the current intelligence suite exercises stricter transport behavior.

**Current regression seams:** `tests/test_enrichment_core.py`, `tests/test_enrichment_cve.py`, `tests/test_enrichment_intelligence.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No source port for the original B3 feature.

**Remaining qualification:** All provider tests here are offline or injected. Live API availability, current upstream compatibility and freshness are separate gates; no applicability inference follows from contextual reranking.

### B18: claude/patchtrace-features

**Assessed scope:** PR #100 local/off/online PDB policy and private launcher plus Diaphora Mode A import.

The local symbol policy, CodeView/PDB identity staging, private launcher and Diaphora storage/import remain. Current implementation adds stricter ownership/read boundaries and newer CLI routing.

Exact tip is in the table above. Merge base with the comparison source: `e093ade3e66eebf915d1c93c75cf18c033c2abb5`. Divergence: 1071 comparison-only / 8 tip-only commits. Of the changed production paths, 13 are byte-identical, 13 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- 13 of 26 changed production paths match exactly; no changed production path is missing.
- Current backend, symbols.staging, ghidriff_launch, diaphora.service and sqlite_guard retain the specific behavior while evolving security and provenance rules.
- test_ptlaunch.py and corresponding contract/support artifacts are retained.

**Current regression seams:** `tests/test_backend_symbol_local.py`, `tests/test_diaphora_import.py`, `tests/test_diaphora_cli.py`, `tests/test_symbols_staging.py`, `tests/test_ui_symbol_local.py`, `tests/test_ptlaunch.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No focal source port; retain newer Diaphora and publication safety changes.

**Remaining qualification:** Local-symbol tests use authored/fake fixtures. No native PDB, Ghidra, IDA or Diaphora engine acceptance is claimed. The tested producer version matrix remains a separate gate.

### B19: claude/spec53-diagnose-launcher

**Assessed scope:** PR #280 backend diagnose showing the private launcher Ghidriff revision as tested/untested.

The exact patch is equivalent and backend._launcher_line has the same AST. The diagnostic behavior is retained.

Exact tip is in the table above. Merge base with the comparison source: `882d1ca0b4190bccddb6ce1f66b46c4db856703b`. Divergence: 226 comparison-only / 1 tip-only commits. Of the changed production paths, 0 are byte-identical, 1 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- test_backend_cli.py is byte-identical.
- The existing tested prefix 4f5d895 is historical qualification metadata, not evidence that this review ran the native tool or validated an arbitrary current revision.

**Current regression seams:** `tests/test_backend_cli.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No selective port.

**Remaining qualification:** Native tested-version claims must be assessed from their own retained receipts.

### B20: claude/bugfix-search-pilot-20261111

**Assessed scope:** PR #288 unsigned address/cursor guards, signature phrase/exclude semantics, exact CVE-ID matching, real UTC timestamp validation and bounded multiline buildenv provenance.

The patch is equivalent. Three production files are byte-identical; the evolved search service retains the address bounds, cursor error and phrase/exclude controls. The entire original regression file is identical.

Exact tip is in the table above. Merge base with the comparison source: `882d1ca0b4190bccddb6ce1f66b46c4db856703b`. Divergence: 226 comparison-only / 1 tip-only commits. Of the changed production paths, 3 are byte-identical, 1 differ and 0 are absent by that path. These counts are mechanical evidence, not semantic scores.

- pilot/contracts.py and buildenv report/viewmodel paths match the tip; search/service.py retains the reviewed boundary behavior in a later implementation.
- test_search_pilot_buildenv_bugfixes_20261111.py ran unchanged.
- Saved/recent search is separately accepted at saved-integration ef34fff23ff62a4ad0e0b7319006f45897314761 and is not a new omission here.

**Current regression seams:** `tests/test_search_pilot_buildenv_bugfixes_20261111.py`. Results map to the shared gates below; repeated references are not additional runs.

**Recommendation:** No port for these six defect families; preserve later saved/recent generation guards.

**Remaining qualification:** This does not certify all search/pilot behavior or supersede the separately reviewed CVRF/staleness work.

## Current gates and preserved failures

| Gate | Pinned source | Result | Elapsed pytest summary | Interpretation |
|---|---|---|---|---|
| 50 selected current files | `ac789497` | 1,069 passed; 1 skipped | 69.24 s | Current retained-behavior evidence; the skip is the Windows-only `msdelta.dll` synthetic delta execution. |
| Owner-thread/adoption replacement, 3 additional files | `ac789497` | 51 passed | 6.62 s | Actual held-project snapshot, worker calculation, stale result refusal and transactional adoption. |
| External incomplete-project schema controls | `ac789497` | 3 failed; 1 passed | 0.30 s | Original foreign view/trigger/column failures plus healthy incomplete retry. |
| Unchanged historical callgraph controls | `ac789497` | 7 failed; 2 passed | 0.66 s | Cap truth/focus/copy/cancellation omissions; below-cap and shortest-order positives. |
| Unchanged historical shared-budget control | `ac789497` | 1 failed | 0.38 s | 202 adjacency examinations despite a caller budget of 40. |

All pytest executions use the current worktree source through absolute `PYTHONPATH`; Qt uses `QT_QPA_PLATFORM=offscreen`. Commands and JUnit durations are retained separately from pytest summary wall times. The first selection preflight named two absent historical test files and started no pytest; its original script and an explicitly labeled post hoc failure summary remain in the archive. No source repair was applied to turn these red controls green.

The separate accepted raw-alignment tree is `e6f9ea3fafa400d5585a2db17131efcac8791bcd`; saved/recent search is `ef34fff23ff62a4ad0e0b7319006f45897314761`. Their author and independent receipts stay with those slices. Tests from those tasks are not added to this batch’s counts.

## Remaining branch work

The 111 unselected reconciliation tips still need source inspection. Within B01/B02/B05, unified semantic proofs, typed literals/CFG matching, calibration and native producer changes remain explicitly partial. The successful narrow replacements in B03–B20 do not authorize deleting or merging their branches. Root owns separately assigned repairs, final review and publication. No native/manual/Windows/live-provider acceptance is claimed here.
