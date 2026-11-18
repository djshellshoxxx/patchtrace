# Semantic branch disposition, batch six

Frozen comparison: **`55f3d0742f7d4cf32357a42b8b1cc76d85875e71`**, tree `11a0c1598764ebd3fd8d3b540377aa52e949f88a`. Later root continuation and published PR316 changes remain separately attributed.

This batch inspects all fourteen remaining tips with net production-source deltas and six related fixture/test tips. No new product defect was confirmed. Retained composition, exact aliases, stronger current guards, historical fixture corrections and broad inherited residue are recorded separately.

**120 of 131 original reconciliation tips now have selected-scope entries; 11 remain unselected.** This count is not a product percentage or whole-branch disposition. No source, test, workflow, remote ref or branch was merged or deleted.

[Machine-readable ledger](semantic-disposition-batch6.json) · [Exact-source QA and archive](../../qa/semantic-disposition-batch6-20261118.md).

| Branch | Exact tip | Selected scope |
|---|---|---|
| `chatgpt/java-probe-boundaries-20261016` | `09bb4519d7d8e9ff8f40abcba7e11cb297d8b61e` | Bounded Java runtime-version probing |
| `chatgpt/java-probe-ci-fix-20261016` | `0254841e3e635ed717e35abcf83021f001d7df29` | Bounded Java runtime-version probing |
| `chatgpt/kb-fixtures-1` | `781b36fb60e775ce01bf0c114e6a17b609fdb475` | Offline synthetic KB corpus and fixture boundaries |
| `chatgpt/lbl31-windows-qa-fixes-20261016-a` | `ddb2ff077a21c1f0053ba8079564f6f86c3e155f` | Quoted COFF and default-sort QA with inherited replay work |
| `chatgpt/unified-fixture-collection-fix-20261016` | `941c617b6854291e2448cad6d7d5710a24a8543d` | Collected synthetic unified-engine fixtures |
| `chatgpt/unified-fixtures-1` | `161a88345efc6484f4d7809fc6963a0193bd0057` | Collected synthetic unified-engine fixtures |
| `chatgpt/unified-sort-perf-qa-20261016` | `27b0a48bb8007f504b4a127a099136a6ea5c00b7` | Quoted COFF and default-sort QA with inherited replay work |
| `claude/access-test-1791773355` | `726a371ab34d4589b0456d059865ade6b82fac88` | Offline runtime importer and private JDK alias |
| `claude/awesome-ramanujan-o3pxx3-win1` | `7ac57759f3b9b332eaafb48c82f366566892f1b1` | Packaged desktop and executable identity |
| `claude/live-harness-infra-20261111` | `c59ccada97b649366af808a6d83bb465078c9011` | Honest native-harness completion and failure semantics |
| `claude/live-proof-20261111` | `18efb7ef6d196775645f195552a32ad08e277459` | Recorded source roots and honest live-gate measurement |
| `claude/ws-a-20261104` | `dabba4aea4ba0fa19e71ede05ce4fb8ab6741942` | Packaged desktop and executable identity |
| `codex/consolidated-reviewed-20261102` | `6e82fd70f315b99c6798a42c9061a1424a02933e` | Checkpoint replay/protocol composition and preserved ancestry |
| `codex/consolidation-evidence-20261102` | `44c320e37b84a38259f13fa8f0f444b542b96f2c` | Checkpoint replay/protocol composition and preserved ancestry |
| `codex/consolidation-integrity-20261103` | `b58bb53debcb3323e5d8d634e09397cb7e02965f` | Rule/build integrity and explicit native quarantine obligations |
| `codex/corpus-output-main-20261101` | `874e9a267fdc589a796ce573f2958e1aa84ea0f6` | Merged normalized-output and replay-schema lineage |
| `codex/essential-combined-verification-20261030` | `a7f13e13ffb512f8e9621753a0ae162d78942f3b` | Honest native-harness completion and failure semantics |
| `codex/rzdiff-164-investigation` | `20ef68eaab59a2941bd2fb0db918eee36107c75f` | Rule/build integrity and explicit native quarantine obligations |
| `codex/training-prereg-identity-20261101` | `dfe8f421db390ccd3158393a60205fa5dd25df0b` | Merged protocol identity guard |
| `fix/windows-posix-mingw-workflow-20261115` | `3b3ad32f60df9fd6994e25a8920cfb335cc3d602` | POSIX path semantics in the Linux MinGW workflow assertion |

## Qualification and historical controls

The fresh current gate passed **173 cases across 29 files in 7.14 seconds**, with two explicit compiler-backed deselections and zero skipped/failed/error cases. It covers bounded Java probing, KB fixture imports, synthetic unified fixtures, authored GT-01 harness behavior, source-root measurement and workflow parsing. The helper Python process and ZIP-permission snippet are authored controls; compared images and native engines were not executed.

The exact old Java controls pass six cases. Initial unified originals retain one assertion failure, six positives and one setup error; the collection-fix originals retain seven positives and one setup error. The failed gate had one lineage rather than the required thirty. Both PE variants bind timestamp as a nonexistent pytest fixture; current named strategies fix this. All 22 original nodes are individually classified. The five helper files for each historical fixture tip are byte-identical to current source.

Sealed batch4/batch5 exact55 receipts are referenced for inherited replay/protocol, branding, offline-runtime and build/session scopes. They are prior observations, not reruns or additive totals. Rule-specific controls requiring YARA-X were inspected but not run. The two native compiler cases, actual Windows packages, live source acquisition, native engine scoring, hosted workflows and manual acceptance remain open.

The batch-five COFF caller correction is carried forward: the probe exercises an exported optional developer API directly. The factory calls apply_case without extra_check; no normal factory/CLI wiring is claimed.

## Per-tip dispositions

### 1. `chatgpt/java-probe-boundaries-20261016`

**retained test scope.**

**Historical delta:** Adds six authored Java-version retry/cancellation/missing-runtime controls on the prior bounded implementation.

**Current behavior:** The actual backend tries 15 then 30 seconds only after the first timeout with no cancellation; other failures, missing Java and unparsable versions yield unknown. Current tests preserve the six behaviors with a closure-fixture correction.

**Actual caller evidence:** _open_raw_cache calls _java_version, stores unverified for unknown and constructs its runtime fingerprint from the result. The tests replace run_process; no Java process was run.

Current source: `src/patchtrace/backend.py`, `tests/test_backend_java_version.py`.

Contract: `docs/specs/ghidriff-timeout-progress.md`.

Control map: `tests/test_backend_java_version.py`.

Qualification: current-affected; historical-java: exact 09bb original, 6 passed; source projection and current caller proof.

**Selective decision:** No production or test port needed for this scope.

**Residual scope:** The source-free branch does not establish live JVM startup performance, Windows runtime discovery or native engine acceptance.

### 2. `chatgpt/java-probe-ci-fix-20261016`

**retained test scope.**

**Historical delta:** Only reorders threading and SimpleNamespace imports in the existing retry regression; it contains no production delta.

**Current behavior:** The actual backend tries 15 then 30 seconds only after the first timeout with no cancellation; other failures, missing Java and unparsable versions yield unknown. Current tests preserve the six behaviors with a closure-fixture correction.

**Actual caller evidence:** _open_raw_cache calls _java_version, stores unverified for unknown and constructs its runtime fingerprint from the result. The tests replace run_process; no Java process was run.

Current source: `src/patchtrace/backend.py`, `tests/test_backend_java_version.py`.

Contract: `docs/specs/ghidriff-timeout-progress.md`.

Control map: `tests/test_backend_java_version.py`.

Qualification: current-affected; historical-java: exact 09bb original, 6 passed; source projection and current caller proof.

**Selective decision:** No production or test port needed for this scope.

**Residual scope:** The source-free branch does not establish live JVM startup performance, Windows runtime discovery or native engine acceptance.

### 3. `chatgpt/kb-fixtures-1`

**retained with fixture corrections.**

**Historical delta:** Adds 13 fixture/document files, crash injection helper, performance plan and nine test files; no src/tools delta. Some tests request an unregistered no_sockets fixture, a nonexistent scenario or a confusable value the raw fixture does not contain.

**Current behavior:** All underlying synthetic corpus blobs and the crash helper are retained. Current fixtures explicitly register no_sockets, construct the unknown type99 case, exercise BOM refusal and CRLF import, admit the deliberately empty fictional CSAF inventory, and use a real confusable-KB fixture. The old synthetic bytes are preserved.

**Actual caller evidence:** Current fixture tests call actual import_bytes/parse_cvrf with sockets refused. The crash helper tests its own named checkpoints; it does not attach injection hooks to a missing production sidecar.

Current source: `src/patchtrace/kbcorrelation/sources/importer.py`, `src/patchtrace/kbcorrelation/sources/cvrf.py`, `tests/kb_crash_harness.py`, `tests/fixtures/kb/CONTRACT_CONFLICTS.md`.

Contract: `docs/specs/kb-cve/31-A-contracts-identity.md`.

Control map: `tests/test_kb_cvrf_fixture_import.py`, `tests/test_kb_fixture_encoding.py`, `tests/test_kb_fixture_properties.py`, `tests/test_kb_offline_fixture_import.py`, `tests/test_kb_raw_adversarial_inputs.py`, `tests/test_kb_synthetic_fixture_corpus.py`, `tests/test_kb_crash_injection_protocol.py`, `tests/test_kb_metadata_fixture_boundaries.py`, `tests/test_kb_update_relationships.py`.

Qualification: current-affected; all branch fixture/source projection and historical-to-current test diff inspected.

**Selective decision:** Keep the corrected current fixture registrations and actual boundary checks. No old fixture regression should be ported.

**Residual scope:** Fictional rows do not establish vendor accuracy, acquisition, complete crash recovery or real update-package applicability. The historical performance plan remains a plan.

### 4. `chatgpt/lbl31-windows-qa-fixes-20261016-a`

**retained foundation partial research.**

**Historical delta:** Adds quoted COFF masking and a duplicated default-sort fast path, and inherits output retention plus training-artifact transfer. Its handoff records real historical Windows failures but no new current execution.

**Current behavior:** Current quoted operands and function boundaries are retained. Current sort implementation differs from the duplicated historical fast path, but the exact old order and 100k-row threshold controls passed in sealed batch5 at this same55 baseline. Current output store has stronger verified-credit/bounded replay. training_artifacts.py and shard train-job transfer remain absent.

**Actual caller evidence:** ui_unified invokes read_model.sort_rows for displayed row indices; tools/unified/bench.py also benchmarks it. make_masked_body_check is an exported optional developer API exercised directly in batch5; the actual factory calls apply_case without extra_check, and no non-test caller of the optional check was found. evaluate retains normalized outputs; train.load_outputs validates managed credit.

Current source: `src/patchtrace/unified/read_model.py`, `tools/calibration/mutations/engine.py`, `tools/calibration/tier_r/output_store.py`, `tools/calibration/train.py`, `tools/calibration/tier_r/shard.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`, `docs/specs/unified-engine/07-ui-and-cli.md`.

Control map: `tests/test_unified_read_model.py`, `tests/test_tier_r_output_persistence.py`, `tests/test_tier_r_credited_replay.py`.

Qualification: prior exact55 batch5 current-affected and historical-sort; not rerun/additive here; prior optional-API COFF proof with attributed caller erratum62338862; actual tip patch and source projection.

**Selective decision:** Do not port the duplicate sort block. The known unquoted optional-API defect has separate approved repair ownership. Transfer remains a separately designed developer workflow.

**Residual scope:** Historical Windows test reports and current synthetic timing are not Windows native qualification. No claim that the optional COFF check is installed in normal factory/CLI acceptance.

### 5. `chatgpt/unified-fixture-collection-fix-20261016`

**retained with fixture corrections.**

**Historical delta:** Moves the corrected thirty-lineage G-U6 and explicit Hypothesis fixture-health policy into canonical test names and deletes the duplicate -2 files. Positional Hypothesis arguments still leave timestamp interpreted as a pytest fixture.

**Current behavior:** Current canonical G-U6 uses thirty distinct project/lineage labels and preserves the 20% reduction and thirty-lineage requirements. Current PE property test also uses named timestamp/padding strategies, resolving the still-broken positional argument binding. Required helper bytes for these original replays are identical at historical and current sources.

**Actual caller evidence:** The fixture gate calls actual rowgates.g_u6 on authored OutcomeRows; the PE test reads generated bytes through VerifiedArtifactReader/read_pe_tables and never executes them. A passing scripted gate is not observed engine accuracy.

Current source: `tools/unified/rowgates.py`, `tests/test_unified_fixture_gate_u6.py`, `tests/test_unified_synthetic_pe.py`, `tests/unified_support/gate_inputs.py`, `tests/unified_support/synthetic_pe.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`.

Control map: `tests/test_unified_fixture_gate_u6.py`, `tests/test_unified_synthetic_pe.py`, `tests/test_unified_fixture_fusion_properties.py`, `tests/test_unified_fixture_statistics.py`, `tests/test_unified_fixture_timing.py`, `tests/test_unified_synthetic_pairs.py`.

Qualification: current-affected; historical-unified-collection: 7 passed, 1 setup error; g_u6-observations.json: thirty scripted lineages pass; historical-control-source.json and exact helper equivalence.

**Selective decision:** No fixture port needed. Keep the named-strategy correction and canonical tests; retain original failures as fixture defects.

**Residual scope:** No actual engine, compiler, corpus power estimate or native speed result. The old duplicate filenames are not missing product features.

### 6. `chatgpt/unified-fixtures-1`

**retained with fixture corrections.**

**Historical delta:** Adds authored PE/assembler, pair, nuisance, statistics and G-U1..G-U7 fixtures. Corrected G-U6 and PE variants were left under ignored -2 filenames while canonical tests remained defective.

**Current behavior:** Current canonical G-U6 uses thirty distinct project/lineage labels and preserves the 20% reduction and thirty-lineage requirements. Current PE property test also uses named timestamp/padding strategies, resolving the still-broken positional argument binding. Required helper bytes for these original replays are identical at historical and current sources.

**Actual caller evidence:** The fixture gate calls actual rowgates.g_u6 on authored OutcomeRows; the PE test reads generated bytes through VerifiedArtifactReader/read_pe_tables and never executes them. A passing scripted gate is not observed engine accuracy.

Current source: `tools/unified/rowgates.py`, `tests/test_unified_fixture_gate_u6.py`, `tests/test_unified_synthetic_pe.py`, `tests/unified_support/gate_inputs.py`, `tests/unified_support/synthetic_pe.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`.

Control map: `tests/test_unified_fixture_gate_u6.py`, `tests/test_unified_synthetic_pe.py`, `tests/test_unified_fixture_fusion_properties.py`, `tests/test_unified_fixture_statistics.py`, `tests/test_unified_fixture_timing.py`, `tests/test_unified_synthetic_pairs.py`.

Qualification: current-affected; historical-unified-initial: 1 failed, 6 passed, 1 setup error; g_u6-observations.json: one lineage is insufficient; historical-control-source.json and exact helper equivalence.

**Selective decision:** No fixture port needed. Keep the named-strategy correction and canonical tests; retain original failures as fixture defects.

**Residual scope:** No actual engine, compiler, corpus power estimate or native speed result. The old duplicate filenames are not missing product features.

### 7. `chatgpt/unified-sort-perf-qa-20261016`

**retained foundation partial research.**

**Historical delta:** The leaf changes only the sort timing test to best-of-three at the same 0.20-second threshold. Despite its name, its merge-base-to-tip source delta contains no read_model.py change; the six source paths are inherited mutation/output/shard/transfer work.

**Current behavior:** Current quoted operands and function boundaries are retained. Current sort implementation differs from the duplicated historical fast path, but the exact old order and 100k-row threshold controls passed in sealed batch5 at this same55 baseline. Current output store has stronger verified-credit/bounded replay. training_artifacts.py and shard train-job transfer remain absent.

**Actual caller evidence:** ui_unified invokes read_model.sort_rows for displayed row indices; tools/unified/bench.py also benchmarks it. make_masked_body_check is an exported optional developer API exercised directly in batch5; the actual factory calls apply_case without extra_check, and no non-test caller of the optional check was found. evaluate retains normalized outputs; train.load_outputs validates managed credit.

Current source: `src/patchtrace/unified/read_model.py`, `tools/calibration/mutations/engine.py`, `tools/calibration/tier_r/output_store.py`, `tools/calibration/train.py`, `tools/calibration/tier_r/shard.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`, `docs/specs/unified-engine/07-ui-and-cli.md`.

Control map: `tests/test_unified_read_model.py`, `tests/test_tier_r_output_persistence.py`, `tests/test_tier_r_credited_replay.py`.

Qualification: prior exact55 batch5 current-affected and historical-sort; not rerun/additive here; prior optional-API COFF proof with attributed caller erratum62338862; actual tip patch and source projection.

**Selective decision:** Do not port the duplicate sort block. The known unquoted optional-API defect has separate approved repair ownership. Transfer remains a separately designed developer workflow.

**Residual scope:** Historical Windows test reports and current synthetic timing are not Windows native qualification. No claim that the optional COFF check is installed in normal factory/CLI acceptance.

### 8. `claude/access-test-1791773355`

**exact alias of inspected tip.**

**Historical delta:** Exact same commit and complete src/tools/tests/workflow tree as access-test-noprefix already inspected in batch5; access marker add/remove commits do not leave a product artifact.

**Current behavior:** The verified offline bundle validator/importer, bounded runtime discovery, JAVA_HOME_OVERRIDE environment and desktop import hook are retained with later safety improvements.

**Actual caller evidence:** Desktop import_offline_bundle and runtime_cli call the real importer; backend environment uses the selected private JDK. Exact tip identity is proven, not inferred from the access-test name.

Current source: `src/patchtrace/offline_bundle.py`, `src/patchtrace/runtime_discovery.py`, `src/patchtrace/backend.py`, `src/patchtrace/runtime_cli.py`, `src/patchtrace/ui.py`.

Contract: `docs/specs/offline-backend-installer.md`.

Control map: `tests/test_runtime_discovery_bundle.py`, `tests/test_runtime_discovery.py`.

Qualification: overlap.json exact tip726a371a identity; prior exact55 batch4/batch5 offline controls; no duplicate test credit.

**Selective decision:** No additional selective port for this alias.

**Residual scope:** The directory-publication reservation defect found in batch3 and later root repair remain separately attributed. This alias does not qualify a native installed bundle or approve licenses.

### 9. `claude/awesome-ramanujan-o3pxx3-win1`

**retained focal scope.**

**Historical delta:** Introduces the Windows version resource/icon generators, app icon, PyInstaller data hook and bounded PE checker.

**Current behavior:** Three of eight changed source files are exact; the rest are retained through stricter full commit IDs, exact version/PNG checks, complete resources, exclusive adjacent staging and the current console/subprocess policy.

**Actual caller evidence:** build_windows.main writes the version resource and icon used by its PyInstaller command; check_windows_exe.main reads the produced PE without executing it. __main__ installs the application icon. This is source wiring plus synthetic resource evidence.

Current source: `tools/build_windows.py`, `tools/build_linux.py`, `tools/check_windows_exe.py`, `tools/windows_version_info.py`, `tools/windows_icon.py`, `src/patchtrace/__main__.py`, `src/patchtrace/app_icon.py`.

Contract: `docs/specs/windows-acceptance-and-milestone-builds.md`.

Control map: `tests/test_windows_build_resources.py`.

Qualification: source/AST projection; exact nine-file ws-a comparison in overlap.json; prior exact55 batch5 Windows resource gate; no fresh Windows execution.

**Selective decision:** No source port needed. Keep stricter current resource checks and exclusive staging.

**Residual scope:** No installer, Explorer icon, signed publisher, native PE build or Windows GUI/manual acceptance here. Historical reports are not new gates.

### 10. `claude/live-harness-infra-20261111`

**retained focal scope.**

**Historical delta:** Integrates GT-01 raw-result persistence before unified extraction, isolated extraction work, failed-output diagnostics and opt-in native identical-image controls. Workflow hunks restore archived executable bits and add EGL dependencies.

**Current behavior:** Current live_pairs commits completed backend evidence before unified extraction, uses isolated extraction work, refuses an identical shortcut as native execution, forces no-cache A/A only in the harness and preserves bounded/redacted failures. Backend validates the opt-in flag and retains distinct input names. Linux workflow restores ZIP executable bits and includes libegl1.

**Actual caller evidence:** live_pairs.main passes selected labels to analyse_pair; analyse_pair configures run_comparison, checks completion, applies analysis then extracts. The controlled backend test executes only an authored Python stand-in, not Ghidra or target bytes. The ZIP test executes only the fixed Python permission-restoration snippet on synthetic files.

Current source: `tools/unified/live_pairs.py`, `src/patchtrace/backend.py`, `.github/workflows/unified-live-gates.yml`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`.

Control map: `tests/test_unified_live_pairs_r1.py`, `tests/test_unified_live_force_identical.py`, `tests/test_unified_live_native_failure_details.py`.

Qualification: current-affected; prior exact55 batch4 GT-01 source lineage; actual patches and caller/config guards.

**Selective decision:** No selective GT-01 port needed for these paths.

**Residual scope:** Real Ghidriff extraction, pinned runtime installation, live gates, native engine accuracy, hosted workflow execution and platform behavior remain unqualified here. Broader KB consolidation scope stays separately recorded.

### 11. `claude/live-proof-20261111`

**retained focal scope.**

**Historical delta:** Adds native root-spelling normalization, retained passed/resolved build roots, exported planted candidates, asymmetric empty-inventory refusal and G-U2 unpaired outcome accounting, on top of GT-01.

**Current behavior:** Five of eight source paths are exact. Current build retains the same source_dirs behavior with stronger receipt publication; labeler additionally refuses both-empty inventories and does not promote ambiguous unchanged controls. Backend differences are later retained guards.

**Actual caller evidence:** _build_in records source_dirs in BuildResult; factory.Session.side includes source_dirs in its key and labeler.analyze passes them to debuginfo.inventory. Mutation templates place EXPORT in base and mutated functions; evaluator reports unpaired verdicts without counting hits/leakage. These actual callers were inspected.

Current source: `tools/calibration/tier_r/build.py`, `tools/calibration/tier_r/factory.py`, `tools/calibration/tier_r/debuginfo.py`, `tools/calibration/tier_r/labeler.py`, `tools/unified/mutations/templates.py`, `tools/unified/evaluators.py`, `tools/unified/gates_u.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`.

Control map: `tests/test_unified_rb01_harness.py`, `tests/test_unified_gate_eval.py`.

Qualification: current-affected with two explicit compiler deselections; overlap.json exact five-file comparison; current source and caller proof.

**Selective decision:** No source port needed. Preserve the stronger empty-inventory and provenance guards.

**Residual scope:** Authored path strings, DWARF text and template exports do not qualify actual PDB/DWARF compiler output, disassembly discovery or real native recall. No compiler was invoked.

### 12. `claude/ws-a-20261104`

**retained focal scope.**

**Historical delta:** Integrates strict Windows identity/resource checks and exclusive staging, plus the packaged desktop mark for both builders. It explicitly removes a frozen .gitattributes hunk into historical evidence.

**Current behavior:** All nine changed production source paths are byte-identical to frozen55, including the Linux and Windows builder hooks. The retained original mark and PyInstaller hook are exact.

**Actual caller evidence:** build_windows.main writes the version resource and icon used by its PyInstaller command; check_windows_exe.main reads the produced PE without executing it. __main__ installs the application icon. This is source wiring plus synthetic resource evidence.

Current source: `tools/build_windows.py`, `tools/build_linux.py`, `tools/check_windows_exe.py`, `tools/windows_version_info.py`, `tools/windows_icon.py`, `src/patchtrace/__main__.py`, `src/patchtrace/app_icon.py`.

Contract: `docs/specs/windows-acceptance-and-milestone-builds.md`.

Control map: `tests/test_windows_build_resources.py`.

Qualification: source/AST projection; exact nine-file ws-a comparison in overlap.json; prior exact55 batch5 Windows resource gate; no fresh Windows execution.

**Selective decision:** No source port needed. Keep stricter current resource checks and exclusive staging.

**Residual scope:** No installer, Explorer icon, signed publisher, native PE build or Windows GUI/manual acceptance here. Historical reports are not new gates.

### 13. `codex/consolidated-reviewed-20261102`

**retained composition with open residue.**

**Historical delta:** Five-parent merge retains actual integration, replay/schema, preregistration and main ancestry. Its 79-path source delta is a broad inherited checkpoint rather than one independent feature.

**Current behavior:** The replay/schema and preregistration slices are retained together: current managed replay verifies report credit and metadata, and training CLI validates complete visible protocol identity before inputs. Twenty-six changed source files are exact to this tip; the rest are explicitly not wholesale-equivalent.

**Actual caller evidence:** train._run calls PG.select before _inputs, while train.load_outputs uses read_credited_outputs. These are production CLI/data-path calls. The checkpoint title and historical pass counts are not evidence that unrelated GUI, matching, creation or research deltas were integrated.

Current source: `tools/calibration/train.py`, `tools/calibration/prereg_gate.py`, `tools/calibration/tier_r/output_store.py`, `tools/calibration/tier_r/report_schemas.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`, `docs/specs/calibration-corpus-and-model.md`.

Control map: `tests/test_train_prereg_selection.py`, `tests/test_tier_r_credited_replay.py`, `tests/test_tier_r_credit_completion.py`.

Qualification: prior exact55 batch5 replay/protocol gate; overlap.json actual merge parents and evidence-leaf source equality; complete changed-path/AST residue inventory.

**Selective decision:** Retain the scoped replay/protocol composition and evidence, with no wholesale merge or closure recommendation.

**Residual scope:** Broad inherited snapshot remains partial: saved-scope and R2 witness/report omissions at frozen55, missing research/transfer/benchmark helpers, historical creation/retry/UI variants and native rz-diff orientation evidence. Previously reported directory/highlighter/F8/named-source/UI repairs and later COFF/A-A/saved-scope work must be attributed to their own source, never retroactively to55. This focal disposition does not close the 79/85-path checkpoint or all missing symbols.

### 14. `codex/consolidation-evidence-20261102`

**retained composition with open residue.**

**Historical delta:** Docs/evidence leaf over6e82; every src/tools/workflow byte is identical to that reviewed checkpoint. It records historical failures, reconciliation, pending native/package work and research proposals.

**Current behavior:** The replay/schema and preregistration slices are retained together: current managed replay verifies report credit and metadata, and training CLI validates complete visible protocol identity before inputs. Twenty-six changed source files are exact to this tip; the rest are explicitly not wholesale-equivalent.

**Actual caller evidence:** train._run calls PG.select before _inputs, while train.load_outputs uses read_credited_outputs. These are production CLI/data-path calls. The checkpoint title and historical pass counts are not evidence that unrelated GUI, matching, creation or research deltas were integrated.

Current source: `tools/calibration/train.py`, `tools/calibration/prereg_gate.py`, `tools/calibration/tier_r/output_store.py`, `tools/calibration/tier_r/report_schemas.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`, `docs/specs/calibration-corpus-and-model.md`.

Control map: `tests/test_train_prereg_selection.py`, `tests/test_tier_r_credited_replay.py`, `tests/test_tier_r_credit_completion.py`.

Qualification: prior exact55 batch5 replay/protocol gate; overlap.json actual merge parents and evidence-leaf source equality; complete changed-path/AST residue inventory.

**Selective decision:** Retain the scoped replay/protocol composition and evidence, with no wholesale merge or closure recommendation.

**Residual scope:** Broad inherited snapshot remains partial: saved-scope and R2 witness/report omissions at frozen55, missing research/transfer/benchmark helpers, historical creation/retry/UI variants and native rz-diff orientation evidence. Previously reported directory/highlighter/F8/named-source/UI repairs and later COFF/A-A/saved-scope work must be attributed to their own source, never retroactively to55. This focal disposition does not close the 79/85-path checkpoint or all missing symbols.

### 15. `codex/consolidation-integrity-20261103`

**retained integrity with open residue.**

**Historical delta:** Four-parent merge adds six production paths over44c320e3: rule export-name preflight, content-identity rescoring, nonregular input refusal, malformed sidecar handling, complete build receipts, source/build-bound session cache and ambiguous control handling.

**Current behavior:** Current code retains the six-path integrity slice, strengthens bounded receipt reuse and atomic compatibility publication, adds source_dirs to the session key, caps hashed files, preserves equal-second decision ordering and uses strict JSON for sidecars. Production rz-diff singleton orientation quarantine remains. The historical research observation helper is absent; it cannot authorize unquarantine.

**Actual caller evidence:** rules.cli._test uses matrix.rescored on cache reuse, RuleStore.tests invokes _inline through _read, and rule export.write validates the basename before file publication. _build_in calls persist_build_record; factory.Session.side keys actual analyses by build and source context. No native YARA-X or rz-diff run was selected for this batch.

Current source: `src/patchtrace/rules/export.py`, `src/patchtrace/rules/matrix.py`, `src/patchtrace/rules/store.py`, `src/patchtrace/rules/cli.py`, `src/patchtrace/secondary/rzdiff.py`, `tools/calibration/tier_r/build.py`, `tools/calibration/tier_r/factory.py`, `tools/calibration/tier_r/labeler.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`, `docs/specs/yara-x-rule-workflow.md`.

Control map: `tests/test_tier_r_build_receipts_r1.py`, `tests/test_tier_r_session_provenance_r1.py`, `tests/test_tier_r_label_promotion_r1.py`, `tests/test_rules_matrix.py`, `tests/test_rules_store.py`, `tests/test_rules_export.py`.

Qualification: prior exact55 batch4/batch5 authored build/provenance controls; six-path integrity patch and current stronger replacements inspected; rule-specific native controls not rerun; overlap.json and original-rzdiff-164-investigation.md.

**Selective decision:** No port of the older weaker integrity implementations. Keep native quarantine; any producer/witness work requires its separate accepted design and platform gates.

**Residual scope:** Broad inherited snapshot remains partial: saved-scope and R2 witness/report omissions at frozen55, missing research/transfer/benchmark helpers, historical creation/retry/UI variants and native rz-diff orientation evidence. Previously reported directory/highlighter/F8/named-source/UI repairs and later COFF/A-A/saved-scope work must be attributed to their own source, never retroactively to55. This focal disposition does not close the 79/85-path checkpoint or all missing symbols.

### 16. `codex/corpus-output-main-20261101`

**retained composed scope.**

**Historical delta:** The actual merged parent contains the exact reviewed replay/schema src/tools/workflow bytes of ca411e77. Five of its six source-delta files are exact at55; train.py also gained the separate preregistration gate.

**Current behavior:** Managed output credit, bounded engine metadata/schema, completed output publication and faithful replay are retained. Current training input path combines replay integrity with preregistration-before-input access.

**Actual caller evidence:** evaluate writes retained outputs before report credit; train.load_outputs uses read_credited_outputs, refuses duplicates and visible symbols, and labels legacy loading unverified. No branch-merge title is used as the proof.

Current source: `tools/calibration/tier_r/output_store.py`, `tools/calibration/tier_r/evaluate.py`, `tools/calibration/tier_r/contracts.py`, `tools/calibration/tier_r/report_schemas.py`, `tools/calibration/train.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`, `docs/specs/calibration-corpus-and-model.md`.

Control map: `tests/test_tier_r_credited_replay.py`, `tests/test_tier_r_credit_completion.py`, `tests/test_tier_r_output_stat_compat.py`.

Qualification: overlap.json exact ca411/874 source equivalence; prior exact55 batch5 current replay gate.

**Selective decision:** No source port needed for this composed replay scope.

**Residual scope:** Research artifact transfer, final protected-corpus training and native observed prediction accuracy are separate unfinished/ungated scopes.

### 17. `codex/essential-combined-verification-20261030`

**retained focal scope.**

**Historical delta:** Combines the same GT-01 lineage with reviewed synthetic KB fixture reconciliation and a docs-only combined-verification leaf. It is not a new native run in this inventory.

**Current behavior:** Current live_pairs commits completed backend evidence before unified extraction, uses isolated extraction work, refuses an identical shortcut as native execution, forces no-cache A/A only in the harness and preserves bounded/redacted failures. Backend validates the opt-in flag and retains distinct input names. Linux workflow restores ZIP executable bits and includes libegl1.

**Actual caller evidence:** live_pairs.main passes selected labels to analyse_pair; analyse_pair configures run_comparison, checks completion, applies analysis then extracts. The controlled backend test executes only an authored Python stand-in, not Ghidra or target bytes. The ZIP test executes only the fixed Python permission-restoration snippet on synthetic files.

Current source: `tools/unified/live_pairs.py`, `src/patchtrace/backend.py`, `.github/workflows/unified-live-gates.yml`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`.

Control map: `tests/test_unified_live_pairs_r1.py`, `tests/test_unified_live_force_identical.py`, `tests/test_unified_live_native_failure_details.py`.

Qualification: current-affected; prior exact55 batch4 GT-01 source lineage; actual patches and caller/config guards.

**Selective decision:** No selective GT-01 port needed for these paths.

**Residual scope:** Real Ghidriff extraction, pinned runtime installation, live gates, native engine accuracy, hosted workflow execution and platform behavior remain unqualified here. Broader KB consolidation scope stays separately recorded.

### 18. `codex/rzdiff-164-investigation`

**retained integrity with open residue.**

**Historical delta:** Only new leaf content is the bounded PR164 orientation handoff; src/tools/workflow bytes are identical to b58bb53d. It documents conditional singleton inversion, an old ambiguous replay and missing source/runtime access, explicitly without a new implementation or native acceptance.

**Current behavior:** Current code retains the six-path integrity slice, strengthens bounded receipt reuse and atomic compatibility publication, adds source_dirs to the session key, caps hashed files, preserves equal-second decision ordering and uses strict JSON for sidecars. Production rz-diff singleton orientation quarantine remains. The historical research observation helper is absent; it cannot authorize unquarantine.

**Actual caller evidence:** rules.cli._test uses matrix.rescored on cache reuse, RuleStore.tests invokes _inline through _read, and rule export.write validates the basename before file publication. _build_in calls persist_build_record; factory.Session.side keys actual analyses by build and source context. No native YARA-X or rz-diff run was selected for this batch.

Current source: `src/patchtrace/rules/export.py`, `src/patchtrace/rules/matrix.py`, `src/patchtrace/rules/store.py`, `src/patchtrace/rules/cli.py`, `src/patchtrace/secondary/rzdiff.py`, `tools/calibration/tier_r/build.py`, `tools/calibration/tier_r/factory.py`, `tools/calibration/tier_r/labeler.py`.

Contract: `docs/specs/unified-engine/08-evaluation.md`, `docs/specs/known-answer-corpus.md`, `docs/specs/yara-x-rule-workflow.md`.

Control map: `tests/test_tier_r_build_receipts_r1.py`, `tests/test_tier_r_session_provenance_r1.py`, `tests/test_tier_r_label_promotion_r1.py`, `tests/test_rules_matrix.py`, `tests/test_rules_store.py`, `tests/test_rules_export.py`.

Qualification: prior exact55 batch4/batch5 authored build/provenance controls; six-path integrity patch and current stronger replacements inspected; rule-specific native controls not rerun; overlap.json and original-rzdiff-164-investigation.md.

**Selective decision:** No port of the older weaker integrity implementations. Keep native quarantine; any producer/witness work requires its separate accepted design and platform gates.

**Residual scope:** Broad inherited snapshot remains partial: saved-scope and R2 witness/report omissions at frozen55, missing research/transfer/benchmark helpers, historical creation/retry/UI variants and native rz-diff orientation evidence. Previously reported directory/highlighter/F8/named-source/UI repairs and later COFF/A-A/saved-scope work must be attributed to their own source, never retroactively to55. This focal disposition does not close the 79/85-path checkpoint or all missing symbols.

### 19. `codex/training-prereg-identity-20261101`

**retained composed scope.**

**Historical delta:** Actual f27d23a8/9b9452b4 parent merge; all src/tools/workflow bytes equal9b9452b4. The guard parses an unambiguous visible complete Markdown row and exact LF protocol digest before CLI inputs.

**Current behavior:** prereg_gate.py is byte-identical to the tip; train.py incorporates the separate stronger managed-output reader and bounded shared engine-version contract. The public run_training library still requires an already validated SHA from its caller.

**Actual caller evidence:** train._run calls PG.select before _inputs and refuses protocol smoke outside explicit rehearsal. This is an identity guard, not owner approval or a single-use final-look authorization service.

Current source: `tools/calibration/prereg_gate.py`, `tools/calibration/train.py`.

Contract: `docs/specs/calibration-corpus-and-model.md`.

Control map: `tests/test_train_prereg_selection.py`.

Qualification: overlap.json exact9b945/dfe source equivalence; prior exact55 batch5 protocol controls and classified historical mismatches.

**Selective decision:** Keep current composed identity and replay guards; no source port needed.

**Residual scope:** Missing historical owner-signoff/final-run orchestration remains separate. No protected corpus access, training run, accuracy claim or approval was exercised.

### 20. `fix/windows-posix-mingw-workflow-20261115`

**retained test scope.**

**Historical delta:** Only changes the test to PurePosixPath for the Linux workflow path while tests run on Windows. No workflow or production path changes occur.

**Current behavior:** The complete test file is byte-identical to the tip and retains the exact pinned win32 MinGW variant requirement. The current offline workflow parsing tests pass on Linux.

**Actual caller evidence:** The test reads the existing corpus workflow YAML and checks its Linux path with POSIX semantics; it does not install or run MinGW.

Current source: `tests/test_unified_corpus_workflow.py`, `.github/workflows/unified-corpus.yml`.

Contract: `docs/specs/unified-engine/08-evaluation.md`.

Control map: `tests/test_unified_corpus_workflow.py`.

Qualification: current-affected; overlap.json byte-identical entire test file.

**Selective decision:** No source, workflow or test port needed.

**Residual scope:** This assertion correction alone is not a hosted Windows/MinGW gate, compiler build or proof that all workflow proposals were integrated.

## Remaining original tips

| Branch | Exact frozen tip |
|---|---|
| `chatgpt/merge-first-handoff-20261016` | `19153f10780e783bc931739dd26db97d8eaf2b92` |
| `claude/clever-clarke-s4nhi6` | `502402684b0d0aa35d7719bb5a3467de035982bc` |
| `claude/fix-deadline-test` | `22ff025a7710d07d7ad74be2c8f7cc0b4db0daf7` |
| `claude/patchtrace-haiku-agent-motpbx` | `cbabc09e9df8a8190c769164ef0fae44f9c5cb1b` |
| `claude/ws-a2-ci-speed-20261104` | `bef720fdd50c0ab7c93a10955b3e5ec7d2a5f992` |
| `codex/audit-2` | `08b12f1b279d917736cfc17d4b8e447c8f552616` |
| `codex/parser-test-cpu-budget-20261104` | `cb204f7625d4de496642926bbda37d07e2888131` |
| `consolidate/kb-fixtures-20261104` | `820d70744dff58ef484299791d073b2e712f0524` |
| `consolidate/test-stability-20261104` | `64e8374d5d3ae97a719a2bb3ac800497c50892af` |
| `haiku/phase2-handoff-import-20261027` | `4522030ff3ff76d720a5efc33953aaa5e5837398` |
| `integration/kb-fixtures-pr69-20261030` | `2fcd627e52a6d784d5c2e5b4ea8105e90b8589b3` |

## Evidence boundary

The JSON retains merge bases, ahead/behind, git-cherry patch equivalence, all changed paths, current/historical file blobs, AST comparisons, full parent-aware replacement history and exact scoped overlap. Archived original source/test bytes are hashed. These are proofs for the stated focus; broad checkpoint residue and source-free handoff obligations remain explicit. No blanket branch closure, release claim, native qualification or remote action is authorized by this ledger.
