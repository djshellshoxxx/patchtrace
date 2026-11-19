# Semantic branch disposition — batch 3

Comparison source: **`55f3d0742f7d4cf32357a42b8b1cc76d85875e71`**, tree `11a0c1598764ebd3fd8d3b540377aa52e949f88a` (actual published PR #316).

This is a read-only review of 20 source-bearing tips from the 91 original tips left unselected after batch 2. Eighteen inspected focal scopes are retained in current source; one retains a reproduced backup defect and one omits a historical highlighter dispatch guard. No product source was changed.

The [complete JSON](semantic-disposition-batch3.json) retains every exact tip, merge base, ahead/behind count, patch-equivalence record, changed-path/blob projection, source proof, test mapping and all 71 still-unselected tips. The [QA receipt](../../qa/semantic-disposition-batch3-20261118.md) links the sealed raw evidence.

## Observation and criteria

The original inventory was observed at `2026-11-18T13:50:56.954Z`. This batch cross-checks local fetched refs against those frozen tips; it does not refresh GitHub PR/review/check state. Batch 1 selected 20 tips at `ac789497`; batch 2 selected 20 at `3be3af16` and is read from its committed checkpoint `1a07861f`. Batch 2 is not part of this older comparison baseline ancestry. Later named-source/UI/static or backup continuation results do not relabel this source.

All 20 production patches were read against their merge bases, then compared with actual current guards, call sites and tests. Exact file/AST matches support some decisions; moved implementations require their current caller and contract evidence. Source introduction/replacement history is recorded with full merge history and parent presence, including the consolidation that simplified path history omits. A source match does not transfer historical native or release acceptance.

**60 of 131 original reconciliation tips now have selected-scope entries; 71 remain unselected.** These are scope counts, not completed branches, a feature percentage or closure authority. Unreviewed broader checkpoint/packaging/research residue remains open. All branches are preserved.

## Twenty exact tips

| Branch | Exact tip | Focal outcome |
|---|---|---|
| `audit/ai-reports` | `dd6402b9c00d5aae79f152f4fe5ce0fa8597dc24` | Retained focal scope: Total provider deadline and report path redaction |
| `audit/core` | `fae13b2ed3043ddce00bbf387e386e93e7b3ee06` | Retained, confirmed defect: Strict JSON, transactional ownership, backup and manual-correction guards |
| `audit/desktop` | `4d5e48ab7df30f6318a8f3177b37ac98741e2b1f` | Retained focal scope: Plain untrusted tooltips/consent, empty export path, self-test cleanup |
| `audit/runtime` | `9f32a6ecbd056249373b82bc1e814bd938da8c70` | Retained focal scope: Runtime probe parsing, bounded scratch cleanup, process failure and diagnostic filtering |
| `chatgpt/deferred-audit-fixes-1` | `2174837f3172c3ff2a3c676da106f42b55648a70` | Retained focal scope: Isolated backend probes/input copies, explicit acquisition consent and storage guards |
| `feat/alpha-ui-integration` | `c7ed1d90a890afa9eb67c238f9f52f458db96432` | Retained focal scope: Verified PE overview and Hex/Binary/Base64 desktop wiring |
| `feat/artifact-bytes-seam` | `91b35d09afd29e9c78169a3b095d9ea3be6c31b1` | Retained focal scope: Shared verified, bounded artifact reader |
| `feat/byte-representations` | `303bc452d0bb6cd46ee67f731f64ec951e1ee215` | Retained focal scope: Pure byte scopes, exact encodings, bounded pages and offset comparison |
| `feat/local-runtime-discovery` | `b9198705ab4c144746214c1e42c15b6098063009` | Retained focal scope: Bounded read-only installed-runtime discovery and non-destructive Setup prefill |
| `feat/tooltip-registry` | `0a3843ea2abe37d42ff0291d621fa9a7c9744bbc` | Retained focal scope: Semantic static/dynamic tooltip registry and actual widget application |
| `feature/alpha-file-overview-20261013` | `476016590be5cd1315613759af18ff61c7c27851` | Retained focal scope: Backend-independent recorded artifact overview |
| `feature/gui-inspection-preview` | `8b94227a81b71841c65783c775f704a538d35710` | Retained focal scope: Cross-function previous/next hunk navigation and source explanations |
| `fix/backend-exit-diagnostics` | `bc00a6912dde57482a301bf64ef6fbc3f324cb92` | Retained focal scope: Fixed-text actionable Ghidriff failure classification |
| `fix/explicit-offline-symbol-policy` | `2e6618762ab6e15e5be0be60aec3fb8f56af44f3` | Retained focal scope: Default-off symbol downloads and explicit analyst policy |
| `claude/symbol-policy-isolated-settings` | `5db597257decc219db520c0dab8369b4d4e2ea5e` | Retained focal scope: Per-run Ghidra settings isolation and cached-PDB diagnosis |
| `fix/pe-inspection-row-tooltips-20261013` | `0182a8035d64071fc88b5f299edc3ef3760946b5` | Retained focal scope: Source-safe PE/trust/unavailable row explanations |
| `chatgpt/ghidriff-sequential-lock-fix-20261017` | `f6b7545bcc7a161440ab7119233c204510571370` | Retained focal scope: Serial native Ghidriff analysis in every launcher mode |
| `fix/ghidra-dot-paths` | `5c3b1df94c0d2a908bb0459caceb336912527555` | Retained focal scope: Ghidra output-path refusal and visible quarantine paths |
| `fix/isolate-ghidra-scratch` | `7ea7272311271a540a188e5d0de6d3aaa8864611` | Retained focal scope: Private native engine work directories outside the case |
| `fix/codetext-budget-wave3` | `c7fb422c750f1d0e5591277b91492874afd79af7` | Confirmed selective omission: Avoid per-row span dispatch outside the visible code window during bulk load |

## Source-level dispositions

### 1. `audit/ai-reports`

**Retained focal scope.** Frozen PR mapping: none mapped in frozen inventory.

**Historical delta:** Bounds the whole provider exchange to 120 seconds, uses available-byte read1 for slow-drip responses, and redacts Windows absolute paths containing spaces.

**Current replacement:** providers._exchange/_fetch retain the total monotonic deadline and bounded read1 loop; _CallLimit plus interruptible also observes cancellation/deadline while an individual I/O step blocks. reports._redact retains the Windows-spaces pattern. Later _Verbatim handling exempts explicitly included evidence/code from path rewriting while credential redaction remains.

Source: `src/patchtrace/providers.py`, `src/patchtrace/reports.py`.

Verified ancestral source records: `eb66a07b78a7dc44be67a95ea9603b1459402036`, `1223cdd5517c2d49423210a6c7a35b5946679a07`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_audit_ai_reports.py`, `tests/test_interpretation.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No selective port for these two focal fixes. Keep the newer interruptible transport and explicit evidence text behavior.

**Residual scope:** No live provider endpoint, DNS/TLS or production latency qualification; old audit branch full suite and all report/privacy behavior were not recertified.

### 2. `audit/core`

**Retained, confirmed defect.** Frozen PR mapping: none mapped in frozen inventory.

**Historical delta:** Rejects nonfinite/oversized JSON numbers, initializes DDL transactionally, refuses foreign/older saves, refreshes the service after backup recovery, reserves new backup destinations, and restricts match-override annotations to manual corrections.

**Current replacement:** Number validation, BEGIN/identity/revision save guards, manual-correction restriction and service backup refresh remain. Later creation ownership/in-place retry guards replace old unconditional database unlink cleanup and must not be reverted. The backup reservation helper is AST-identical to the old tip, but its pathname reservation is insufficient when replaced by a foreign empty directory: current public backup either overwrites or removes that replacement.

Source: `src/patchtrace/persistence.py`, `src/patchtrace/service.py`.

Verified ancestral source records: `1223cdd5517c2d49423210a6c7a35b5946679a07`, `67e5a6c6919ee711c99d334ed58e3e91298c3038`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_audit_core.py`, `tests/test_core.py`, `tests/test_gui_creation_retry.py`, `tests/test_creation_schema_refusal.py`, `tests/test_creation_replacement_refusal.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** Do not port the old persistence file. Root owns a separate backup publication design/repair. Preserve the unchanged two-red/one-positive public-service reproduction.

**Residual scope:** The confirmed reproduction is POSIX empty-directory substitution only. It is not a Windows finding, full filesystem-sandbox claim, or evidence that the source project database was corrupted. Broader creation/backup publication qualification remains separate.

### 3. `audit/desktop`

**Retained focal scope.** Frozen PR mapping: none mapped in frozen inventory.

**Historical delta:** Escapes dynamic tooltips, makes offline consent plain text/default No, keeps an empty export destination empty across format switches, and closes the desktop self-test window in finally.

**Current replacement:** MainWindow/plain_tip call sites still escape untrusted artifact/match/finding/signal data. Setup/offline consent remains PlainText; change_format returns on an empty destination. __main__.main retains finally window.close(). New semantic tooltip templates and accessible descriptions extend the old controls.

Source: `src/patchtrace/__main__.py`, `src/patchtrace/ui.py`, `src/patchtrace/tooltips.py`, `src/patchtrace/gui/tips.py`.

Verified ancestral source records: `1223cdd5517c2d49423210a6c7a35b5946679a07`, `8b5ae1e912204bafa422e42db70606a8abbad66f`, `e7bd3dd4ac908adea3442056852f916ee3ea0b38`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_audit_desktop.py`, `tests/test_ui.py`, `tests/test_ui_setup_dialog.py`, `tests/test_tooltips.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No selective source port for the inspected audit fixes.

**Residual scope:** No frozen executable self-test, native dialogs, screen-reader or manual Windows/theme/DPI acceptance was performed. The global tooltip sweep has existing documented deferred-state exemptions; this batch added none.

### 4. `audit/runtime`

**Retained focal scope.** Frozen PR mapping: none mapped in frozen inventory.

**Historical delta:** Uses the last merged probe-output line, treats output-tree stat failures as failure, retries private scratch cleanup without hiding the run outcome, handles kill/wait timeout, redacts quoted credentials and URL userinfo, and filters discovery names before the child cap.

**Current replacement:** backend._probe_backend, _output_error and _remove_scratch retain these behaviors; output-check-failed and leftover warnings remain distinct from successful analysis. jobs retains explicit post-kill handling and later process ownership controls. runtime_discovery._children filters the requested prefix before limiting to 64 children. Diagnostic patterns retain the audit's credential classes.

Source: `src/patchtrace/backend.py`, `src/patchtrace/jobs.py`, `src/patchtrace/diagnostics.py`, `src/patchtrace/runtime_discovery.py`.

Verified ancestral source records: `1223cdd5517c2d49423210a6c7a35b5946679a07`, `8b5ae1e912204bafa422e42db70606a8abbad66f`, `e7bd3dd4ac908adea3442056852f916ee3ea0b38`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_audit_runtime.py`, `tests/test_jobs.py`, `tests/test_diagnostics_core8.py`, `tests/test_runtime_discovery.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No selective port. Preserve later child containment and private environment handling.

**Residual scope:** Windows Job Object and long-path cases are explicit skips. Real Ghidra shutdown, protected filesystem cleanup and live runtime readiness remain unqualified. Later GUI attempt-retention repairs are not relabeled as part of this baseline.

### 5. `chatgpt/deferred-audit-fixes-1`

**Retained focal scope.** Frozen PR mapping: #67.

**Historical delta:** Uses private cwd and isolated Python for probes/launches; hashes bounded private input copies; validates early PE headers before large copies; constructs FetchConsent from exact previewed URLs/provider choices; rejects nonpositive log bounds, duplicate prepared imports and empty manual corrections.

**Current replacement:** Those guards are present in backend._snapshot_input, ingestion._validate_pe_prefix, cli.cmd_correlate, diagnostics.redact_log and service prepare/manual correction paths. Full merge history, not simplified path history, identifies their consolidation in 4c963886. The old _secondary_run function is present under secondary/cli_import.py and reached by cli.cmd_secondary.dispatch; its former path is not a lost public workflow.

Source: `src/patchtrace/backend.py`, `src/patchtrace/ingestion.py`, `src/patchtrace/cli.py`, `src/patchtrace/diagnostics.py`, `src/patchtrace/service.py`, `src/patchtrace/secondary/cli_import.py`.

Verified ancestral source records: `4c96388678a8f496757b56dc4b8f57312a91b48a`, `a04f5a299a8d4afef023261e52e08d14678cf1e7`, `e275dbc9d4e6a64e3369fab34ad5d0197b9eea94`, `fd76a20af33d0d492c82c78f59b4781d8b08e465`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_backend_sec1.py`, `tests/test_backend_sec3.py`, `tests/test_backend_bundle_env.py`, `tests/test_ingestion_core10.py`, `tests/test_cli_acq13.py`, `tests/test_acquisition_acq12.py`, `tests/test_network_consent_symbols.py`, `tests/test_core.py`, `tests/test_diagnostics_core8.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No historical whole-file port. Current isolation, explicit consent and storage guards already implement the selected behavior.

**Residual scope:** No live acquisition or native backend was executed. This is not a new audit of every delegated secondary engine or all source paths reachable from the broad CLI dispatcher.

### 6. `feat/alpha-ui-integration`

**Retained focal scope.** Frozen PR mapping: #25.

**Historical delta:** Inspects both oriented artifact copies independently, retains verified readers for raw views, exposes whole-file/entry-start scopes with truthful unavailable/extent text, bounded pages and exact copy attribution, and integrates cancellable inspection into File overview.

**Current replacement:** artifact_inspection, raw_view and MainWindow retain the pure orchestration and raw controls. FilesController/RowsModel replaces the old modal table-fill and overview-widget helpers; it consumes the same inspection result and keeps recorded fields separate from parsed/trust fields. MainWindow guards results by project/root/oriented hashes, retains and joins worker threads, and closes stale readers. New paired alignment composes these controls without making entry-start bytes a verified function extent.

Source: `src/patchtrace/artifact_inspection.py`, `src/patchtrace/raw_view.py`, `src/patchtrace/ui.py`, `src/patchtrace/ui_inspection.py`.

Verified ancestral source records: `58578e176ff420f0e80eb1d41c740d43bd01ea4a`, `21a005e242177f07a984937a7cd924e826c17b9f`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_alpha_integration.py`, `tests/test_preflight_overview.py`, `tests/test_ui_inspection_signing.py`, `tests/test_audit116_stale_inspection_failure.py`, `tests/test_tooltips.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No selective port of the old modal UI or lifecycle code. Use the current Files panel and shared inspection service.

**Residual scope:** The wide SPEC-26 wishlist is not declared complete: no native Authenticode/manual/package acceptance, full asynchronous paging claim, or inferred verified function extent follows from this scoped review.

### 7. `feat/artifact-bytes-seam`

**Retained focal scope.** Frozen PR mapping: #21.

**Historical delta:** Hashes and subsequently reads the same open file, validates artifact hash/size and ranges, caps one read to 16 MiB, serializes seeks and supports cancellation/close.

**Current replacement:** VerifiedArtifactReader preserves this API and adds regular-file/nonblocking admission, before-and-after stat checks, exact short-read handling, and per-4 KiB digest checks for every requested block. This later content check handles same-size restored/coarse timestamps, including where ctime is not a mutation signal. Empty/EOF, clipping and failure codes remain explicit.

Source: `src/patchtrace/artifact_bytes.py`.

Verified ancestral source records: `0ec471016d2838a90753e014a0d647dd90168e87`, `e5f9302e20ee37e8e3323a8d8b177fd8b0649e6a`, `379e228919a414faa39f54b2e0db845d0c4db337`, `7ac014786144022508cdd0f022e106d7931b776c`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_artifact_bytes.py`, `tests/test_representations.py`, `tests/test_alpha_integration.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No port of the old weaker size/mtime-only read implementation; keep the independently introduced block-digest verification.

**Residual scope:** Current Linux/source controls do not provide new native Windows I/O acceptance. Verification-index memory and read overhead remain the documented bounded design, not an unbounded-file performance certification.

### 8. `feat/byte-representations`

**Retained focal scope.** Frozen PR mapping: #23.

**Historical delta:** Defines whole/file-range/RVA scopes; rejects invalid/ambiguous mappings; reads at most 64 KiB per page; formats physical-offset Hex/Binary and exact RFC 4648 Base64; records range/length/hash/copy provenance; compares bytes at equal logical offsets.

**Current replacement:** compare.py, formatters.py, paging.py, render.py and scope.py are byte-identical between the old tip and current baseline. __init__.py differs only by later alignment imports and exports. Current desktop raw_view consumes these contracts and distinguishes equal-offset differences from optional alignment.

Source: `src/patchtrace/representations/compare.py`, `src/patchtrace/representations/formatters.py`, `src/patchtrace/representations/paging.py`, `src/patchtrace/representations/render.py`, `src/patchtrace/representations/scope.py`, `src/patchtrace/representations/__init__.py`, `src/patchtrace/raw_view.py`.

Verified ancestral source records: `34d2b480921769fa699997993265e2b4d10ce15e`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_representations.py`, `tests/test_alpha_integration.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No selective port; preserve current additive alignment exports.

**Residual scope:** Byte identity is strengthened by the current callers/tests here, but it is not a historical full-suite or native/manual qualification and does not qualify every later alignment feature.

### 9. `feat/local-runtime-discovery`

**Retained focal scope.** Frozen PR mapping: #5.

**Historical delta:** Probes explicit/local installation hints and one bounded child level, refuses symlink candidates, never executes tools, preserves configured fields and refuses to silently select multiple candidates.

**Current replacement:** runtime_discovery retains the file/marker guards and bounded search; current candidate tiers explicitly order environment hints, adjacent bundle, per-user and other discoveries. Setup performs discovery in a retained worker, applies results only to empty fields and lists at most eight choices; bundle fast checks and BinDiff candidates are separate additive capabilities. Diagnosis/native comparison is still required.

Source: `src/patchtrace/runtime_discovery.py`, `src/patchtrace/ui.py`.

Verified ancestral source records: `736332cf63d3c7927f5c17f4aea5150f624bf957`, `fd6cdbaf52837ecbcc33504d40d12bc04abc80a9`, `cda7fe8630a76ff321f9cbd114b4a69fe7d9a71a`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_runtime_discovery.py`, `tests/test_runtime_discovery_bundle.py`, `tests/test_runtime_discovery_bindiff.py`, `tests/test_ui_setup_dialog.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No port of the older synchronous discovery or flat ordering.

**Residual scope:** Discovery candidates are not verified runtimes. Native bundle, installed filesystem and Windows local-app-data acceptance remain separate; the Windows work-directory test was skipped.

### 10. `feat/tooltip-registry`

**Retained focal scope.** Frozen PR mapping: #24.

**Historical delta:** Replaces ad hoc tooltips with stable IDs, what/why/effect/source/availability text, escaped/capped dynamic templates, keyboard/status/accessibility descriptions and explicit New/Open exceptions.

**Current replacement:** All 143 historical static IDs and all three templates remain. Of the static entries, only viewer.mode and profile.symbol_policy copy changed for later raw/local-symbol modes; current static data has 214 IDs and 10 templates. gui.tips.apply_tip now owns short bounded accessible descriptions/UIA naming while tooltips.apply_tooltip delegates. The current global sweep constructs real dialog/panel widgets, including KB InventoryDialog status/tab containers.

Source: `src/patchtrace/tooltips.py`, `src/patchtrace/gui/tips.py`, `src/patchtrace/ui.py`.

Verified ancestral source records: `1e6703a81c068201758179f5ac884e4fd5375eb7`, `21a005e242177f07a984937a7cd924e826c17b9f`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_tooltips.py`, `tests/test_audit_desktop.py`, `tests/test_inspection_row_tooltips.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No registry/UI port. Keep current delegation, bounded values and actual-widget coverage.

**Residual scope:** Static ID survival alone is not widget coverage. Existing explicitly documented deferred-state/Related-panel sweep allowances remain; no new exemption was added. Native screen-reader/theme/manual DPI acceptance is not asserted.

### 11. `feature/alpha-file-overview-20261013`

**Retained focal scope.** Frozen PR mapping: #19.

**Historical delta:** Shows oriented names, sizes/delta, saved SHA-256 comparison, format and architecture without disk I/O; exposes File overview before expensive analysis.

**Current replacement:** preflight.py is byte-identical. ui_inspection.recorded_rows displays it in a read-only Files dock instead of the old separate dialog; parsed PE data lives in a separate model with separate provenance. MainWindow.show_file_overview opens and refreshes the Files panel, and run_analysis calls it before worker comparison.

Source: `src/patchtrace/preflight.py`, `src/patchtrace/ui_inspection.py`, `src/patchtrace/ui.py`.

Verified ancestral source records: `f0086f797556afca5848c2b68a3819be5c0c0064`, `21a005e242177f07a984937a7cd924e826c17b9f`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_preflight_overview.py`, `tests/test_alpha_integration.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No port of the old dialog or obsolete 'PE not yet inspected' global explanation.

**Residual scope:** Saved metadata remains explicitly different from a new integrity/trust check. The broad preliminary-inspection specification retains independent future/native acceptance criteria.

### 12. `feature/gui-inspection-preview`

**Retained focal scope.** Frozen PR mapping: #15.

**Historical delta:** Moves to the next/previous visible function at a hunk boundary, lands on its first/last hunk, gives a visible terminal boundary message and states text-source/availability in code-pane tooltips.

**Current replacement:** MainWindow.navigate_hunk retains the actual filtered navigator traversal and first/last hunk selection; raw modes explicitly report that they have no text hunks. The semantic tooltip registry retains decompiler/assembly/metadata provenance and explains raw-byte modes separately.

Source: `src/patchtrace/ui.py`, `src/patchtrace/tooltips.py`.

Verified ancestral source records: `8b5ae1e912204bafa422e42db70606a8abbad66f`, `e7bd3dd4ac908adea3442056852f916ee3ea0b38`, `0a4bc09bb0f658a8b39a799e489b0239620504f0`, `1e6703a81c068201758179f5ac884e4fd5375eb7`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_diff_navigation_extra.py`, `tests/test_ui.py`, `tests/test_alpha_integration.py`, `tests/test_tooltips.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No source port for the selected navigation and provenance behavior.

**Residual scope:** The historical branch also wrote a large forward-looking SPEC-26 proposal. That proposal is not credited as implemented merely because these narrow controls survive.

### 13. `fix/backend-exit-diagnostics`

**Retained focal scope.** Frozen PR mapping: #6.

**Historical delta:** Classifies dot paths, Java/runtime mismatch, missing module, heap, disk and permission failures into fixed hints while preserving the original bounded log separately.

**Current replacement:** diagnostics.describe_backend_exit retains the categories and adds cached-symbol conflict guidance. backend passes the actual return code and redacted bounded log after supervision; untrusted failure text is not interpolated into the category hint.

Source: `src/patchtrace/diagnostics.py`, `src/patchtrace/backend.py`.

Verified ancestral source records: `ba10a52bde0c3a2892193d8d178e493b59e8daff`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_jobs.py`, `tests/test_diagnostics_core8.py`, `tests/test_audit_runtime.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No selective port of the original classifier.

**Residual scope:** Authored log/process controls exercise classification. Actual Ghidriff/Java compatibility and platform failure incidence are not established by those controls.

### 14. `fix/explicit-offline-symbol-policy`

**Retained focal scope.** Frozen PR mapping: #4.

**Historical delta:** Adds strictly Boolean allow_symbol_downloads default False, --no-symbols when off, UI opt-in persistence, diagnostic mode explanation and safe report setting export.

**Current replacement:** BackendConfig and launcher retain default-off behavior. Later explicit off/local/online modes preserve the Boolean compatibility field; UI effective_profile_symbol_mode cannot widen configured consent. Local mode uses a controlled launcher/store; online consent remains a separate radio choice. Reports retain only a real Boolean for this field.

Source: `src/patchtrace/backend.py`, `src/patchtrace/ui.py`, `src/patchtrace/ui_symbols.py`, `src/patchtrace/reports.py`.

Verified ancestral source records: `0f1b4ce5a0b51526fdceb5533f0553321899fd2a`, `f0af3fe2b4bfd6a8413d6d3cec093238d34e9d93`, `5ed624e91468c410f2cf738ed4e36c2be3e0201d`, `a04f5a299a8d4afef023261e52e08d14678cf1e7`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_jobs.py`, `tests/test_network_consent_symbols.py`, `tests/test_ui_symbol_local.py`, `tests/test_ui_profiles.py`, `tests/test_ghidriff_threading.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No whole-file port that would remove current local-symbol mode or consent ceiling.

**Residual scope:** Argument/env policy is not OS-level air-gap or native effective-network-denial evidence. Live symbol-server access and Windows backend behavior remain separate.

### 15. `claude/symbol-policy-isolated-settings`

**Retained focal scope.** Frozen PR mapping: #9.

**Historical delta:** Points XDG_CONFIG_HOME at a private per-run settings directory, records isolation/policy provenance, and adds a fixed cached-symbol conflict diagnosis; also changes Linux build tooling.

**Current replacement:** Both child-environment paths set XDG_CONFIG_HOME when a settings directory is supplied; run_comparison creates ghidra-settings below private scratch and records metadata. The classifier retains the PDB conflict case. The historical QtGui hook and symbol-cache seed tool are byte-identical, but build_linux.py has later changes and is not recertified in this scope.

Source: `src/patchtrace/backend.py`, `src/patchtrace/diagnostics.py`, `tools/pyinstaller_hooks/hook-PySide6.QtGui.py`, `tools/seed_symbol_cache.py`, `tools/build_linux.py`.

Verified ancestral source records: `2148a3fba9d41a11cd0d60215b4c7926196bf4fc`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_backend_bundle_env.py`, `tests/test_jobs.py`, `tests/test_network_consent_symbols.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No runtime source port. Preserve the branch for separately tracked package/build residue rather than declaring whole-branch closure.

**Residual scope:** Linux/frozen build workflow changes and actual cached PDB native behavior were not executed or fully disposed. Current package qualification must use its own exact source.

### 16. `fix/pe-inspection-row-tooltips-20261013`

**Retained focal scope.** Frozen PR mapping: #26.

**Historical delta:** Adds the overview.pe_row template to every cell, including all-unavailable records and offline Authenticode trust rows, carrying provenance and limitations.

**Current replacement:** The old fill_pe_table implementation moved to pure pe_rows plus RowsModel.data(ToolTipRole). The template is retained; every cell shares its row tip, changed fields retain bold state, unavailable reasons remain explicit, and trust labels do not claim fully valid/revocation-checked signatures.

Source: `src/patchtrace/tooltips.py`, `src/patchtrace/ui_inspection.py`.

Verified ancestral source records: `7cdb12053dd053e6a4a444a2a70e24a06ce0b4ed`, `21a005e242177f07a984937a7cd924e826c17b9f`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_inspection_row_tooltips.py`, `tests/test_alpha_integration.py`, `tests/test_tooltips.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No port of the old QTableWidget filler. Keep the current view-model implementation.

**Residual scope:** This verifies rendering/provenance mechanics, not actual Windows Authenticode trust, revocation or signature validity.

### 17. `chatgpt/ghidriff-sequential-lock-fix-20261017`

**Retained focal scope.** Frozen PR mapping: #96.

**Historical delta:** Centralizes argv, adds exactly one --no-threaded, and increments the raw-adapter identity to /2 so changed native behavior cannot reuse an old raw-cache identity.

**Current replacement:** _ghidriff_argv retains --no-threaded for bundled and unbundled/off and online modes, and current local-symbol wrapper paths reuse the same argument list. RAW_ADAPTER_VERSION remains /2. Later argv uses isolated -I -X utf8 and preserves virtual-environment interpreter symlink spelling with abspath.

Source: `src/patchtrace/backend.py`.

Verified ancestral source records: `bb84b2606f0674a1db675645f2db98b3a8d3d789`, `22b63e88edafdccee0a9c3ff9f4d680c95cb073a`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_ghidriff_threading.py`, `tests/test_backend_bundle_env.py`, `tests/test_backend_sec1.py`, `tests/test_jobs.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No source port; preserve later isolation and local-symbol handling.

**Residual scope:** The four current threading argument combinations pass; no new Windows JPype/Ghidra lock stress or live native acceptance was run.

### 18. `fix/ghidra-dot-paths`

**Retained focal scope.** Frozen PR mapping: #2.

**Historical delta:** Rejects dot-prefixed resolved path components and overlong Windows paths before launch, and removes the dot prefix from quarantine directories.

**Current replacement:** _validated_ghidra_output_path remains in output/scratch/argv paths and is called before native startup. Failed-run and new-run quarantine paths retain quarantine-<id> spelling. Other caller-selected unsafe ancestor paths fail explicitly.

Source: `src/patchtrace/backend.py`.

Verified ancestral source records: `5667b759f553e946885d0998953c301666907de6`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_jobs.py`, `tests/test_audit_runtime.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No selective port of the old path helper.

**Residual scope:** The Windows path-length control is skipped on this Linux host. Native Ghidra path parsing and platform filesystem limits require their own qualification.

### 19. `fix/isolate-ghidra-scratch`

**Retained focal scope.** Frozen PR mapping: #3.

**Historical delta:** Moves transient Ghidra projects/GZFs into OS temporary storage and supplies explicit --project-location/--gzfs-path while retaining raw JSON/log outputs in the project.

**Current replacement:** run_comparison uses unique private mkdtemp roots, projects/gzfs/settings subdirectories and explicit argv. The audit's bounded cleanup/retry warning replaced plain TemporaryDirectory teardown; raw output/logs still belong to the run and cache/retention options are explicit.

Source: `src/patchtrace/backend.py`.

Verified ancestral source records: `1223cdd5517c2d49423210a6c7a35b5946679a07`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_jobs.py`, `tests/test_audit_runtime.py`, `tests/test_backend_sec3.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** No port of the earlier cleanup lifetime. Keep bounded cleanup and explicit retained-output ownership.

**Residual scope:** No native OneDrive/synchronized-directory, antivirus-held-file or Windows cleanup stress was performed. Cache and optional GZF retention are not automatically qualified by this row.

### 20. `fix/codetext-budget-wave3`

**Confirmed selective omission.** Frozen PR mapping: none mapped in frozen inventory.

**Historical delta:** CodeHighlighter.highlightBlock checks model/failure/window before controller.spans and avoids redundant block-state assignments. A historical regression counts calls on 3,000 rows per side, requires all calls in-window and under 1,000, and preserves unformatted off-window text/default -1 state.

**Current replacement:** Current highlightBlock unconditionally sets -1 and calls controller.spans for every Qt block callback; spans rejects off-window work internally, so existing formatting/scroll controls still pass but the historical dispatch control fails. No equivalent early guard/detached bulk-load mechanism exists. The unrelated native_control.c distinct-I/O controls are retained, with only later worker-count reporting added.

Source: `src/patchtrace/ui_codetext.py`, `tools/rzdiff/native_control.c`.

Verified ancestral source records: `21a005e242177f07a984937a7cd924e826c17b9f`, `ada33236e0f278c2241dd5f015ddd369a2c7c283`, `fd76a20af33d0d492c82c78f59b4781d8b08e465`. Exact code needles, line locations, blobs and parent-presence evidence are in the JSON/receipt.

Current test map: `tests/test_ui_codetext.py`. These are subsets of the shared 36-file execution, not separate additive runs.

**Selective decision:** Propose a separately owned one-file highlightBlock guard repair with spec/current regressions first, preserving exact historical bytes and nearest formatting/scroll/high-DPI controls. Do not wholesale-port the branch or native helper.

**Residual scope:** No new native timing/performance or native Rizin validation claim. This is a deterministic missing dispatch bound with visible formatting preserved; broader workbench/package gates remain open.

## Confirmed candidates and unchanged contrary evidence

### B3-C1 — retained backup reservation defect (root-owned follow-on)

`persistence._publish_no_replace` is AST-identical in `audit/core` and this baseline (`b4891d17d2e2d25da1a12005520f0e3620c94d7e04aaf579774887bb2e24c43b`). The current public `ProjectService.backup` path reserves a new directory with mkdir, then uses rename; its failure handler removes the pathname. An external control substitutes another owner’s empty directory between those operations. Successful publication replaces it; a forced rename error removes it in cleanup. Both fail the preservation assertion while the ordinary complete-backup control passes. The held replacement directory descriptor confirms deletion; original project database bytes remain unchanged.

The unchanged probe SHA-256 is `2fb21e2ff6b346f8c0ec96a1cac1abdfbd9547c87fd519f68153991816c20006`. Scope is **POSIX empty-directory substitution**, not native Windows or general backup corruption. The no-overwrite contract is `docs/specs/cli-project-compare.md` §3.6 and `docs/specs/architecture.md` §3. Root owns a separate design/repair on continuation `3faf436a` and is checking the installer’s duplicated helper. No subsequent fix is included or credited here.

### B3-C2 — omitted window guard before highlighter dispatch

Original source/test tip: `c7fb422c750f1d0e5591277b91492874afd79af7`. The complete historical `tests/test_ui_codetext.py` is retained byte-for-byte, SHA-256 `238abb33cad9ff066f73564c97ee1215e514735c17aa62ea26a4e39d8f5721e3`. `test_bulk_load_skips_span_dispatch_outside_the_window` fails at the assertion that all recorded span calls belong to the installed window. Its later call-count/state assertions are not reached in that failing case. The unchanged window-formatting and scroll-budget neighbors pass. The current `spans` method filters internally, preserving visible formatting while `highlightBlock` still dispatches every Qt block callback.

Proposed separate slice: `src/patchtrace/ui_codetext.py::CodeHighlighter.highlightBlock`, the WBQ integration-plan contract and focused regressions. Install a guard before dispatch, keep exception-to-plain text behavior, constant default block state, scroll window cleanup, source/model ownership, font metrics and extra selections. Reuse the exact historical control and nearest current tests under normal and high-DPI offscreen settings. No bulk native/Rizin or broader UI refactor is indicated. The branch’s distinct-I/O native control already survives, differing only by later worker-count reporting; it was not run.

## Qualification and open boundaries

| Pinned execution at `55f3d074` | Result | Pytest summary time |
|---|---|---|
| 36 current focal replacement files, including actual global tooltip sweep | 666 passed, 4 skipped; zero failures/errors | 62.85 s |
| Unchanged external public backup controls | 2 failed, 1 passed; zero setup errors | 0.31 s |
| Three unchanged historical highlighter controls | 1 failed, 2 passed; zero setup errors | 0.51 s |

The skips are Windows containment denial, suspended-child cleanup, Ghidra long paths and local-app-data work directory. JUnit durations and exact commands/environment/source hashes are retained separately. Overlapping positives are not summed into an aggregate success score. The original failure receipts are unchanged; this docs-only checkpoint does not repair either issue.

No historical full suite, final integrated full suite, new native engine/Windows, live acquisition/provider, target execution, frozen package or manual/screen-reader acceptance ran. In particular, Linux build-tool residue on the symbol-settings branch and large SPEC-26 future requirements remain separate. No older PR closure, branch deletion, merge or release is authorized.
