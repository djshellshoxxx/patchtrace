# SPEC-DA-01: Optional Diaphora comparison technique for PatchTrace

Status: developer-ready DESIGN; no code implemented. 2026-10-14. See ../research/diaphora-feature-study-20261014.md and ../plans/diaphora-integration.md. Upstream reference: Diaphora 3.4.3; verify pinned release SHA in implementation.

## Goal / invariants
Integrate Diaphora as an explicitly OPTIONAL engine which adds function-matching evidence and potential patch indicators. Ghidriff remains primary and the default; existing analysis and manual corrections cannot be overwritten by a secondary proposal. No IDA, Hex-Rays or Diaphora installation is required for normal PatchTrace. Never execute analyzed binaries, install external tools automatically, run user-provided Python scripts, upload data, or treat similarity as verified vulnerability confidence. Offline-only by default.
Features: SQL/heuristic match reason, best/partial/unreliable/multimatch buckets, raw ratio, pseudocode/code evidence, optional microcode, inferred compilation units, callers/callees, unmatched and alternatives, uncalibrated patch-candidate patterns, provenance.

## Implementation modes and capability gates
A. IMPORT EXISTING RESULT FIRST: user selects .diaphora SQLite result and optional old/new Diaphora export DBs + trusted provenance sidecar. Parse, validate, associate carefully, store a separate evidence set. Zero IDA dependency, no engine execution.
B. DIFF EXISTING EXPORTS: user has two exported Diaphora SQLite DBs; explicit opt-in uses user-installed compatible Python and Diaphora, producing .diaphora result in a bounded private temp directory then importing as A. IDA not needed after exports exist.
C. FULL IDA EXPORT: optional user-installed IDA/Diaphora/Hex-Rays on supported version; batch-export both old/new binaries and then B. Implement only after a licensed clean-Windows smoke test. Historic Diaphora automation uses DIAPHORA_AUTO, DIAPHORA_EXPORT_FILE and IDA -A -B -S; Diaphora 3.4.0 warned of migrating away from script mode. Do not hardcode production flags before testing 3.4.3.
D. FUTURE IDA WORKFLOW: suggested transfer of comments, symbols, structs, types through an explicit reviewed export only; no direct mutation of IDA DB or original binaries.

Profiles: basic (match metadata), semantic (requires decompiler), microcode (requires Hex-Rays microcode), patch indicators (requires bounded code/asm spans). Each unavailable capability is an explicit status, not score zero.

## PatchTrace baseline and versioning decision
Observed current modules: src/patchtrace/secondary/{contracts,registry,runs,scheduler,store,reconcile}.py; enrichment/storage.py; Ghidriff primary, C1 engine orchestration, current-set cache and trust guards. The current strict Engine and EngineRun literals accept only existing engines. Current secondary/1 and secondary/2 rows are strict, and load_secondary() parses every stored row.

**Never persist Diaphora as secondary/2 directly or as engine-run/1 without compatibility work.** Older PatchTrace will fail strict parsing on an unknown engine and may lose access to normal project workflows. First implement new additive enrichment kinds 'diaphora-matches' and 'diaphora-runs', with versioned 'diaphora/1' and 'diaphora-run/1' records, leaving old secondary rows unchanged. Extend KINDS and storage tests. In-memory provide an adapter-neutral proposal bridge for reconciliation. Later, only after migrations/old-reader tests, unify through a new versioned secondary/3 or adapter layer, not a silent enum widening in the old persisted kind.
Store data behind ProjectStore/EnrichmentStore owner-thread guard; current-snapshot validation before commit, additive schema only. Large code should remain in bounded content-addressed sidecar data rather than duplicate 32 MiB DB rows.

## Module architecture: pure core, subprocess adapter, Qt shell
Register module IDs in docs/modules.md before any implementation:
- diaphora/contracts.py: strict frozen pydantic v2 versioned match, export, run, signal and capability records.
- diaphora/sqlite_guard.py: private snapshot, read-only SQLite, schema/limits/time budgets, allowlisted fixed SQL.
- diaphora/result_import.py: results/unmatched/config tables, typed rows, source-ratio parsing, duplicate policy.
- diaphora/export_import.py: optional functions, basic blocks, CFG, callgraph, compilation units and program_data; missing mode capability explicit.
- diaphora/provenance.py: verified manifest/hash/orientation binding; user attestation recorded lower trust.
- diaphora/address_map.py: EA to image-relative RVA, validated against PE base/sections separately on each side.
- diaphora/normalize.py: safe match proposals and in-memory reconciliation bridge, no code changes to primary normalizer.
- diaphora/signals.py: independent-derived candidate detectors (no AGPL source copying), provenance/false-lead reasoning.
- diaphora/context.py: on-demand bounded code, assembly, microcode and compilation-unit evidence, no HTML execution.
- diaphora/store.py: additive evidence kinds and cache/read strategy; old kinds untouched.
- diaphora/profile.py: user profile/options, versioned digest, capability policies and resource bounds.
- diaphora/probe.py: optional external Python, Diaphora and IDA capabilities with read-only probes.
- diaphora/runner.py: external diff using existing jobs.run_process, no direct subprocess.
- diaphora/ida_export.py: later optional IDA runner; no IDA modules loaded into PatchTrace.
- diaphora/service.py: inspect/import/compare/query façade, transactional ownership.
- diaphora/cli.py: headless commands, called by existing cli.py with minimal dispatch.
- ui_diaphora.py: Qt-only UI imported lazily, no business logic.
- tests/diaphora: fixtures, parser/property/security/storage/runner/Qt/live compatibility tests.

Public pure protocols (contract-first):
DiffSource.inspect(path,budget,cancel) -> InputInspection
DiffSource.import_results(diff_db,old_export?,new_export?,manifest?,project_artifacts,cancel) -> DiaphoraMatchSet
EngineCapability.describe() -> Capabilities
DiaphoraRunner.compare_exports(old_export,new_export,profile,runner,cancel) -> validated output artifact
MatchBridge.reconcile(diaphora_set,ghidriff_pairs,address_mapper) -> reconciliation report / NotComparable
SignalDeriver.derive(changed_code,verified_match,profile) -> candidate signals
DiaphoraStore.publish_validated(guard,match_set) -> immutable entry
All externally supplied objects validated at boundary. No Qt dependency in any pure component.

## Persisted records, fields and constraints
Use Pydantic strict/frozen and explicit Literal version, bounded tuple/string lengths. New JSON schemas generated with existing schema tool, committed with tests.
DiaphoraExportManifest (diaphora-export/1): side older|newer, producer patchtrace|user-attested, Diaphora version/commit, IDA/Hex-Rays version if used, export schema, processor/arch, binary SHA-256 and length, export SHA-256, export profile hash, image base known?, coverage flags pseudocode/assembly/microcode/blocks/CU, created UTC and attestation verified-run|unverified.
DiaphoraDiffManifest (diaphora-diff/1): old/new export and old/new binary SHA-256 pairs, output diff SHA-256, profile digest, version, orientation older->newer, producer trust.
DiaphoraMatch (diaphora-match/1): source row index, category best|partial|unreliable|multimatch, old/new original address strings, validated EA and optional RVA per side, names, raw ratio text/finite parsed numeric, safely normalized ratio_milli or null, explicit transform direct|capped-bonus|unavailable, graph nodes counts, heuristic description, input pair/export hashes, address status verified-rva|external-ea-only|ambiguous, source/availability/capability and limitations.
DiaphoraMatchSet (diaphora/1): engine diaphora, version, verified pair SHA-256, optional export DB SHA pair, input result SHA, orientation, profile hash, provenance trust, all match/unmatched/alternative rows, limitations, status and run id.
DiaphoraRun (diaphora-run/1): stage import|diff-exports|export-old|export-new, source/output hashes, tool/version/config digest, redacted argv digest/path digest, status ok|failed|timeout|cancelled|unsupported, elapsed, error code and bounded sanitized stderr summary.
DiaphoraCodeEvidence (diaphora-code/1): code representation pseudocode|assembly|microcode, producer tool/version, source export SHA, function side/EA/RVA, content checksum, bounded text/hunks, unavailable reason.
DiaphoraPatchSignal (diaphora-signal/1): match/evidence refs, detector version, kind added-guard|signedness-jump|api-call-delta|validation-transition|other, evidence availability, candidate-only certainty, false-lead notes and optional separately sourced KB/CVE context.
Do NOT include config.main_db/diff_db absolute paths in reports; they can disclose system names.

### Diaphora output mapping
Read result SQLite separate from export SQLite. Diff DB upstream save_results() defines config(main_db,diff_db,version,date), results(type,line,address,name,address2,name2,ratio,nodes1,nodes2,description), unmatched(type,line,address,name). Categories best/partial/unreliable/multimatch; unmatched primary/secondary. Source ratio is Diaphora-specific, NOT BinDiff confidence or probability. Its config has MATCHES_BONUS_RATIO=0.01, so do not assume raw ratio strictly <=1 without real fixture. Preserve raw; if bounded secondary similarity requires <=1000 milli, cap transparently with transform label only and never discard original. Missing score != zero. For a separate Diaphora proposal view, prefer preserving exact upstream ratio.
Function/export schema contains RVA and source image metadata but source result addresses are text IDA EAs. Map old and new independently using verified PE image bases/sections. Reject overflow and ambiguous VA/RVA mapping; no linking by name-only. Unresolvable rows stay visible as external-only, NEVER counted as agreeing with Ghidriff.

### Provenance and anti-misattribution
Diaphora result DB does NOT intrinsically bind a SHA-256 pair. 'config.main_db/diff_db' merely refers to paths; program.md5sum is not sufficient as provenance. The safest binding is a PatchTrace-generated manifest recording exact SHA of original binaries, each export and result, orientation, versions and options. Without it allow an explicit user-attested association only for manually inspected imported rows. Label unverified distinctly and EXCLUDE from automatic KB/CVE match enrichment or auto-corroboration until verified. Rehash artifact/DB at use time.

## SQLite and external process safety
1. Stage immutable copy under private safe project root, SHA-256 hash, never modify imported bytes, prohibit symlink/path escape.
2. Bound SQLite inputs initially to 256 MiB per file; check header/schema/version and PRAGMA quick_check under deadline; read URI mode=ro/query_only=ON/trusted_schema=OFF from stable immutable snapshot; prohibit load_extension/ATTACH, no user-supplied SQL, set query progress handler and size/row/string limits. Input may be malicious. Limit 500k match rows/200k function rows as initial hard budget, adjust downward after measured tests.
3. Validate numeric strings, addresses, finite scores, category, duplicate endpoints, ranges, UTF-8, no HTML execution, no path traversal, no false SHA association. Preserve unmatched/alternative categories.
4. External comparator argv only: compatible_python /absolute/diaphora.py /staged/old.sqlite /staged/new.sqlite -o /work/results.diaphora. No shell; explicit execution enabled; env allowlist removes user hooks, tokens and unknown DIAPHORA_* flags; private cwd; bounded capture; no background network. Use jobs.run_process and Windows Job Object / POSIX group cancellation. No engine error can destroy prior results.
5. **Existing scheduler lifecycle bug for file outputs:** secondary/scheduler.py currently calls adapter.parse() AFTER exiting its TemporaryDirectory. Diaphora's results are a FILE, not stdout; never return a soon-deleted RawResult.file_path. Before plugging into the generic registry, either parse within the temp directory via a tested scheduler extension or let a Diaphora-owned orchestrator parse there. Prefer the latter for mode B initially. No secret/spawn behavior copied from upstream.
6. New cache key MUST include binary pair SHA, export pair SHA, result or profile/input hash, engine/tool/IDA/decompiler versions, parser version, orientation and options. Existing engine-run/1 cache key of binary pair + executable argv/version is insufficient for export-mode changes. Never reuse stale results.
7. Publish only after complete parsing and strict binding checks; store on ProjectStore owning thread via Guard; crash/cancel leaves old committed output intact.
8. Large code blobs on demand (initial 256 KiB/function and 2 MiB displayed page), render plain text; escape all generated HTML reports; no untrusted scripts or IDA imports in main process.
9. No bundling of AGPL Diaphora code or IDA binaries. Diaphora AGPLv3 and PatchTrace MIT require an explicit distribution/license review if code or a combined product is contemplated. External invocation alone does not automatically resolve every possible licensing issue.

## Derived evidence and GUI behavior
Diaphora signals are optional advisory candidates: newly added guards, changed signed/unsigned conditional jump, added error return, verified added/removed API call. Implement clean-room rules over recorded old/new code/CFG evidence, not verbatim upstream script. Flag compiler noise, decompiler-version drift, thunk/shared-runtime identity, PDB-only changes, uncertain mapping. Pseudocode/microcode/graph match evidence is often correlated with Ghidriff. Never sum native scores or interpret multiple overlapping signals as independent proof. KB/MSRC/CSAF/CVE narratives can prioritize a verified candidate, cannot verify the root cause automatically.

GUI optional engine selector Off/Import result/Compare exports/Full IDA (disabled until verified). Display source versions, trust level, decompiler availability, raw similarity, matching heuristic, code representation, inferred compilation unit, address map status, agreement/contested/unknown, provenance and proposed potential patch indicator. Code panel options: default Ghidriff pseudocode and Diaphora pseudocode/assembly/microcode only if present. Optional annotations never overwrite user-reviewed notes. Every new functional control has a descriptive tooltip. Keep Qt in ui_diaphora.py, no changes to existing code pane logic for first import PR.
CLI (future, not implemented yet):
  patchtrace diaphora inspect DIFF_DB --json
  patchtrace diaphora import PROJECT --diff DB [--older-export DB] [--newer-export DB] [--manifest FILE] [--user-attest-pair] --json
  patchtrace diaphora compare-exports PROJECT --older-export DB --newer-export DB --python PATH --diaphora-script PATH --json
  patchtrace diaphora runs PROJECT --json
All imported code/evidence is local; reports add optional namespace without changing existing Ghidriff fields.

## Tests and release gates
- Strict contract/json schema round trip, pair/orientation/hash spoofing, incomplete/unverified sidecar and old-project loading unchanged.
- Synthetic SQLite fixtures all categories/unmatched/multimatch, duplicated rows, odd EA encoding, absent pseudocode/microcode, over-1.0 bonus, NaN/Inf, malicious SQL-like fields, large db, corrupt db, version drift.
- Architecture and EA->RVA tests with real PE section layouts, relocations, wrong base, split/inline ambiguity, no name-only matches; disagreement takes priority, absence != negative vote.
- Store backup/atomic rollback/retention/cap, re-run replacement and cache invalidation across export profile/IDA/decompiler changes; no old-reader crash.
- Fake child process timeout, cancellation, huge stdout/stderr, environment secrets, nonzero exit and temp-file lifetime regression.
- Qt offscreen with no installed Diaphora, tooltips, source-only rendering, disabled capability and availability reasons, no default Ghidriff behavior change.
- Native real fixtures: known patched PE, unchanged PE, compiler changed/stripped and rebased pair, actual IDA/Hex-Rays sample only where licensed. Record precision/recall of verified pairs, top-K true patched-function recall, false positive rate, runtime, peak memory, missing-feature fraction; prove measured marginal value over Ghidriff alone. Never count synthetic/mock fixtures as live integration evidence.
- Full gates: QT_QPA_PLATFORM=offscreen python -m pytest -q; python -m ruff check src tests tools; Linux/Windows CI; Windows frozen alpha without Diaphora installed plus separately installed Diaphora live smoke; airgap; notices/license audit.

## Completion criterion
Mode A successful safe import and paired reconciliation -> Mode B supervised external comparison -> optional Mode C licensed IDA export -> GUI/code context -> candidate signals/CU -> held-out value evaluation. All behind default-off setting, wholly removable without changing existing Ghidriff paths or persisted old contracts. Follow docs/plans/diaphora-integration.md for ownership and PR sequence.
