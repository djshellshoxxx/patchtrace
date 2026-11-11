# PatchWatch reuse and open-source integration roadmap (2026-10-26)

Status: PLANNED, documentation only. Owner requested PatchTrace work resumed for this roadmap. No runtime functionality claimed. Baseline: main; reconcile with open PR #64 unified engine and PR #100 Diaphora/PDB before implementing.

## Engineering rules
- Audit current main and active PRs before each slice; reuse existing services and stable contracts rather than introducing competing implementations.
- No Microsoft binaries/PDBs in Git. Synthetic and permissively licensed fixtures only. Explicit network consent; offline default.
- License gate: record exact upstream commit, license, NOTICE, modifications and fixture provenance before copying code. Apache-2.0/MIT may be adapted subject to notices; GPL/AGPL external-process integration only, no code copy without explicit licensing review.
- Each feature: red tests -> implementation -> lint -> Linux/Windows CI -> live opt-in acceptance -> docs and registry -> merge. Failed live gates remain BLOCKED, never called complete.
- Distinguish verified identity from heuristics; LLM confidence is not calibrated vulnerability probability.

## PatchWatch implementation packages
| ID | Priority | Feature | Upstream reference | Existing PatchTrace seam | Acceptance |
|---|---|---|---|---|---|
| PW-01 | P0 | KB file CSV parsing and Microsoft support-page link extraction | kb/csv.rs, kb/tier1.rs | KB patch search and intelligence adapters | multi-section x86/x64/arm64, duplicates, locale, malformed CSV, strict URL allowlist; offline fixtures |
| PW-02 | P0 | Update Catalog MSU/CAB manifest fallback | kb/tier2.rs | acquisition transport/quarantine | bounded extraction, all selected architectures, verified metadata, cancellation and corrupt archive tests |
| PW-03 | P0 | MSRC SUG CVE/release ingestion and affected-product mapping | sug/client.rs, analyze/ingest.rs | intelligence/csaf, enrichment, KB resolver | full product/KB multiplicity, revision-aware cache, offline snapshot, no arbitrary highest-build assumption |
| PW-04 | P0 | Verified pre/post pair resolution | winbindex/client.rs | acquisition and SPEC-32 pair lifecycle | KB/version/approximate tiers remain distinct; SHA256 recheck on cache hit; ambiguous pairs abstain |
| PW-05 | P1 | CVE investigation coordinator | analyze/orchestrator.rs | project service, jobs, unified and secondary engines | persisted resumable state machine, per-binary errors, cancellation, repeatable idempotency and no duplicate runs |
| PW-06 | P1 | LLM file triage | triage/anthropic.rs | interpretation/providers and intelligence | provider-neutral bounded JSON, no-code metadata stage, consent preview, deterministic fallback |
| PW-07 | P1 | Cross-binary synthesis | triage/synthesis.rs, ghidra/diff_summary.rs | pilot/ patch intent, unified results | bounded compact summaries, independent evidence preserved, counterevidence, traceable function IDs |
| PW-08 | P1 | Deep-analysis selection and AI review | triage/deep_analysis.rs | interpretation, evidence, calibration | dedup by stable function identity, changed-code fallback, strict citation validation, no fabricated snippets |
| PW-09 | P1 | CVE investigation Qt dashboard | web/views.rs as UX reference only | Qt panel registry, KB pane | CVE->KB->binary->pair->function navigation, pending/failed states, keyboard accessibility |
| PW-10 | P2 | Portable investigation context export | report/pocsmith_context.rs, commands/export_poc_context.rs | reports/project backup | manifest, content digests, redacted paths, explicit code inclusion, no hidden binary export |
| PW-11 | P2 | Revision-aware CVE/job persistence | storage/schema.rs, storage/db.rs | SQLite persistence and schema migration | multiple CVEs/KBs/products/architectures/runs; stable foreign keys, rollback/recovery, migration tests |
| PW-12 | P2 | Dependency smoke tests and in-memory dry-run | validate.rs | diagnostics and CLI | isolated SUG, CSV, MSU, Winbindex, Ghidra and full mocked pipeline; no real DB mutation |

## Execution sequence and integration gates
Wave A: PW-01 -> PW-02 -> PW-03 -> PW-04. Deliver verified KB inventory and candidate pairs before automated analysis.
Wave B: PW-11 -> PW-05 -> PW-06 -> PW-07 -> PW-08. Connect existing engines and provider abstraction, preserving provenance.
Wave C: PW-09 -> PW-10 -> PW-12. Finish UI, export and acceptance.
For each wave: inspect open PR overlap; create ADR for changed schemas; run synthetic fixture tests, fuzz malformed inputs, cross-platform CI and explicitly opted-in real-source smoke tests. No new feature branch merges without current-head checks.

## Additional open-source reuse research tracks
| ID | Project | Candidate use | Approach / gate |
|---|---|---|---|
| OS-01 | ByteRay-AI/patchpair (Apache-2.0) | PSFX .cix.xml exact source match, PA30/MSU fallback, kernel-mode pair corpus | Inspect exact implementation and fixtures; port parser and matching tests only after license/security audit |
| OS-02 | joshterrill/post-patch-postmortem (MIT) | KB/binary listing, pinned SHA pair CLI, BinExport/BinDiff orchestration | Compare to acquisition and BinDiff modules; adapt missing workflow tests, not duplicate runners |
| OS-03 | google/bindiff (Apache-2.0) | independent matching, names/comments transfer, multi-architecture support | External tool adapter first; consider isolated library integration only after dependency/build review |
| OS-04 | mandiant/capa (Apache-2.0) | before/after capability deltas, Ghidra/PyGhidra integration | Consume versioned JSON and pinned rule sets; verify v10 breaking API changes |
| OS-05 | joxeankoret/diaphora (AGPL-3.0) | graph/pseudocode matching and result import | External-process/SQLite output integration only; no code copy; validate real schema against PR #100 |
| OS-06 | clearbluejar/ghidriff (GPL-3.0) | function diffs and normalized decompilation | Existing external backend; pin/test native versions, no embedded source copy |
| OS-07 | radareorg/radare2 / rizinorg/rizin | byte, opcode and CFG delta; rz-diff | Existing secondary adapter; compare CLI JSON and pinned native goldens; verify each license |
| OS-08 | Quarkslab/qbindiff | graph-based matching and ambiguous function pairs | Research algorithms and formats, independent implementation only after license review |
| OS-09 | mandiant/flare-floss | decoded/stack string deltas | External tool output adapter and bounded parser; verify licensing and version |
| OS-10 | horsicq/Detect-It-Easy | compiler/packer fingerprint noise suppression | External diec adapter and fixtures; verify license |
| OS-11 | VirusTotal/yara-x | rule compilation/validation and before-after match testing | CLI/SDK adapter, rule provenance and license review |
| OS-12 | m417z/winbindex | binary metadata and provenance | Preserve existing acquisition adapter; test cache and source-version drift |

## Exit criteria
Each PW/OS package gets an owner, status, precise source commit/license, target module, contract changes, threat review, fixture list, tests, benchmarks and CI evidence before status can move from PLANNED. Track changes in docs/plans and tasks/todo.md; do not interpret this document as implementation approval or proof.
