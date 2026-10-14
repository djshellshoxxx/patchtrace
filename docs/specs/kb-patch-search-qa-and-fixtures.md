# SPEC-32D: Test Corpus, Acceptance Gates, and Failure-Injection Protocol

Status: expanded implementation QA requirements, 2026-10-14, docs only.
Normative parent: docs/specs/kb-patch-search-and-pair-resolution.md.
Additional specs: kb-patch-search-source-adapters.md, kb-patch-search-pair-lifecycle.md, kb-patch-search-ui-cli-contract.md.

## 1. Test outcomes and release policy

The feature is **not release-ready** when unit tests alone pass. Acceptance requires:
- normalized MSRC CVRF product-specific associations correct against pinned official samples and adversarial synthetic samples;
- no automatic pre-/post-fix claim without source-backed boundary evidence;
- no mismatch, delta payload, malformed metadata or unsupported product silently promoted as a verified full PE;
- existing PatchTrace acquisition, ProjectService, diff/evidence and CLI regression tests passing;
- GUI+CLI offline end-to-end on actual Windows standalone;
- failure injection across project create / sidecar attach boundary proving recoverable project;
- malicious input and file transport limits pass;
- source adapter real live probe explicitly opt-in and documented, no network in hermetic CI;
- no measured "accurate CVE function localization" claim unless independent held-out evidence supports it.

Release must be blocked, not skipped, on core integrity, false proof, cross-thread DB or deterministic offline failures. Environment-dependent live tests can report BLOCKED with reason; they may not be represented as PASS.

## 2. Test fixture manifest and provenance

Directory layout:

    tests/fixtures/patch_search/
      MANIFEST.json
      README.md
      cvrf/
         one_product.json
         multi_product.json
         conflicting_status.json
         revision_old.json
         revision_new.json
         malformed_product_id.json
         unknown_dialect.json
      csaf/
         group_status.json
         known_not_affected.json
         vendor_fix_no_kb.json
      index/
         clfs_winbindex.json
         delta_only.json
      pe/
         synthetic_old.bin
         synthetic_new.bin
      golden/
         kb_edges.json
         variants.json
         pair_candidates.json
         state_transitions.json
         triage_view.json

Each MANIFEST item includes:
- fixture_id, intended test kind: synthetic | official_redacted | owned_compiled_binary;
- raw SHA-256, byte length, source origin and exact URI if official;
- retrieval timestamp UTC, upstream doc version/revision, license and distribution permission;
- expected parser dialect and schema revision;
- expected product IDs/KB-CVE edges and negative assertions;
- authorship; synthetic builders and compiler version+flags if binary;
- why each fixture is necessary and tests referencing it.

Before committing official advisory docs or binaries: check redistribution/licensing, minimize/transform payload when appropriate, and retain source-level references. Do not commit proprietary Microsoft binaries as fixtures. For native live symbol testing use opt-in downloads and record local digests/results, not distribute payload.

### 2.1 Fixture build recipe

- Use current repository tests/pe_builder.py or existing two-binary fixture builders for deterministic synthetic complete PE, rather than downloading actual OS files into repo.
- Build old/new binary pair with a controlled added bounds check or branch, plus a second compiler-only rebuild fixture with no intentional vulnerability fix.
- Synthetic CVRF fixture should include at least P-CLIENT, P-SERVER, P-ARM64; CVE-A/B, KB-A/B; same-month unrelated CVE-C.
- Include a Type-5 known issue remediation that must NOT be treated as Type-2 KB.
- Include one unknown CVRF status Type requiring cautious parser abstention.
- Include one CSAF VEX known_not_affected product with explicit remediation/note; not silently affected.
- Include older/newer source document revisions and contradictory data.
- Include 64-bit correct PE headers and extra short/truncated/delta formats for rejection.
- For each real official sample, snapshot exactly the schema dialect exercised by parser; do not back-translate it to synthetic dialect before testing normalization.

## 3. Required property and metamorphic tests

Invariants:
1. Adding an unrelated CVE to the same monthly document never changes existing KB-CVE matches.
2. Reordering vulnerability/remediation/product arrays does not change normalized edge set or canonical sorted result IDs (source pointers may differ; pointer identity must be intentionally content-derived or order-aware).
3. Adding an unrelated product variant never changes an existing selected product's association.
4. Removing necessary product evidence can only decrease certainty, not increase it.
5. Replacing a source snapshot with a newer revision must not erase historic raw provenance.
6. Changing only display name/capitalization never establishes cross-product identity.
7. Changing a binary SHA invalidates its acquisition plan and previous function-localization results.
8. Swapping older/newer changes orientation-dependent pair ID, never advisory facts.
9. Two unrelated comparison engines reading the same Ghidra evidence lineage cannot count as two independent vulnerabilities.
10. No input with invalid/unknown product status can be normalized as confirmed vulnerable.
11. Search output is stable across repeated offline runs with same inputs, irrespective of dictionary iteration order/locale/time zone.
12. Untrusted control characters/HTML/Unicode confusables are escaped/rejected at boundary and never flow to generated requests.
13. Every confirmed KB-CVE association has a replayable verified source pointer.
14. A search that checked no documents cannot be COMPLETE_IN_SCOPE.
15. Adding an unresolved candidate cannot remove an existing candidate from the unexplained queue without explicit reasons.

Hypothesis property tests:
- number of candidates capped, stable deterministic ordering by exact typed tie-break IDs;
- no unsupported "vulnerability fixed" or "vulnerability confirmed at function" message in auto-generated outputs;
- run orientation, product and source hashes must match before a function reference is emitted;
- no probability percentages displayed unless a separate calibration release gate explicitly passes.

## 4. Negative test matrix

| ID | Input | Required result | Release blocker |
|---|---|---|---|
| NEG-01 | KB contains slash/control | INPUT error, no network | yes |
| NEG-02 | KB absent from one scanned month | NO_ASSOCIATIONS_IN_SCOPE with coverage | yes |
| NEG-03 | provider times out after prior good month | PARTIAL_SOURCE, retain prior | yes |
| NEG-04 | CVE same month, different remediation KB | no false association | yes |
| NEG-05 | remediation KB for server, user selects client | no false association | yes |
| NEG-06 | Type-5 known issue mistaken for KB | parser rejects edge | yes |
| NEG-07 | malformed/duplicate-key JSON | reject source; keep last known good | yes |
| NEG-08 | CSAF known_not_affected | no affected/fixed assertion | yes |
| NEG-09 | advisory lacks filename | component_unknown/manual input | yes |
| NEG-10 | Winbindex wrong architecture | no automatic pair | yes |
| NEG-11 | two identical full PE hashes | no patch-pair claim | yes |
| NEG-12 | newer build predates older in different release branch | no automatic ordering | yes |
| NEG-13 | two builds already fixed same CVE | no pre-fix label | yes |
| NEG-14 | PA30-only or PSFX-only source | no binary promotion | yes |
| NEG-15 | expected SHA different from downloaded | discard download, no project | yes |
| NEG-16 | signed hash matched but trust not evaluated | authenticity not checked | yes |
| NEG-17 | cancel during source request | no source partial commit | yes |
| NEG-18 | cancel between older/newer fetch | no incomplete project | yes |
| NEG-19 | crash just after project create | project valid, context-pending repair | yes |
| NEG-20 | crash during sidecar append | core project still opens | yes |
| NEG-21 | corrupt optional sidecar file | core comparison still accessible | yes |
| NEG-22 | concurrent attach using same revision | exactly one writer wins | yes |
| NEG-23 | swap orientation after report | old triage stale, not linked as current | yes |
| NEG-24 | malicious JSON source with HTML | plain text, no active content | yes |
| NEG-25 | malicious external redirect | no unauthorized origin fetch | yes |
| NEG-26 | zip bomb/oversized JSON | bounded abort, no memory blowup | yes |
| NEG-27 | stale engine report for other pair | abstain from localization | yes |
| NEG-28 | generic guard added unrelated to CVE | only contextual hint, no proof | yes |
| NEG-29 | 10k source variants | pagination, response budget, GUI responsive | conditional perf gate |
| NEG-30 | impossible exact source lineage | exploratory/manual, not verified boundary | yes |
| NEG-31 | Windows offline DISM leaves package pending | no "patched binary verified" claim | future package module only |
| NEG-32 | checkpoint prerequisites missing | blocked before servicing | future package module only |

## 5. Test process and fixtures

Local test groups (names proposed, not yet created):
- tests/test_patch_kb.py: parsing, URL and query boundary.
- tests/test_patch_cvrf.py: CVRF product-specific remediation.
- tests/test_patch_sources.py: transport/consent/source revision/cache.
- tests/test_patch_products.py: normalization and ambiguity.
- tests/test_patch_pairs.py: identity, chronology, boundary.
- tests/test_patch_acquiring.py: SPEC-08 reuse and staging.
- tests/test_patch_storage.py: sidecar schema/locking/atomicity/recovery.
- tests/test_patch_correlate.py: evidence join/uncertainty/stale.
- tests/test_patch_cli.py: command grammar/status/JSON/zero-network.
- tests/test_ui_patch_search.py: Qt controller lifecycle and UI state.
- tests/test_patch_security.py: malicious JSON, paths, redirect, quota.
- tests/test_patch_e2e_offline.py: full fixture flow, no provider calls.
- tests/test_patch_property.py: Hypothesis/property tests.

Seed corpus goal: >=20 independent source/product cases and >=5 deliberate false-association traps, plus 2 own-compiled PE pairs. Multiple randomly duplicated records from the same document do not count as independent cases.

Example commands after tests exist:
    python -m pytest tests/test_patch_cvrf.py tests/test_patch_pairs.py -q
    python -m pytest tests/test_patch_storage.py tests/test_patch_security.py -q
    python -m pytest tests/test_patch_e2e_offline.py -q
    python -m pytest tests/test_acquisition_winbindex.py tests/test_acquisition_transport.py -q
    python -m pytest tests/test_enrichment_cve.py tests/test_enrichment_intelligence.py -q
    python -m pytest -q
    python -m ruff check src/patchtrace tests
    python tools/build_windows.py

These are proposed verification commands and not executed as part of this docs-only PR.

## 6. Mock transport and crash-test design

Use injected pure Python fake providers with:
- predictable ordered request list;
- fail-on-request number;
- 200/404/429/500 statuses, bounded Retry-After;
- no redirect, approved redirect, hostile redirect;
- partial response, truncated content-length, oversized response, decompression bomb;
- injected monotonic clock, cancellation events, deterministic latencies;
- request counters so accidental network attempts fail tests.

For crash recovery, run helper processes against temporary copy of synthetic project; inject abrupt process termination at named checkpoints:
    source_before_commit
    source_after_commit
    first_binary_verified
    both_binaries_verified
    project_created_before_attach
    sidecar_before_transaction_commit
    sidecar_after_commit_before_ack
    triage_before_store
    sidecar_migration_midflight

Check project.sqlite3 with SQLite integrity and existing ProjectService.open after restart; assert artifact files unchanged and still matched by SHA-256, no orphan user files deleted. Verify sidecar reconciliation returns a machine-readable pending/repairable result.

Avoid simulating crash with Python exceptions only; use subprocess hard-termination tests where platform permits, in isolated temporary directories.

## 7. Performance acceptance, actual measurement

Proposed budgets (measured and then ratified, not asserted as achieved):
- one cached indexed scope 1,000 KB/product edges: search < 500 ms on reference Windows CI runner;
- data-bound background work: no GUI event handler blocks >100 ms without progress/worker handoff;
- 10,000 candidates virtualized, scroll/filter actions remain interactive;
- frozen package memory and startup delta recorded against baseline, not assumed;
- raw advisory bytes, decompression ratio, JSON depth and parse node count bounded;
- binary streaming computes hash incrementally, not one giant bytes allocation;
- only one binary copy per SHA in project; cache duplication measured;
- cancellation responsive within bounded request/worker completion, with hard timeout and cleanup;
- parallel HEAD probes honor existing SPEC-08 cap; new source search does not multiply concurrency beyond configured ceilings.

Benchmark tooling outputs JSON with OS, CPU, Python, Pydantic, PySide6, test corpus digest, wall time, peak memory and pass/fail. Avoid comparing Linux offscreen latency with Windows interactive acceptance.

## 8. CI/workflows and explicit gate statuses

Required jobs:
1. Linux hermetic unit and pure parser/property suite: offline only; deny network at OS/test harness layer.
2. Windows hermetic unit and full CLI/local PE integration: offline only.
3. Windows PySide6 frozen EXE startup/one full synthetic flow, platform-specific ctypes integration tests if used.
4. Manual or scheduled LIVE-MSRC probe on explicit opted-in source month and pinned golden schema; not required for every PR but required before advertising online search.
5. Manual or scheduled LIVE-SYMBOL small file acquisition via existing SPEC-08, compare expected SHA (no binary committed).
6. GUI manual accessibility and high-DPI checklist, Narrator/NVDA and keyboard only.
7. Main repo regressions: acquire, correlate, history, N-way, secondary evidence, packaging, offline backend.
8. Product-localization empirical validation only if ranking is marketed beyond contextual findings.

Each gate uses PASS / FAIL / BLOCKED / NOT_RUN and includes runner version/time/commit+fixture digests. BLOCKED does not equal PASS. If the feature is disabled/behind flag, report precisely which gates are outstanding.

## 9. Phased release criteria

R0 (contracts): source fixtures and schemas, no UI, hermetic tests pass.
R1 (offline search): product-scoped CVRF join + explicit coverage + manual filename, no automatic misleading edge.
R2 (pair MVP): Winbindex metadata reuse, verified full-PE pair, manual import, project creation, recoverable sidecar.
R3 (Windows alpha): GUI wizard, CLI, source-aware expectations, offline full flow frozen EXE.
R4 (consented online): official MSRC live source, exact request consent, symbol fetch, error rate/timeout and provider version gates.
R5 (CVE triage): run-bound linked evidence; still hypotheses, preserve unclassified and contradicted queue.
R6 (package fallback, optional): supported offline Windows servicing with checkpoint/pending verification; separate acceptance, not part of MVP.

Do not block R1-R4 on speculative CFG/data-flow or unimplemented unified engine. Do not prematurely ship R6 on successful CAB extraction alone.

## 10. Traceability matrix to SPEC-32

- Parent F01-F07 -> source adapter spec S01-S20, NEG-01..08, NEG-24.
- Parent F08-F15 -> pair spec B01-B20, NEG-09..18/30.
- Parent F16-F21 -> NEG-23/27/28, stale and evidence tests.
- Parent F22-F26 -> CLI/UI spec C01-C16, Windows GUI gates.
- Parent acceptance A01-A16 -> this document's full-negative suite and releases R0-R6.
- Failure and recovery -> crash inject checkpoints + NEG-19..22.
- Optional package fallback -> NEG-31/32 and separate Windows acceptance only.

Every merge request must identify which requirement IDs and negative tests its code implements, and attach real test evidence with exact runner/commit. A failing core gate must not be reduced to a TODO after merge.
