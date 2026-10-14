# SPEC-31-H: Test Corpus, Quality Gates, PR Ownership and Failure Reproduction

Status: developer-ready validation and handoff. Parent [SPEC-31](../kb-cve-correlation-and-acquisition.md). Integrator must add tests before claiming a slice complete. Existing frozen Windows beta, source contracts, QA ledger, CI and independent product/build fixtures are the baseline.

## H1. Ownership and chronological delivery

31-A schemas and identity -> 31-B source index and 31-C product/build graph in parallel once contracts frozen -> 31-G component claims -> 31-D acquisition -> 31-F workflow, persistent linkage, CLI and UI -> 31-E documentary correlation initially, optional semantic engine later -> 31-I release integrator.

Only integration owner edits shared src/patchtrace/cli.py, ui.py, ProjectStore migration code, docs/modules.md and docs/qa.md. Worker branches touch only src/patchtrace/kbcorrelation/* plus owned tests and their docs, with explicitly agreed source contracts. Import surfaces are reviewed before merge. Rebase/merge promptly, close obsolete branches, record Windows checks that cannot be run. Feature flags expose incomplete optional capabilities, not promise them.

## H2. Fixture structure

tests/fixtures/kbcorrelation/
- identifiers.json: valid/invalid KB and CVE boundary strings including Unicode.
- source-msrc-sug.json: sanitized shape with exact KB->CVE->product remediation, source pointers.
- source-cvrf-month.json: synthetic full source document with multiple CVEs, remediations and products, repeats/withdrawals.
- source-csaf-multi.json: synthetic CSAF 2.0 product tree, groups, fixed/not-affected/unknown and revision.
- source-unknown-product.json: unresolved product/group labels.
- source-contradictions.json: conflicting remediation/build claims from same provider lineage.
- coverage/complete.json, partial-page.json, missing-month.json, cancellation.json.
- product-graph/adjacent.json, checkpoint-dag.json, cycle.json, cross-branch.json.
- winbindex/versions.json.gz: reduced synthetic entry set matching acquisition parser schema.
- packages/synthetic inventory only; generated CAB/PA30 deltas with repo-owned source code on Windows CI as required, no Microsoft software distributed.
- expected/*.json: fully specified normalized output and reason codes (documented contract, not snapshots of accidental implementation).

Synthetic fixture IDs and KB/CVEs use clearly non-real CVE-2099..., KB5000001 etc. Real source captures, if retained, must be trimmed according to license and verified provenance; real Microsoft binaries are never committed.

## H3. Stage-by-stage negative matrix

Source/coverage: duplicate JSON keys, malformed UTF8, huge/deep JSON, wrong MIME type, unexpected redirect, HTTP 404, 429 retry, 304 without matching cached bytes, doc appears in two monthly release feeds, ambiguous KB support URL, unknown CVE, negated CVE text, product status not affected, revoked source revision, interrupted scan. Expected safe output with no invented verified remediation.

Product/pair: client/server name overlap, x64/ARM64 overlap, LTSC vs GA, preview vs production, dotted build .9 vs .10, unknown UBR, PE timestamp inverted, KB numeric order opposite date, checkpoint DAG, version graph cycle, duplicate SHA across builds, target KB in different product scope, intervening updates unknown, stale alias mapping. Assert no incompatible pair can receive auto-verified status.

Acquisition: metadata success/direct file 404, first file success/second fail, redirect off allowlist, hash tamper same size, PA30 needs base, PA31 helper unavailable, wrong base SHA, malformed PE machine, source mutated during copy, truncated download, huge file, cancellation after first byte/after last byte/between create and commit, fake symlink, wrong package architecture and Catalog browser-only fallback.

Correlation: stale run/source, function identity contested, same advisory repeated three ways, shared Ghidra-derived signal repeated, fake log string, CWE omitted/negated, missing capa rule, distant/confounded update window, wrong product, decoder strips source pointer, E1 optional module absent. No uncalibrated numeric vulnerabilities or verified-vulnerability claims.

Persistence and GUI: close dialog before worker completes, rapid search switch generation stale result, busy SQLite/project revision conflict, interrupted DDL/transaction, cache pruned before backup restore, future-schema reject, immutable previous history, cross-project file link refusal, Unicode/HTML injection in plain text, high-DPI and keyboard-only, frozen ZIP tests.

## H4. Test-first workflow and tool boundaries

For each PR: (1) failing pure contract/edge-case tests; (2) minimal implementation; (3) deterministic golden output with model_validate; (4) contract schema regeneration + binary/API compatibility tests; (5) relevant integration tests; (6) QA note with exact command/OS; (7) single-issue review and merge. No code accepted based only on compilation or type checking; tests must exercise externally visible behavior.

Recommended suites (test names to be added, not assumed present):
- tests/test_kbc_contracts.py, test_kbc_msrc_index.py, test_kbc_products.py, test_kbc_updates.py
- test_kbc_components.py, test_kbc_pairs.py, test_kbc_acquisition.py, test_kbc_package.py
- test_kbc_workflow.py, test_kbc_storage.py, test_kbc_correlate.py, test_kbc_cli.py, test_ui_kbc.py
Tests should be hermetic with fake opener and deterministic clock, no live network requirement. Do not conflate pytest-qt Linux offscreen with native Windows GUI test.

## H5. Integration gates

Gate A: generated schemas/positive and negative fixtures pinned; validation property tests green; no prohibited domain imports.
Gate B: one offline KB→CVE product association with exact pointer; indexed historical revision, partial scan and negative missing KB cases correct.
Gate C: 100% forbidden cross-product/unknown-orientation pairs blocked from AUTO_VERIFIED; signed/user asserted states distinct.
Gate D: one direct-download synthetic pair imported through existing SPEC-08 service, all hashes verified, one project created atomically, without altering existing CLI acquire workflow.
Gate E: re-open existing project and attach investigation with reproducible source, no stale linkage into wrong run; backups restore history.
Gate F: GUI full 6-step flow works with no network before consent and no analyzer invocation before explicit action; keyboard support and status text tested on Windows.
Gate G: E0 vendor documentary context/candidate changes present, full E1 blocked when optional semantic engine missing. Strong mechanism labels only if evidence obligations met.
Gate H: package functionality is independently gated; do not delay the basic feature for checkpoint reconstruction.
Gate I: existing full suite and native Windows frozen ZIP smoke green, report/export round-trip, provenance/limitations visible.

## H6. Independent field acceptance

Produce two separate real-world cases, kept local: (a) official KB, product-specific CVE link, valid old/new Microsoft PE pair, successful comparison and evidence export; (b) legitimate KB with no downloadable or unknown predecessor, explicit partial workflow without inventing binary links. Record exact source URLs/retrieval time and SHA, build/architecture, reason for pair choice, update interval, compare-engine/version, run hashes, manual steps, and what remains unverified. One non-adjacent pair demonstrates confounder banner. Verify three error cases on native Windows: wrong architecture, missing signing catalog and PA30 missing base.

Do not call any development milestone 'end-to-end complete' until frozen Windows application can reopen/export the same investigation, including offline copies/manifest for all cited source snapshots.

## H7. Regression and evaluation metrics

CI gates: all existing CLI/acquire/correlate/Qt tests green; no project DB corruption, no leaked connections/temporary artifacts, no unexpected network or child process; source lookup deterministic across ordering; scan retrieval has bounded time and memory; error semantics stable. Track source lookup recall against manually audited sample source corpus and function localization precision@K separately. Target >=20% false lead reduction from SPEC-30 is a proposed evidence gate, not presumed accomplishment. Numeric probability disabled until independent labeled calibration.

## H8. Developer-ready PR descriptions

Each PR includes: what changes; public interfaces; test fixtures plus expected reason codes; exact commands/OS and results; backward compatibility/migrations; known limitations; fixtures/licenses; external URLs used; security and cancellation checks; owner; dependencies; reviewer and whether another worker is touching same files. Integrator merges or explicitly closes each branch. Documentation in docs/modules.md and docs/qa.md must match running code; never advance status using planning alone.
