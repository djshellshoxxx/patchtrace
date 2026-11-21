# C4 / updated PR349 merge-record audit

**Verdict: PASS. No blocking integration-history issue was found at the frozen checkpoint.**

This is a bounded independent record-integrity review. It compares immutable Git objects and inspects the coordinator’s existing local test receipts. It does not run repository tests, mutate the coordinator checkout, operate on remote refs or PRs, or re-audit the earlier publication and archive qualifications. Later documentation/evidence additions are outside this checkpoint.

## Frozen source and ancestry

| Role | Commit | Tree |
|---|---|---|
| Three-way base | `11f51c105bf63946f59373ae605b937c4fee607a` | `4939056ceb0e02b419c820b9e5748c869c40a857` |
| Prior C4 documentation package | `a76189cc0e7ec4312baf3662da5946d39bdd019c` | `8c4ee69d38e8066a18cad28ecb7e171ca97ba960` |
| Updated PR349 parent | `daee337c48c63dda8aeac149c407e900c79dcc86` | `6c2a8d018ccc00bf65ef074579604b40627f7658` |
| Merge | `e7391634a46bbb1f9f1fdc3563abadb837d1b45b` | `419af4313bc711437886c4d2bd6c72c8062bf679` |
| Registry-only checkpoint audited here | `111803d54cfebc1b779f4832a069904b3ee91a7c` | `d3264bf26f83d039fa212c26b47c094f86691c3f` |

The merge’s ordered parents are exactly prior C4 followed by the updated PR349 parent. The registry commit has exactly the merge as its parent. Git independently resolves the common merge base to the stated `11f51c10…` object. All repository reads used these explicit objects, not the moving working tree or branch head. Evidence: `controls.json` → `git`.

## Ledger and ownership preservation

The base contains 77 tasks, prior C4 contains 80, the updated parent contains 90, and both the merge and the audited checkpoint contain **93 unique task IDs**. All 90 parent task objects are an exact decoded-JSON prefix, including every nested status, owner, qualification, and history value. The final three objects exactly equal the three prior C4 additions:

- `buildenv-header-help-20261121-95fe`
- `pages-site-isolation-and-hashes-20261121-95fe`
- `codex5-per-command-audit-gap-20261121-95fe`

Every parent top-level field except the intentionally refreshed `updated_at` and additive `tasks` list is semantically unchanged. The only added top-level field is `parallel_followup_cycle4`, whose complete value exactly equals prior C4. The registry-only follow-up leaves the entire merged ledger byte-identical. Parent ownership and qualification fields therefore survive without reinterpretation; the C4 CODEX-5 task retains its existing instruction to preserve 837FE Action-pin file ownership.

The feature-status JSON, C4 consolidation report, and C4 handoff also retain their prior C4 bytes exactly. The release-readiness document retains its base history and prior C4 addition exactly. Evidence: `controls.json` → `ledger`, `preserved_c4_documents`, and `markdown_histories`. The controls include a canonical SHA-256 and original provenance for every task object.

## Shared Markdown histories

For each file below, both branches changed the common base only by inserting complete sections. The audit independently rebuilt the final file from the unchanged base and both branches’ exact insertion bytes at their original positions. Every reconstruction equals the final blob byte-for-byte, and each added section occurs exactly once. This establishes preservation of content, order, and multiplicity without relying on Git’s merge-success indication.

| File | C4 added lines | Parent added lines | Result |
|---|---:|---:|---|
| `docs/engineering/AUDIT_FINDINGS.md` | 14 | 4 | Exact union; each addition once |
| `docs/engineering/BRANCH_INVENTORY.md` | 12 | 6 | Exact union; each addition once |
| `docs/engineering/CONSOLIDATION_LEDGER.md` | 12 | 4 | Exact union; each addition once |
| `docs/engineering/FEATURE_MATRIX.md` | 14 | 4 | Exact union; each addition once |
| `docs/engineering/INTEGRATION_QUEUE.md` | 14 | 4 | Exact union; each addition once |
| `docs/engineering/WORKER_HANDOFF.md` | 13 | 4 | Exact union; each addition once |
| `docs/qa.md` | 16 | 8 | Exact union; each addition once |
| `tasks/todo.md` | 16 | 25 | Exact union; each addition once |
| `docs/engineering/release-readiness-20261119.md` | 13 | 0 | Exact union; each addition once |

The six shared indexes retain the C4 section after their title and the parent’s combined PR349 section at the end. QA and todo retain the C4 preamble and the parent’s appended record. The parent did not change the release-readiness file relative to the common base. No loss, duplication, or reordering of the common history or either branch’s added sections was found. Evidence: `controls.json` → `markdown_histories`, including line counts, insertion offsets, occurrence counts, and SHA-256 digests for each source and insertion.

## Sealed evidence bytes

The final `docs/engineering/evidence/` tree is the exact union of **355 parent files** and the **17 C4 files** under `docs/engineering/evidence/cycle4-95fe/`. The namespaces are disjoint, producing exactly **372 files**. Every retained file was read from its original commit and the frozen final commit and compared byte-for-byte. Git modes, types, and blob IDs also agree. There are no overwritten, missing, or unexpected evidence files within this frozen tree.

This check preserves existing archives, bundles, manifests, original review findings, and test receipts as sealed records. It does not requalify their contents or convert historical local results into current hosted acceptance. Evidence: `controls.json` → `sealed_evidence`, which records all 372 paths, original side, mode, blob ID, byte size, SHA-256, and exact-byte result.

The two known raw bundle verification receipts retain their original literal trailing space on line 4:

- `docs/engineering/evidence/cycle4-95fe/source-bundle-verification.txt`, compared with prior C4.
- `docs/engineering/evidence/cycle837fe-20261121/source-history-verification.txt`, compared with the updated parent.

A read-only `git diff --check` from the common base to the frozen checkpoint reports exactly those two paths and returns 2. Excluding only those sealed raw receipts returns 0 with empty output. Their spaces are preserved evidence bytes, not newly introduced source defects. Evidence: `whitespace-all.log`, `whitespace-excluding-sealed-receipts.log`, and `controls.json` → `raw_receipt_whitespace`. This independently agrees with `parent-upgrade-evidence/merge-resolution.json`.

## Registry-only repair and recorded failure continuity

The entire difference from merge `e7391634…` to checkpoint `111803d5…` is nine inserted lines in `docs/specs/REGISTRY.md`. The original registry is an exact byte prefix of the updated registry. The new section registers the two existing C4 specifications by path, describes the aliases as proposed, and retains the local/platform/hosted acceptance boundaries.

`tests/test_spec_registry.py` is unchanged in the updated parent, merge, and final checkpoint: Git blob `3480cbf028225b9c9f92f04e1db04cfcc56618df`. Inspection of the existing clean-source receipts gives:

| Existing receipt | Bound source | Registry cases | Result |
|---|---|---:|---|
| `parent-upgrade-evidence/registry-before-clean.json` and `.xml` | `e7391634a46bbb1f9f1fdc3563abadb837d1b45b` | 110 | 108 passed, 2 failed |
| `parent-upgrade-evidence/combined-after.json` and `.xml` | `111803d54cfebc1b779f4832a069904b3ee91a7c` | The same 110 identities, selected from the recorded combined run | 110 passed |

Both receipts record the stated tree, unchanged head before/after, and clean working trees before/after. The baseline failures are exactly `test_registry_cites_spec_file_by_path[docs/specs/buildenv-header-help.md]` and `test_registry_cites_spec_file_by_path[docs/specs/pages-build-isolation-and-hashes.md]`. The same identities pass after registration, with no test edit or change in the registry case set. Evidence: `registry-only.diff` and `controls.json` → `registry`, including source receipt hashes and the full registry identity/status lists. These are inspected local receipts; no new test execution or hosted/native acceptance is claimed by this audit.

## Audit artifacts and limits

- `check_merge_records.py` reproduces the frozen-object and existing-receipt checks without project imports or test execution.
- `controls.json` contains the complete machine-readable findings and source bindings.
- `registry-only.diff` preserves the complete post-merge delta.
- The two whitespace logs preserve the exact output and the clean result after excluding the two raw receipts.
- `manifest.json` records sizes and SHA-256 digests of this report and the audit payloads.

The original publication/archive audit remains a separate historical qualification. This report does not examine the newly produced three-commit bundle, the broader combined test selection, the separate Ruff scope disposition, or any later documentation commit. It establishes that the frozen merge preserves the requested ledger, ownership, Markdown histories, and sealed evidence, and that the bounded registry repair is supported by unchanged-test local receipts. It does not authorize or assert a main merge, release, deployment, or native acceptance.
