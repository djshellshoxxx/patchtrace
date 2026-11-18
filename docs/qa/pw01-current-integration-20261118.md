# Continuation handoff and feature matrix — 2026-11-18

This checkpoint separates reviewed implementation, source-specific observations
and remaining acceptance. Final publication mappings and current CI observations are recorded below.
References target existing files in `docs/qa`; raw records remain in their
original evidence packages.

## Exact integration checkpoint

| Role | Preserved identity / state |
|---|---|
| Main, last observed by the integration lead | `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`; unchanged |
| Published consolidation #304 | `75ffee3840894adb52aff7f3df28043cc8e832ba` |
| Independently reviewed PW source | `0be3b9eb950a2a5a19261fd2f5d2f1fc2eb25b82` |
| PW documentation/evidence head | `d492c0e630c783c287e4143266fd87f7a949317c`; production/tests/tools unchanged from `0be3b9eb` |
| Qualified local combined source | `939d4a9051ecbd6ebc0cc97e20756c1a881ee070`, tree `11358e92063107e484dc30906f55ddeb8a61dd4f` |

The local combined candidate has actual parents `d492c0e6` and published `75ffee38`.
Its REST-published counterpart is `5eee139279e77c25c5fb292caa11a165af696059`,
with the identical tree and actual parents `f5b1c737` and `75ffee38`.
The [full local-to-published mapping](pw01-current-integration-20261118/publication-code-mappings.json)
preserves all thirteen source/merge/QA stages. The next commit adds only
qualification records and this handoff.
PW already preserves current #303 `2b697222` and its prior `76de3933` history.
The integration lead's blob audit found the 38 PW and 11 search changed paths
disjoint and exact to their owning parents; only two additive documentation
conflicts required resolution. The recorded 63-file combined selection completed: **2,121 passed,
2 native Windows skips**, in 64.02 seconds. Whole Ruff and the KBC schema check
passed. The two skips are held-handle/ancestor replacement and reparse-mutation
acceptance tests that require Windows. These are focused results, not a full-suite
claim. [Exact commands and raw results](pw01-current-integration-20261118/commands.json). No source PR has been closed,
no branch deleted, and no integration into main is implied.

The [independent merge review](pw01-current-integration-20261118/independent-review.md)
confirmed the same 49 source/test/tool paths, preservation of both histories and
all introduced documentation blocks, and 207 hashes across the three inherited
evidence archives. Four missing legacy QA targets predate both parents; none is
newly missing. The [verbatim combined-gate and review archive](pw01-current-integration-20261118/evidence.zip)
contains the original JUnit/logs, two merge audits, publication mappings and the
source-specific hosted checkpoint. Its [manifest](pw01-current-integration-20261118/manifest.json)
refers to archive members; the readable review removes trailing whitespace only.

## Feature and evidence matrix

| Area | Implemented / retained | Remaining boundary |
|---|---|---|
| Advisory, index and lineage | Scoped MSRC/Winbindex ingestion; mixed-architecture filtering; calendar/UTC chronology; uncertainty-preserving predecessor and pair choice; bounded enumeration | Metadata and pair availability do not prove a vulnerability fix. See [lineage integration](current302-integration-20261118.md). |
| Advisory search anchors | Closed binary-kind restrictions prevent advisory/note circularity; long valid anchors retain the original query budget; default stored-source CLI uses the existing project owner | Search matches remain hints. Ranking accuracy and unsupported source coverage are separate work. See [search integration](search-anchor-integration-20261118.md). |
| PW-01 inventory workflow | Saved CSV/support metadata, exact consent plans, immutable provenance, explicit filename selection, CLI/Qt retention and visible cross-page witnesses | V1 default/hard ceiling 50,000; independent v2 ceiling 5,000. Production retrieval and native/manual acceptance remain open. See [capacity qualification](pw01-capacity-compat-20261118.md). |
| Research receipt identity | Bounded linked-worktree gitdir/commondir/ref handling for future receipts; no Git process, config or hook execution | Historical null-SHA receipts stay unchanged; a commit ID alone does not prove a clean or authentic tree. See [receipt identity](pw01-retained-pages-20261118.md#research-receipt-identity). |
| Owned pair publication | Linux ownership controls and reviewed Windows native-handle/status/cleanup repair preserve prior evidence | Native Windows execution is still mandatory; portable checks are not that acceptance. See [Windows repair](winpairs-windows-native-20261118.md). |
| L1 / L2 / L3 | Separate frozen source replay, immutable native pilot, and metadata-only acquisition planning | No blended score, inferred aggregate accuracy, or promotion of unverified facts. |

## PW evidence and actual CSV behavior

At PW source `0be3b9eb`, the 14-file inventory/service/CLI/Qt/schema selection
passed **581 tests**; the separate reviewer passed **38 focused plus 6 authored
controls**. Ruff, generated-schema and whitespace checks passed. These selections
overlap and must not be summed. Genuine captured 5,000/50,000 v1 records and
existing v2 records replay byte-for-byte. New pages lower only the parent entry
budget to at most 5,000; they never revise an investigation or select a row.

Nine sequential shipped-CLI processes exercised the existing 3,300,683-byte
KB5036893 proxy capture offline. V1 retained **37,595 entries**, scanned **42,845
records**, and rejected **5,244 rows**, without truncation. AMD64 pages 1, 2 and 4
retained **5,000 / 5,000 / 3,761** entries with complete scans and exact earlier
IDs. `aarsvc.dll` witnesses still reference records **24,355 and 41,380**. Repeated
retention was idempotent; original body/raw hashes and zero revisions/decisions
were preserved. All nine commands correctly returned partial/exit 3. Largest
observed child RSS was **459,328 KiB**, not an enforced ceiling.

The first external launcher failed before import because its socket replacement
broke SSL class initialization. Its raw failure remains archived; a corrected
external launcher and fresh workspace produced the successful run. Product
source did not change. This is offline capture qualification at `0be3b9eb`, not
a production fetch or a newly executed measurement at `939d4a90`. The
[PW report and archives](pw01-capacity-compat-20261118.md) retain exact commands,
hashes, original failures and scopes.

## Accuracy layers remain distinct

**L1:** The final preserved replay belongs to published
`f69614fa6b5bb9d25d4233b06a4c4ce179964a52`: **73 PASS, 6 FAIL, 0 BLOCKED,
8 excluded**, across 87 frozen cases. Its command returned exit 1 / FAIL.
Expectations, exclusions and raw inputs are unchanged. Four Server coverage gaps
and two unchanged-preview cases remain failures. `winspool.drv` now exposes two
candidates; its expected-filename PASS does not establish unique selection or a
confirmed fix. This debugging corpus supplies regression/compatibility evidence,
not independent prediction accuracy. The [exact L1 replay](search-anchor-integration-20261118/l1-replay.md)
must not be relabelled as a run on later search or PW commits.

**L2:** The [first native pilot](l2-native-pilot-20261118.md) remains an immutable
MISS / FAIL. Rizin exited successfully but omitted `http_parser_execute`; the
unchanged ranking returned no candidates. Subsequent authored controls and
pinned-source inspection diagnosed a native function-discovery limitation.
[That diagnosis](l2-rizin-discovery-20261118.md) did not repair production,
rerun/rescore the candidate, or establish Windows/MSVC acceptance. An isolated native discovery correction has since been built and checked on
authored controls. It seeds functions before deeper analysis; an unchanged rebuild
reproduces the official tool output. The patched shared/executable controls expose
all four authored exports, and the production normalizer accepts the raw output.
The integration lead independently reran the shared control and reviewed the
narrow source change. [Native experiment and limits](l2-rizin-discovery-patch-20261118.md).
Production tool selection, Windows qualification, the prospective engine-aware
source-oracle naming contract and ranking validation remain separate work.

**L3:** CVE-2022-34718 `tcpip.sys` remains a
[metadata-only plan](pw01-retained-pages-20261118/l3-cve-2022-34718/provenance-review.md).
The older `.918` pin is an August preview; the newer `.978` pin is the September
security update. Article function names do not establish the author's exact byte
pair. Target/PDB/package acquisition is unapproved. Keep `facts: unverified`;
there is no function-ranking score or acquisition authorization by inheritance.

## Gates and highest next steps

The earlier full-file attempt remains **INCOMPLETE**: completed batches reported
**5,308 passed, 1 failed and 31 skipped**; eight other batches ended -9/137 without
completed JUnit. Neither a complete suite nor a termination cause is established.
The prior `bb4277ae` Windows gate had **15 failures**, with later full/package
steps skipped. Reviewed repairs do not erase those observations. See the
[preserved failures](pw01-retained-pages-20261118.md) and [native gate](winpairs-windows-native-20261118.md).

1. Qualify the final published head on required full Linux/Windows, Qt, package, native and dependency gates. The combined local selection is complete and preserved. At the last 75ffee38 checkpoint, native Linux BinDiff passed while Windows and the other required jobs remained queued/pending; no overall workflow conclusion was established. Older-head successes and queued jobs cannot substitute.
2. Merge #304 only after its gates pass; then retarget the inventory continuation from the #304 branch to canonical main, re-evaluate its base/tree and current-head gates, and refresh candidate heads, reviews and settings before a head-SHA-guarded REST merge with `[no release]`. Verify main ancestry before any closure, recheck each PR's current scope, and preserve every remote branch and partial/selective recovery.
3. Complete exact-plan production CSV retrieval and native/manual UI acceptance. Keep PW-02 bounded local MSU/CAB extraction and Server source coverage separately specified; do not substitute a client product or rewrite frozen failures.
4. Continue native discovery repair, source-oracle naming, ranking evaluation and L3 provenance/consent as distinct tracks. Preserve the original MISS and acquire no L3 target until the concrete plan is approved.
