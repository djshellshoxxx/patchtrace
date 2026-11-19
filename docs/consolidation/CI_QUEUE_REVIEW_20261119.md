# CI queue investigation and archived evidence — 2026-11-19

## Recorded outcome and scope

At the final archived observation, PR #322 had **six queued workflow runs and
23 substantive jobs without an assigned runner or step output**. The available
metadata did not establish the queue cause. The ten requested superseded runs
on that same branch were already completed/cancelled, so there was **no obsolete
queued run to cancel**. No remote mutation was performed.

This report preserves existing read-only REST observations. The late CI refresh
is clock-bounded at **13:33:41–13:36:55 UTC on 2026-11-19**; main and PR #319
metadata followed at **13:37:30–13:37:31 UTC**. The earlier 11:59 and 13:07
snapshots remain unchanged in the archive. Packaging made no further network
request or benchmark. These observations do not qualify a later publication.

## Exact source bindings

| Source | Full recorded SHA / tree |
| --- | --- |
| Main | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` |
| PR #322 head | `eb94510bda73935b1b5b99d00acde879d6474d14`, open/draft |
| PR #322 base | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` |
| Published source tree | `62665b03d9c2c7431ceaa1d181505d28105ccb93`; local source checkpoint `0ed53876c0460edafdb089121744c167493fb8ff` |
| Current PR #319 head at retrieval | `8d130aefe1be6e737cff1d90d2a5b1658d60a3a6`, open/draft |
| Current PR #319 base at retrieval | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` |
| PR #318 workflow head | `c4ace2088ce8dc9ce78a0bf3036b81096accbdb5` |
| PR #318 actual checkout | Merge `de9a8cf060a5def95acb9d887f68e0dc01237221`, tree `ee130e5c201683794abf42b76fb6c9372731d892`, into base `f2b6827fc6270b96fb241b0722f2878de5a17361` |

The workflow-binding receipt records the five workflow blobs at the local
published checkpoint; the coordinating review separately verified its tree
against PR #322. Current PR #319 head `8d130aef...` is distinct from frozen
retained-source head `a56ab13aaf9916fc12bea70ba1494075991b7f09`, used in earlier
recovery work. This refresh changes neither that contribution provenance nor
the frozen branch census.

## Current-head runs and superseded inventory

| PR #322 workflow | Run ID | Queued substantive jobs |
| --- | --- | ---: |
| QA and Windows standalone | 44528877391 | 7 |
| Optional dependency wheels probe | 44528877381 | 2 |
| Live BinDiff | 44528877303 | 2 |
| Native Windows Ghidriff, PR event | 44528877271 | 5 |
| Live rizin | 44528877581 | 2 |
| Native Windows Ghidriff, push event | 44528869138 | 5 |

Each run is queued with a null conclusion. Each substantive job has runner ID
zero, a blank runner name, and no steps. Populated `started_at` values do not
establish execution. QA's PR release gate is intentionally skipped; downstream
Linux packaging and smoke jobs were not yet instantiated. The six earlier
`pending_deployments` reads were empty. No retrieved run reported an approval
requirement, and none of the five workflow definitions has a draft predicate.
Draft state remains a separate merge-readiness condition.

The branch inventory returned all 16 records on one page: six current and ten
older runs, all associated with PR #322. The older heads were
`32cc4b04cf1f5b9e69d1d0e8691db7083c7a45a7` and
`2511301fc26bf0e039f54828959c422b4ff761a2`. All ten runs were terminal/cancelled;
their 50 jobs comprised 48 cancellations and two release-gate skips. The archived
inventory contains every run/job ID. No cancellation actor is inferred.

The concurrency formula includes workflow, event, and ref. PR #318 uses a
different PR ref; native push and PR runs use different event/ref groups. The
records do not establish a shared workflow-concurrency blocker, absent runners,
account-wide capacity, provisioning delay, or billing as the cause of the wait.

## PR #318 failure and later job completion

Run **44502066991** became completed/failure at **13:31:42 UTC**. Its eleven
job records contain five successes, one failure, one cancellation and four skips.
Windows Qt succeeded at 13:09:55 UTC. Linux Qt shard 3/4 was cancelled at
13:31:41 UTC. The original Windows full-QA failure remains:

- Job **135484259463**, on the actual merge checkout listed above.
- `tests/test_kev_parse.py::test_a_full_size_catalog_parses_within_the_budget`.
- All **1,741 entries** parsed; elapsed **1.4662241000000904 seconds** failed
  the unchanged strict **`elapsed < 1.0`** assertion.
- **1 failed, 25,615 passed, 151 skipped, 2 xfailed**, 25 warnings; subsequent
  Windows packaging and frozen/installer steps were skipped.
- CPython 3.12.10, Pydantic 2.13.5 and pydantic-core 2.46.5.

The tested KEV source/fixture blobs matched the then-current root
`cf55415587f996f54a9d957a48d57818ebe9ff42`; its Pydantic pin differed. The
existing test passed locally under Linux with Pydantic 2.14.2/core 2.50.2 and
the same assertion. That Linux result and its small authored-fixture profile
do not reproduce or resolve the Windows failure. The later scoped ASCII
optimization and independent review have separate
[KEV evidence](evidence/kev-text-performance-20261119.zip) and a
[performance report](KEV_TEXT_VALIDATION_PERFORMANCE_20261119.md).

The two active Qt log reads initially returned **404 BlobNotFound**. After
completion, the Linux Qt log became readable: progress continued through
13:30:54 UTC, followed by **“The operation was canceled” at 13:31:39 UTC** and
process cleanup. The observed duration is consistent with the configured
120-minute timeout; the cancellation actor and exact cause are not established.
The returned check-run detail URL was rejected by the connector allowlist with
HTTP 400. Both the initial access results and later cancellation excerpt are
preserved without rewriting the older observations.

At the late snapshot, another source still received runner allocation: PR #319
native run **44517235766**, at current head `8d130aef...`, had four successful
variants and `raw-cache-hit` job **135536306714** active on runner **1000066287**.
This does not identify PR #322's queue cause or qualify its source.

## Qualification boundaries

The owner's all-applicable-test-jobs-green/no-blocker rule remains in force.
Final-head QA includes both full-QA platforms, every repeated Qt leg, downstream
Linux package/smokes, and Windows frozen/portable/installer acceptance. Triggered
native Ghidriff matrices and pinned live rizin checks require their actual
conclusions and source-bound receipts. Queued, cancelled, missing or failed
required records do not satisfy those gates.

Windows BinDiff live execution is advisory in the recorded workflow: provisioning
may record blocked status, the live step uses `continue-on-error`, and the
summarizer does not use `--fail-on-failed`. Inspect the actual status JSON before
claiming compatibility. The Windows BinExport memory-cap measurement is also
non-gating. Green jobs do not prove those measurements or manual clean-machine,
accessibility or disconnected acceptance. The earlier Snyk “No manifest changes”
status is not a vulnerability audit.

Before any merge, refresh the final reviewed head/main and every applicable
newest-attempt result, inspect native/live artifacts, resolve blockers and PR
readiness through an allowed mechanism, and use REST with the exact expected
head SHA. The recorded ready-for-review connector requires GraphQL; this review
did not use it or bypass the repository's REST-only rule.

## Archive and integrity

[ci-queue-review-20261119.zip](evidence/ci-queue-review-20261119.zip)
contains **22 unchanged original files plus one new archive index**:

- All 14 payloads named by the frozen CI manifest, plus that original manifest.
- The two earliest queue-review receipts.
- All four late-CI receipts, including the cancellation excerpt, allowlist
  rejection, and exact main/current-PR-319 bindings.
- The final handoff manifest, which also refers to separately archived KEV data.

Archive bytes: **67,680**. Original payload bytes: **528,728**.

**Archive SHA-256:**
`6c355229b91abfbb8d7fe89923f929b370c215c19fd5f286ebfca888be88606e`

| Frozen record | Verified SHA-256 |
| --- | --- |
| Original 14-file CI manifest | `627c86b7e1b423e493acfb8c8cdcfb5373c88adf877a8c38b462a8e761a113d8` |
| Original 40-file performance manifest, verified but retained in the separate KEV archive | `6e1e1e3952447eb6b74a96352187f916947b59d46a33a1a382d462a5bf952f69` |
| Final handoff manifest | `37464abc1e8b4211f485a43739a98a35872b9b48332404484d0922afc91fb9dc` |

Packaging verified every referenced file in those manifests before archiving,
including the separately retained KEV data. Every archive filename is unique;
all 23 members passed ZIP CRC decompression, exact byte comparison, and SHA-256
comparison. `CI_QUEUE_ARCHIVE_MANIFEST.json` records each original payload's
size/hash and the explicit external references. The full KEV 40-file payload set
and peer-review payloads are not duplicated here. Original timestamps, failures,
access blockers and pending-review fields remain historical records.
