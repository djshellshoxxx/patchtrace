# Cycle 2 consolidation and qualification

Date: 20 November 2026, America/Los_Angeles. Artifact identifiers use the UTC cycle date.
Authority: [task ledger](task-ledger.json). Source: `3cf7ad23f66611d6bbf3e4d08e10daa2715fd300`; complete source tree `60ed420c11116f1b92bdbedae34e3e82269458e5`.

## Delivered changes

The candidate retains PR #345's report, TaskRunner, Linux replacement-refusal and Evidence repairs, PR #347's selective sibling recovery, and the three published inventory-validation successors through `91618abec4c4f13a27fd5821a25d1500f17601e4`. It adds strict malformed-quote refusal, a real invalid-UTF-8 regression, all eight Strings application header mappings, and original JSON-display assertions beside CSV-prefix controls. The published inventory branch later advanced through six documentation-only commits to `e2385c22c0397a547b15b2fbca9f0c07dc4ac199`. Those refinements were merged after verifying source, tests, tools and workflow contents were unchanged. No serializer, backend matching, acquisition or target-execution capability changed.

The independent inventory reviewer demonstrated three malformed-quote failures against unchanged code: the incomplete note reached Git and CLI publication replaced the previous report. `csv.DictReader(..., strict=True)` now routes those cases through existing input-error/refusal handling. The old invalid-escape control remains separate from byte `0xff` decoding coverage. [Inventory review](cycle2-inventory-review-20261121-2bad.md).

Strings headers Change, String, Type, Older, Newer, Function, Cues and Source now register and use their existing help. Header labels, cells, row identities, filtering, sorting and export content remain stable. The global audit reads actual QTableView header sections after ordinary host activation; it has no additional exemptions. A fresh mutation removing Source help makes that audit fail. The static scan finds 90 direct ColumnSpec calls and 8 constant help IDs; other panels are still open. [Author evidence](cycle2-strings-header-help-20261121-2bad.md), [independent peer](cycle2-peer-review-20261121-2bad.md).

## Exact-source verification

| Selection | Result | Scope |
| --- | --- | --- |
| Clean combined final source, 7 files | **188 passed, 0 skipped** | Source and working tree unchanged through pytest, Ruff, dependencies and isolated-import checks |
| Candidate admission lower baseline | 4 failed, 17 passed | PR #345; exact current regression source imported against retained baseline |
| Recovered admission/CSV/Qt review | 38 passed | Published `91618abe`; production/test blob comparisons match PR #347 |
| Inventory before quoted-field repair | 36 passed; then 3 new failures | Shows the existing suite missed damaged quoting |
| Inventory repaired maintained suite | 40 passed | Includes inherited TSV/OID/strict JSON cases and new quote/UTF8 controls |
| Independent inventory controls | 11 passed | Real SHA-1/SHA-256, quoting, bounded reads and output preservation |
| Strings new header regressions | 17 failed before; 17 passed after | Idle/ready states, escaping, cells, labels and fallback |
| Author maintained Strings selection | 91 passed | Earlier author source; overlaps the 17 cases |
| Fresh peer maintained/independent selections | 34 passed; 5 independent passed | Overlap maintained results; reviewer corrected one test expectation and retained its original failure |

Do not sum these selections. The authoritative final local result is 188 passes on one clean combined source. Whole-tree `python -m ruff check src tests tools`, `pip check`, and isolated `python -I` source binding pass. No new full local suite was repeated after the retained unexplained SIGKILLs; supported hosted qualification of this new source remains required.

The initial integrated check produced 187 passes/1 audit failure and a Ruff import-order finding. The author corrected the audit's Qt-model assumption and then its missing host activation; original failures are retained. The final audit changes were independently reviewed and mutation-tested, without increasing exemptions or changing a test budget.

The inventory reviewer replayed 353 exact retained branch/tip rows and 2,228,790 bytes byte-identically, SHA256 `d82d52544646eb029f38684e2dd3802ffa1596c7eb02d5c11d0ae0b5783aa902`. This proves compatibility with that snapshot, not semantic equivalence of its branches.

## Hosted evidence and qualified merge boundary

The [hosted receipt](hosted-qualification-cycle2-20261120-2bad.md) binds tested synthetic merge trees to exact PR heads. PR #345 completed Linux 23,974 passed / 53 skipped / 6 xfailed and Windows 23,847 passed / 181 skipped / 5 xfailed; its original Windows job then failed on the external NSIS Chocolatey feed HTTP 503 after Ruff/build/frozen/portable checks passed. One failed-job-only retry was accepted and later observed active. Its outcome remains pending in this checkpoint; the original failure is not erased.

PR #346 at `c07774ec` completed both QA legs, five Qt jobs, five native jobs, Windows installer checks, Linux packaging and both Linux smoke checks. Linux 23,958 passed / 53 skipped / 6 xfailed; Windows 23,845 passed / 167 skipped / 5 xfailed. Its unique work already exists in PR #347, so a broad sibling ledger merge was avoided. PR #347 at `b461ac64` has successful Linux QA, all Qt and all five native jobs at the latest read; Windows QA remains active. These receipts qualify their named sources only. No new-source or main acceptance is inferred.

## Branch recovery and history

The refreshed references contain 360 remote heads, 59 tags and 337 fetched PR head refs. Six branch names were added after the prior 354-head census; no prior head moved or disappeared. Five new heads are ancestors of `91618abe`. The remaining sibling's unique code was selectively recovered with shared accessibility retained once. This does not replace an all-pages PR metadata census or the original 181 unmatched / 16 patch-equivalent semantic backlog.

The [new historical review](cycle2-historical-ui-review-20261121-2bad.md) adds bounded behavior-level dispositions and exact recovery candidates. It does not authorize deleting a branch or subtracting a whole branch from the backlog without complete review. Four examined scopes cover Files/Export accessibility, runtime housekeeping, an older packaging audit and build-environment report presentation. Existing focused selections yielded 86 passes, 4 strict expected failures and 7 deselections. The outstanding audit gates are CODEX-1 (mutable Action tags), CODEX-5 (unhashed package installs), CODEX-6 (cache-hit verification bypasses) and CODEX-14 (full Linux frozen CLI smoke). The donor carries no implementation that closes these gaps; existing Linux GUI self-tests do not close CODEX-14.

## Publication and continuation

Integration branch: `codex/patchtrace-integration-20261121-2bad`, proposed against PR #347's branch at `b461ac64eb9beb74449ce2b18b6795a2af34a02a`. Resolve the matching live draft PR for final publication head/tree; its description records exact fetched local/remote tree equality. The Git Data API publication preserves the complete tree; a verified bundle preserves local coordinator and worker histories through `6ed9642bae637cb73b17de03a2a67eb659c4f301`. [Machine qualification](evidence/cycle2-coordinator-20261121-2bad.json), [coordinator evidence](evidence/cycle2-coordinator-20261121-2bad.zip), [history bundle](evidence/cycle2-local-history-20261121-2bad.bundle).

All five fresh worker assignments are complete. The existing scheduled continuation receives the exact publication identity after verification. Inspect new-source hosted results and the one PR #345 retry, then use a fresh expected-head REST guard for any merge with every applicable job green and no blocker. Main/release remain unqualified for this successor. Native/manual accessibility and trust, provenance membership, remaining header mappings, historical semantic review and separate L1/L2/L3 evidence remain explicit unfinished work. [Executable handoff](../engineering-handoffs/cycle2-20261121-2bad.md).
