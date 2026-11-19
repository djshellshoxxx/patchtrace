# Repository census refresh — November 19, 2026

This supplemental record preserves a fresh read-only GitHub census after new work appeared during consolidation. It does not replace the original 319-branch inventory or extend that inventory's semantic conclusions to new commits. The machine-readable evidence is in [inventory/refresh-20261119](inventory/refresh-20261119/manifest.json).

## Enumeration and checks

The GitHub connector returned **323 branches, 312 pull requests and 59 tags**. Pull requests comprise **56 open, 84 closed without merge and 172 merged**. All-state pull-request pages contained 100, 100, 100 and 12 records; branch pages contained 100, 100, 100 and 23 records. Each final page was short. The matching-refs tag response contained 59 records. Branch names, pull-request numbers and tag references are unique within their collections.

Every recorded branch tip, pull-request head and tag target resolves locally to a commit: 415 distinct commit objects. All recorded tags directly target commits. These checks establish the available census, not semantic retention, test success or a lock on mutable references. An open pull request's `merge_commit_sha` can identify a provider-generated preview; it is not evidence that the pull request merged.

The evidence includes full names and immutable head SHAs for every enumerated branch and pull request, tag references and targets, page sizes, SHA-256 hashes of each evidence file, and per-path blob comparisons for the new or advanced source families. The blob comparisons are explicitly frozen against candidate **`ecfd596093802f75bd6aacfae6c3c0dca3ce7619`**. Subsequent candidate commits require another comparison.

## New and advanced references

Main remains **`fdc2696c23bdbfe7668348f25e3b336ce33039f7`** in this census.

| Reference | Recorded head | Pull request | Review disposition at this checkpoint |
| --- | --- | --- | --- |
| `codex/patchtrace-checkpoint-20261119-81e4` | `bdc929ebd3c6aaa2563c758936beb315a10eeea0` | None in the census | Preserved source checkpoint; ancestor of the completion branch. |
| `codex/patchtrace-completion-20261119-81e4` | `2511301fc26bf0e039f54828959c422b4ff761a2` | #322, open draft against main | Contains actionable cache, parser, provenance and adapter changes absent from the compared candidate. Selective recovery review is pending; the whole branch has not been accepted. |
| `consolidation/patchtrace-continuation-20261119` | `f851d74d134a09cb9b12013d2c1adba1fde0c24f` | #321, open draft against the reviewed consolidation branch | Many inventory modules already match the candidate exactly. Remaining GUI, service, Search and Strings differences require scoped review against current replacements. |
| `integration/exhaustive-patchtrace-consolidation-20261119` | `087f50aae76f815dc013fb65e304eef8e21596c1` | #320, open draft against main | This task's published integration checkpoint; later locally reviewed work is not implied by this remote head. |
| `consolidation/patchtrace-reviewed-20261119` | `8d130aefe1be6e737cff1d90d2a5b1658d60a3a6` | #319, open against main | Advanced from original `a56ab13aaf9916fc12bea70ba1494075991b7f09`. The observed advance contains consolidation documentation and a shard cache-pin test expectation. The original recorded tip remains historical evidence. |

No active branch, tag or pull request was modified, deleted or closed by this census.

## New source review queue

### Completion branch, pull request #322

The source lineage is `bdc929ebd3c6aaa2563c758936beb315a10eeea0` → `32cc4b04cf1f5b9e69d1d0e8691db7083c7a45a7` → `2511301fc26bf0e039f54828959c422b4ff761a2`, based on main. Comparison against the frozen candidate identifies two missing modules, `pe_overview/cache_codec.py` and `pe_overview/cache_store.py`. Fourteen changed production or tool paths are still identical to that source branch's main baseline in the candidate: Winbindex acquisition, artifact inspection, CVE enrichment, enrichment storage, CSAF transport, N-way pair access and series, PE cache and signing view, BinDiff, BinExport checks, rz-diff, milestone notes and research-qualification scoring.

The source also changes `kbcorrelation/service.py`, `ui.py`, `ui_evidence.py` and `ui_inspection.py`, which already contain independent candidate changes. These require an interface-preserving port and focused regression controls. They must not be overwritten with the source snapshot. The source's own tests and claims have not yet been accepted as exact-candidate verification.

### Continuation branch, pull request #321

The principal source commit is `2042e24dc7f3eac265e0eb183c738527852b22cf`, followed by documentation at `f851d74d134a09cb9b12013d2c1adba1fde0c24f`. Many KB inventory contracts, CSV, fetch, store, service, CLI and Qt modules already have identical candidate blobs. This is stronger evidence than an absent merge commit for those exact paths, but does not establish whole-branch equivalence.

The new `intelligence/tools/admission.py` overlaps the candidate's independently reviewed shared tool snapshot. Its predicates must be compared with that replacement before deciding whether any unique admission behavior remains. Shared table accessibility additions, evidence/UI changes and the remaining Search, Strings and KB service differences remain explicitly open for scoped comparison. Restoring historical source verbatim could discard newer identity, ownership, cancellation and source-admission fixes.

## Limits and next inventory pass

This refresh is a census and source-difference checkpoint. It does not claim exhaustive semantic completion, full-suite success, native-tool qualification or assistive-technology acceptance. The older per-branch inventory continues to describe its original candidate; newly discovered references and the advanced #319 tip are tracked here without silently reusing old decisions. Final branch dispositions must be recomputed after selective recoveries are integrated and tied to their exact candidate, source commits, tests and review receipts.
