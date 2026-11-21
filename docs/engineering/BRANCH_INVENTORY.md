# PatchTrace branch inventory

## Current reference snapshot — cycle3, 21 November 2026 UTC

[Authoritative ledger](task-ledger.json) · [Complete census and comparison](evidence/cycle3-95fe/inventory-report.md).

Captured 04:55:49–04:57:48 UTC using all REST pages and empty terminal pages:364 branches; 338 PRs (82 open,172 merged, 84 closed-unmerged). Open PRs comprise66 drafts and16 non-drafts. PR #345–348 are unchanged open drafts at their recorded heads. Relative to recovered cycle95fe's354 branches:10 new, 0 moved, 0 missing. Relative to the explicit341-branch g30-at-PR #348 file:23 new, 0 moved, 0 missing. This snapshot predates the new cycle3 publication branch/PR and is not a current-count extrapolation.

The20 missing PR #346 documents/evidence files were recovered exactly; [blob receipt](evidence/cycle3-95fe/document-recovery.json). Original cycle95fe raw capture times are unavailable; inventory replay times are not substituted. Source census is not semantic supersession, branch deletion permission, or live ownership.

## Retained historical cycle95fe record

The authoritative task states remain in [task-ledger.json](task-ledger.json).
This page records discovery and the replay contract for `tools/branch_inventory.py`.
Earlier dated inventories remain historical evidence.

## Captured repository state

Captured on 20 November 2026 from GitHub REST collections and a complete Git fetch:

- Main: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.
- Review baseline: `67f7e08ea9bee61653f8ab5ad66048d3e7141810` (PR #344).
- 354 remote branches, including main; 353 topic branches.
- 334 pull requests: 78 open, 172 merged, 84 closed without a merge.
- 59 tags and 59 published prereleases.

These are frozen observations, not declarations that every branch is semantically
reviewed. Main remains unchanged and no branch is approved for deletion.

| Mechanical disposition | Topic branches | Meaning |
| --- | ---: | --- |
| Already integrated by ancestry | 128 | No commits beyond captured main |
| Contained in the unmerged candidate | 28 | History in PR #344, not main |
| Contained in another retained open stack | 6 | No main-integration claim |
| Patch equivalent; review required | 16 | Git patches match; semantics may have evolved |
| Partial recovery required | 6 | Existing explicit review disposition |
| Experimental or deferred | 7 | Existing scope/qualification restrictions |
| Historical documentation review | 6 | Unresolved relevance |
| Research-tool review required | 12 | Separate source/scope assessment |
| Unresolved | 144 | Further semantic review required |

181 branches have unmatched non-merge patches relative to the captured candidate.
This overlaps the dispositions and does not count merge-ready features. Every
topic branch has a recorded merge base with main.

## Reproducible replay contract

The tool reads complete local Git history and saved all-page PR metadata. It
never fetches, changes refs, closes PRs, authorizes deletion or infers semantic
equivalence from patch identity. Each row retains exact heads, merge bases,
divergence, unmatched/equivalent commit IDs, changed paths and PR relationships.

`--refs-tsv` replays exact branch names and commit IDs from a generated report
after live refs move. This snapshot contains a 162,564-character evidence field,
above Python's default CSV field limit. Replay must accept such quoted fields
within a **32 MiB UTF-8 input budget**, preserve embedded quotation/tab/newline
content, and restore the process CSV field limit after parsing or failure. The
byte budget applies before decoding, CSV materialization or per-row Git lookup.

Oversized, undecodable or invalid snapshots must fail without replacing prior
successful output. Strict commit resolution, duplicate-name refusal, complete
history and `delete_safe=no` remain unchanged.

## Selective donor recovery

PR #321 remains retained at `f851d74d134a09cb9b12013d2c1adba1fde0c24f`.
This cycle separately recovers registered table-header help and Evidence state
announcements. Broad Search-source/Strings-composition adoption requires further
review and would overwrite newer lifecycle fixes if applied wholesale.
