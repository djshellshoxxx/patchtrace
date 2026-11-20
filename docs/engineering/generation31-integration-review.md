# Independent generation 31 integration review

## Decision

**The bounded source integration is accepted. No blocking source integration finding was found. Two low-severity documentation corrections are required before the final handoff is presented as current.**

Reviewed commit: `a024f9ece556daa6e4f095c52fe9a8cc4c31ce28`.
Complete tree: `1eb4f2197e22c9e46d25bded163ee241835572e6`.
Starting candidate: `6c8b33b851a22fb16d39b31693922359cd34ad12`.

The reviewer did not implement or integrate these repairs. A separate evidence worker independently checked the saved receipts. No tests were run, no checkout files were changed, and no remote state was modified. The coordinator's unsplit full suite was already running on the frozen source.

## Source integration

All 21 explicit Git blob comparisons passed:

- Receipt production and maintained test blobs match retained donor `0f63e0dc`.
- Search source, test and contract match independently reviewed `5d06ec7d`.
- Strings source, tests and contracts match independently reviewed `cf71c457`; the recovered helper and its maintained tests also match donor `2042e24d`.
- Existing Strings export, owned publication, acquisition guards, ToolStore, dependency declarations and QA workflow match generation 29 unchanged.

Only eight code/test/tool paths differ from generation 29: the four production/tool files and four maintained test files described in the handoff. The final `a024f9ec` checkpoint changes no runtime, test or tool content after `c0108749`.

The receipt plan conflict was resolved without dropping intervening requirements: the entire generation-29 plan remains an unchanged prefix, followed by the recovered source-identity amendment. No unresolved conflict remains. The integration does not import broad donor composition or Search wiring, change comparison algorithms, or alter export publication guarantees.

## Saved evidence and inventory

The evidence worker verified 26 payload hashes, 21 recorded source-file hashes, five compressed files, and 13 JUnit files. Six peer source mappings also match and overlap the source checks rather than constituting six more distinct checks. Reported failures, skips and passing counts match their saved records.

The Strings implementation selections are disjoint at 41 plus 61 cases. The recent input-guard selections are disjoint at 33 plus 63 cases. Receipt baseline remains 18 failed/11 passed; recovery remains 140 passed/one optional dependency skip, with a later separate pass for that skipped control. Search peer selections are disjoint from each other, while their main selection repeats the implementation suite.

The census contains 341 distinct branches, 330 distinct PR numbers and 59 tags. PR states reconcile to 74 open, 84 closed-unmerged and 172 merged. Classification totals reconcile exactly: 146 contained by ancestry, 16 patch-equivalent with unreviewed semantics, one specifically equivalent, 176 unknown, and two baseline/candidate rows. All 671 recorded branch and PR SHA entries resolve to commit objects. These checks support object availability and count accuracy, not full semantic review.

All eight local Markdown links in newly added Markdown files resolve. The explicit limits on pending full/native/Windows/release qualification remain intact.

## Required documentation corrections

### G31-DOC-1 — Strings peer overlap

The handoff table and task-ledger summary say all 97 Strings peer tests overlap earlier tests. Exact node comparison instead finds **87 overlapping cases and 10 additional existing GUI cases** from `tests/test_ui_strings_run.py`. The two peer history controls are separately additional.

Use: “The independent selection contains 87 overlapping tests and 10 additional existing GUI tests, plus two separate history controls.” This corrects a conservative undercount of distinct coverage; it is not an inflated pass total or product defect. Continue keeping all of these results separate from full-suite acceptance.

### G31-DOC-2 — Durable census replay inputs

The census report lists `patchtrace-remote-inventory.json`, `patchtrace-all-prs.json` and `build-patchtrace-inventory.py` as reproducible evidence, but none is present in the committed tree. The main census retains only ten recent release records while recording that 59 releases were observed.

The reviewer prepared `generation31-census-replay.zip` from the unchanged existing scratch inputs. It contains all 59 raw release records, all 330 PR metadata records, the original read-only generator, and a SHA-256 manifest. Archive size: **147,135 bytes**. SHA-256: `e32f5dc05e45d3247b49a77bc2bf5bfe664a6453747b446347434ba7a775085b`.

Persist and link that bundle in the publication worktree after preserving the frozen test source. State that the main JSON stores ten recent release details and the bundle retains the complete observed release input. The generator retains its original absolute workspace paths, so replay in a different environment requires adjusting those paths. The later all-PR-head fetch is separately recorded in the current census.

## Artifacts and limits

Detailed checks are retained in `generation31-source-comparisons.json`, `generation31-document-checks.json`, `generation31-evidence-check.json`, `generation31-census-replay-check.json` and `generation31-integration-review.json`. The coordinator confirmed both documentation corrections and plans to apply them in a separate publication worktree, keeping the running full-suite checkout unchanged.

This review does not qualify the complete inherited product, live adapters, native Windows, package trust, Qt advisories, empirical accuracy, or the unresolved Linux forced-export race. It does not authorize a main merge while required checks or blocking findings remain unresolved. The active aggregate result and final-source hosted gates remain separate evidence.
