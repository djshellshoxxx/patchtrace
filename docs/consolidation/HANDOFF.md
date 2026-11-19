# PatchTrace continuation handoff — 2026-11-19

## Current position

Authoritative branch: `codex/patchtrace-completion-20261119-81e4` in `/workspace/scratch/81e4938f4a3a/PatchTrace`. Latest runtime/test checkpoint: `bc485a6644bee406fbfd92f4bfa47fdfbb4dbcbd`. Main is still `fdc2696c23bdbfe7668348f25e3b336ce33039f7`. **No main merge, tag, release or deployment has been performed by this continuation.**

Draft [PR #322](https://github.com/djshellshoxxx/patchtrace/pull/322) initially published `32cc4b04cf1f5b9e69d1d0e8691db7083c7a45a7`; its tree `e00ee281fa43744e892bbcf806e4b07a90c15e13` exactly matches local `3cde10ae`. The earlier checkpoint `bdc929eb` retains local `af8772bf`'s tree. Read the live PR head before every update or merge; subsequent source checkpoints may advance it.

## Active verification

The original all-856-file diagnostic froze runtime/tests at `520b524b` and stopped after 34/54 groups at the 256 MiB temporary-storage reserve. Its JUnit counters total 15,971 tests, four failures, four teardown errors and 86 skips. The original stopped manifest and every completed receipt are preserved. Separate continuation session 78011 executes only groups 35–54 from the identical source/test/tool fingerprint, using the relocated checkout `/workspace/scratch/81e4938f4a3a/pt-candidate` (documentation head `3cde10ae`). No aggregate pass is available. Later integrated repairs require their own final-head qualification.

Results and scripts: `/tmp/pt81-final-results`; interpreter: `/tmp/pt81-final-venv/bin/python`. The resumed manifest records the prior manifest hash and executes only original groups 35–54. The source fingerprint is `9ecd20b2dd0f83047551f8a9f85e28c34a34236f65d77b74e46483eecf33a2b2`. Do not edit that candidate, relabel prior failures or launch a duplicate aggregate run.

The initial failures are explained and preserved: two downstream identity pins corrected independently; AF_UNIX EPERM before product imports remains an environment acceptance block; a preview assertion mistakenly matched the public output path; global OS fault mocks leaked into immediate cleanup. Five affected test modules now scope their faults or compare the intended fields, preserving behavioral assertions. Group 40's original error remains recorded separately.

## Newly integrated evidence

| Slice | Source or integration | Completed checks |
| --- | --- | --- |
| Downstream contextual stage pin | `18ccab51` | Independent original-map reconstruction, cold/warm equivalence and exact domain-hash proof; 12 related tests pass. |
| Acquisition plan/product binding | Source `5131bd94`, merge `d7842532` | 5 red/2 green before repair; 255 affected passes; 55 integrated acquisition/lifecycle/identity passes. |
| Four-file harness repair | `f114eb96` | 85 passed/1 existing optional skip under both cleanup policies. |
| Symbol scanner fixture lifetime | `bc485a66` | Original teardown error reproduced; 30 affected passes. |

Earlier reviewed N-way, installer, parser, PE-cache, facts-eligibility, adapter text, CSAF, exact CVSS/time and attempt-history diagnostic slices remain integrated. Their overlapping test counts must not be summed. [Recovered work](RECOVERED_WORK.md), [test results](TEST_RESULTS.md), [feature matrix](FEATURE_MATRIX.md) and [security audit](SECURITY_AUDIT.md) identify exact scopes and limits.

## Current parallel follow-ups

- Attempt-retention repair: isolated branch `codex/patchtrace-attempt-retention-20261119-81e4`, worktree `/tmp/pt81-pair-recovery`. Malformed metadata, mixed NULL/BLOB IDs and engine-run cap protection are being corrected. No source is credited as integrated until review and commit acceptance. Preserve generic post-write uncertainty.
- Pydantic 2.14.2/core 2.50.2 qualification: isolated worker branch/environment; the current 2.13.5 pin falls in four upstream advisory ranges. Relevant production APIs have not been found in a bounded search. Do not change shared dependencies or infer full unreachability.
- Dependency/CI review: queued jobs have no established scheduling cause. Resolved Python and native Qt advisory coverage are separate. PySide6's currently queried index lists 6.12.0 as latest; availability of a safe replacement must be evidenced.

## Hosted promotion gate

Initial PR head has five queued workflow runs and 21 substantive jobs with no assigned runner or executed steps. Existing main/other-PR success does not qualify this head. Required evidence includes Linux/Windows QA, all repeated Qt legs, downstream packages/smokes, and applicable native/live workflows. Read actual BinDiff provision/live JSON because advisory Windows steps may report blocked despite a successful job.

The available ready-for-review connector uses GraphQL and is not permitted by the REST-only instruction. After a concrete head is qualified, a new non-draft PR on a new branch at the same exact commit is an allowed REST route; qualify its applicable checks, merge with expected head SHA and `[no release]`, then verify main before closing the superseded draft. Do not use unprotected-main status to bypass the owner's all-jobs-green/no-blocker gate.

## Durable evidence and next actions

1. Finish the remaining original diagnostic groups and archive their actual manifests/logs/JUnit. Preserve the stopped 34-group archive independently.
2. Review and integrate only passing compatible retention/dependency follow-ups; keep their exact source and dependency identities distinct from the running diagnostic.
3. Publish accepted source using REST blob/tree equality and an expected-ref guard. Preserve all source branches and original failures.
4. Refresh main and all final-head checks; resolve actual code failures. Merge only when qualified and verify the resulting tree.
5. Continue semantic recovery and unresolved behavior within available execution resources.

[Phase 5 evidence](evidence/continuation-phase5-20261119.zip): 58 verified payloads, 135,694 bytes, SHA-256 `a12a4571ebbbf8e15aa1fe70b751c21f496563ac35aede6fbd6711a826ca7d19`.
[Stopped 34-group evidence](evidence/candidate-stopped34-20261119.zip): 71 verified payloads, 364,804 bytes, SHA-256 `608d65b6bcaa51a705b78499b44be4ff83b428de406dbdff89a2e806881dba81`.
[Stage identity review](evidence/contextual-stage-key-review-20261119.zip): nine verified payloads, SHA-256 `51af1e41cb11765d3191edbdf09c0472b4575a58d6635c4fa01b2e057a161e1e`.

The [frozen inventory](BRANCH_INVENTORY.md) contains 320 heads/309 PR records; 139 branches remain for semantic review. Later PR320/321/322 and narrow recovered contributions do not silently change that census. Forced strings-export ownership races, complete index provenance, native trust/packages, manual/accessibility acceptance, real adapter compatibility and independent L1/L2/L3 results remain open. Never score `facts: unverified` or turn an unrun/blocked analysis into a negative result. See [remaining work](REMAINING_WORK.md) and [main promotion log](MAIN_MERGE_LOG.md).
