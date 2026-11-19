# Complete remote census — 2026-11-19

**Observed 2026-11-19 11:22:32 UTC through 2026-11-19 11:22:34 UTC.** Repository: [djshellshoxxx/PatchTrace](https://github.com/djshellshoxxx/PatchTrace). Read-only GET collection; no remote changes.

## Final counts

| Collection | Count | Page sizes through empty page |
| --- | ---: | --- |
| Branches, including main | **322** | 100 / 100 / 100 / 22 / 0 |
| Topic branches | **321** | Branch collection minus main |
| Distinct commit heads, including main | **321** | 320 distinct topic heads |
| Open PRs | **55** | 55 / 0 |
| Open non-PR issues | **10** | Issue endpoint 65 / 0, minus 55 PR rows |

No duplicate branch names or PR/issue numbers were returned. Every open PR head SHA matches its branch. The issue endpoint's PR set exactly matches the open-PR collection. The only repeated branch head is `726a371ab34d4589b0456d059865ade6b82fac88`, shared by `access-test-noprefix` and `claude/access-test-1791773355`.

Main remains **`fdc2696c23bdbfe7668348f25e3b336ce33039f7`**. Open non-PR issues: **#35, #36, #39, #104, #105, #116, #118, #120, #121, #255**.

## Recommended current topic tally

| Disposition | Current branches | Relationship to frozen318 snapshot |
| --- | ---: | --- |
| Already integrated | **144** | All exact heads unchanged: 128 ancestry-contained + 16 patch-equivalent |
| Dependency-blocked | **11** | All exact heads unchanged |
| Requires review / retained active work | **166** | 161 unchanged historical heads + updated PR318 + four added refs |
| **Total topics** | **321** | 317 historical topics + four additions |

“Requires review / retained active work” is an unmerged disposition, not a claim that no review has occurred. The historical162 heads have focal dispositions: 116 prior exact-head receipts +46 fresh receipts (32 source/tooling/research,14docs). That historical coverage does not prove exhaustive every-commit approval or automatically qualify later source movement.

**No new branch is counted integrated.** The checkpoint branch's earlier main-equal state was superseded by its new source commit before this census.

## Four added refs

| Branch | Current SHA | PR | Current disposition |
| --- | --- | --- | --- |
| `codex/patchtrace-checkpoint-20261119-81e4` | `bdc929ebd3c6aaa2563c758936beb315a10eeea0` | No PR | ACTIVE EXTERNAL CHECKPOINT |
| `consolidation/patchtrace-continuation-20261119` | `976dddfbbcdf9a320e48813d8cf2c3c6540aac81` | PR321 | ACTIVE DOCUMENTATION CHECKPOINT |
| `consolidation/patchtrace-reviewed-20261119` | `a56ab13aaf9916fc12bea70ba1494075991b7f09` | PR319 | ACTIVE REVIEWED CORE CANDIDATE |
| `integration/exhaustive-patchtrace-consolidation-20261119` | `bc7eb6328b477e2ff19cfe36317279eaf5856fb6` | PR320 | ACTIVE EXTERNAL INTEGRATION |

The PR321 head above is the published documentation-only checkpoint on PR319a56. Later local assembled recoveries are not implied published by this census. The PR320 and external source checkpoint focal review is pinned separately in `external-branch-focal-review-20261119.json`.

## One moved historical ref; no removals

`codex/patchtrace-stabilization-20261119` / **PR318** moved from
`2e301a74649e59e27b19a83bc283d646109ccd09` to
`c4ace2088ce8dc9ce78a0bf3036b81096accbdb5`.

It remains an unmerged broad stabilization candidate. Its old exact-head receipt must not be silently attributed to c4. All **317 other existing branch refs**, including main, retained their frozen head. No branch disappeared.

## Evidence boundaries

The frozen318-branch report remains intact: **144 integrated +11 dependency-blocked +162 requiring review =317 topics**. Classification reuse comes from its final `post-foundation-residue.json`, which includes patch-equivalence/dependency reconciliation; the preliminary ancestry-only file is not the final disposition map.

The historical merge simulations remain 164 conflicted /153 clean /0 errors. This census does not claim a fresh merge simulation for all322 branches. External current-head CI and earlier author-reported test results remain separate in the focal receipt. No source was executed, edited or merged during this census.

This is a timestamped paginated observation, not an atomic lock. Later remote movement belongs in another receipt.

## Files

- `final-remote-census-raw-20261119.json`: full parsed REST page responses, URLs and observation window.
- `final-remote-census-20261119.json`: all322 normalized branch rows,55PRs,10issues, current classifications, source hashes and new/moved-ref proof.
- `final-remote-census-delta-20261119.json`: exact delta from the frozen post-foundation snapshot.
- `final-remote-census-manifest-20261119.json`: byte counts and SHA-256 hashes.
