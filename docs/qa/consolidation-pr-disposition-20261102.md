# PatchTrace consolidation disposition

Reviewed 2026-11-02 23:07:40 UTC. This is a read-only disposition of exact PR heads and retained changes; no PR was closed and no source was changed.

## Decision and counts

**The published draft contains the commit histories of 16 existing open PRs. Two additional PRs, #90 and #158, have all of their unique PR-specific changes accounted for without their heads being ancestors. The other 32 existing PRs are not certified for retirement by this audit.**

The live inventory used here contained **50 open PRs before #163 was created**. [PR #163](https://github.com/djshellshoxxx/patchtrace/pull/163) is now the additional integration wrapper, giving **51 open PRs**. It remains **open, draft, and unmerged**. The 16 plus 2 are candidates for disposition **after the integration lands**; these counts do not state that they have already landed or that all product acceptance gates have passed.

| Disposition of the 50 predecessor PRs | Count |
|---|---:|
| Exact remote head equal to or an ancestor of an actual integration parent | 16 |
| Unique changes retained, without ancestry absorption: #90 and #158 | 2 |
| No complete retirement certification in this audit | 32 |

Keep the original remote refs. Recheck the exact heads and actual main landing before any closure.

## Immutable identities and publication check

The frozen local review target was commit `f2b7d981008dea25ac09ea82734da64a1dccb96d`, tree `985078aed0feb4f909690d6082ec4940540cda17`, with local parent `4cb829f3f0790c565f8b8ea47d47109d48e418aa`.

The independently fetched published [commit 6e82fd70f315b99c6798a42c9061a1424a02933e](https://github.com/djshellshoxxx/patchtrace/commit/6e82fd70f315b99c6798a42c9061a1424a02933e) has tree `2e7cd8e258821f50d776ca3b3a4caef594e2a417` and the following **five actual remote parents**, in order:

| Parent | Exact commit |
|---|---|
| main | `ce8c65bf41541cf6adb52289d2a530ce2817a53a` |
| PR #159 | `56374f867594dd923383c91ea71970cb7d24d173` |
| PR #160 | `ca411e77f43a9fd95ca5e0bcc7d2b58071ccae37` |
| PR #161 | `9b9452b4677ee3809a6e0f43d49567a8d15602e6` |
| PR #162 | `f1a55c4cf21ddb0dea243bd417b74f86caaed142` |

An independent complete recursive-tree comparison found exactly five differences between the frozen local tree and the published tree, all **new QA documents**:

- `docs/qa/consolidation-final-validation-20261102.md`
- `docs/qa/consolidation-native-gate-evidence-20261102.json`
- `docs/qa/consolidation-native-gate-triage-20261102.md`
- `docs/qa/consolidation-protocol-independent-review-20261102.md`
- `docs/qa/consolidation-replay-independent-review-20261102.md`

Every previously present path retains its blob ID and mode. Source, tests, tools, workflows, and schemas are unchanged by publication. The content conclusions below therefore apply to the published head as well as the frozen local review target.

## Exact ancestry: 16 PRs

The GitHub Git Commit API supplied the actual parent graph. Remote parent chains were followed to six locally available anchors with complete successful `git rev-list` walks. All 50 live remote PR-head SHAs were checked against those exact reachable commit IDs. There is **no unresolved graph frontier**. Equal trees and patch similarity were not used as ancestry evidence.

| PR | Exact current remote head | Contained via actual parent |
|---|---|---|
| [#136](https://github.com/djshellshoxxx/patchtrace/pull/136) | `2fcd627e52a6d784d5c2e5b4ea8105e90b8589b3` | #159 |
| [#139](https://github.com/djshellshoxxx/patchtrace/pull/139) | `c04ad725551fe8daa139b37aa2cdf46d6d161b65` | #159 |
| [#140](https://github.com/djshellshoxxx/patchtrace/pull/140) | `fb91cff6d91c77a2c539c896b670d81180dcc637` | #159 |
| [#141](https://github.com/djshellshoxxx/patchtrace/pull/141) | `d76d23372acef4049115e9ae176acbeb538a82e5` | #159 |
| [#142](https://github.com/djshellshoxxx/patchtrace/pull/142) | `a4d1e6a38c34d1952584aa65d7f5f908c45547b3` | #159 |
| [#143](https://github.com/djshellshoxxx/patchtrace/pull/143) | `a7f13e13ffb512f8e9621753a0ae162d78942f3b` | #159 |
| [#144](https://github.com/djshellshoxxx/patchtrace/pull/144) | `745e93426a16e0a91a961b6e0bbcb71be69f2a7e` | #159 |
| [#147](https://github.com/djshellshoxxx/patchtrace/pull/147) | `8f4c4a2e0021d424d403317c6780b6db026ad76b` | #159 |
| [#148](https://github.com/djshellshoxxx/patchtrace/pull/148) | `c3868d8335a8f32f676905032dc1a6d0e9f22fd6` | #159 |
| [#152](https://github.com/djshellshoxxx/patchtrace/pull/152) | `0130bf81e2fe3154f30af7b68a0e6ab197946040` | #159 |
| [#154](https://github.com/djshellshoxxx/patchtrace/pull/154) | `f27d23a80ee49573ccca54cdf036427f57eebb2a` | #161 |
| [#157](https://github.com/djshellshoxxx/patchtrace/pull/157) | `dac9b89a297f428bdcf364b4be37a448a5b2ce4e` | #160 |
| [#159](https://github.com/djshellshoxxx/patchtrace/pull/159) | `56374f867594dd923383c91ea71970cb7d24d173` | #159 |
| [#160](https://github.com/djshellshoxxx/patchtrace/pull/160) | `ca411e77f43a9fd95ca5e0bcc7d2b58071ccae37` | #160 |
| [#161](https://github.com/djshellshoxxx/patchtrace/pull/161) | `9b9452b4677ee3809a6e0f43d49567a8d15602e6` | #161 |
| [#162](https://github.com/djshellshoxxx/patchtrace/pull/162) | `f1a55c4cf21ddb0dea243bd417b74f86caaed142` | #162 |

Grouped for the integration PR body:

- **Via #159:** #136, #139, #140, #141, #142, #143, #144, #147, #148, #152, #159 — 11.
- **Via #160:** #157, #160 — 2.
- **Via #161:** #154, #161 — 2.
- **Via #162:** #162 — 1.
- **Via main:** no currently open predecessor head. #153 is already merged and closed, and is outside the 50-open-PR inventory.

Ancestry establishes retained history. It does not, by itself, prove every merge resolution preserves every feature or that native acceptance is complete. Those questions belong to the separate source reviews and QA receipts. Stacked PRs may target a branch other than main; their actual base names and full head mappings are retained in the accompanying JSON.

## Content retained without graph absorption

### #158 — mixed native/synthetic revision regression

Remote head: `e1b79e048d3963d747bc9f07448b039a250180ed`. It is **not** reachable from any of the five actual parents.

Both changed paths were reviewed:

- `src/patchtrace/kbcorrelation/index.py`: the current-main successor includes active synthetic and native documents in the release-month ambiguity group after scope selection. It requires a native member and an ambiguous revision before disputing missing remediation edges. The native-only exclusion that #158 removed is absent. This retains the correction with the newer source/scope safeguards reviewed in the independent combined-merge receipt.
- `tests/test_kbc_msrc_review_findings.py`: the **19 added lines** containing `test_mixed_native_and_synthetic_revisions_dispute_withdrawn_remediation` match the actual #158 patch **verbatim** in the frozen final file. This is the unique entirely empty synthetic-document regression, distinct from the other retained synthetic revision case.

Final blobs:

| Path | Final blob |
|---|---|
| `src/patchtrace/kbcorrelation/index.py` | `007b72fc8f201335868b182006574e1f3db0d318` |
| `tests/test_kbc_msrc_review_findings.py` | `e7dffea5e9b373768a1d90d5643b459c8f429a3a` |

**Post-landing disposition:** eligible to close as superseded with explicit provenance to #153 and #163. Do not describe #158's head as merged or graph-absorbed.

### #90 — canonical test collection repair and historical handoff

Remote head: `941c617b6854291e2448cad6d7d5710a24a8543d`. It is **not** reachable from any of the five actual parents.

All five PR-specific changed paths are accounted for:

| Path | Retained effect |
|---|---|
| `tests/test_unified_fixture_gate_u6-2.py` | Deleted duplicate remains absent. |
| `tests/test_unified_fixture_gate_u6.py` | Exact PR blob `3ae05b9cc009502453333236dbb371239e59616e`. |
| `tests/test_unified_synthetic_pe-2.py` | Deleted duplicate remains absent. |
| `tests/test_unified_synthetic_pe.py` | The `HealthCheck` import and targeted `function_scoped_fixture` suppression remain. The later split import and keyword `@given(timestamp=..., padding=...)` preserve the intended binding. |
| `tests/unified_support/fixture-gaps.md` | All **36 added lines** of the October 16 continuation match verbatim. A preceding qualifier explicitly marks the branch/verification statements as historical and refers readers to the November 2 status. |

The historical continuation does not establish native or live G-U gate acceptance; its limitation statements remain present. The current synthetic test and handoff blobs are `67009dde67af68f48d1c5460fffa95456b368ed8` and `45f4272112e5515afdb35b6a5b799010bd6a2bdf`, respectively.

**Post-landing disposition:** eligible to close as superseded by the retained canonical tests and provenance document in #163. Do not describe #90's head as merged or graph-absorbed.

## Remaining 32 predecessor PRs

The following focused path comparisons provide positive reasons not to retire a whole PR merely because some of its content appears in the combined tree. Counts describe its actual changed paths at the observed head, compared with the frozen final tree.

| PR | Exact files | Different files | Missing files | Disposition evidence |
|---|---:|---:|---:|---|
| [#61](https://github.com/djshellshoxxx/patchtrace/pull/61) | 0 | 4 | 18 | 18 added skill/spec/license files absent; 4 other paths differ. Retain. |
| [#67](https://github.com/djshellshoxxx/patchtrace/pull/67) | 8 | 11 | 0 | 8 changed files identical and 11 differ. Complete semantic equivalence not certified. |
| [#70](https://github.com/djshellshoxxx/patchtrace/pull/70) | 0 | 1 | 24 | 24 help-topic additions absent and 1 path differs. Retain. |
| [#72](https://github.com/djshellshoxxx/patchtrace/pull/72) | 0 | 0 | 10 | All 10 added panel specifications/build-plan paths absent. Retain. |
| [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) | 2 | 4 | 1 | 2 changed files identical; 4 differ; docs/handoff/ue-r3-retain-decompiled-20261016.md absent. Retain. |
| [#94](https://github.com/djshellshoxxx/patchtrace/pull/94) | 0 | 1 | 0 | The best-of-three sort timing/determinism change remains absent; final test still performs a single measured sort. Retain. |
| [#98](https://github.com/djshellshoxxx/patchtrace/pull/98) | 6 | 1 | 0 | All 6 wiki source pages are byte-identical. README differs; its PR-specific delta was not certified in this bounded disposition. No closure recommendation. |
| [#100](https://github.com/djshellshoxxx/patchtrace/pull/100) | 27 | 25 | 0 | 27 changed files identical and 25 differ. Whole-PR semantic equivalence not certified. |
| [#102](https://github.com/djshellshoxxx/patchtrace/pull/102) | 6 | 31 | 3 | 6 changed files identical, 31 differ, and NOTES.md, SECURITY_REVIEW.md, SPEC_STATUS.md are absent. Selected Windows resources were integrated; the original PR is not fully certified. |

#98's six wiki pages are exact copies, but this bounded report does not certify its differing README delta or make claims about publishing the GitHub wiki. This is deliberately left as an incomplete retirement assessment.

These additional **23 PRs** were included in the exact ancestry inventory, but not subjected to a complete PR-specific content-equivalence audit in this bounded task:

[#68](https://github.com/djshellshoxxx/patchtrace/pull/68), [#69](https://github.com/djshellshoxxx/patchtrace/pull/69), [#71](https://github.com/djshellshoxxx/patchtrace/pull/71), [#78](https://github.com/djshellshoxxx/patchtrace/pull/78), [#79](https://github.com/djshellshoxxx/patchtrace/pull/79), [#82](https://github.com/djshellshoxxx/patchtrace/pull/82), [#85](https://github.com/djshellshoxxx/patchtrace/pull/85), [#125](https://github.com/djshellshoxxx/patchtrace/pull/125), [#126](https://github.com/djshellshoxxx/patchtrace/pull/126), [#127](https://github.com/djshellshoxxx/patchtrace/pull/127), [#128](https://github.com/djshellshoxxx/patchtrace/pull/128), [#129](https://github.com/djshellshoxxx/patchtrace/pull/129), [#130](https://github.com/djshellshoxxx/patchtrace/pull/130), [#131](https://github.com/djshellshoxxx/patchtrace/pull/131), [#132](https://github.com/djshellshoxxx/patchtrace/pull/132), [#133](https://github.com/djshellshoxxx/patchtrace/pull/133), [#134](https://github.com/djshellshoxxx/patchtrace/pull/134), [#135](https://github.com/djshellshoxxx/patchtrace/pull/135), [#137](https://github.com/djshellshoxxx/patchtrace/pull/137), [#138](https://github.com/djshellshoxxx/patchtrace/pull/138), [#145](https://github.com/djshellshoxxx/patchtrace/pull/145), [#146](https://github.com/djshellshoxxx/patchtrace/pull/146), [#150](https://github.com/djshellshoxxx/patchtrace/pull/150).

Preserve their PRs and refs. The accompanying JSON records every exact head, title, base, ancestry result, and the available changed-path comparisons, including all missing paths.

## Evidence and practical limits

- The ancestry inputs are the live GitHub PR inventory and exact Git Commit API records; six complete local DAG anchors close the graph. The accompanying JSON preserves the remote graph and the contained-head results for each anchor.
- The content checks above read immutable `git show` and tree objects. No pytest run, native program, compared target, source edit, or remote mutation was performed for this disposition.
- The historical comparison files and prior independent review receipts supply context; this report's final-tree comparisons supersede earlier main-only comparisons where the final candidate now retains additional content.
- Full-suite results and native Windows acceptance are separate gates. Rizin/corpus quarantine remains outside this disposition and must not be relabeled as passed because history or synthetic fixtures were consolidated.
- This report is **not a closure action**. The integration PR is still unmerged. Retire predecessors only after the reviewed integration lands, preserving original refs and linking the exact superseding commit.

Machine-readable companion: `/tmp/patchtrace-consolidation-disposition-20261102.json`.
