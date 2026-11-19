# PatchTrace continuation handoff — 2026-11-19

## Current position

Authoritative branch: `codex/patchtrace-completion-20261119-81e4`. Accepted source/test checkpoint: `5aebd98f362e7cc5f01a0c96878860b04835cea4`, tree `1b4fdd985ccea86e436172ee52ad3b5ab51b8877`. It adds a test-only backup-fixture correction after runtime/dependency integration `5208c758`; the current source has 859 tracked test files. Evidence checkpoint `e430309ac9c9d1ea7a5b271af68df5a5113ea1bb` preserves the Phase 6 archives and advisory report. Main remains `fdc2696c23bdbfe7668348f25e3b336ce33039f7` at the last observation. **No main merge, tag, release or deployment has been performed by this continuation.**

Draft [PR #322](https://github.com/djshellshoxxx/patchtrace/pull/322) last published `2511301f`, tree `f2366be08a4951880692b56ecbbefbe92a3611dd`, exactly equal to local `7093ee68`: 78 changed files, ahead 3/behind 0. That publication predates retention/Pydantic integration and the final fixture correction. Initial publication `32cc4b04` remains recorded separately. Refresh actual refs before any update or merge; tree equality does not establish CI acceptance.

## Final frozen diagnostic

All **856 original files reached terminal pytest results through 59 processes** on frozen runtime/tests `520b524b` (documentation head `3cde10ae`), using Pydantic 2.13.5. Actual pytest summaries: **23,110 passed, 139 skipped, 6 xfailed, 4 failed and 8 teardown errors**. The diagnostic **FAILED**. JUnit reports 23,259 tests, 4 failures, 8 errors and 145 skips including xfails; teardown errors must not be subtracted from pytest passes.

Sessions 74806 and 78011 ended at storage reserve after groups 1–34 and 35–45. Tail 46–50 passed, then original group 51 ended SIGKILL/-9 without summary/JUnit. Eight final subpartitions plus an isolated dense case reached the remaining files. All seven residual-performance cases pass split 6+1; all 1,396 collected node IDs in the final four groups exactly match the terminal XML node-ID multiset, without omissions or duplicates. That later success does not establish the original kill's cause.

The source/test/tool fingerprint remains `9ecd20b2dd0f83047551f8a9f85e28c34a34236f65d77b74e46483eecf33a2b2`. The [complete diagnostic archive](evidence/candidate-partitioned-20261119.zip) preserves every original outcome and chained manifest. Full original-file coverage is not an unsplit pass or qualification of the newer 859-file source and Pydantic 2.14.2.

The frozen failures remain explicit: two downstream identity pins, an AF_UNIX constructor EPERM before product imports, a path-sensitive preview assertion and eight teardown errors caused by OS fault mocks outliving their intended operations. The pins and fixture lifetimes have separate reviewed repairs; the external AF_UNIX acceptance block remains unchanged. No historical failure becomes a pass through later correction.

## Accepted follow-ups

| Slice | Source / local integration | Completed evidence |
| --- | --- | --- |
| Acquisition plan/product binding | `5131bd94` / `d7842532` | 255 affected passes; 55 integrated acquisition/lifecycle/identity passes. Full index proposal/window/source-entry persistence remains open. |
| Earlier harness and stage identities | `18ccab51`, `f114eb96`, `bc485a66` | 12 stage checks; 85 passed/1 existing optional skip under both cleanup policies; 30 symbol/backend passes. |
| Attempt-retention integrity | `74d5f4bb` / `153f6cea` | 26 red/6 green initially; 175 final passes across 10 files and independent NULL/BLOB preservation replay. [Batch 6](RECOVERY_BATCH_6.md). |
| Pydantic 2.14.2 / core 2.50.2 | `b28f6971` / `5208c758` | 2,903 passes and 1 existing strict xfail across 79 files; 301 schemas and generated CSAF table unchanged across 16 generators. [Qualification](PYDANTIC_SECURITY_UPGRADE_20261119.md). |
| Integrated retention/acquisition/cache/identity | `5208c758` | 254 passes across four groups on actual new dependency versions; configured Ruff and pip check pass. |
| Backup-test fault lifetime | `5aebd98f` | Current-source reproduction 3 passed/3 teardown errors; 41 affected passes in 2.62s after test-only correction. [Harness report](TEST_HARNESS_FIXES_20261119.md). |

These selections overlap; do not sum them into a combined suite result. Retention preserves indeterminate original records, honors explicit protection and counts NULL-ID bytes against the cap. It does not make publication atomic or establish universal hostile-database budgets. Generic post-write uncertainty remains valid. Earlier N-way, installer, parser, PE-cache, facts-eligibility, adapter text, CSAF and CVE integrity slices remain accepted with their recorded limits.

## Dependency and scanner findings

Both actual 15-package Linux runtime/search/rules graphs were audited with PyPI and OSV; all four runs returned zero findings. Direct API cross-checks also miss four upstream Pydantic advisories affecting the old 2.13.5 pin. Qualified 2.14.2 clears those four assessed ranges. Zero automated findings are a demonstrated lookup coverage gap, not a clean-security conclusion. Original shared/frozen environments retained 2.13.5; the source/root private environments were separately verified on 2.14.2/core 2.50.2.

Qt 6.12.0 remains in seven assessed native-component advisory ranges. Official PyPI supplied no PySide6/shiboken6 6.12.1 files at retrieval; 6.11.3 is not a complete fix. A bounded source scan does not establish full unreachability or a frozen-artifact SBOM. [Advisory audit](DEPENDENCY_ADVISORY_AUDIT_20261119.md) preserves exact graphs, primary findings, retrieval limits and the 26-file evidence manifest. Native Qt remediation remains open.

The fresh source scan at `5208c758` has 64 findings, with no normalized path/rule/message additions or removals against frozen `520b524b`. A separate tools expansion has 70 findings requiring review; the original source classifications do not classify all 134 combined results. [Static scope](STATIC_AUDIT.md).

## Hosted promotion gate

At published `2511301f`, QA `44522261517`, rz `44522261469`, native PR `44522261551`, native push `44522248460` and BinDiff `44522261617` were queued. Earlier initial-head jobs had no runner or executed steps; the scheduling cause is unestablished. Existing main/other-PR success does not qualify these heads. Require actual final-head Linux/Windows QA, repeated Qt, packages/smokes and applicable native/live checks. Read BinDiff provision/live JSON because advisory Windows steps can report blocked despite a successful job.

The available ready-for-review connector uses GraphQL and cannot be used under the REST-only rule. After a concrete head is qualified and blockers resolved, an allowed route is a new non-draft PR on a new branch at that exact commit, its applicable checks, then a normal expected-head REST merge with `[no release]`. Verify resulting main before closing the superseded draft. Unprotected-main status does not bypass the owner's all-jobs-green/no-blocker gate.

## Evidence and next actions

The verified [retention/integrated](evidence/attempt-retention-20261119.zip), [Pydantic](evidence/pydantic-upgrade-20261119.zip), [advisory](evidence/dependency-advisory-audit-20261119.zip), [complete diagnostic](evidence/candidate-partitioned-20261119.zip) and [backup-test correction](evidence/backup-scandir-harness-20261119.zip) archives contain 41/82/27/132/6 payloads plus their manifests. [TEST_RESULTS.md](TEST_RESULTS.md) records exact hashes, sizes and scopes. Earlier archives and original red receipts remain preserved.

1. Publish accepted source with exact local/remote tree equality and an expected-ref guard; refresh all actual final-head gates.
2. Qualify combined current source/dependencies separately from the failed frozen diagnostic and focused slices.
3. Resolve native Qt and other blocking findings, then perform only a qualified head-guarded main merge and verify its tree.
4. Continue semantic recovery, full index provenance, native trust/packages, manual/accessibility acceptance and separate L1/L2/L3 evidence obligations.

Forced strings-export recovery and build-tool HTTPS redirect triage are ongoing separate work; they are excluded from this checkpoint's accepted-source claims. The [frozen census](BRANCH_INVENTORY.md) remains 320 heads/309 PR records, including 139 semantic-review dispositions. Narrow recoveries do not close their parent branches. Never score `facts: unverified` or turn unrun/blocked work into a negative result. [Remaining work](REMAINING_WORK.md) and [promotion log](MAIN_MERGE_LOG.md).
