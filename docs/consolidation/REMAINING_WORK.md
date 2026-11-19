# Remaining continuation work — 2026-11-19

The reviewed N-way, installer-receipt, parser, PE-cache, facts-eligibility, adapter-text and CSAF slices are integrated
locally on `codex/patchtrace-completion-20261119-81e4`, recorded through
Phase 7 source `8efb7a45`, with 866 tracked test files. This includes reviewed
CVE numeric/time, digest-fixture, acquisition, history/retention, Pydantic,
test-fixture, strings publication, sampler/JUnit, HTTPS and KEV changes. These
slices do not complete the feature backlog or main qualification.
The [feature matrix](FEATURE_MATRIX.md) identifies implemented scope;
[test results](TEST_RESULTS.md) separates completed evidence from pending gates.

## Finish the current candidate

- [x] Integrate history diagnostic source `254190a0` through `520b524b`; final 81 passed in 37.33s, with post-write uncertainty stated truthfully.
- [x] Review the contextual ROUND constant and correct its sole digest golden at `70b82275`; 9 passed in 1.85s.
- [x] Preserve the verified [history evidence](evidence/history-diagnostic-20261119.zip), including original red and independent post-write failures.
- [x] Reach and archive all 856 original diagnostic files through 59 terminal processes; the frozen diagnostic FAILED. Preserve both storage-reserve stops, original group-51 kill and all original failures/errors.
- [x] Correct bounded attempt-retention admission, invalid IDs, explicit protection and NULL-ID cap accounting at `74d5f4bb` / `153f6cea`; 175 affected passes. Generic post-write uncertainty remains.

- [x] Integrate facts-eligibility source `d87af037` through `69fa6b8b`: 11 base failures, 33 focused passes and 140 final scoped/caller passes. Retain the intermediate 106-pass/1-fail caller receipt and its fixture-metadata correction.
- [x] Accept and integrate CVE source `93c9e395` through `a4d6dd9b`: exact-tenth, caller-context, UTC-boundary and CLI controls; final 124 passed in 6.70s.
- [ ] Complete qualification of `8efb7a45`. Its running 111-group diagnostic collected 866 files/23,529 nodes; group 001 has 181 passes/70 orchestration setup errors, preserved before the temporary-parent correction and any separate replay. The first full attempt at `69fa6b8b` ended 137/SIGKILL without a summary/JUnit; the later original 856-file diagnostic FAILED. Grouped coverage is not an unsplit full pass.
- [x] Run configured whole-tree Ruff, pip check and all 16 schema generators at `8efb7a45`; all pass, and 301 schemas plus the generated CSAF table are unchanged. [Gate evidence](evidence/phase7-gates-20261119.zip).
- [x] Create and verify the [focused evidence archive](evidence/continuation-20261119-focused.zip): 94 payloads, manifest hashes checked, red/green and interrupted-run limits retained. Preserve later partition results separately.
- [ ] Obtain required hosted Linux/Windows, repeated Qt, package and other applicable checks on the actual candidate head and base. Existing main or PR319 results do not qualify this aggregate.
- [ ] Resolve blockers, refresh refs, perform the normal expected-head REST merge, and verify the resulting main tree. Keep `[no release]` on this repair/integration work.

The exact local validation commands are in [TEST_RESULTS.md](TEST_RESULTS.md).
Remote promotion must follow the standing all-jobs-green/no-open-blocker rule;
there has been no main merge or release from this continuation.

## Confirmed unresolved behavior

**Successful forced strings replacement:** fresh source and parent substitution
schedules remain reproduced after the accepted publication repair. Establish
ownership at successful replacement without claiming an unqualified native
primitive. [Batch 7](RECOVERY_BATCH_7.md) repairs held-source no-force publication,
collisions, unsupported-capability refusal and foreign-stage deletion during
forced failure. Such failures can retain partial or revealed stage bytes. Keep
compatible document-level extraction/truncation/redaction metadata, including
empty exports, as separate follow-up scope.

**Native PE trust:** run catalog and WinVerifyTrust acceptance on Windows with
source-pinned receipts. Keep cached offline metadata separate from current OS
chain/revocation state. `--trust cache|online` remains blocked until the existing
native acceptance gate is satisfied.

**Native packages and desktop:** complete Windows standalone, portable and
installer checks on Windows; then retain clean-machine, manual desktop and
accessibility acceptance as separate gates. The recovered installer digest row
is release-note correctness, not evidence of an installed working package.

## Preserve accuracy boundaries

| Layer | Remaining evidence obligation |
| --- | --- |
| L1 advisory join | Retain the frozen failed receipt (73 PASS, 6 FAIL, 8 excluded at `f69614fa`); resolve source/expectation work with explicit versioning, not rewritten historical outcomes. |
| L2 open-source pairs | Establish independently identified projects and completed real-tool pair results with verified producer compatibility. Authored adapters and parser tests do not substitute for those inputs. |
| L3 real Windows pairs | Verify function facts and artifacts, then obtain native receipts for the selected pairs. Unverified facts remain excluded from scoring. |

Keep L1/L2/L3 reports separate and preserve PASS/FAIL/BLOCKED/CANCELLED semantics.
Unrun or incomplete analyses are blocked, not misses. The facts-eligibility repair
enforces this policy at a code boundary; it does not create an accuracy result.
The original timeout pair, RB-01 targeted live check and real BinDiff/Rizin
producer acceptance remain in the [accuracy handoff](../plans/accuracy-program-handoff-20261107.md)
and existing QA records.

## Continue historical recovery

The complete census covers **320 heads and 309 PR records**, including **139
branches retained for semantic review**. Compare current behavior and contracts,
retain source identity, and recover compatible slices with targeted red/green
controls and independent review. Do not treat an inventory disposition, clean
merge simulation, patch equivalence or a recovered installer row as closure of a
whole historical branch.

Broad PR316/318 holds remain unchanged. Their inventory, package admission,
native diagnostics and qualification remainder must be reviewed separately.
The [third recovery report](RECOVERY_BATCH_3.md) supplies bounded dispositions for
all 10 issues and 39 comments, without closing those issues or all their findings.
The frozen census predates later PR320 and PR321. Retain PR320's broad draft
928-file/333-commit integration and PR321's documentation checkpoint separately;
neither is silently adopted into this local candidate. The remaining source-level
and unconfirmed issue findings still require their own reproduction and scope decisions.
Retain research/automation branches under their existing scope; no automation
activation, branch deletion or blanket PR closure is part of this work.

Prior PW-01/PW-02, real-source coverage, manual and release obligations recorded
in [the delivery tracker](../../tasks/todo.md) remain open unless a later entry
provides a specific accepted replacement. This checkpoint does not silently close
older tasks.

## Phase 5 priorities and subsequent dispositions

- [x] Publish the initial reviewed candidate as draft PR #322 and verify its tree equals local `3cde10ae`.
- [x] Review and integrate the downstream stage pin correction, acquisition plan/product binding, four-file harness repair and symbol scanner fixture correction through `bc485a66`.
- [x] Preserve the stopped 34-group diagnostic and phase 5 receipts in verified archives; retain every original failure.
- [x] Complete original groups 35–54 through chained frozen-source continuations/subpartitions; all seven residual-performance cases pass split 6+1. No failed outcome is relabelled.
- [x] Integrate the independently reviewed retention correction and preserve all original rows, peer NULL/BLOB findings and post-write uncertainty.
- [x] Qualify and integrate Pydantic 2.14.2/core 2.50.2 at `b28f6971` / `5208c758`: 2,903 passes and one existing strict xfail across 79 files; 301 schemas unchanged across 16 generators. Native Qt remediation remains open.
- [ ] Publish later accepted source with exact local/remote tree equality; obtain actual final-head Linux/Windows/Qt/package/native/live evidence.
- [ ] Resolve draft readiness through an allowed REST-only route after qualification, then perform a head-guarded main merge and verify the result.

The later publication and accepted slices are recorded below. Main integration,
broad branch, release, native and separate L1/L2/L3 obligations remain open.

## Phase 6 completed evidence and remaining gates

- [x] Publish observed checkpoint `2511301f`, tree-equal to local `7093ee68` (78 changed files, ahead 3/behind 0); five new workflows were queued, not passed.
- [x] Integrate retention `74d5f4bb` / `153f6cea`; 175 affected passes, independent NULL/BLOB preservation and protected-run/null-safe-cap controls.
- [x] Integrate qualified Pydantic `b28f6971` / `5208c758`; 2,903 passes plus existing strict xfail, unchanged schemas and separately verified actual new dependency versions.
- [x] Verify integrated `5208c758`: 254 affected passes across four groups; configured Ruff and pip check pass. This is not a full current-head suite.
- [x] Complete and archive original 856-file coverage: 59 terminal processes, 23,110 passed, 139 skipped, 6 xfailed, 4 failed, 8 teardown errors. Frozen diagnostic FAILED; original kill and reserve stops preserved.
- [x] Correct final backup-test mock lifetime at `5aebd98f`: 3 passes/3 teardown errors before repair, then 41 affected passes. Production source and assertions unchanged; original errors remain recorded.
- [x] Preserve verified 41/82/27/132/6-payload archives and exact report in evidence checkpoint `e430309a` and backup-test commit.
- [ ] Qualify combined current source separately from old frozen-source results and overlapping focused checks. Phase 6 had 859 files; Phase 7 now has 866 and its diagnostic is running. External AF_UNIX constructor EPERM remains an unchanged acceptance block.
- [ ] Resolve seven assessed native Qt findings using a supported qualified artifact or evidenced disposition. No official 6.12.1 binding wheels were available; 6.11.3 is not a complete fix.
- [x] Classify the separate 70 baseline tools findings in Phase 7; [the review archive](evidence/tools-static-review-20261119.zip) preserves the dispositions. Current supplemental scanning remains non-clean. Preserve the demonstrated PyPI/OSV coverage gap for old Pydantic.
- [ ] Publish accepted source with exact local/remote tree equality, obtain actual final-head Linux/Windows/Qt/package/native/live gates, resolve REST-only draft readiness, then use expected-head merge and verify main.

Strings-export recovery and build-tool HTTPS redirect triage were still pending
at Phase 6; their accepted Phase 7 scope is recorded below. Full index proposal/window/source-entry
persistence remains separate from recovered acquisition binding. Retention does
not make saves atomic or establish general hostile-database budgets. Broad
branches, release/manual obligations and separate L1/L2/L3 evidence remain open.
[Current handoff](HANDOFF.md), [test results](TEST_RESULTS.md), [dependency audit](DEPENDENCY_ADVISORY_AUDIT_20261119.md).

## Phase 7 accepted scope and pending gates

- [x] Publish Phase 6 as `eb94510b`, tree-equal to local `0ed53876`, with 93 changed files and ahead 4/behind 0. This publication predates Phase 7.
- [x] Accept strings source `397abd44` through `cf554155`: 74 focused passes and 115 integrated CLI/UI passes; retain successful-force source/parent ownership defects.
- [x] Accept observation-health/JUnit source `45828168` through `541bf83c`: 111 passes/3 existing unshare skips; partial endpoint evidence survives failed observations.
- [x] Accept build-tool HTTPS `7d4aead2`: 289 passes/1 historical wheel skip, followed by a pass of that exact wheel test; bounded per-hop validation and header controls remain.
- [x] Accept KEV source `c84ca5a2` through `8efb7a45`: 386 passes and 77 new semantic cases; measured local gains do not establish a Windows fix or change the strict one-second budget.
- [x] Preserve Phase 7 review/gate archives and classify all 70 baseline tools findings. Fresh scan: 134 findings, 64 source plus 70 tools, with one added guarded S310 and one removed swallowed-sampler S110.
- [ ] Finish the running combined diagnostic and record affected-group replay separately from original setup errors. Group 021 also fails the existing ASM tokenization budget, 0.156169465s against strict 0.150s; triage and unchanged-source replay remain pending. Keep source/test identity and every failure receipt.
- [ ] Publish Phase 7 with exact tree equality and obtain its own hosted checks. The observed Phase 6 head has six queued runs/23 runner-zero jobs; that is not a qualification result.
- [ ] Resolve successful forced replacement, seven native Qt findings, full index provenance, native/manual acceptance, retained semantic recovery and separate L1/L2/L3 gates before applicable promotion claims.

Main remains `fdc2696c` at the 13:37:30 UTC observation. No main merge or release
is recorded; the frozen census remains 320 heads/309 PRs with 139 semantic-review
dispositions, irrespective of later PR319/320/321/322 movement.

### Restored current-source diagnostic

- [x] Preserve original groups 001–025 and the storage-reserve stop, including 79 orchestration setup errors and one unchanged ASM timing failure.
- [x] Complete the two setup-only replays on the same source: 251 and 74 passed. No original receipt changed.
- [x] Restore frozen `8efb7a45` and verify identical source/dependency identities after the executor reset.
- [ ] Finish original groups 026–111, reconcile every collected node ID, and separately qualify the unchanged ASM timing gate. Current continuation is running; no full pass is recorded.
- [ ] Review newly reproduced WinPairs malformed-URL/error-boundary behavior and qualify its separate proposed repair. No network request or contacted unallowlisted destination was demonstrated.
