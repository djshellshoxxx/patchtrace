# Remaining continuation work — 2026-11-19

The reviewed N-way, installer-receipt, parser, PE-cache, facts-eligibility, adapter-text and CSAF slices are integrated
locally on `codex/patchtrace-completion-20261119-81e4`, recorded through
`5aebd98f`, including reviewed CVE numeric/time, digest-fixture, acquisition,
history/retention, Pydantic and test-fixture repairs. They do not complete the feature backlog or main qualification.
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
- [ ] Qualify the final source. The first full attempt at `69fa6b8b` ended 137/SIGKILL with no summary or JUnit; retain that incomplete result. Smaller sequential groups can provide scoped coverage, not an unsplit full pass.
- [ ] Run whole-tree Ruff, dependency checks and schema regeneration on the final aggregate; review any generated differences.
- [x] Create and verify the [focused evidence archive](evidence/continuation-20261119-focused.zip): 94 payloads, manifest hashes checked, red/green and interrupted-run limits retained. Preserve later partition results separately.
- [ ] Obtain required hosted Linux/Windows, repeated Qt, package and other applicable checks on the actual candidate head and base. Existing main or PR319 results do not qualify this aggregate.
- [ ] Resolve blockers, refresh refs, perform the normal expected-head REST merge, and verify the resulting main tree. Keep `[no release]` on this repair/integration work.

The exact local validation commands are in [TEST_RESULTS.md](TEST_RESULTS.md).
Remote promotion must follow the standing all-jobs-green/no-open-blocker rule;
there has been no main merge or release from this continuation.

## Confirmed unresolved behavior

**Forced strings export ownership:** reproduce and repair the source-substitution
and OSError cleanup races retained in the PR319 audit. A cancellation correction
does not cover those schedules. Verify failure preservation and foreign-file
ownership before any replacement or cleanup. Keep the existing no-clobber race
and compatible document-level extraction/truncation/redaction metadata, including
empty exports, as explicit follow-up scope.

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

## Phase 5 current priorities

- [x] Publish the initial reviewed candidate as draft PR #322 and verify its tree equals local `3cde10ae`.
- [x] Review and integrate the downstream stage pin correction, acquisition plan/product binding, four-file harness repair and symbol scanner fixture correction through `bc485a66`.
- [x] Preserve the stopped 34-group diagnostic and phase 5 receipts in verified archives; retain every original failure.
- [x] Complete original groups 35–54 through chained frozen-source continuations/subpartitions; all seven residual-performance cases pass split 6+1. No failed outcome is relabelled.
- [x] Integrate the independently reviewed retention correction and preserve all original rows, peer NULL/BLOB findings and post-write uncertainty.
- [x] Qualify and integrate Pydantic 2.14.2/core 2.50.2 at `b28f6971` / `5208c758`: 2,903 passes and one existing strict xfail across 79 files; 301 schemas unchanged across 16 generators. Native Qt remediation remains open.
- [ ] Publish later accepted source with exact local/remote tree equality; obtain actual final-head Linux/Windows/Qt/package/native/live evidence.
- [ ] Resolve draft readiness through an allowed REST-only route after qualification, then perform a head-guarded main merge and verify the result.

These are active follow-ups, not completed main integration. The broad branch, release, native and separate L1/L2/L3 obligations above remain open.

## Phase 6 completed evidence and remaining gates

- [x] Publish observed checkpoint `2511301f`, tree-equal to local `7093ee68` (78 changed files, ahead 3/behind 0); five new workflows were queued, not passed.
- [x] Integrate retention `74d5f4bb` / `153f6cea`; 175 affected passes, independent NULL/BLOB preservation and protected-run/null-safe-cap controls.
- [x] Integrate qualified Pydantic `b28f6971` / `5208c758`; 2,903 passes plus existing strict xfail, unchanged schemas and separately verified actual new dependency versions.
- [x] Verify integrated `5208c758`: 254 affected passes across four groups; configured Ruff and pip check pass. This is not a full current-head suite.
- [x] Complete and archive original 856-file coverage: 59 terminal processes, 23,110 passed, 139 skipped, 6 xfailed, 4 failed, 8 teardown errors. Frozen diagnostic FAILED; original kill and reserve stops preserved.
- [x] Correct final backup-test mock lifetime at `5aebd98f`: 3 passes/3 teardown errors before repair, then 41 affected passes. Production source and assertions unchanged; original errors remain recorded.
- [x] Preserve verified 41/82/27/132/6-payload archives and exact report in evidence checkpoint `e430309a` and backup-test commit.
- [ ] Qualify combined current 859-file source and Pydantic 2.14.2 separately from old frozen-source results and overlapping focused checks. External AF_UNIX constructor EPERM remains an unchanged acceptance block.
- [ ] Resolve seven assessed native Qt findings using a supported qualified artifact or evidenced disposition. No official 6.12.1 binding wheels were available; 6.11.3 is not a complete fix.
- [ ] Review the separate 70-finding tools scan; original source classifications do not cover all 134 combined findings. Preserve the demonstrated PyPI/OSV coverage gap for old Pydantic.
- [ ] Publish accepted source with exact local/remote tree equality, obtain actual final-head Linux/Windows/Qt/package/native/live gates, resolve REST-only draft readiness, then use expected-head merge and verify main.

Strings-export recovery and build-tool HTTPS redirect triage are ongoing separate
work, not completed Phase 6 source. Full index proposal/window/source-entry
persistence remains separate from recovered acquisition binding. Retention does
not make saves atomic or establish general hostile-database budgets. Broad
branches, release/manual obligations and separate L1/L2/L3 evidence remain open.
[Current handoff](HANDOFF.md), [test results](TEST_RESULTS.md), [dependency audit](DEPENDENCY_ADVISORY_AUDIT_20261119.md).
