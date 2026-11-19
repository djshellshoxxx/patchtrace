# Remaining continuation work — 2026-11-19

The reviewed N-way, installer-receipt, parser, PE-cache, facts-eligibility, adapter-text and CSAF slices are integrated
locally on `codex/patchtrace-completion-20261119-81e4`, recorded through
`520b524b`, including the reviewed CVE numeric/time, digest-fixture and attempt-history repairs. They do not complete the feature backlog or main qualification.
The [feature matrix](FEATURE_MATRIX.md) identifies implemented scope;
[test results](TEST_RESULTS.md) separates completed evidence from pending gates.

## Finish the current candidate

- [x] Integrate history diagnostic source `254190a0` through `520b524b`; final 81 passed in 37.33s, with post-write uncertainty stated truthfully.
- [x] Review the contextual ROUND constant and correct its sole digest golden at `70b82275`; 9 passed in 1.85s.
- [x] Preserve the verified [history evidence](evidence/history-diagnostic-20261119.zip), including original red and independent post-write failures.
- [ ] Finish session 74806: all 856 files/54 groups on `520b524b`, results `/tmp/pt81-final-results`; no aggregate result yet.
- [ ] Address malformed-row retention and the underlying post-write retention exception separately.

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
