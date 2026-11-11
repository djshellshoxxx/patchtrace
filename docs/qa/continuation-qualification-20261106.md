# Continuation qualification and retained research evidence

This records qualification of the frozen subprocess repair (#246) and product
continuation (#247). Their code heads stay unchanged while this documentation
branch records later results. It supplements the
[implementation/review receipt](continuation-20261106.md), not the underlying
release or native-tool requirements.

## Exact tested sources

| Candidate | Local tested commit | Published equivalent | Identical tree |
|---|---|---|---|
| #246, subprocess interpreter repair | `e52047ae1b1bbb19a42680b8d9881338f2595f93` | `c804e4d94430368c0eafe1da899493a8cf6520aa` | `cf59135e03b1c4a84ff628b29b4abb9d308a2b7d` |
| #247, combined product continuation | `75903db30b8f66e6426d3f5674b1d84fe2b190c3` | `37b771300053e8872febead1fc384fea9126ae90` | `cdbab24d14295b4450cd0d3c744d76734c98a561` |

Both local runs use the same Python 3.12 virtual environment, offscreen Qt,
`PYTHONPATH=src`, and no inherited `PYTEST_ADDOPTS`. The commands are unfiltered
`python -m pytest -q --junitxml=...`. No test assertion, limit, threshold,
permission or skip condition was changed for qualification.

The [final source audit](continuation-qualification-20261106/source-integration-audit.json)
checks all 16 canonical contribution blobs, all 13 changed source/test paths,
the actual source ancestry, and append-only ledger preservation. The published
#247 tree exactly matches its reviewed local tree; no unreviewed workflow,
engine, schema, dependency or packaging change entered it.

## #246 complete local result: failed

**5 failed, 18,637 passed, 134 skipped, 7 xfailed, 1 warning in 3,101.65 seconds**,
exit code 1. The run began at 07:46:29 UTC and finished at 08:38:20 UTC on
2026-11-06. Its head and tree remained unchanged and its ending worktree was
clean. The separate 3,111.51-second wrapper duration includes process overhead.

| Failed control | Actual failure | What the trace establishes |
|---|---|---|
| Tokenizer `char-flood-c` | 9.314983511 seconds against `<3.0` | Wall-time limit failed after the exact-coverage assertion passed. |
| Tokenizer `comment-openers-asm` | 3.074213013 seconds against `<3.0` | Same wall-time limit failure; exact coverage passed. |
| Local AF_UNIX socket | `PermissionError: [Errno 1] Operation not permitted` | Socket construction failed before bind/connect or entry into `NetworkGuard`. |
| Pilot, 5,000 pairs by eight CVEs | 5.312991952 seconds of CPU against `<=5.0` | CPU limit failed; later result/schema assertions were not reached. |
| Related panel, 100,000 rows | `waitUntil` expired after 5,000 ms | Synchronization failed in `start()/settle()`; later row/page/state assertions were not reached. |

Neither modified subprocess test file failed. Their earlier complete-file
selection passed 116 tests. Tokenizer/pilot test and relevant implementation
blobs are unchanged across #246, #245 and #247. The earlier exact #245 local
full run passed both tokenizer cases and the pilot control. These observations
do not establish why the timing outcome changed; scheduler delay alone does
not explain a CPU-time measurement.

The train already contains the reviewed GUI synchronization repair from
`b14b536d3af237939c96416053e9a77f1d0d537a`: 30,000 ms for the same wait while
retaining row/page/state assertions. The #246 trace confirms that this is the
wait that expired. The prior #245 local run also records the same AF_UNIX
construction denial. Those comparisons do not convert this full run into a pass.

The 18,780 runnable collected nodes and 18,783 JUnit cases differ by three
collection-skip records. JUnit's 141 skipped entries comprise 134 skips and
seven expected failures. Existing unavailable live-tool cases remain explicit
in the original log.

[Original run metadata](continuation-qualification-20261106/pr246-full-result.json),
[reviewed failure interpretation](continuation-qualification-20261106/pr246-completed-review.json),
[complete console log](continuation-qualification-20261106/pr246-pytest.log.gz), and
[complete JUnit report](continuation-qualification-20261106/pr246-pytest.xml.gz).
The compressed archives decode to the exact original bytes. Their encoded and
decoded hashes are recorded in
[archive hashes](continuation-qualification-20261106/archive-hashes.json).

## #247 combined qualification

The frozen combined regression selection passed **243 tests in 72.29 seconds**,
with zero failures, errors or skips and a clean worktree before and after.
It includes both product files, the investigation service/dialog, recovery and
bounded diagnostics, and both subprocess isolation files.
[Exact command and result](continuation-qualification-20261106/combined-focused.json).
The [complete focused console log](continuation-qualification-20261106/combined-focused-pytest.log.gz)
and [focused JUnit report](continuation-qualification-20261106/combined-focused-pytest.xml.gz)
are retained with encoded and decoded hashes in the archive manifest.
Whole-tree Ruff passed on the exact hosted #247 tree. The earlier reviewed
[implementation validation](continuation-20261106.md) recorded clean diff
hygiene and no drift from KBC schema generation; this bundle does not add a
separate command receipt for those two earlier checks.

### Complete local run: one environment refusal

The unfiltered combined run finished at **09:19:00 UTC** with **1 failed,
20,284 passed, 139 skipped, 6 xfailed and 18 warnings in 3,356.58 seconds**,
exit code 1. It began at 08:22:54 UTC; wrapper duration was 3,366.415 seconds.
The exact head/tree remained unchanged and both worktree snapshots were clean.

The sole failure is the local Unix-socket control: the environment raises
`PermissionError: [Errno 1] Operation not permitted` while constructing
`socket.socket(socket.AF_UNIX)`, before bind/connect or entry into the network
guard. No permission workaround, skip or code change was introduced. This
local full run remains failed; hosted Ubuntu qualification is separate.

JUnit confirms passes for both previously failed tokenizer controls, the
pilot performance control and the 100,000-row related-panel control, including
its retained row/page/state assertions after the reviewed wait repair. JUnit
case durations are wall time, not the pilot's internal CPU measurement; they
do not identify the cause of the earlier timing failures.

[Original result](continuation-qualification-20261106/pr247-result.json),
[console log](continuation-qualification-20261106/pr247-pytest.log.gz), and
[JUnit report](continuation-qualification-20261106/pr247-pytest.xml.gz) retain
the actual failed outcome, original live-tool blockers and archive hashes.
The [independent completed-run review](continuation-qualification-20261106/pr247-completed-local-qualification-20261106.json)
reconciles all 20,430 JUnit cases and the optional-live limitations, including
three collection skips because YAML was unavailable and 18 recorded warnings.

### One unchanged #246 timing follow-up

After the combined full run ended, exactly one replay on unchanged #246
selected the two failing tokenizer cases and the pilot CPU-limit control:
**3 passed in 12.31 seconds**, with zero failures, errors or skips, from
09:19:27 to 09:19:41 UTC. No limits, assertions, dependencies, permissions or
source files changed; the worktree was clean before and after.

These failures did not reproduce in that single follow-up. Their cause is
still unestablished, and the original five-failure full result is unchanged.
The GUI control was not repeated separately because the completed #247 full
run already exercised its reviewed repair. Hosted #246 results below provide
separate cross-platform evidence.

[Exact command and result](continuation-qualification-20261106/pr246-timing-followup-result.json),
[console log](continuation-qualification-20261106/pr246-timing-followup-pytest.log.gz), and
[JUnit report](continuation-qualification-20261106/pr246-timing-followup-pytest.xml.gz)
are retained with hashes. No additional application test run was started for
the subsequent documentation-only changes.

## Hosted prerequisite evidence

Unchanged #245 `4465a0492367d08f324e80b290a594791921691c` passed both full
application QA legs on merge ref `9e0bfefa3d036d080efef30f62ead1a5578ed6f5`.
The merge has the expected base/head parents and exactly the repair's tree,
`6db3490e96da2a8f0a200d834f8816bc41421f57`.

| Platform | Exact full-suite result | Evidence |
|---|---|---|
| Ubuntu 26.04.1 / CPython 3.12.16 | 19,708 passed, 52 skipped, 6 xfailed, 1 warning in 1,697.35 s | [Linux job](https://github.com/djshellshoxxx/patchtrace/actions/runs/42169559762/job/127733918805) |
| Windows / CPython 3.12.10 | 19,671 passed, 90 skipped, 5 xfailed, 1 warning in 2,750.13 s | [Windows job](https://github.com/djshellshoxxx/patchtrace/actions/runs/42169559762/job/127733918608) |

The [Ubuntu receipt](continuation-qualification-20261106/pr245-ubuntu-qa.json)
preserves its source, environment, passing steps, artifact digest and 13
explicit optional live-acceptance blocker entries. These include unavailable
BinDiff, DIE, capa/FLOSS, MinGW, a missing capa move fixture and Windows-only
MSVC execution. A passing application suite does not qualify unavailable tools.

The Windows job also passed standalone build, frozen EXE smoke/self-test,
portable ZIP execution outside the checkout, installer construction and
install/launch/uninstall. Its
[downloadable candidate](https://github.com/djshellshoxxx/patchtrace/actions/runs/42169559762/artifacts/13485625163)
belongs to #245 and does not contain the later #244/#247 features. Its complete
identity remains in the earlier continuation receipt.

### Later hosted results and newest available Windows candidate

In the latest available snapshots collected from 09:13 to 09:20 UTC, both complete application QA legs passed on
unchanged #244 and #246. Their tested merge trees exactly match their source
trees; Windows build, frozen EXE, portable ZIP, installer smoke and artifact
upload steps also passed.

| Candidate | Windows result | Ubuntu result | QA run |
|---|---|---|---|
| #244 `f393bb68` | 20,264 passed, 94 skipped, 5 xfailed | 20,305 passed, 52 skipped, 6 xfailed | [42175119317](https://github.com/djshellshoxxx/patchtrace/actions/runs/42175119317) |
| #246 `c804e4d9` | 18,696 passed, 81 skipped, 6 xfailed | 18,729 passed, 47 skipped, 7 xfailed | [42183372079](https://github.com/djshellshoxxx/patchtrace/actions/runs/42183372079) |

The newest verified [Windows candidate from #244](https://github.com/djshellshoxxx/patchtrace/actions/runs/42175119317/artifacts/13491065612)
is 131,687,358 bytes with SHA-256
`3c117e5702bf072cf37d6c36d5c3204850d19e6fb85bf7ddca0fa1d02c981da7`.
It includes the portable package and installer from `f393bb68`; it does not
include #247's new product-start workflow. It remains an application candidate,
with separate live-tool and release acceptance requirements.

In those snapshots, #244 still had Ubuntu Qt shard 1/4 active. All five #246 Qt
jobs had passed, with Linux package job `127812233908` queued; both Ubuntu
22.04/24.04 smoke legs remained behind packaging. #247 Windows QA was still
running. Completed native Windows Ghidriff jobs remain separate from the
application suites. Expected pull-request release-job skips are not passes.

Detailed snapshots: [#244 suites and artifact](continuation-qualification-20261106/pr244-windows-linux-qualification-20261106T0913Z.json),
[#246 suites and remaining gates](continuation-qualification-20261106/pr246-qualification-eligibility-20261106T0920Z.json),
and [#247 hosted status](continuation-qualification-20261106/pr247-hosted-qa-snapshot-20261106T0913Z.json).
The Windows artifact digest was corroborated between API and upload logs;
the archive itself was not downloaded and independently rehashed in this review.

### #247 completed Ubuntu application QA

Frozen #247 passed **20,372 tests, with 52 skipped, six xfailed and 19 warnings
in 1,856.06 seconds** on Ubuntu 26.04.1, CPython 3.12.16 and protobuf 7.36.2
with the upb backend. The [complete Linux job](https://github.com/djshellshoxxx/patchtrace/actions/runs/42187353481/job/127790743638)
tested merge `bfecc248af653d8c93d7bf3bf46a2121122c6d23`, with the expected
`f393bb68` and `37b77130` parents and exact tree
`cdbab24d14295b4450cd0d3c744d76734c98a561`.

The [hosted receipt](continuation-qualification-20261106/pr247-ubuntu-qa.json)
records the environment, steps, exact merge identity, artifact digest and
13 optional-live blocker entries (11 distinct messages). The warnings comprise
one duplicate-ZIP fixture warning and 18 intentional legacy-unverified-output
warnings. The [QA artifact](https://github.com/djshellshoxxx/patchtrace/actions/runs/42187353481/artifacts/13489838041)
is 353,375 bytes with SHA-256
`363ab1476615b42c9c952369ae0ccfd5e3dc4878897b9dd6a424faf1050a76b0`.
The skipped and unavailable live-tool cases retain their original meanings.

## Historical R8 preservation

The separate [R8 reconciliation](../research/r8-reconciliation-20261106.md)
preserves five source documents (42,639 bytes), with independent byte/hash,
provenance, current-disposition and link review. The source-only local commit
`3dc4b15f751d56e9980bcc5c39741b6328273021` and published equivalent
`d1c10387f14b7a9ed0c908b3f2bdf66cf551d774` share tree
`7faa6f1b10162d30d81bda9acd6d69b40a4b55af`.

The R8 typed-literal implementation remains unported. Existing ICF handling and
the independent register-only proof-blocker repair are distinguished from old
claims. Two omitted code files have pinned original-source links; no historical
probe, compiler experiment or target binary was executed. The archival commit
changes only eight research documents. This subsequent qualification receipt
separately updates the QA/task evidence; it adds no runtime implementation.

## Promotion checkpoint and remaining gates

At the 09:20 UTC snapshot, main remains
`d02b94bcedb29dae201941f01f2c94d42ebbb297`. #205 is ready at accepted
`6095f702`, but its exact-head Sonar check `127807997139` still fails with
C security and reliability ratings. Its three annotations are at
`src/patchtrace/unified/facts/anchors.py:76` (always-true condition),
`tools/rzdiff/native_evidence.py:52` (CLI path handling), and
`tools/unified/bench.py:254` (pseudorandom generator). These match the prior
triage locations/messages; no additional annotation appeared in that check.
The gate remains unresolved and requires normal disposition. A passing repair
delta does not replace that decision.
The [current #205 receipt](continuation-qualification-20261106/pr205-exact-head-status-20261106T0913Z.json)
retains the exact issue identifiers, check results and direct-ref/merge identity.

CodeRabbit skipped #205 because its 304 selected files exceed the 300-file
limit; this is not a completed review. Formal reviews and inline threads were
empty in the snapshot. Current-head application/native checks, the parent
#218/#235 scanner dispositions and the remaining release/live/manual gates
remain distinct. No scanner rule, permission or branch gate was bypassed.

The normalized #205 base SHA was stale in the snapshot. Direct main-ref and
Git merge-object evidence instead recorded prospective merge
`b9946a7cc5441119b3f4fcf77b1ec30f658ff083` has parents `d02b94bc` and `6095f702`
and tree `6db3490e96da2a8f0a200d834f8816bc41421f57`.

### Later main acceptance at 09:29 UTC

After Linux packaging and both smoke jobs passed, #246 merged normally at
**09:29:12 UTC** as `dc53b529560453e84cf45e356a40432ff3fc6725`. Its parents are
`d02b94bc` and `c804e4d9`; the merged tree is exactly the qualified
`cf59135e03b1c4a84ff628b29b4abb9d308a2b7d`. Main now points to that commit,
and the original repair branch remains at `c804e4d9`. The
[acceptance receipt](continuation-qualification-20261106/pr246-accepted-main.json)
retains the expected-head guard, completed check IDs, source retention and
post-merge tree/ref verification. The failed local run remains preserved.

The earlier #205 prospective merge identity is therefore historical. Its
merge tree and current gates must be rechecked against the new main before
promotion; the outstanding parent Sonar dispositions remain open.

This documentation branch records results without changing frozen #247 code.
It preserves both failed local runs, suitable-runner successes, the single
timing follow-up, the historical research and the retained source branches.

## Accepted recovery repair and forward propagation

After all applicable #245 source checks passed, the normal expected-head merge
completed at **09:05:35 UTC on 2026-11-06**. Accepted commit
`6095f702400e7fe19c2f462ae79f6ab650c5db58` has the exact qualified tree
`6db3490e96da2a8f0a200d834f8816bc41421f57` and parents `f33e2a0a` and
`4465a049`. Its original source branch remains at `4465a049`; #205 was marked
ready for review at 09:09:38 UTC. This acceptance advances the #205 owner,
not main.
The [final exact-source gate receipt](continuation-qualification-20261106/pr245-final-source-gates.json)
was retrieved after acceptance and confirms all recorded completion times
precede the merge: 16 successful checks, three explicit policy/PR skips, and
a separate successful Snyk status. CodeRabbit's skip is not a completed review.

[PR #248](https://github.com/djshellshoxxx/patchtrace/pull/248), opened ready at
09:13:50 UTC, carries the repair and actual accepted parent into #218's next
stage. Published head `a1ed8c9167529fbf855d7dc088132379ee385cf4` and local
equivalent `a2dacfd178ab48ad42097a6930af7567b6a9309e` share tree
`b59a105796e4c5cc8665cf157d5fbbae0c2ed9fd`. The source-owned blobs are exact;
the destination's later work and complete QA/task ledger prefixes are retained,
with each repair suffix appended once.

The combined recovery/crash selection passed **54 tests in 14.72 seconds**;
whole-tree Ruff and diff hygiene passed. Adding the actual accepted parent
changed no files, so those checks were not repeated. Independent
[content review](continuation-qualification-20261106/recovery-forward/independent-review.json),
[accepted-parent identity](continuation-qualification-20261106/recovery-forward/accepted-parent-ancestry.json)
and [publication review](continuation-qualification-20261106/recovery-forward/publication-review.json)
confirm preservation and exact tree identity. This newly published combined head
still requires its own hosted checks and review before owner #218 changes.
