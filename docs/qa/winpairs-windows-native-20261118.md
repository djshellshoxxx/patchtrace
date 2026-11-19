# Windows owned-publication repair — 2026-11-18

## Observed blocker

PR #304 at `bb4277aed685d485b57ffe7a718e70bab3e34467` failed its early native
publication controls on Windows: **15 failed, 61 passed, 3 skipped in 3.68s**.
[QA run 44263225792](https://github.com/djshellshoxxx/patchtrace/actions/runs/44263225792),
[Windows job 134661411666](https://github.com/djshellshoxxx/patchtrace/actions/runs/44263225792/job/134661411666).
The full Windows suite and package steps did not start. This head is not qualified
for merge regardless of other successful jobs.

The log reports OS error 87 during safe publication. Normal binary and receipt
publication and the Unicode case failed. The held-ancestor/stage test reached its
completed attack-attempt assertion: flushing, ancestor and stage rename rejection,
and stage-write rejection ran before publication failed. That narrows the failure
location but does not prove which Win32 parameter or call failed.

Two independent reviews reproduced a separate exception-flow defect: discard or
descriptor-close failures can replace the original write error, collision or
cancellation. The old error-87 message could therefore conceal a prior failure.
Current Microsoft documentation permits relative `RootDirectory` usage and declares
disposition's `DeleteFile` as one-byte `BOOLEAN`; neither is a proven ABI defect here.
No categorical native root-cause claim is made from the old log.

## Repair and preserved boundaries

Local code commit `1c49199e9333e955e2bd947fda2824d68b7da65d`, published as
`540c7df771e721148fba94a0ec707fe591aba875` with identical tree
`aa7749a9a1c2abe7c3a4bde2473e717411f7ac9e`, changes the information calls to
`NtSetInformationFile` classes 10 and 13, matching the native rooted opens. Each
call receives a fresh `IO_STATUS_BLOCK`; signed negative status is translated through
`RtlNtStatusToDosError`, and unexpected pending/informational status blocks success.
The filename remains UTF-16LE with a byte count and a zeroed allocation at least the
structure size plus filename bytes. The held source/parent, no-replace flag, DELETE
access, synchronous handle, identity checks and no-reparse boundaries remain in force.

Cleanup records bounded secondary diagnostics while preserving the primary
`BaseException`, always attempts to close the exact owned handle, and never reopens
a pathname for deletion. Failure after successful rename does not delete a published
destination or claim success. The wrapper retains the bounded cleanup notes.

The specification was amended before implementation. Its Microsoft API links and
the retained independent contract review explain the native requirements. This is
a candidate repair whose native filesystem behavior still requires new-head Windows
acceptance; switching APIs alone is not proof of a fix.

## Focused evidence

- Against the old production code, **20 new controls failed**: native dispatch and
  status handling, primary write/collision/cancellation preservation, and cleanup
  before ownership transfers to the CRT descriptor. This is portable regression
  evidence, not an emulated Windows success claim.
- With the repair, all three existing winpairs/integrity/publication modules yielded
  **101 passed, 2 skipped in 0.51s** on Linux. The skips are the existing actual
  Windows sharing/reparse tests. One-character, BMP and non-BMP target filenames are
  included; existing collision, mutation, failure and cancellation controls remain.
- Independent review of the exact code/tree found no blocker. A separate rerun gave
  **101 passed, 2 skipped**; **15 additional external adversarial controls passed**,
  including failed pre-transfer close, cleanup BaseExceptions, post-rename
  guard-plus-close failures, full-width handles and constructor binding checks.
- Whole `src tests tools` Ruff and `git diff --check` pass. No persisted schema or
  external CLI grammar changed.
- The new exact-head hosted full Linux/Windows, Qt, packaging, smoke, native and
  dependency gates remain required. Old-head successes do not qualify this repair.

Raw old Windows failure, portable red/green logs, independent API review and exact
hash/size manifest are retained in [the evidence directory](winpairs-windows-native-20261118/manifest.json).
No target download or execution was performed for these authored-file controls.

## Integration state

The repair is an additive descendant of #304. Preserve every remote branch and every
prior failure receipt. Merge remains blocked until all required jobs pass at the
final published head; use the REST expected-head SHA guard and a literal
`[no release]` merge message. No release or superseded-PR closure is implied by this
local result.
