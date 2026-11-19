# Hermetic no-input backend-pin verification fixture

The no-input unit fixture now injects the existing process runner, in addition
to its offline fetch stub. It preserves the original assertions and refuses
fallback to real subprocess execution. **No production tool or pin changed.**

## Source

| Item | Identity |
|---|---|
| Approved baseline | `3faf436a3b11c69220641a167cf424e7f4060839` |
| Specification and failing process guard | `42f063a7de4a4ca15dd40d1ab5c820662d5ec809` |
| Fixture repair | `e4ee7ca4b8178db159b0edf16e2afbf59363b4a8` |
| Branch | `codex/backend-pin-fixture-20261118` |
| Worktree | `/workspace/scratch/c7a9e8d98848/backend-pin-test-hermetic` |

Only `tests/test_verify_backend_pins.py` and a short amendment to the existing
`BUNDLE-pin-digest-and-upgrade-spec.md` changed before this QA checkpoint.
Independent review and root integration remain separate steps.

## Confirmed defect and protected reproduction

`test_verify_without_inputs_records_nothing` previously replaced `_fetch` but
called `verify_all(args)` with the default real process runner. The verification
tool also reaches Git through `rebuild_tarball`. The fetch stub therefore did
not make this fixture hermetic.

The baseline probe intercepted `subprocess.run` before any external invocation.
It supplied synthetic Git/GPG version results and a synthetic successful Git
initialization, then refused the attempted fetch. The retained trace records
four default-runner requests, including the pinned
`https://github.com/clearbluejar/ghidriff` repository and
`4f5d895fcbb1eacd65efd81145922c15bb7e741d` commit. **None of those commands was
executed.** A separate Python audit hook would reject actual process creation
or socket activity; no such event occurred. The unchanged original fixture
assertions completed, and the independent isolation assertion failed as
intended. This protected failure is in `baseline-protected-red.*` and
`baseline-interception.json`.

The specification and committed test guard then produced a second red result
at `42f063a7`: the fixture refused the initial uninjected `git --version` call
before process creation. This proves the regression guard fails when the
default runner is used; it does not rely on a network connection failing.

## Repair and stronger assertions

The fixture passes an authored `offline_run` to `verify_all`. That runner
records the exact command/cwd sequence, reports both version probes unavailable,
simulates repository initialization, and returns a failed fetch for the exact
configured repository and commit. No subprocess is started by that fixture.

The original failed-result/no-pin-record and schema/tool assertions remain.
Additional checks require the exact process and fetch requests, unavailable
Git/GPG evidence, separate Python/Ghidriff failures, no admitted Ghidriff rebuild
facts, unchanged pin bytes and no downloaded/rebuilt files in the work area.
The process guard remains active, so omission or loss of the injected runner
fails the fixture before execution.

## Verification at the repair commit

The entire affected test module and the unchanged protected external probe
passed: **26 passed, no skips, in 0.82 seconds**. The normal Ruff check over
`src`, `tests` and `tools` passed. Command, source/tree, environment, raw log,
JUnit and exit status are retained.

The repaired external probe recorded zero default-runner calls and zero blocked
audit events. Neighboring deterministic-archive tests used authored local Git
repositories. Their bounded run used an additional audit hook, a Git protocol
allowlist of `file`, disabled system/global Git configuration and disabled
interactive prompting. The receipt records 89 local Git processes and zero
denied events. Those controls protect this inspected test scope; they are not a
general operating-system network sandbox claim.

The original broad runner was not resumed. No vendor signature, upstream
repository, native backend, package, release or full-suite qualification is
claimed from these synthetic results. No dependency upgrade, production edit,
remote mutation, workflow dispatch, release, deployment or tag occurred.

## Evidence

`evidence.zip` contains both protected red runs, exact-source snapshots,
unchanged independent probe, bounded-run audit helper, final receipts and this
report. `manifest.json` records the archive and each member's size and SHA-256.
The archive was reopened, CRC-checked, checked for duplicate paths, and every
member revalidated before the QA-only checkpoint commit.
