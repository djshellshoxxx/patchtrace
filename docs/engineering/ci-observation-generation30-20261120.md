# PatchTrace CI diagnosis — 2026-11-20 15:48:55 UTC

## Current source and gates

- Main remains `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.
- [PR #340](https://github.com/djshellshoxxx/patchtrace/pull/340) remains draft, head `6c8b33b851a22fb16d39b31693922359cd34ad12`, base `a5c6ff87ececcaffce01404f723aac455ee17e0c`.
- Proposed merge `f904062a23951db87568fd717b31fef6b8004e0a` has tree `b4eb779a6e4ddc7082dc12e87aec850d9b3e213f`, exactly equal to the PR head tree. Its ordered parents are base then head. This verifies Git object identity, not an actual checkout log for the running jobs.
- [Current QA run 44763480171](https://github.com/djshellshoxxx/patchtrace/actions/runs/44763480171) is **in progress**. Both full QA jobs and all five Qt jobs are running. Release gate is intentionally skipped on a pull request.
- Eight check records are present: seven running and one skipped. The separate Snyk status is success.
- Only one workflow run is associated with this exact head. No current-head native Ghidriff, rz-diff, or unified-extraction receipt is present. These workflows have path filters; absence is not a pass.
- Downstream Linux package/smoke jobs have not started because they depend on QA/Qt completion.

## Earlier main Linux package failure

[Main QA run 44489196124](https://github.com/djshellshoxxx/patchtrace/actions/runs/44489196124) completed with failure. Both full Linux/Windows QA jobs and all five Qt jobs passed, but [linux-package job 135514886000](https://github.com/djshellshoxxx/patchtrace/actions/runs/44489196124/job/135514886000) failed in the system dependency step:

```text
Run sudo apt-get update && sudo apt-get install -y libegl1 libopengl0 libgl1 libxcb-cursor0 libxkbcommon-x11-0 xvfb
Could not connect to azure.archive.ubuntu.com:80 (52.250.76.244), connection timed out
E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?
Process completed with exit code 100.
```

The failed job stopped before Python dependency installation or `tools/build_linux.py`. This is direct evidence of a runner package-download prerequisite failure, not a PatchTrace packaging traceback. The log does not establish why that mirror was unreachable. Linux smoke and release were skipped.

The QA workflow is byte-identical on main and generation 29: Git blob `4f40db05893e436230d2f739efe2d3ca87e5e8aa`. There is no intervening workflow fix. A speculative product-code change is not justified by this log.

## Next useful action

Inspect the current run's final QA/Qt and downstream Linux package/smoke results after completion. If a current candidate repeats the mirror failure, retain its source-specific logs before considering a narrow package-download resilience repair. Keep the original failed gate in history. Do not report an old passing pytest step or a skipped smoke step as whole-workflow acceptance.

The source snapshots and exact job/step statuses are in `patchtrace-ci-current.json`; the original decoded package log is `patchtrace-main-package.log`. No jobs were triggered, rerun or cancelled. No repository code or remote state changed.
