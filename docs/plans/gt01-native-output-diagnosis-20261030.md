# GT-01 native output rejection diagnosis — 2026-10-30

Status: defect reproduced from preserved on-host evidence; GT-01 is not accepted or merged.

## Original 7-Zip comparison

The preserved quarantine is runs/quarantine-251ae3ff-7a57-4538-a722-279acbfcfdc7 in the original local project. Read-only inspection found one JSON file of **105,077,223 bytes**, exceeding the backend's **104,857,600-byte** combined JSON ceiling by **219,623 bytes**. No symlinks were observed in the inspected tree. failure.txt contains the generic unsafe-or-oversized rejection. This confirms the output-limit condition; it does not establish which serialized structures caused the growth.

| Evidence | SHA-256 |
| --- | --- |
| Older input | 86926f78fad0d8c75c7ae01849bf5931f4484596d28d3690766f16c4fb943c19 |
| Newer input | 3691adcefc6da67eedd02a1b1fc7a21894afd83ecf1b6216d303ed55a5f8d129 |
| Quarantined JSON | be18eac42bdf56cc168fe02ae51e963ff899a6f33010e93420a64a8f5e3ba46d |

The original Markdown report remains present (118,676 bytes), alongside analysis.log and raw/ghidriff.log. None of these original files was changed. Quarantined JSON is diagnostic evidence, not an accepted completed result; its syntax/completeness was not validated or imported. Function matching counts are not proof of semantic equivalence or security accuracy.

The reported run used Ghidra 12.1.4. The currently installed local runtime reports Ghidra 12.1.4, Ghidriff 1.0.0 and PyGhidra 3.1.0; this installation inventory is not a historical lockfile for the failed run. The acceptance workflow instead pins Ghidra 12.0.4, Ghidriff commit 4f5d895fcbb1eacd65efd81145922c15bb7e741d and PyGhidra 3.0.2. Results across these environments must remain distinct.

## Current-head CI reproductions

PR #140 head b87193d1dd30635fce33986f80ceade136507a1a:

- [QA run 41152314039](https://github.com/djshellshoxxx/patchtrace/actions/runs/41152314039): Linux job 124391393407 and Windows job 124391393566 each fail both orientations of test_harness_never_counts_an_identical_shortcut. The fixture uses equal image hashes in the release stratum, which KnownAnswerLabels correctly rejects before the intended harness assertion. Use the aa stratum; retain the strict contract and the requirement that a shortcut never counts as native evidence.
- Windows repeated Qt job 124391393611 fails test_discovery_prefills_one_and_runs_nothing at its 5-second wait. This is a separate unresolved failure, not proven fixed by changing the A/A fixture.
- [Native Windows run 41152313989](https://github.com/djshellshoxxx/patchtrace/actions/runs/41152313989) and [live extraction run 41152314162](https://github.com/djshellshoxxx/patchtrace/actions/runs/41152314162) succeeded within their scopes. Neither supplies a full native G-U1–G-U8 report.

## Required acceptance and remaining access

Preserve the 100 MiB limit, path guards, failed status, prior completed results and diagnostic artifacts. Report output-limit, unsafe-output-path and output-check-failed distinctly, including guard failures detected after process exit.

Fresh exact-head Linux/Windows QA, repeated Qt, full native unified-live-gates outcomes with real denominators, applicable independent review, and post-merge checks remain required. The connector exposes no workflow dispatch operation; the local CLI has no authenticated session and the available browser is signed out. Rerunning an old workflow tests its old revision and is not a substitute. No acceptance threshold or protection is to be weakened to work around this access blocker.
