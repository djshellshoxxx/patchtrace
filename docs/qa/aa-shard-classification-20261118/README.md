# Preserve A/A rebuild failures in shard provenance

The research shard runner now classifies an A/A summary with a nonempty
`not_byte_identical` list as failed for exit 0 or 1. The existing case-stop,
persist/load, merge, Markdown and CLI paths then retain that failure and a
bounded reason. Ordinary findings, empty A/A lists, other command summaries,
timeout/blocked status and prior runner-error precedence retain their contracts.

Baseline: `740869debb111f8edbef33899316e4c75e6fdf7a` (equal tree to published PR #316 `14efc523`).
Spec/tests: `a2d3011ebb47bb6e5566e70106ff0b47fde624f6`. Exact reviewed source: `9bd17bbecb54f5a3de05d235a1617a3d2f196883`.
The production diff is four added lines in `tools/calibration/tier_r/shard.py`.
The preceding specification and regression tests define the behavior first.

## Evidence and independent review

| Source-specific invocation | Passed | Failed | Skipped | Interpretation |
| --- | ---: | ---: | ---: | --- |
| Original unchanged public probe on baseline | 1 | 2 | 0 | Both exit-0/1 failures were omitted from merged failing cases |
| Spec/tests before production edit | 59 | 5 | 0 | New propagation, stop and CLI controls fail on the prior source |
| Author affected gate on `9bd17bbe` | 67 | 0 | 0 | Existing shard suite, new controls and unchanged peer probe |
| First independent gate | 69 | 1 | 0 | Authored 8,018-character identifier correctly exceeds the pre-existing summary budget |
| Final independent gate | 71 | 0 | 0 | Fixture corrected to admitted 1,918 characters; separate over-budget refusal retained |

These overlapping counts are not additive. The final independent gate took
0.92 seconds; the author gate took 0.77 seconds. Exact commands, JUnit, logs,
imported-source receipts, original fixture bytes and their correction are in
the archive. Both final gates used the clean exact source, with no foreign
project import or source drift. Normal repository Ruff passed. No assertion
was weakened and no frozen research outcome was rewritten.

The independent reviewer inspected the real `cmd_aa`, source/spec/tests,
case-step termination, persisted shard reload, merged provenance, Markdown and
CLI exits. Additional authored controls cover the real command summary,
bounded diagnostics, generic findings reload and the unchanged summary cap.
The initial independent failure was a fixture-domain error; no product edit
followed it. The unchanged original public probe and original observations
are SHA-verified before/after and retained separately from new observations.

Root verified every member of the independent 27-member archive, its three
source snapshots against exact Git objects, all five JUnit totals and original
observation hashes. Independent archive SHA-256: `4a49ec5c7e12791f6618aeff74511233b6993a6a6273b4e4e0608e4452890238`.

## Qualification limits

All producers here are authored. This repair adds no compiler, native engine,
target execution, network, statistical accuracy or frozen-corpus acceptance.
Historical card/recipe grammar remains a separately incomplete research scope.
Only newly produced shard summaries adopt the repaired classification. The
combined integrated candidate still requires its own gate. Main integration,
native/platform/package/security acceptance and release readiness remain held.

[Complete evidence](evidence.zip), [member hashes](manifest.json).

Archive: 274,206 bytes, 74 payload members;
SHA-256 `d7ccb0aa06e75c6fb40ac2c756d04cf6a893f6def59f5c0f90df97c0fa3809ed`.
