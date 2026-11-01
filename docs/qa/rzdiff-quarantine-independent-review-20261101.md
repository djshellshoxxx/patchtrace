# Independent rz-diff quarantine review — 2026-11-01 UTC

Reviewed and approved defensive source behavior at `e8319b9476898935dd2d3a3259e18982644991ed` on `codex/rzdiff-orientation-20261101`, based on `241f445`. Review performed in `wt-rzdiff`; no source edits, GitHub mutations, new native invocation or tool installation by this reviewer.

## Evidence and disposition

Primary source was independently read through GitHub at Rizin `v0.9.1`:

- `librz/arch/similarity.c`, blob `8544259e17a692bcb3c1d8858f104745cd0cba4c`: lines 568–574 swap `list_b/list_a` only when recovered `list_a` length is one. The normal callback retains order; the singleton callback constructs `match_pair_new(fcn_a, fcn_b)` after that swap.
- `librz/main/rz-diff.c`, blob `3be455f898e91b906ed2d2307060f41c0833450e`: lines 2042–2047 serialize `fcn_a` as `original` and `fcn_b` as `modified`; lines 2211–2219 consume `pair_a/pair_b` without restoring orientation.

This supports conditional side ownership, not a global swap. The retained fixture has 27 historical records: seven nonempty outputs are now rejected for orientation, while 20 empty outputs retain input errors. Replay is regression evidence, not a fresh native run.

The reviewed code:

- Rejects known 0.9.1 probes before scheduler cache lookup, with observed version and explicit reason.
- Rejects nonempty valid 0.9.1 parser output with `PT-SECONDARY-ORIENTATION` and exact stdout digest; never invents corrected ownership or a successful empty result.
- Preserves stored/raw source data, but removes affected matching votes, contests, numeric features, candidates, alternatives and engine-only links at active reconciliation/evidence/calibration boundaries.
- Retains unified SourceRef/raw provenance, emits no affected atoms or names, and adds a degrading orientation limitation that makes the result partial.
- Changes matching policy to `matching/3`; an independent check confirmed changed config/result identity with unchanged source refs, preventing reuse of pre-quarantine current results. ProgramIR keys are untouched.
- Preserves bounded/sanitized evidence view text. Generic synthetic tests use an explicitly unaffected version label; positive 0.9.0 and 0.9.10 controls do not claim native compatibility.
- Makes the pinned live harness report explicit `blocked` orientation status while returning nonzero. Workflow and tool pins are unchanged, so the live acceptance gate remains honestly failing.

## Independent checks

At the exact reviewed head, the following bounded suites passed together: `test_rzdiff_orientation_20261101.py`, `test_secondary_rzdiff.py`, `test_live_rzdiff_check.py`, `test_secondary_reconcile.py`, `test_secondary_evidence.py`, `test_calibration_runtime.py`, `test_evidence_view.py`: **179 passed in 4.17 s**. Focused Ruff passed; worktree was clean. These tests include authored fake executables and retained recordings and are not live compatibility acceptance.

No blocking source defect remains in this scoped quarantine. Integration atop the identity fixes requires its own combined tests because the reviewed branch intentionally contains only the small policy hunks in shared unified modules.

GT02 and native orientation acceptance remain open. A verified same-version preflight of the exact recovered input0 list is READY follow-up work using approved tools; JSON shape, row count, authored exports, Ghidra cardinality or a blanket side swap are not substitutes. No human DPI, frozen Windows, native comparator compatibility or broader gate completion is established here.
