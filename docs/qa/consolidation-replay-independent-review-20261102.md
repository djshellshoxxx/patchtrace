# Independent replay/schema integration review — 2026-11-02

Reviewed immutable commit: `1b23201527fb13b17384e3a8aa94cd08c3869517`.
Tree: `53a0f7faaa75db2ff814942f4cfdfa35760033f0`.
Parents: `ca80cc0f310ad1a82174cd17ee1fa8443b016b73` and
`5cdbd968e77c34dd4194ffe3cc35f42de6df24d3`.

Verdict: **approve this bounded merge; no blocking findings**.
Review used immutable Git objects and an independent `git archive` at
`/tmp/patchtrace-replay-review-1b232015`. The author's moving checkout and remote
state were not modified. This is local integration evidence, not a GitHub
review action, native Windows acceptance, or release approval.

## Source and receipt preservation

The incoming replay/schema branch changes 44 paths against its `63d11d3` base.
Of those, 38 are byte-identical in the reviewed merge, including all incoming
replay/metadata QA receipts, the six affected schemas and attention example,
all five incoming replay test files, and contracts/evaluator/output-store/report
schema implementations. The six remaining paths are the merged module index,
QA appendix, corpus specification, delivery tracker, CLI, and training module.
Their differences retain candidate transfer/schema CLI wiring and preregistration
selection while preserving the incoming metadata propagation.

Candidate `training_artifacts.py`, `shard.py`, `prereg_gate.py`,
`test_tier_r_training_artifacts.py`, and `test_train_prereg_selection.py` are
byte-identical to the first parent. The transfer writer still invokes the shared
credit-manifest preflight before `_fresh(root)`, so known aggregate overflow
does not create a transfer destination. Exact-byte ownership, managed completion,
and manifest-last publication remain together.

Every nonblank line, with multiplicity, from both parent QA appendices and the
intact candidate tracker survives in the merged files. Independent replay
tracker reconstruction followed the recorded base64-prefix removal and damaged
range replacement. Its SHA-256 matched the receipt exactly:
`c4da3814ced0abf01abd8685252dc4b0bc078dfce125f5fadcc2d48fb4a2c04b`.
Every nonblank reconstructed line survives with multiplicity. The actual replay
merge base is `63d11d316c70e1f1e83baa80acabd3cf3c4c2245`, as recorded.
Text that existed only in the previously truncated span remains unknowable;
the recovery receipt states this limitation.

## Runtime and schema checks

All 17 generated schema renderings matched committed files: seven calibration,
five corpus, four normalized-output/completion, and one training-transfer schema.
An independent boundary control accepted and preserved 4,096-character names
and order keys and 1,024-character versions across normalized-output parsing,
wrong-match rows, credits, and training engine provenance. All eight one-character
over-bound controls were refused. Output and credit aggregate caps remain 64 MiB.

## Independent execution

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q \
  tests/test_tier_r_credit_completion.py \
  tests/test_tier_r_credited_replay.py \
  tests/test_tier_r_output_persistence.py \
  tests/test_tier_r_output_stat_compat.py \
  tests/test_tier_r_training_artifacts.py \
  tests/test_tier_r_eval_report.py \
  tests/test_train_pipeline.py \
  tests/test_calibration_tools.py::test_schemas_render_and_committed_copies_are_current
```

Result: **238 passed, 1 skipped, 11 warnings in 34.17s**. The single skip was the
explicitly blocked Clang/LLVM native fixture; the warnings were expected
`LegacyOutputWarning` compatibility-boundary observations. The console is
`/tmp/patchtrace-replay-independent-1b232015.log`.

Whole-tree Ruff and the immutable first-parent whitespace check passed. The
author's stored receipt archive was also inspected: its console and JUnit agree
on 237 passed, one skipped, zero failures/errors, and Ruff passed. Those earlier
counts overlap this independent run and are not additive.

## Limits

No real corpus, target execution, external analysis engine, or locked evaluation
was used. Native Windows and the eventual fully assembled candidate's complete
Linux/Windows and hosted gates remain separate. Approval applies only to the
exact commit/tree above and the bounded replay/schema merge; later integration
changes require their own applicable checks.
