# Verified Tier R shard transfer recovery — November 2, 2026

Source freeze: `7767fc9e27449f184f78b3ff9e9ab044c97af258`, on
`codex/verified-shard-transfer-recovered-20261102`, based on central checkpoint
`039c696c93a443d152d4ddc1383179408ff86b75`. This receipt records a newly restored
implementation and fresh tests. It does not adopt the erased worktree's earlier
250-test claim or any earlier native acceptance.

## Reproduction and scope

The preserved #78 branch was inspected at
`2019a37fa65fc37f4758469143c2daadc07e0098`; its transfer intent was selectively
reimplemented against the published `OutputStore.write_raw`, `finalize(reports)`,
`MANAGED_FILES` and `read_credited_outputs` API. Its flat loose-output transfer was
not copied over current managed replay behavior.

A fresh baseline reproduction executed the exact `shard.py` source from
`039c696` around the actual current evaluator CLI, using a constructed provider
that returned the wrong engine identity. The evaluator returned exit **1** and
`status=failed`; the baseline shard recorded `findings` and returned exit **0**.
The restored CLI regression now records `failed` and returns exit **1**. No
completion threshold or metric calculation changed.

The new path is actual `run_shard` -> actual evaluator CLI -> managed retained
outputs -> completed per-shard bundle -> actual `shard merge --artifacts` ->
`train.load_outputs(..., allow_legacy=False)`. Builders and providers in this
suite are constructed controls. No target binary, native engine, training fit,
locked final evaluation or probability promotion is executed.

`training_artifacts.py` copies only explicitly named evaluator reports, labels
named by completed builder summaries, and successful managed output references.
It checks ordered images, pair/provider/symbol metadata and managed version
bindings; exact report/label/output bytes and managed metadata get SHA-256
entries in a final exclusive manifest. Shard diagnostics bind pair-to-case
assignments before their digest. Merged ownership derives the source shard and
completed case from those bound assignments. Duplicate pair ownership is
refused, including identical bytes from separate shards.

Every lexical source and target component is checked for links/reparse points.
The consumer test for a Windows reparse **training parent** calls the actual
merge CLI and confirms no destination is published. This is a portable injected
attribute control, not native Windows acceptance. The separately owned Windows
handle/path-stat repair is not part of this source freeze.

Publication is exclusive and manifest-last. A partial destination remains for
diagnosis without transfer completion. Successful-reference enumeration never
adopts extra loose output files. Failed evidence in a source run does not become
training credit. Existing managed metadata size bounds remain unchanged;
aggregate-credit overflow is tested fail-closed with a reduced injected bound.

The workflow adds only transfer flags, step IDs and artifact handling. Completed
payloads are gated by fixed `verified_training=true`; diagnostics remain under
`always()`. Payload paths select fixed visible JSON directories with an
alphanumeric filename prefix and the exact hidden managed marker. No entire
training/scratch directory, unknown hidden file, image, binary or Tier W payload
is authorized. Triggers, runner matrix, timeouts, tool pins, calibration budgets
and thresholds are unchanged. Actual Actions archive creation was not run here.

## Fresh frozen-source verification

The following command ran on the clean frozen source above:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests \
  /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q \
  tests/test_tier_r_training_artifacts.py tests/test_tier_r_shard.py \
  tests/test_ci_summary.py tests/test_tier_r_credited_replay.py \
  tests/test_tier_r_output_persistence.py tests/test_tier_r_contracts.py \
  tests/test_tier_r_eval_cli.py tests/test_train_helpers.py
```

Result: **237 passed, 2 skipped, 3 warnings in 7.42s**. Both skipped controls
reported `LIVE ACCEPTANCE BLOCKED: tier-r-msvc-free`: clang, lld-link,
llvm-pdbutil, llvm-objdump, llvm-nm and llvm-strip were unavailable. The three
warnings are expected `LegacyOutputWarning` messages from existing tests that
explicitly exercise unverified legacy compatibility.

`PYTHONPATH=.:src:tests .../venv/bin/python -m ruff check src tests tools` passed;
`git diff --check` passed. The schemas command was regenerated, existing corpus
schemas had zero drift, and the new `TrainingManifest.json` has a regenerate-and-
compare test plus the actual CLI schemas control.

Controls cover exact bytes, both ordered image identities, provider/symbol/
version binding, status-ok-only credit, source extras, missing/changed data,
source links at every bundle component, source and destination parent reparse
attributes, exclusive reuse refusal, interrupted publication, aggregate credit
limits, duplicate builders/pairs, absent builder ownership, forged plan/shard/
case/report metadata, and deeply nested malformed report/manifest JSON.

Independent review of the moving draft found merged-case ownership and raw
`RecursionError` gaps. Both were repaired and included in this frozen run.
Independent review of the frozen commit is tracked separately by the coordinator.

## Remaining acceptance

Coordinator integration, required full combined Qt suite, native Windows and
real Actions artifact round-trip acceptance remain separate. The full corpus,
pre-lock review, source/pin/license growth, native lineage/OOD evidence, single-use
final CLI and guarded promotion gates are not completed by this transfer slice.
No remote branch, PR, workflow dispatch or final evaluation was mutated by this
worker; the coordinator owns review and remote integration.

## Frozen-review follow-up

The final implementation freeze is now
`bb892a2cc0c7053b73b2539c05e897e5e6c8f6bf` (the intervening `3c269be` is this
receipt only). Independent frozen review reproduced a raw `KeyError` for older
or corrupt diagnostic shards that lack the additive `pair_cases` map. The
transfer owner constructor now explicitly refuses absent ownership as a contract
error; the actual merge CLI returns usage exit 2 and writes no destination.

A further source inspection found that normalizing with `abspath` before
checking parents could hide a link preceding `..`, even though later filesystem
IO used the original path. Parent checks now preserve lexical components until
inspection, explicit producer paths are checked before normalization, and shard
diagnostic destinations get the same parent/leaf checks. Actual merge controls
cover both source and destination `linked/../...` paths and confirm no writes to
the intended or linked external destination.

The expanded command above reran on this exact implementation content:
**240 passed, 2 skipped, 3 warnings in 7.74s**. The same two native-tool BLOCKED
conditions and three expected legacy warnings remain. Whole-repository Ruff and
`git diff --check` passed. A post-commit rerun of the transfer test file passed **53 tests in 4.66s**
on the recorded final implementation SHA; the independent reviewer owns the
final review receipt. No schema, budget, threshold, trigger or matrix changed in this
follow-up.
