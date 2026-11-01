# Tier R normalized output retention — November 1, 2026

This is the bounded persistence portion of GT-05/#78, based on coordinator
checkpoint `06b56a69320ce289cd0d1fb62675b4dc5b148fca`. It does not complete
verified shard/merge transfer, corpus growth, native evaluation, final-look or
numeric-confidence acceptance. All exercised labels, responses and imports are
constructed controls. No private/Tier W data or actual corpus was read.

## Source and contract reconciliation

Preserved #78 head `2019a37fa65fc37f4758469143c2daadc07e0098` contains
`output_store.py` and `training_artifacts.py`; neither exists at this candidate's
base. Its LICENSE was inspected: MIT, Copyright 2026 Circuit Drift Labs. The
repository retains the same license bytes; the companion JSON records source
and license hashes. This is selective adoption of the retention contract and
filename convention, with a new non-replacing publisher. The old writer's
check-then-`os.replace` sequence and adoption of an existing empty directory are
not carried over. Its older duplicate-scoring implementation and unrelated
training/mutation/read-model changes are not imported. Original author refs
remain intact; branch activity/ownership is not inferred.

Baseline `evaluate_full` returned a normalized output digest but no corresponding
document; the real CLI only wrote the report and Markdown. The first three
regressions reproduced **3 failures** in 1.30 s: missing document behind the
actual CLI digest, a provider credited under a foreign response identity, and
duplicate provider ownership accepted. The initial repair passed **29 tests**
with **2 native-tool skips** in 2.02 s.

The next synthetic check used the actual production AttentionProvider and exposed
an existing schema mismatch: `attention` and its already-emitted `order_key`
were not accepted by the strict output schema. With only the engine vocabulary
extension, **19 tests passed and 1 failed** in 0.87 s. The spec-first repair adds
that kind and an optional bounded tuple of strict integer, finite float or
bounded string keys. Production attention uses one integer rank. Existing
documents, missing-key omission and canonical bytes retain their meaning. This
is an additive `/1` field/kind extension, not universal reader compatibility:
older strict readers reject the new kind or field. Only EngineOutputDoc and its
owned example were regenerated; scorer/default/model behavior is unchanged.

## Resulting boundary

- CLI evaluation defaults to a fresh exclusive `<selected-store>/outputs/<run>`
  directory. `--outputs` can select a different nonexisting directory; existing
  empty directories, files, links and previous runs are refused before providers
  execute. The library API retains its in-memory default and requires an explicit
  `output_dir` for persistence.
- Each successful report reference hashes the exact original normalized JSON
  bytes, with ordered image hashes, symbols, engine/version and prediction keys.
  Validation does not replace bytes with model defaults or coerced values.
  Serialization is capped at 64 MiB; filenames bind pair and provider identities.
- A private stage is flushed/fsynced and atomically hard-linked without replacing
  an existing artifact. Unsupported hardlinks, permission/fsync failures,
  changed file bytes/identity or changed run-directory identity produce a failed
  pair with no digest, metrics or successful-run credit. Earlier outputs remain.
  There is no weaker publication fallback. This is not a lock against arbitrary
  same-user hostile activity or a claim of universal power-loss durability.
- JSON reports and Markdown are also published exclusively. Repeated evaluations
  retain identical report bytes/digests at distinct default paths. An explicit
  report-path conflict preserves previous bytes and completed outputs; the CLI
  returns the complete computed report and actual output path in its error
  summary. These are separate publications, not a multi-file transaction.

## Bounded verification

Final focused command (own editable worktree/interpreter):

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_tier_r_output_persistence.py tests/test_tier_r_eval_cli.py \
  tests/test_tier_r_eval_report.py tests/test_tier_r_eval_metrics.py \
  tests/test_evalcore_engines.py tests/test_evalcore_scoring.py \
  tests/test_evalcore_report.py \
  tests/test_train_deferred.py::test_dedupe_is_order_independent_and_counts_the_dropped_duplicates \
  tests/test_train_deferred.py::test_scorer_views_ignore_provider_order_and_the_report_carries_a_warning
```

The first expanded suite passed **164 tests, 2 skipped in 2.96 s**, using an inline
reconstruction for the replay check. Independent review then found the existing
production `train.load_outputs` reader discarded `order_key`. The actual-reader
regression failed **1 test in 0.72 s**, with a retained rank `(1,)` replaying as
the default `(inf, 'C')`. The narrowly approved correction passes `p.order_key`
through the existing prediction constructor; no other training function changes.
The final control uses two production attention ranks and the real reader, then
compares complete scorer views and report bytes. Attention remains excluded from
the calibration feature-engine set, as the control also verifies.

Final source: **164 passed, 2 skipped in 3.09 s.** The two skips explicitly report live/native
acceptance BLOCKED because clang/lld-link and the required LLVM inventory tools
are unavailable on PATH. No native engine or real model accuracy is credited.
Whole-repository `ruff check src tests tools` and diff hygiene pass.

Controls cover the real CLI default and explicit paths, the actual production
attention import/enrichment/ranking path with constructed code, exact replayed
ranking/scoring/report bytes, immutable old no-key fixture digests, Unicode and
omitted-default byte preservation, invalid/nonfinite keys, filename containment,
race-created destinations, hardlink/permission/fsync failures, second-pair
failure retaining the first output, and output-directory identity replacement.
The scorer and duplicate rules retain their existing dedicated checks. Raw logs
are preserved, hashed and compressed into the companion JSON; production file
hashes identify the tested source. Independent review and coordinator integration
remain pending at this commit.

## Still required

Verified output/label transfer through actual shard and merge consumers is a
separate #78 requirement; this slice does not import `training_artifacts.py` or
modify shard/workflow/pilot/receipt helpers. All growth source/license/pin audits,
both-side recipe A/A/noise, pin-provenance collision decisions, pre-lock/native
lineage and OOD acceptance, final CLI lifecycle/single-use lock wiring, and guarded
promotion remain open. No frozen protocol, fitting/grouping/scoring rule or
feature engine was changed. The only training-source edit preserves the
already-produced prediction field in the output reader. No final evaluation was
consumed and no numerical confidence was promoted.

## Independent review complete

Reviewer `cancel_fix` cleared source `ad35469860d402c4dfa86f041be3ce6996323465`,
tree `bb7bd51dc64b08cc6fd33d8d7c90f4bf72b47841`. Its independently tested eight-file
hash map matches that clean commit. The reviewer ran **164 tests passed, 2
native-tool BLOCKED skips in 3.30 s**, plus separate actual CLI/two-rank production
reader replay, exact baseline no-key decoder comparison, foreign image/symbol
refusal, descriptor-open failure, unsupported-hardlink failure and descriptor
leak controls. Scoped Ruff and diff hygiene passed. The reader finding is closed;
no remaining concrete blocker was found within this narrow scope.

The companion JSON includes the independent receipt, hashed raw red/green logs
and control script. Tests ran before documentation/commit finalization and were
bound to the exact source hashes; they are not represented as a later rerun.
This evidence-only follow-up changes no tested source. It supersedes the pending
independent-review statements above; integration/cross-OS and every remaining
requirement listed above stay separate.
