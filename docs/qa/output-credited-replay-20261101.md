# Credited normalized output replay repair, 2026-11-01

This bounded follow-up to PR #157 starts at published `99660cc825b366a28e50b18eacad44dbb069ca69`
(tree `5636d45531a73deb522935712307588951a2e282`). All controls use constructed inputs;
no real corpus, final evaluation, native accuracy or promotion was consumed. The
author subset performed no training fit; the independent reviewer also ran the
existing bounded synthetic training-pipeline regressions.

## Reproduced defects and repaired boundary

The independent original repro accepted incompatible `[1]`/`['first']` ordering keys
through the strict schema and actual `train.load_outputs`, then ranking raised
`TypeError`. A valid JSON mutation after publication was correctly reported failed
with no digest, but the actual reader adopted that failed artifact. A 513-character
invalid name was encoded before schema rejection; this tiny control proves ordering,
not an out-of-memory event. The same invalid producer name succeeded in memory but
failed with retention because the existing strict limit was 512 characters.

Provider documents now receive strict scalar/array validation before encoding and
scoring. Effective flagged ordering keys follow the actual dedupe/fallback scorer,
so comparable heterogeneous lexicographic prefixes remain accepted. No scorer,
model, feature engine or existing name/version bound changes. In-memory unified
support uses a private validation vocabulary; retained output/credit schemas still
exclude unified. A real UnifiedProvider regression first failed, then passed this
compatibility repair without changing hashes or scoring.

New run directories receive a managed marker before any provider output. After
report assembly, an immutable credit manifest embeds digest-checked reports and
binds each unique successful pair/engine reference to exact canonical raw bytes,
ordered image hashes, symbols and version. Finalization and the actual reader both
reverify bytes and ownership. Failed files remain inspectable but uncredited.
Incomplete, missing, linked, unreadable, ambiguous or altered managed evidence fails
closed, including when selecting one run. Parent directories are not implicit run
selections. Transfer can use `OutputStore.write_raw`, `finalize`, `MANAGED_FILES` and
`read_credited_outputs` without a second replay format.

Existing unmarked directories, including runs made by the original #157 writer,
remain **unverified legacy compatibility**, with `LegacyOutputWarning`; callers may
refuse them with `allow_legacy=False`. Their historical success cannot be inferred.
Removing all managed metadata by the filesystem owner is outside this local
integrity claim. There is no signature or hostile same-user filesystem lock.

## Verification

Initial new focused controls: **11 failed, 4 passed** in 1.32 s. The compatibility
control additionally reproduced the unified regression (**1 failed, 1 passed**).
Final bounded selection: **237 passed, 2 native-tool BLOCKED skips**, 5 expected
legacy diagnostics in 4.70 s. It includes actual default/explicit CLI retention,
production AttentionProvider/ranking/loader replay, unchanged no-key fixture bytes,
strict producer controls, report/credit substitutions, metadata failures, transfer
API multi-report ownership, failure preservation, and existing scoring/contracts.

```
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q --tb=short \
  tests/test_tier_r_credited_replay.py tests/test_tier_r_output_persistence.py \
  tests/test_tier_r_eval_cli.py tests/test_tier_r_eval_report.py tests/test_tier_r_eval_metrics.py \
  tests/test_evalcore_engines.py tests/test_evalcore_scoring.py tests/test_evalcore_report.py \
  tests/test_evalcore_unified.py tests/test_tier_r_contracts.py \
  tests/test_train_pipeline.py::test_visible_symbol_outputs_and_duplicates_are_refused \
  tests/test_train_deferred.py::test_dedupe_is_order_independent_and_counts_the_dropped_duplicates \
  tests/test_train_deferred.py::test_scorer_views_ignore_provider_order_and_the_report_carries_a_warning
```

Whole-tree Ruff, `pip check` and diff hygiene pass. Schema generation adds only
`OutputCredits.json`; persisted EngineOutputDoc and existing report examples are
byte unchanged. The isolated interpreter is `venv-output-replay/bin/python`,
installed editable from this worktree; no shared environment was rewritten.
Raw log/source hashes are recorded in the companion JSON receipt. Full-suite,
independent final review, cross-OS and transfer integration remain pending. Broader
GT05 corpus growth/source/pin/license, both-side recipe controls, pre-lock/native
lineage/OOD, single-use-final CLI and guarded promotion remain open.

## Independent review disposition

Independent reviewer `ci_review` approved source
`5c26af904a28dd41aaacb3a60f9826037a85980d` / tree
`f57a7dd2c210b773956bf218ad088295a03f93ff` with no remaining blocker.
The reviewer separately ran **119 passed, 1 native-tool BLOCKED skip**, 11 expected
legacy diagnostics in 26.55 s (credited replay, persistence and existing synthetic
train-pipeline regressions), direct strict scalar and post-link valid-JSON mutation
controls, generated-schema equality, scoped Ruff and diff checks. The valid failed
artifact remained present and the strict managed loader adopted zero outputs.
The independent receipt embedded in the companion JSON is a reviewer summary of
observed outputs, explicitly not a saved raw command log. This supersedes only the
pending independent review above; integration, cross-OS, verified transfer and
broader GT05 safeguards remain open. Source and test bytes are unchanged by this
receipt follow-up.
