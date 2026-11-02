# Full replay/schema branch integration — 2026-11-02

This merge starts at local combined candidate
`ca80cc0f310ad1a82174cd17ee1fa8443b016b73` and integrates the complete local
replay/schema branch `5cdbd968e77c34dd4194ffe3cc35f42de6df24d3`.

## Published and local identities

| Role | Published commit | Local commit | Shared tree |
|---|---|---|---|
| Latest PR #157 source | `dac9b89a297f428bdcf364b4be37a448a5b2ce4e` | Snapshot `9017fc0f583505177452ef9c279f51acc36d7161` | `e0428d6cc7ce7a29cf3b7a835666edac47da6857` |
| PR #160 schema follow-up | `ca411e77f43a9fd95ca5e0bcc7d2b58071ccae37` | `5cdbd968e77c34dd4194ffe3cc35f42de6df24d3` | `0b644486ec1d2b3e94bacc55e85cce7a7c5dd83c` |

The published follow-up commit, its parent and tree were read through the GitHub
connector. The local snapshot has parent
`63d11d316c70e1f1e83baa80acabd3cf3c4c2245`; its commit identity and ancestry are
explicitly different from the published source. The local merge retains the
whole source tree and its receipt additions, not just the final schema edit.

## Conflict decisions and evidence

- The latest shared bounds are retained: names and string ordering keys at
  4,096 characters, engine versions at 1,024. Their values propagate unchanged
  into wrong-match report rows, output credits and training feature rows. Values
  beyond those bounds still fail before adoption; sorting is not truncated.
- Replay contracts, normalized-output validation, evaluator and output-store
  implementation match the replay/schema branch byte-for-byte. Candidate shard
  transfer implementation and its tests remain byte-for-byte unchanged. Managed
  completion, exact-byte credit and manifest-last transfer safeguards coexist.
- `EngineOutputDoc.json` and `OutputCredits.json` were regenerated from the
  merged models. All corpus, calibration and training-transfer schema renderings
  match their checked-in files, including the corrected `PairRows.json` bound.
- Latest metadata acceptance/rejection and propagation tests, completion and
  Windows-stat receipts, and both QA/tracker histories are retained.

The replay branch repeats the published tracker corruption pattern. Its binary
blob `86a77e4494af03b964f54c2b970c3d5839f982bc` yields two readable new sections
after removing the exact encoded truncation-warning prefix. The damaged middle
is restored from the actual merge base `63d11d3`; every nonblank line from the
candidate and reconstructed replay tracker is retained with its multiplicity.
`combined-replay-tracker-recovery-20261102.json` records exact identities, hashes,
range and recovery limits. Text lost inside that earlier truncation is unknown.

This commit also corrects the earlier current-main recovery receipt's base label:
its actual merge base was `25c9795bd9cd58bfad855f30594ee3a0c7584cec`, while
`63d11d3` was the snapshot parent. The recovered blob, restored range and source
changes were correct; their bytes are unchanged by this documentation correction.

## Validation

The seven-file replay/completion/transfer/report/constructed-training selection
passed **237 tests**, with **1 native-tool BLOCKED skip** and 11 compatibility
warnings, in 33.60 seconds:

```text
tests/test_tier_r_credit_completion.py
tests/test_tier_r_credited_replay.py
tests/test_tier_r_output_persistence.py
tests/test_tier_r_output_stat_compat.py
tests/test_tier_r_training_artifacts.py
tests/test_tier_r_eval_report.py
tests/test_train_pipeline.py
```

The command used `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests`. The native
fixture was blocked because the Clang/LLVM toolchain is absent; it is not native
acceptance. Legacy-output warnings retain the unverified-compatibility boundary.
Whole-tree Ruff and whitespace checks passed. Console, JUnit and Ruff receipts
are in `combined-replay-integration-20261102.tar.gz`.

No real corpus or locked evaluation was consumed. Full immutable integration,
native Windows execution and exact-head hosted gates remain root-owned work.
