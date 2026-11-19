# Verified Tier R transfer recovery — November 19, 2026

## Source and integration boundary

This slice recovers the missing LBL-31 transfer path from preserved checkpoint
`c13d3257c88140c23fb585a8a59a4dce81e81928`. That implementation supersedes the
original `17576698` / `6808f438` / `0843de5f` loose-file transfer and already uses
managed output credit, exact source reports, explicit builder pair ownership,
credit-manifest preflight, parent/link checks, and exclusive final manifests.
The repository's MIT-licensed implementation was selectively adapted; the
checkpoint's unrelated older workflow, diagnostics, and schema bounds were not
restored. Historical test receipts are not proof of this recovered tree.

The current evaluator remains the producer. The integration is:
`run-shard --collect-artifacts` -> actual evaluator CLI -> managed output run ->
verified shard bundle -> `merge --artifacts` -> fresh managed merged output run ->
`train.load_outputs(..., allow_legacy=False)`.

The aggregate shard remains separate from per-function JSON. Transfer validates
exact report/label/output bytes, ordered image identities, provider, symbols and
version ownership. Completed manifests bind plan/shard/case assignments and
managed metadata. Current action/tool pins, triggers, matrices, Windows jobs and
A/A failure precedence remain unchanged. Upload payloads explicitly select JSON
and the one managed hidden marker; diagnostics remain independently retained.

Without transfer, the newer recognized-exit-1 diagnostic policy remains intact.
Only the opt-in transfer path treats declared failed/error builders and evaluators
as failed on exit 0 or 1, so incomplete producing cases cannot acquire ownership.
This recovery does not add the originally proposed training dispatch or fit job.

## Reproduced defects and repairs

| Finding | Control before repair | Repair |
|---|---|---|
| A refused transfer rerun overwrote the earlier shard diagnostic, breaking the completed bundle's owner binding | Actual CLI rerun: 1 failed, 7 passed | Transfer-mode diagnostic publication is exclusive. Existing diagnostic and completed bundle remain usable; legacy no-transfer behavior is unchanged. |
| Inventory comparison materialized arbitrary extra directory contents before refusal | Independent review finding; 8 lazy-iterator controls failed across root/labels/outputs/reports and unknown/repeated entries | Consume only expected names, refuse an unknown/repeated name immediately, and reject missing names at exhaustion. The bound is expected entries plus one. |

Both repairs are specified before implementation. The lazy iterator controls use
finite guarded generators to demonstrate early refusal; they allocate no large
directory and are not native filesystem performance measurements.

## Fresh verification

On the final implementation bytes listed below:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python -m pytest -q -p no:cacheprovider \
  tests/test_tier_r_transfer_integration.py tests/test_tier_r_training_artifacts.py \
  tests/test_tier_r_shard.py tests/test_tier_r_exit1_diagnostics.py tests/test_tier_r_aa_failures.py \
  tests/test_ci_summary.py tests/test_tier_r_credited_replay.py tests/test_tier_r_output_persistence.py \
  tests/test_tier_r_credit_completion.py tests/test_tier_r_eval_cli.py tests/test_train_helpers.py
```

**370 passed, 2 skipped, 3 expected legacy-compatibility warnings in 18.66s.**
The two blocked native checks require clang, lld-link, llvm-pdbutil, llvm-objdump,
llvm-nm and llvm-strip. These tools were not present. The three warnings are from
existing controls that deliberately select unverified legacy loose output files.
Earlier overlapping runs are not added to this result.

Scoped Ruff and `git diff --check` passed. Generated training schema bytes are
checked against `write_schema`; the actual CLI schema path remains covered by
the focused selection. The actual transfer/evaluator/merge/reader integration
uses authored builders and providers. No target binary, native engine, training
fit, workflow dispatch, locked final evaluation or probability promotion ran.

The workspace logs are `tier-r-transfer-rerun-red.log`,
`tier-r-transfer-inventory-red.log`, and `tier-r-transfer-reviewed.{log,xml}`.

## Implementation SHA-256 receipt

| Path | SHA-256 |
|---|---|
| `tools/calibration/tier_r/training_artifacts.py` | `33b043eb7d6fef22958b94c6fad87dc97eced2d97f00cae8efd6afcb47eeeb29` |
| `tools/calibration/tier_r/shard.py` | `ef340fb9d39b9c19f026d47c18362f771a00129650321c412d0006beb6df1e6c` |
| `tools/calibration/tier_r/cli.py` | `39a8bf8ba4063676abc748002ce1c842eb6fd5db7469f72fa0c6f5e949b09553` |
| `.github/workflows/corpus-tier-r.yml` | `8df48daa6eeba062c917dfa4b4f6361757f67d51db2eb1ae018591daeffc2a9f` |
| `docs/schemas/corpus/TrainingManifest.json` | `2de1fd6e33b748fa13e6d0d26f6b4e9288daea703e728f5dca24a179ad2c3b27` |
| `tests/test_tier_r_training_artifacts.py` | `76b91a4d4cc685f7cc10a33235b103ba393495f84269b6b7f87579dfe06cde2e` |
| `tests/test_tier_r_transfer_integration.py` | `dd8c21e35deb66b180df9dfeadafa2c2cdb66f3c219f0272d2fdf4d3525bb71f` |
| `tests/test_ci_summary.py` | `809b03853522bfa71b4c484ace0663161cca0741052e3312bf7e21ba72e9be5b` |

## Remaining acceptance

The coordinator owns combined-source CI and publication. Real Actions artifact
archive round-trip and native Windows qualification remain unverified by these
Linux constructed controls. This is bounded local integrity verification, not
an authenticity signature, a lock against arbitrary same-user mutation, or a
power-loss durability claim. The current OutputStore publisher is reused as-is;
this slice does not qualify its named-stage cleanup against adversarial pathname
races. Full corpus, lineage/OOD evidence, pre-lock and final-evaluation gates are
separate.
