# Tier-W offline CLI recovery — 2026-11-19

## Scope and dependencies

This slice connects the existing sampler, human terminal workflow, audit
statistics and reviewed runner to `python -m tools.calibration.tier_w`.
The starting integrated snapshot was `3c6f59059b123499dcea15a559a5e41084214ec4`.
The paired-output runner repair `204b7cf12f9566f3b02c1e7dc497a593af0959a8`
was cherry-picked locally as `1c34e7c2`; this CLI slice does not edit `runner.py`
or its section 9 specification.

- `audit` validates the current corpus and complete label population, samples
  deterministically, derives body hashes/previews from verified PE inputs and
  publishes an exclusive key/queue pair. Identical reruns resume; incompatible
  prior audits are preserved.
- `review --annotator NAME` calls the existing terminal workflow. Strict queue
  admission recomputes the selected sides and binds the key, typed pairs,
  exact label bytes and symbol producer. Only terminal responses produce
  annotations. Logs bind both the exact key and queue, validate their chain,
  refuse mixed annotators and enforce byte limits.
- `audit-report` derives the existing population-weighted report from those
  verified inputs and annotations. Insufficient/weak review stays partial.
  Managed reports cannot silently survive changed populations or annotations;
  foreign/malformed prior reports are preserved.
- `run` uses the reviewed runner for explicitly configured symbols-hidden
  analysis. Filesystem-only backend checks precede project creation. Timeout
  bounds, CI refusal, existing project provenance and paired-output admission
  remain effective. A summary names the retained current-attempt record, which
  can differ from selected `run.json` after cancellation.

The three strict review profiles have generated schemas in
`docs/schemas/calibration/`. The existing calibration schema generator and its
freshness test include them.

## Verification

The final source selection passed **214 tests in 12.38 seconds** on the Linux
executor. The exact command, run from `pt-adapters`, was:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests \
  /workspace/scratch/792fd5ca6555/.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_tier_w_cli.py tests/test_tier_w_cli_admission.py \
  tests/test_tier_w_review_cli.py tests/test_tier_w_run_cli.py \
  tests/test_tier_w_runner.py tests/test_tier_w_runner_publication.py \
  tests/test_tier_w_labels.py tests/test_tier_w_audit.py \
  tests/test_calibration_tools.py::test_schemas_render_and_committed_copies_are_current \
  --junitxml=/workspace/scratch/792fd5ca6555/tier-w-offline-cli-final.xml
```

The log is `tier-w-offline-cli-final.log` at the task root. Scoped Ruff and
`git diff --check` passed. Schemas were regenerated with
`PYTHONPATH=.:src python -m tools.calibration.schemas`; existing schema files
outside the three additions did not change.

Controls use self-made PE/PDB fixtures, real project stores and real publication
paths. Engine results and terminal responses are explicitly authored test
boundaries. These are neither native compatibility results nor human-reviewed
Tier-W calibration evidence.

Before wiring, the new review controls produced 13 failures and 7 passes; the
new run controls produced 14 failures and 1 pass. During implementation,
additional controls first demonstrated and then closed:

| Controls | Demonstrated missing behavior |
| --- | --- |
| 7 | Current binary/label/population binding, prior report ownership, aggregate label-input budget and pre-append log budget |
| 5 | Actual queue RVA/hash/preview/image-byte verification and typed cancellation during held-image admission |
| 3 | Hard-linked append/report write refusal, foreign alias permission preservation and cancellation between key/queue publication |

These development red results distinguish absent CLI functionality and defects
in the initial adapter implementation; they are not additional claims against
the already-reviewed runner or the earlier repository baseline.

## Limits and open acceptance work

Symbols-visible analysis remains BLOCKED because its online symbol policy has
no reviewed CLI consent route. Catalogue/resolve/fetch network adapters remain
separate work. No target image, native analysis engine, online transport or
Microsoft corpus was executed by these tests. Native Windows and Ghidra
qualification remain open.

Annotation appends and replaceable reports remain a local single-writer
workflow. Observed links, hard links, reparse/nonordinary files and foreign
contents are refused where admitted, but the generic append/report writers do
not close the final concurrent pathname replacement race. The chain is an
integrity/binding check, not an authenticity signature. No broader hostile-parent
publication guarantee is claimed. Key and queue publication is not an atomic
two-file transaction: cancellation can retain a valid key for exact resumption,
and incomplete pairs are not reviewable. The runner's separately documented
selected-output and retained-history limitations still apply.

The root integrator owns global QA/todo/module-index updates. This receipt is
bounded evidence for this source selection, not a full-suite or release gate.

## Exact source SHA-256 values

| Path | SHA-256 |
| --- | --- |
| `tools/calibration/tier_w/cli.py` | `74a325e5ca642d8c7c84b7cfb97ed76b8ad5eb6a76099fe384b45e21e86329c3` |
| `tools/calibration/tier_w/review_cli.py` | `1ef5c5adf7af81dc57ec8c8ad7ca5768ace723495db481c96c5c042be62d4fcf` |
| `tools/calibration/schemas.py` | `4b7e119da6f5c621115cc2ce44615e45971a4311af68211a683eac7f0de3df4f` |
| `tests/test_tier_w_cli.py` | `6fab14cce3b66db81559956823931c6c519f753c4d12d545702e08f46f3f0e11` |
| `tests/test_tier_w_review_cli.py` | `1ae9621e0e3655ec3a0f94ccbdedc152eec13451807651e74f4a6d70724170a2` |
| `tests/test_tier_w_run_cli.py` | `dcadc438695673726af0acba3c84e00062813850637867dd86edef43d4e20b88` |
| `tests/test_calibration_tools.py` | `a5c7224ea5330e95745c421e0619f613e0a1b8a975f9809993224de28f2ee86c` |
| `docs/specs/tier-w-local-corpus.md` | `83aa91680fa1e7ece78764c820b0451a66c0a4a6f8d6badb5a23d466cc639726` |
| `docs/schemas/calibration/AuditQueueHeader.json` | `d8d10cd89fc85c222da9ce86d86799796aae5cdc9bb56cb1ae5568a556af7865` |
| `docs/schemas/calibration/AuditQueueItem.json` | `f57642e75356a57be058154408c4286151442df52a512a91d2bb0aba3a368321` |
| `docs/schemas/calibration/AuditAnnotation.json` | `391fe58477473aeed6126ca6ac22b05ea0c2d9e5b10ad42bda3aa4597231fed6` |
