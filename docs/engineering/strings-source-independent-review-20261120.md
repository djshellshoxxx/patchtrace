# Independent review: current stored Strings evidence and cache provenance

Reviewed on 2026-11-20 by a fresh worker that did not author or integrate the repair.

## Decision and source

**Accepted for this bounded repair; no blocking finding identified.**

Reviewed source/specification/test commit:
`cf71c457665092b11448c6515c33360f68a590dd`. The subsequent observed head,
`9ea3797fc857b396336fcfc519278c165e30f9b9`, adds the author's evidence only.
The reviewer verified an empty `git diff cf71c457 -- src tests` and a clean
worktree after testing. Exact source and evidence hashes are recorded in
`strings-independent-review-source.json`.

The recovered helper and maintained helper tests retain donor blobs
`ae64016dc65d575d649aafae1264d15d6d434e3c` and
`626e95da8297eea959d7c9b0344e1e32eecc3e4d` from
`2042e24dc7f3eac265e0eb183c738527852b22cf`. The integration changes only the
existing Strings CLI selector to consume that helper. It does not import the
donor's broad Strings composition or Search wiring.

## Review findings

The prior selector asked `ToolStore.latest` for an engine and side without
binding the result to the current artifact hash. It also required a raw sidecar
on the selected run itself, although valid cache-hit attempts intentionally have
no new raw sidecar. These are distinct defects: stale orientation labels and
unnecessary loss of a valid cached source.

The new opt-in helper retains the original Entry metadata and JSON, chooses the
newest produced matching engine/side run, and checks the current project/artifact
guard before returning evidence. A different current artifact is refused,
including after orientation changes. Selected run, evidence and cache-origin
rows must agree on their ownership, state, identity and configuration fields.
Refusal does not silently select an older produced record. Ordinary failed
attempts preserve the existing newest-produced selection rule.

Cache selection filters by side before admitting its evidence. The helper then
admits the originating run named by the evidence, so the Strings basis retains
that original run's recorded tool identity and raw provenance. The CLI maps an
unavailable stored source to the existing behavior: Auto can use the verified
built-in scan, while explicit FLOSS selection refuses.

The caller still verifies the current artifact bytes through its existing image
inspection path before selecting a source. Comparison, cue generation, ranking,
function linking, export publication and Search/dock behavior are unchanged.
The existing `ToolStore` readers and sidecar loader are unchanged; this review
does not treat the helper as comprehensive hardening of those shared facilities.

The reviewer inspected the prior selector, runner cache behavior, strict model
validation, storage ordering/guards and the downstream Strings source/basis
conversion. The author's eight failing baseline controls were not independently
rerun; they remain separate author evidence. The current-source executions below
were performed independently.

## Independent verification

Environment: Linux, CPython 3.12.14, PySide6 6.12.0, offscreen Qt, with
`PYTHONPATH` explicitly selecting the Strings worktree's source.

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_intel_tools_admission.py \
  tests/test_strings_stored_source_admission.py \
  tests/test_strings_cli.py \
  tests/test_strings_sources.py \
  tests/test_intel_tools_runner.py \
  tests/test_ui_strings_run.py
```

Result: **97 passed in 11.97 seconds**, no failures or skips. This covers the
maintained new regressions and existing CLI, source conversion, runner and
controller behavior. JUnit: `strings-peer-suite.xml`.

Two additional independent history-selection controls use the actual store and
authored producer fixtures:

1. Publishing a later unsuccessful attempt leaves the preceding produced source
   selected.
2. Publishing a new produced attempt without its evidence refuses; it cannot
   reuse older output, and the failed read leaves the database unchanged.

Result on the final peer-control file: **2 passed in 0.73 seconds**, no failures
or skips. Executable controls: `test_strings_peer_history.py`; JUnit:
`strings-peer-history.xml`. These two controls are separate from the 97-test
selection. Earlier author runs and this peer rerun overlap and must not be added
together as distinct test coverage.

Scoped Ruff passed for both production files, both maintained test files and the
peer controls. No source or remote repository state was modified by this review.

## Limits

All producer inputs and results in these tests are synthetic; the producer is an
authored test program, and analyzed PE files are never executed. This does not
qualify native FLOSS or establish an empirical accuracy result. Raw sidecar paths
and hashes remain recorded provenance, not a claim that this helper rereads raw
bytes. Whole-candidate CI, native Windows, packaging, accessibility and the
separately documented Linux forced-export race remain outside this approval.
