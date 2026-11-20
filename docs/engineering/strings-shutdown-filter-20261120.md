# Strings filter callbacks after shutdown

## Confirmed defect and uniqueness

Base commit: `5cc3f2a540f2e49e8b86e20decf7d4f62ce89d0a`.
The Strings controller stops its current tasks and marks itself closed during
shutdown, but its filter callback previously admitted new `strings-view` work
without checking that closed state. A filter-control callback already queued
before shutdown could therefore start new work afterward. When the host had
also shut down its shared task runner, the callback raised
`RuntimeError: TaskRunner is shut down` in the Qt event loop.

The defect is present in the current candidate. A retained-history search with
`git log --all -G 'def _refilter|def shutdown|strings-view' --
src/patchtrace/strings/qt_panel.py` identifies the original `fc2c86d9` panel
implementation; it found no later change to these lifecycle methods. The
previous Search debounce repair changes a different controller and cannot
prevent this Strings callback. The relevant source, tests, and specification
also have no intervening differences between this base and the coordinator's
`9fdb02ab` publication checkpoint inspected during this work.

## Narrow repair

The WB3 contract now requires closing admission of filter-preparation work when
the controller shuts down. `_refilter()` returns immediately when `closed` is
set. The existing current-generation and project-key checks still reject earlier
results. No scan, parser, matching, persistence, export-publication, or external
tool behavior changes.

## Regression and verification

`test_shutdown_refuses_queued_filter_work` loads synthetic rows into the actual
offscreen Qt panel, queues a filter-control change, shuts down the controller,
and then processes the queued callback. Its two cases keep the shared runner
open or close it in the same order as the panel host. Both require no new task,
no Qt callback exception, and unchanged loaded rows.

On the unchanged base source, both cases fail because `strings-view` is
submitted after closure. The closed-runner case additionally records the
actual Qt traceback above. The durable baseline replay first verifies that
the complete production source is byte-identical to the base commit, then
restores the repair in a `finally` block. Its source/test hashes, commands,
return codes, and raw output are retained in
[`evidence/strings-shutdown-20261120/receipt.json`](evidence/strings-shutdown-20261120/receipt.json).

Results:

- Baseline lifecycle cases: **2 failed in 1.10s**; raw output in
  [`baseline.log.gz`](evidence/strings-shutdown-20261120/baseline.log.gz).
- Repaired lifecycle cases plus the positive ordinary-filter control:
  **3 passed in 0.98s**; raw output in
  [`focused-green.log`](evidence/strings-shutdown-20261120/focused-green.log).
- Affected Strings panel, Strings run-controller, and shared task-runner suite:
  **96 passed in 13.60s**. This selection includes the new lifecycle cases;
  the three-test replay is additional evidence, not an added test count.
- Ruff for the changed Python files passed. The author reported a whitespace pass before all evidence was included; independent complete-range verification later found ten trailing-whitespace lines in the raw failure log. The artifact correction below preserves every original byte.

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_ui_strings_panel.py \
  tests/test_ui_strings_run.py \
  tests/test_gui_tasks.py
python -m ruff check src/patchtrace/strings/qt_panel.py tests/test_ui_strings_panel.py
git diff --check
```

Testing used CPython 3.12.14, the repository development environment, and an
explicit `PYTHONPATH` pointing at the isolated worker source. These results are
Linux offscreen lifecycle evidence. Independent review, current-candidate CI,
and native desktop qualification remain separate. No merge or release is
claimed by this scoped repair.

## Independent review and evidence correction

The [fresh independent review](strings-shutdown-independent-review-20261120.md) accepts the source for bounded integration. Its 100 passes comprise the same 96 maintained cases and four additional lifecycle controls; these counts are not additive. The source integrated at `ad891694` has the same complete tree as reviewed worker `9997aaa9`.

The coordinator retained the original worker history in `evidence/generation32/strings-shutdown-worker.bundle`. The exact baseline failure log is now deterministic gzip; decompression has the original SHA-256 `138912449de8dd57c7178a43292e63608259fec4868de589ae40f30bbf2b3a8c`. The [correction record](evidence/generation32/evidence-log-format-correction.json) preserves the original complete-range whitespace failure. No source, assertion, or failure evidence was normalized or removed.
