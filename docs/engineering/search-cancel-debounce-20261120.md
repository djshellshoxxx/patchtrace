# Search cancellation preserves the stopped state

## Problem and source

The generation-29 candidate at
`6c8b33b851a22fb16d39b31693922359cd34ad12` cancels active Search dock tasks
without stopping its pending 250 ms input-debounce timer. If an analyst edits
the query while another query is running and clicks Cancel, the timer can
submit the edited query after the interface reports cancellation.

This is a desktop scheduling defect. It does not change query parsing, search
matching, stored data, adapter behavior, or network access.

## Repair

The WB1 integration plan now explicitly requires cancellation of pending input
debounce alongside active search, index-build, and coverage tasks.
`SearchController.cancel()` stops the existing timer before cancelling those
tasks. The editor text remains available for a subsequent explicit search.

The regression uses the actual offscreen Qt panel, a mouse click on its enabled
Cancel button, and a bounded synthetic search worker. It verifies that a pending
edited query does not run, a late result cannot replace the cancelled state,
the edited text is retained, and Enter can subsequently run that text.

## Verification

Before the production change, the new regression failed on the named source:
the observed calls were `['original', 'replacement']` instead of
`['original']`. The failing node was
`tests/test_ui_search_panel.py::test_cancel_stops_pending_debounce_and_enter_can_search_again`
(`1 failed in 1.66s`).

After the repair, the following affected selection passed: **58 passed in
7.27s**.

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_ui_search_panel.py \
  tests/test_ui_search_saved.py \
  tests/test_search_saved_workflow.py
python -m ruff check src/patchtrace/search/qt_panel.py tests/test_ui_search_panel.py
git diff --check
```

Ruff and whitespace checks passed. The commands used CPython 3.12.14 in the
project development environment, with `PYTHONPATH` explicitly bound to this
worker's source tree. This is Linux offscreen event-lifecycle evidence, not
native Windows, manual desktop, or complete release qualification.

## Review and integration

The change removes an unintended scheduled request and adds no new parser,
execution, persistence, or transport interface. Independent review and
integration into the current candidate remain the coordinator's next steps.
No merge or release acceptance is claimed by this scoped repair.
