# Independent review: Search cancellation and pending debounce

Date: 2026-11-20 UTC. Reviewer: a fresh worker that did not implement the repair.

## Source and scope

- Reviewed commit: `5d06ec7dd5ce8a75ef49d300a282fcf8b4955377`.
- Complete tree: `3e1d923272e006d36cbcb3980552d858809233d3`.
- Parent: generation-29 candidate `6c8b33b851a22fb16d39b31693922359cd34ad12`.
- Reviewed the one-line production change in `src/patchtrace/search/qt_panel.py`, the new Qt regression in `tests/test_ui_search_panel.py`, the WB1 cancellation amendment, and the implementation evidence note.
- Inspected the surrounding Search lifecycle, saved-query actions, and `gui/qt/tasks.py` channel cancellation and result delivery.

Disposition: **accepted for this bounded repair; no blocking finding**. This is not approval of the entire inherited candidate or a main merge.

## Reasoning

The controller owns a single-shot timer whose timeout calls `submit()`. Before this repair, Cancel superseded active task channels but left that timer running. A previously typed replacement could therefore start another search after cancellation. The added `self.debounce.stop()` directly removes that scheduled request before the task channels are cancelled.

Cancellation still sets the existing presentation state and leaves the editor text and completed result rows intact. `submit()` remains reachable from Enter and later edits; it clears the cancellation flag and starts a new request normally. The new test exercises an enabled Cancel button through a real Qt mouse event, waits beyond the debounce interval, and then uses a real Return key event to run the preserved replacement text.

Late active-task output is suppressed by the existing TaskRunner channel generation check. Cancel increments that channel generation even if the worker ignores its token; `_deliver()` drops the old result. The repair does not change that mechanism or saved-query persistence. Saved-query paths already stop the same timer before explicit load/save/run operations.

The reviewer inspected the original method preimage and confirmed the missing timer stop. The original failing execution in the implementation note was not independently rerun; it remains the implementer's baseline evidence. The passing executions below were performed independently on the exact reviewed commit.

## Independent verification

Environment: Linux, CPython 3.12.14, PySide6 6.12.0, offscreen Qt. `PYTHONPATH` explicitly selected this worktree's `src` directory.

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_ui_search_panel.py \
  tests/test_ui_search_saved.py \
  tests/test_search_saved_workflow.py
```

Result: **58 passed in 7.22 seconds**, with no failures or skips.

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_gui_tasks.py::test_cancel_drops_a_result_the_worker_still_produces \
  tests/test_gui_tasks.py::test_new_submit_supersedes_the_channel_and_drops_the_old_result
python -m ruff check src/patchtrace/search/qt_panel.py tests/test_ui_search_panel.py
```

Result: **2 passed in 0.66 seconds**, disjoint from the 58-test selection; Ruff passed. The worktree remained clean.

JUnit evidence produced for the coordinator:

| File | SHA-256 |
| --- | --- |
| `search-independent-suite.xml` | `e3d9ded95b9b62e5e84b76ab37378949b23b11924ff887b1cd4138577165dec8` |
| `search-independent-task-controls.xml` | `708c86e935ca61afb29de805fd75910472cd6d129b1a37de5551d14b7a0fa685` |

Reviewed source hashes:

| File | SHA-256 |
| --- | --- |
| `src/patchtrace/search/qt_panel.py` | `9dedc8cf6d600b593efce87e80008a4041cd1955cee97766ad39d3d60e308cd3` |
| `tests/test_ui_search_panel.py` | `8244e1b41f413e2c4fcd310a88b61da3e3bbcae8a23f8fc7815e459f0175262f` |
| `docs/specs/program-e/WB1-integration-plan.md` | `59ac9970301ce67fd622a5df87c53df047786dbb5c6e5d68ac92cfd3eba8805a` |

## Limits

The panel regression uses injected, bounded synthetic query workers. The saved-query selection includes the existing real-service save/run/reopen test, but this review does not establish live adapter compatibility, native Windows behavior, manual desktop accessibility, complete repository acceptance, or release readiness. No source files or remote state were changed by this reviewer. Integration and the combined candidate's required gates remain the coordinator's responsibility.
