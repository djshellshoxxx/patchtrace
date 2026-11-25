# Qt formatting review, 23 November 2026

Reviewed source `cbdb6c26c381633b22be51e2403fc88fdefa740a`, tree `4fa83ce73de1f4386d4e3e011a04c3caef171634`, against its direct parent `ea16019601486c831941f9bc1a7ba5862a170317`.

The bulk-load regression failed against the unchanged parent because the Qt callback forwarded off-window rows to the formatter. The candidate checks the pane's current window before dispatch and keeps formatting for the visible rows. Its repository test module and two separate PySide6 controls passed together, **37 passed**. The controls checked independent scrolling of the two panes, edit/undo, visible formatting, disabled or missing models, preserved text, and default block state.

Ran in detached worktrees with `QT_QPA_PLATFORM=offscreen`, Python 3.12, and `TMPDIR=/workspace/scratch/eed8744ccd63/qa-tmp`. Parent log: `paint-red.log`. Candidate log: `paint-positive.log`. Dispatch correctness is established on this fixture. No independent end-user latency or native Windows result is claimed.
