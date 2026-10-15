# Read idle, loading, and ready states

State messages describe the panel’s current work. They are separate from conclusions about the compared files.

| State | Meaning | Next step |
| --- | --- | --- |
| No project | The feature needs an open project | Create or open the intended project |
| Idle | No result is available yet | Follow the stated preparation or run instruction |
| Loading | The first result is being loaded | Wait, or use an offered cancellation action |
| Refreshing | Existing content is being updated | Wait and check the resulting status |
| Ready | The panel has completed its current preparation | Inspect coverage, filters, and provenance |

A ready panel can still contain rows marked unknown or not applicable. “Ready” describes completion of the view’s work, rather than completeness of every evidence channel.

Some features show additional partial or stale notices alongside content. Read those notices before interpreting a ready table.

When no counts are available, progress is indeterminate. This does not by itself establish that the operation has stopped responding.

An idle panel is also different from a completed search with no matches. Check whether the prerequisite operation has run.

If expected rows are missing, clear relevant filters and inspect coverage. **Do not infer an empty analysis from an empty filtered table.**

Experimental: shared state infrastructure is implemented in the reviewed source. Individual panels may retain feature-specific wording while migration continues. Behavior in a particular package is UNVERIFIED.

Sources: src/patchtrace/gui/state.py; src/patchtrace/secondary/evidence_view.py; src/patchtrace/unified/read_model.py.
