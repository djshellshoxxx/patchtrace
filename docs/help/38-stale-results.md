# Understand stale results

A stale result describes an earlier set of inputs or assumptions. PatchTrace retains it for reference while identifying that it no longer describes the current comparison context.

Changes that can invalidate derived results include a new Ghidriff run, changed artifact identity, reversed orientation, manual match correction, different stored engine outputs, changed advisory data, or changed analysis configuration. The applicable reasons depend on the feature.

Read the stale notice before using the table or copying its conclusion. Historical evidence can remain useful when its original context is preserved.

Choose the appropriate next action:

| Result | Next action |
| --- | --- |
| Display loaded before a project change | Reload or refresh the view |
| Derived analysis built from superseded inputs | Recompute the derived result |
| Interpretation tied to an older context | Preview a new context and interpret the current selection |
| Series hop from a changed pair project | Reload the series and inspect that pair |
| Advisory context tied to different inputs | Review and reattach or rebuild through its supported workflow |

Refreshing a display is not always recomputation. For example, `Leads Refresh` reloads stored data, while `Prepare leads` creates a derived result.

Stale citations must not silently navigate into a different current function. Review their retained historical context instead.

Record the original run and artifact identities if your investigation intentionally discusses the earlier result. A stale label does not by itself establish that the historical observation was incorrect.

Sources: README.md; src/patchtrace/gui/state.py; src/patchtrace/unified/read_model.py; src/patchtrace/pilot/read_model.py.
