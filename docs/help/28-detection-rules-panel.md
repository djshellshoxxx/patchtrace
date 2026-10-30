# Detection rules panel

The **Detection rules** panel shows the proposed rules, the test grid and the saved rule versions for a project. It is a right dock, shown with `Ctrl+Shift+R`. It needs an open project.

The panel has three tabs:

- **Proposed rules** lists candidates. Search by name, function or label. Each row shows its decision: `Proposed`, `Accepted`, `Rejected` or `Deferred`.
- **Test grid** shows how each build matched a rule version. Filter by build role, by result, or with **Unexpected results only**.
- **Saved rules** lists the stored rule versions.

Buttons: **Copy rule text** copies the exact text of the selected rule. **Open pair** goes to the changed function that the rule came from.

The panel shows stored results. It does not propose, accept or test rules. Use the command line for those steps:

- `patchtrace rules propose` creates candidates from one accepted changed-function pair. Nothing is accepted.
- `patchtrace rules decide` accepts, rejects, defers or archives one candidate. Accepting needs `--label` and stores a version. It writes no file.
- `patchtrace rules test` scans builds with one rule version.
- `patchtrace rules export` saves one version as a `.yar` file on your computer. Nothing is uploaded.

Test cells read `Match`, `No match`, `Timed out`, `Error` or `Not scanned`. A file that could not be read or was too large stays `Not scanned`. A match on a local test set does not show general selectivity. An unexpected result needs investigation, not a changed label.

See [`patchtrace rules`](71-cli-rules.md) for every verb.

Sources: `src/patchtrace/rules/panel.py`, `src/patchtrace/rules/qt_panel.py`, `src/patchtrace/rules/view_model.py`, `src/patchtrace/rules/cli.py`.
