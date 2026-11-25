# GUI backup truthfulness

Reviewed live PR 360 `76bcca7afe4ade59db2294b86b88de175c8a3172` in a clean checkout. No repository files or remote state were modified.

The Project menu triggers `MainWindow.backup_project`. After the user picks a parent, it calls `ProjectService.backup` via `_guard`. A nonempty result generates a “Backup:” log and a “Backup created:” status. An exception opens an error dialog, writes an error log, and suppresses both success messages. The tooltip and README promise a complete separate backup, including the database, stored inputs, and outputs. The desktop does not explicitly claim to have reopened or hashed the copy. The CLI does explicitly verify and compares the reopened snapshot with its source after publication. [GUI action](https://github.com/djshellshoxxx/PatchTrace/blob/76bcca7afe4ade59db2294b86b88de175c8a3172/src/patchtrace/ui.py#L1877) · [Tooltip](https://github.com/djshellshoxxx/PatchTrace/blob/76bcca7afe4ade59db2294b86b88de175c8a3172/src/patchtrace/tooltips.py#L154) · [User promise](https://github.com/djshellshoxxx/PatchTrace/blob/76bcca7afe4ade59db2294b86b88de175c8a3172/README.md#L300) · [CLI verification](https://github.com/djshellshoxxx/PatchTrace/blob/76bcca7afe4ade59db2294b86b88de175c8a3172/src/patchtrace/project_cli.py#L348).

The store loads the source, copies the SQLite database and five companion directory types, then renames the staging directory into place. The staged copy is not compared against the source snapshot before publication. In an isolated Linux offscreen Qt test, the GUI QAction ran the actual service, SQLite, filesystem copy and project reopen. Only the user’s directory selection, modal display, and controlled test seam were substituted.

| Case | GUI result | Filesystem and reopen |
|---|---|---|
| Healthy copy | Success log and status | One final folder; backup reopened with identical project snapshot. |
| Raised copy error | One error dialog, error log/status; no success | No destination and no residual staging directory. |
| One same-size byte changed in the staged copy of a snapshot-owned input | Success log and status | One final folder; immediate reopen rejected it with PT-STORAGE: immutable input is missing or has changed. |

The source project ID, complete snapshot, and original file bytes remained intact in all three cases. A companion worker covers concurrent source mutation; the independent control here changes only the disposable staging copy, to isolate the GUI's observable success rule. The correction should reject a snapshot mismatch in the common backup service/store before publication. Existing GUI error handling is sufficient. Keep the healthy reopen as a positive control and require error/no success/no final folder on the mismatched copy. Snapshot-bound input/raw verification by itself does not establish atomic capture of every independently modified export or auxiliary file.
