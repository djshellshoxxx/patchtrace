# Save, reopen, and back up a project

A PatchTrace project includes `project.sqlite3,` copied inputs, raw comparison output, and run data. Keep the project directory and its companion files together.

Review actions, corrections, notes, and accepted result imports persist through the project service. Use Save or `Ctrl+S` for an explicit snapshot. To resume work, choose `Open` or `Ctrl+O` and select the project directory.

PatchTrace uses a writer lock to prevent concurrent editing. If the project is open in another instance, close it there before retrying. **Do not remove an active lock to force a second writer.**

Create a complete backup before moving between versions that might require a schema migration:

1. Finish or cancel the active job.
2. Choose `Project → Back up project….`
3. Select a parent directory outside the current project.
4. Allow PatchTrace to create a new backup directory.
5. Confirm the reported destination.

The backup includes a SQLite backup and companion files. Copying only `project.sqlite3` does not preserve the entire project.

An exported report is also not a project backup. It contains selected reporting material rather than the complete working state.

Project storage is local and is not encrypted by PatchTrace. Retained interpretation contexts and raw responses can contain decompiled code even when a report excludes function code.

Keep projects outside the application directory so replacing the portable application does not replace your research.

Sources: `README.md,` “Projects, backups, and data handling”; `docs/windows.md;` `docs/specs/ui.md.`
