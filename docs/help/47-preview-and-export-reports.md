# Preview and export reports

Choose `Export` or press `Ctrl+E` to produce a report from saved project data.

1. Select Markdown, HTML, or JSON.
2. Choose the destination file.
3. Decide whether to include function code.
4. Decide whether to include analyst notes.
5. Choose `selected findings only` when that scope is required.
6. Read the exact preview.
7. Select Write report.

Function code is excluded by default. Analyst notes are included by default. Only selected findings requires a finding selection in the main workspace.

The preview reflects the selected format and options. Changing an option can change the output, so review the final preview before writing.

The documented exporter redacts absolute source paths and excludes raw provider responses, API keys, and complete interpretation context payloads. Inspect names, notes, optional code, and remaining project metadata before sharing.

HTML reports are documented as self-contained escaped content without scripts. That export format is separate from raw Ghidriff JSON.

A report is not a full project backup and cannot substitute for the project’s database, inputs, and run files. A PatchTrace JSON report is also not automatically importable as a Ghidriff comparison.

`Write report` can create or overwrite the destination. Choose a new filename when preserving an earlier report matters. Cancelling the export dialog writes nothing.

Sources: README.md, “Export and share results”; src/patchtrace/tooltips.py, export.*; docs/specs/ui.md.
<!-- FORMAT NOTE: Grammar: “Only selected findings requires a finding selection” appears to be missing a word (for example, “The Only selected findings scope requires...”). Left unchanged. -->
