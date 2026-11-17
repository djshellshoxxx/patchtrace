# Preview and export reports

Choose **Export** or press `Ctrl+E` to produce a report from saved project data. The dialog is titled **Export report · review exact preview**.

1. Set **Format** to `md`, `html`, or `json` and choose a **Destination** file. The initial destination is `exports/report.md` within the project.
2. Choose **Contract** and **Profile** using the table below.
3. For **Report v2**, review **Sections**. Available sections show a count and a checkbox; unavailable sections show the reason. Uncheck any optional section you do not want.
4. For **Local analysis**, choose whether to **Include function code** and **Include analyst notes**.
5. Choose **Only selected findings (N)** when that scope is required. Select findings in the main workspace before opening Export; the option is disabled when none are selected. It limits findings, not all project metadata.
6. Read the final preview, then select **Write report**. The status bar reports **Report written:** followed by the destination after a successful write.

| Control | Choices and effect |
| --- | --- |
| **Contract** | **Report v1 (current)** is the default. **Report v2** adds versioned provenance and optional stored-evidence sections. |
| **Profile** | **Local analysis** is the default: code is initially excluded and notes included. **Share with others** selects Report v2, excludes code and notes, removes file paths, and makes web addresses inert. The code and notes controls are disabled while sharing. |
| **Sections** | Available only for Report v2. Examples include Engine evidence, Unified result, Build facts, Symbols, Advisories, and Leads when their stored inputs exist. A missing section does not cause analysis to run. The Unified result section is a reference to the stored result, not its complete row set. |

Selecting **Report v1 (current)** while sharing returns the profile to **Local analysis** and displays an explanation. Review the options again after changing either choice.

For keyboard use, `Alt+C` focuses **Contract**, `Alt+P` focuses **Profile**, and `Alt+S` focuses **Sections**. Use `Tab`/`Shift+Tab` to follow the dialog's displayed order; disabled options are skipped. Use arrow keys to select a section and `Space` to toggle it. Enter in an option field does not write the report: focus **Write report**, then press `Enter` or `Space`. `Escape` closes the dialog without writing the chosen destination.

The preview reflects the selected format and options. Report v2's generation timestamp can change when the file is written; its content digest excludes timestamps and remains stable when the other report content is unchanged. Review the content and scope rather than expecting byte-identical preview and output.

Reports contain the project/artifact provenance, function relationships, findings and reviews selected by the export options, plus available ranking and optional v2 sections. Raw provider responses, API keys, and complete interpretation context payloads are excluded. Local reports redact absolute source paths in ordinary report text, but included code and evidence excerpts can retain original paths. The share profile is not a guarantee of anonymity: inspect remaining names, evidence and project metadata before sharing.

HTML reports are self-contained escaped content without scripts. That export format is separate from raw Ghidriff JSON.

A report is not a full project backup and cannot substitute for the project’s database, inputs, and run files. A PatchTrace JSON report is also not automatically importable as a Ghidriff comparison.

**Write report** can create or overwrite the destination. Choose a new filename when preserving an earlier report matters. Project inputs, database, and internal run files are not report destinations. Cancelling the dialog does not write the chosen destination.

For command-line export, see [`patchtrace export`](75-cli-export.md). To preserve an editable project, see [backups](10-save-reopen-and-back-up.md).

Sources: `src/patchtrace/ui.py` (`ExportDialog`, `export_report`); `src/patchtrace/ui_export_v2.py`; `src/patchtrace/report2/{export_vm,options}.py`; `src/patchtrace/reports.py`; `docs/specs/report-export-contract-v2.md`.
