# `patchtrace export`

Writes a report from a stored comparison project without running a new analysis or making a network request. This command is different from exporting the project as a backup: a report cannot be reopened as a project.

```text
patchtrace export <project> --out <report.json>
patchtrace export <project> --format md --out <report.md>
patchtrace export <project> --report-version 2 --format html --profile share --out <report.html>
```

Choose `--format json|md|html` (default: `json`) and `--report-version 1|2` (default: 1). Version 2 also supports `--profile local|share`, `--urls text|defanged|removed`, and `--include-ordinal-index`. The share profile excludes code and analyst notes and does not allow plain-text URLs. These options are validated together; incompatible combinations fail rather than being ignored.

For a local report, `--include-code` includes code and `--include-notes`/`--no-include-notes` controls notes (included by default). Use repeated `--finding ID` options to limit the selected findings. By default, code is excluded. Check the contents before sharing; a report can still contain project-specific information.

`--json` emits the `enrichment-cli/1` result on stdout. Exit codes: 0 exported; 2 invalid options or inaccessible project; 3 export failure; 4 no project matches to export; 5 cancelled. A failed export preserves any previous destination file according to the exporter contract.

Desktop equivalent: [Preview and export reports](47-preview-and-export-reports.md) (`Export`, `Ctrl+E`).

Sources: `src/patchtrace/cli_commands/export.py`, `src/patchtrace/report2/{cli,options}.py`, `src/patchtrace/reports.py`.
