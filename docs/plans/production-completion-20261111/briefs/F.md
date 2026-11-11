# WORKSTREAM F - CLI, automation and the GUI/CLI parity matrix
Scope: src/patchtrace/cli.py (COMMANDS registry), cli_commands/**, backend_cli.py, cli_backend_progress.py, __main__.py and
every package-level CLI module (`grep -rln 'argparse\|add_parser\|add_subparsers' <main checkout>/src`).
Docs: docs/cli-reference.md, docs/specs/cli-umbrella.md (SPEC-44; s8 exit codes pending an owner decision),
kb-patch-search-ui-cli-contract.md, docs/specs/unified-engine/07-ui-and-cli.md, docs/audits/20261015-reports-cli.md,
20261015-qa-cli-persistence.md.

Enumerate the REAL CLI by running `--help` on the root and on every subcommand (and sub-subcommand); save the raw output to
docs/status/cli-help-main-882d1ca0.txt.
Enumerate substantial GUI capabilities from the panel manifest (src/patchtrace/panel_manifest.py, and `patchtrace panels` if
it exists), ui.py menus / QAction definitions, and each ui_*.py panel.

Deliverable 2 (besides the JSON): write
docs/status/gui-cli-parity-matrix.md - a Markdown
table: GUI capability | GUI location (file) | CLI command (exact) | output formats (text/JSON/CSV) | non-interactive? | exit
codes documented? | tests (file) | parity status (full / partial / GUI-only / CLI-only / not-applicable + reason).
It must cover the directive's required CLI list: binary import; binary comparison; adapter selection; analysis execution;
CVE lookup; patch correlation; patch recommendations; historical run retrieval; manual correction import/export; result
export; configuration management; diagnostics; health checks; batch processing; scriptable workflows; output formats
(human text, JSON, CSV where applicable, machine-readable diagnostics); stable exit codes and meaningful error messages;
unattended execution without interactive prompts; command-line installation / configuration / verification /
troubleshooting procedures.

Check docs/cli-reference.md against the real help output: list every command or flag that is documented but missing, or
present but undocumented (doc file:line).
actionable_now: the missing CLI equivalents (each as a bounded task naming the service function it would wrap and the
contract/spec it must follow - AGENTS.md says update the spec before changing contracts), exit-code inconsistencies,
missing JSON output modes, doc drift. cli.py is a shared file: tasks that add commands should add a module under
cli_commands/ plus one registry line.
