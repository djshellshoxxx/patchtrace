# Strings comparison and current-source identity recovery

Reviewed runtime source: `90ae12381795e12061a8cf8e929cfbd306d54dd6`, based on
core candidate local `ac3a98150bd17bbbd973c7e7dcadb7edcf551934` (published #319
has the identical tree). Original shared-comparison slice:
`150d9b9618b4f621ce31101c64502fb555734d46`. Local recovery commits are
`e4fdeff0` (contract/index), `f5b919ca` (selective source/tests), `edbce6f5`
(identity contract and red controls), and `90ae1238` (identity repair/help).

## Reproduced defects and changes

The independent baseline probe used the same inert PE pair through CLI and dock
loaders. The CLI identified an imported API name; the dock omitted that cue.
The recovered Qt-free composition supplies the same source tables, project
links, import/export contexts and section regions to both routes. The dock
offers Auto, Built-in scan and existing FLOSS results, with owner-thread store
reads and no new tool execution. Missing explicit FLOSS results preserve the
displayed comparison. The Scan tooltip now describes display updates and does
not claim that a new project result is saved.

Review then reproduced an inherited identity error: after a real project
orientation swap, the CLI and newly recovered dock reused pre-swap FLOSS
records against the wrong artifact. Three controls failed on `f5b919ca`.
A standalone real-service probe also reproduced the CLI error on core #319;
the manifest proves that CLI source blob is identical on current main `fdc2696c`.
On the repaired source the same probe returns the correct current hashes.

The composition seam now binds the selected run and evidence to the current
artifact, side, engine, configuration and cache key. Direct evidence must name
the selected run; an otherwise matching cache hit may retain its original
evidence run identity. Auto falls back to the built-in scan for unavailable
current evidence; explicit FLOSS refuses. Swapping back permits correctly bound
original evidence again. No stored records, ToolStore APIs or export publication
paths were changed. No new schema is introduced.

## Observed validation

Commands use `QT_QPA_PLATFORM=offscreen` and the dedicated
`patchtrace-composition-venv` interpreter, whose source path names this worktree.
Dependencies are the previously prepared shared environment; this is not an
independent package-install or Windows qualification run.

| Source / selection | Observed result |
| --- | --- |
| Shared comparison before the identity follow-up: `tests/test_strings*.py tests/test_ui_strings*.py` | 511 passed in 35.35 s |
| Real orientation-swap regression controls before repair | 3 failed in 2.68 s |
| Final affected Strings/UI plus `test_help_docs.py test_spec_registry.py` | 843 passed in 47.59 s, no skips |
| Separate real-service probe on core #319 / repaired source | Wrong artifact reproduced / correct current artifact hashes |
| Ordinary `python -m ruff check src tests tools`; `git diff --check` | Passed |

Selections overlap and are not added. The original cue reproduction, raw red
and green pytest output, JUnit, and both identity probes are preserved in
`evidence.zip`; `manifest.json` pins every member. All PE inputs are synthetic
bytes. The only executable is an authored fixture that prints committed FLOSS
output; no target or real native engine was run. Independent review and fresh
combined hosted gates remain required. Inherited forced-export ownership and
other release blockers remain separately documented.
