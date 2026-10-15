# Read older and newer code

Select a function match to display its older and newer records. Check the artifact headers before interpreting the differences, especially after changing project orientation.

The representation selector changes the material shown on both sides:

| Representation | Meaning |
| --- | --- |
| `Decompiled code` | C-like output produced by the decompiler, rather than original source |
| `Assembly` | Retained instruction text, when available |
| `Metadata` | Recorded information about the selected records |

Use `Previous diff,` `Next diff,` or the changed-hunk selector to move between changed regions. `Alt+Up` and `Alt+Down` provide the documented keyboard routes.

Alignment can insert blank display rows where line counts differ. These gaps are presentation aids. Equal display row numbers do not establish corresponding source lines or function identity.

Sync scroll coordinates vertical movement between panes. It does not strengthen the evidence that the functions correspond.

The viewer limits displayed text to 200,000 characters. Large text can also use a bounded alignment fallback. Check the displayed availability, truncation, and alignment information before treating the view as complete.

Use `Copy` for a representation accompanied by project, artifact-hash, run, match, and function provenance.

Unavailable assembly remains unavailable. PatchTrace must not manufacture instructions from an instruction hash.

For byte-oriented representations, verify the selected scope and its provenance separately. Decompiled text is not evidence that an exact function byte range has been recovered.

Sources: `README.md,` “Function navigation and paired code”; `src/patchtrace/tooltips.py;` `docs/modules.md.`
