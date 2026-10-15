Check BinExport identity and orientation
Experimental. The reviewed BinDiff setup validates two BinExport inputs before enabling execution. Availability in a particular package is UNVERIFIED.
BinDiff compares exported analysis structures. Each export must belong to the corresponding project artifact.
Choose the export from the older file as the primary input and the export from the newer file as the secondary input. Use compatible address-basis settings on both sides.
Select Validate .BinExport files and inspect the result. The documented validation checks structure, architecture, limits, identity, and pair orientation in an isolated checker.
A SHA-256 executable identity must match the project’s recorded artifact hash. A conflicting SHA-256 remains a rejection.
Some exporters supply an MD5 value, no executable identity, or another identifier that cannot establish SHA-256 binding. The documented Accept unbound option records your explicit assertion that the exports belong to these files.
That assertion is a different evidence basis from a matching SHA-256. Preserve the distinction in your notes and reports.
Changing an input path or project clears the prior validation and unbound confirmation. Revalidate after making a change.
Cancelling validation leaves the exports unvalidated. Selecting paths alone does not make them eligible inputs.
If validation rejects swapped or foreign exports, obtain the correct exports. Renaming files does not repair their artifact identity.
Sources: src/patchtrace/tooltips.py, engine_setup.*; src/patchtrace/ui_engine_setup.py; docs/modules.md, BinExport2 and BinDiff entries.
