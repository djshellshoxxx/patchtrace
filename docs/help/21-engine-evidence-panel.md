# Engine evidence panel

Experimental. The reviewed source contains the Engine evidence panel and its controller. Availability in a particular downloadable package is UNVERIFIED.

Open the panel with `Ctrl+Shift+E` when that command is available. It compares function relationships from stored Ghidriff, BinDiff, and rz-diff results.

Read the verdict before comparing individual engine cells:

| Verdict | Meaning |
|---|---|
| `Agree` | Engines with address-comparable records select the same endpoints as Ghidriff |
| `Contested` | An engine selects a different endpoint |
| `Single engine` | Only Ghidriff provides a comparable record |
| `Unknown` | No usable engine output could be compared |
| `Engine-only record` | A secondary relationship has no covering Ghidriff match |

Agreement concerns pairing. Engines can share disassembly artifacts, so agreement is not independent proof.

Use the verdict filter, text search, and `Hide agreed` control to narrow review. Select a row to read its details. `Go to match in navigator` opens the associated primary match when navigation is available. `Copy provenance` preserves the selected evidence as plain text.

The `Engines` tab provides engine status, probing, selected-engine execution, cancellation, and BinDiff setup or import controls. Opening the evidence view does not itself authorize running every engine.

Native engine values retain their own scales. **Do not average them or compare their numeric magnitudes across engines.**

For partial results, inspect which engines failed or were not run. Missing output is unknown, rather than disagreement. Stale output describes earlier inputs and remains reference material.

Sources: src/patchtrace/secondary/evidence_panel.py; src/patchtrace/secondary/evidence_view.py; src/patchtrace/ui_evidence.py.
