# Read limits, truncation, and empty results

PatchTrace bounds displayed text, table size, parsing, and external operations. A limit notice describes the portion that could be processed or shown.

The core paired-text viewer documents a 200,000-character display cap. Larger records can contain material beyond the visible text. Alignment can also use a bounded fallback.

The shared table state says `Too many rows to display` and asks you to narrow the filter. Feature-specific views can have different ceilings.

| Message or condition | What to check |
| --- | --- |
| Too many rows | Narrow the feature’s filters |
| Text truncated | Retain the notice when citing visible text |
| Partial scan | Identify which side or source reached a limit |
| No visible rows | Clear filters and inspect result status |
| No matches after complete search | Read the search scope and coverage |

A display limit does not establish that later records are unimportant. A scan limit can prevent added-or-removed conclusions when one side’s inventory is incomplete.

For a byte view, a short final page can simply mean the end of the selected scope. For a code view, unavailable text can mean the upstream result did not retain it.

**Do not interpret an empty filtered list as proof of identical binaries.** Confirm that analysis completed, the intended run is active, and the requested evidence was available.

> UNVERIFIED: performance at a documented ceiling on your Windows machine requires local testing.

Sources: README.md; src/patchtrace/gui/state.py; relevant Program E integration plans.
<!-- FORMAT NOTE: The Sources line says “relevant Program E integration plans” without naming a specific file. -->
