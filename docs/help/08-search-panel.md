# Search panel

**Planned:** the Search dock is reserved in the manifest, but its panel implementation is absent from the inspected branch. Ctrl+Shift+F is its reserved shortcut, not a promise that a search interface is available in this build.

The planned workbench search brings stored evidence into a common query workflow. Search results must retain their artifact side, source, and navigation identity. A hit in a string, advisory, or code record is evidence that the text was observed in that source; it does not establish that a particular function implements the described behavior.

For current work, use the navigator's name/address filter, the finding text search, or the Engine evidence search. These controls have different scopes. An empty function-name search does not mean the term is absent from strings, raw bytes, or an advisory. Clear filters before treating a visible list as complete.

Keep older and newer results distinct when taking notes. A repeated name can identify multiple functions, and a stale link should return you to the source rather than choose a current record silently. Missing code remains outside the searchable evidence available to a representation.

The detailed query syntax, indexing controls, and limits are not documented here as shipped functionality.

Sources: [panel guide](../guide/13-panels-and-layout.md), src/patchtrace/panel_manifest.py, and [WB1 plan](../specs/program-e/WB1-integration-plan.md). **UNVERIFIED:** planned commands, performance, panel behavior, and accessibility require implementation and acceptance.
