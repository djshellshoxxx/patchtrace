# Search panel

Planned. The reviewed WB1 plan specifies this panel. Its manifest slot exists, but the corresponding panel declaration was unavailable during review. Working desktop availability is UNVERIFIED.

Search is intended to find indexed project material across functions, code, strings, imports, exports, capabilities, build facts, advisories, notes, and findings. It is separate from the core navigator’s name-and-address filter.

The planned entry shortcut is Ctrl+Shift+F. Enter a query, then choose side, kinds, scope, mode, and sort order. **An empty query does not request the entire project.**

The planned modes include words, exact, prefix, substring, and similar. Similarity suggestions help discover names; they do not establish function correspondence.

Results carry side, kind, location, change information, and an explanation of their reading order. Select a result to inspect its provenance and limitations before using `Go to code` or Show other side.

Use `Coverage…` to check which source groups were indexed. An empty result is meaningful only within completed coverage. Failed or missing index segments leave absence unresolved.

The design includes saved searches and Rebuild index. Rebuilding concerns the search index, rather than rerunning binary analysis.

Planned keyboard behavior includes `Enter` to open a result, `Space` to focus details, and `Ctrl+C` to copy its reference. Search-specific Escape handling closes suggestions or clears the query without cancelling the comparison job.

Sources: docs/specs/program-e/WB1-integration-plan.md, section 8; src/patchtrace/panel_manifest.py.
