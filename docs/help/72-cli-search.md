# `patchtrace search`

Searches a project's saved names, strings, APIs, code, notes and advisories. It is offline: nothing is uploaded and no target runs. Results keep their side (older, newer or both), their kind and their source.

Stored FLOSS strings, capa capabilities, Detect It Easy build information, imported advisories and existing CVE snapshots join the search when available. Tool results must describe the current artifact and side; after swapping builds, older stored results may be unavailable until fresh matching results exist. Search does not run these tools. Coverage explains unavailable groups, while other indexed project groups remain searchable.

```
patchtrace search [PROJECT] --query TEXT [--kind K] [--side older|newer|both] [--scope indexed|changed]
                  [--mode auto|words|exact|prefix|substring|similar] [--sort relevance|change|name|address]
                  [--limit N] [--cursor C] [--no-group] [--no-expand] [--json]
patchtrace search [PROJECT] --status     # coverage, segment digests and staleness
patchtrace search PROJECT --query TEXT --rebuild  # rebuild the index segments before searching
patchtrace search --probe                # runtime capabilities; needs no project
```

- `--kind` takes one of: `function`, `code`, `asm`, `string`, `import`, `export`, `capability`, `rule`, `build`, `advisory`, `cve` and the other kinds the command lists in its help.
- `--scope changed` limits results to changed items (the Search panel calls this "Changed only").
- A search with no matches is meaningful only within the coverage that `--status` reports.

## Saved queries

Saved queries belong to a project and are shared with its desktop Search panel. They retain query text, matching mode and effective filters; results are recomputed when run.

```text
patchtrace search PROJECT --save "Older reads" --query read_item --mode exact --side older --scope changed
patchtrace search PROJECT --saved-list --json
patchtrace search PROJECT --saved-run ID --json
patchtrace search PROJECT --saved-delete ID --json
```

Replace `ID` with the `saved_id` returned by saving or listing. Names contain 1–64 characters. Saving the same name and effective query again returns the existing entry; another query under that name is refused until the old entry is deleted or a different name is chosen.

| Operation | Effect |
| --- | --- |
| `--save NAME` with query/filter options | Save the effective query without running it or building an index. |
| `--saved-list` | List active saved queries and report unreadable stored rows. No index is needed. |
| `--saved-run ID` | Reparse the saved text and matching mode, then perform an ordinary search against current project data. Normal result, paging and index options apply. |
| `--saved-delete ID` | Remove an entry from the active list and retain its history. Repeating deletion reports `deleted: false`. |

Use one saved-query operation per command. They cannot be combined with `--probe`, `--status` or `--anchors-from`. Query and filter options apply to `--save`; they cannot override `--saved-run`, listing or deletion. Result and index options apply to running a query, not saving, listing or deleting it.

For a normal query or `--save`, explicitly supplied `--side` and `--scope` replace corresponding filters in the query text; omitted flags preserve those textual filters. Quoted phrases are kept as text. A saved run restores its saved mode and filters.

With `--json`, output remains one `enrichment-cli/1` document. Save/list/delete results identify the operation; saved runs return normal search results. An invalid option combination or missing saved run target exits 2; a saved-store failure exits 3. Desktop recent text is separate per-user history and is not managed by these CLI operations.

Desktop equivalent: the [Search panel](23-search-panel.md).

Sources: `src/patchtrace/search/cli.py`, `src/patchtrace/search/saved_actions.py`, `src/patchtrace/search/saved.py`, `src/patchtrace/cli_commands/search.py`, top-level `patchtrace --help`.
