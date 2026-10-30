# `patchtrace search`

Searches a project's saved names, strings, APIs, code, notes and advisories. It is offline: nothing is uploaded and no target runs. Results keep their side (older, newer or both), their kind and their source.

```
patchtrace search [PROJECT] --query TEXT [--kind K] [--side older|newer|both] [--scope indexed|changed]
                  [--mode auto|words|exact|prefix|substring|similar] [--sort relevance|change|name|address]
                  [--limit N] [--cursor C] [--no-group] [--no-expand] [--json]
patchtrace search [PROJECT] --status     # coverage, segment digests and staleness
patchtrace search [PROJECT] --rebuild    # rebuild the index segments first
patchtrace search --probe                # runtime capabilities; needs no project
```

- `--kind` takes one of: `function`, `code`, `asm`, `string`, `import`, `export`, `capability`, `rule`, `build`, `advisory`, `cve` and the other kinds the command lists in its help.
- `--scope changed` limits results to changed items (the Search panel calls this "Changed only").
- A search with no matches is meaningful only within the coverage that `--status` reports.

Desktop equivalent: the [Search panel](23-search-panel.md).

Sources: `src/patchtrace/search/cli.py`, `src/patchtrace/cli_commands/search.py`, top-level `patchtrace --help`.
