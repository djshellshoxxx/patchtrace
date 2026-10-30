# `patchtrace flags`

Lists WIL feature-flag transitions between the older and newer build of a project. Use it to see which flags changed state, not to decide whether a change matters.

```
patchtrace flags <project> [--json] [--run RUN] [--feature-id ID] [--profile NAME|FILE] [--refresh] [--dry-run] [--cache-dir DIR]
```

- `--feature-id ID`: show one feature only.
- `--run RUN`: the analysis run to read. The default is the latest completed run.
- `--dry-run`: do not store the result in the project.
- `--json`: print exactly one JSON document on stdout.

A partial result exits 3 for `flags`. Check the status before you rely on an empty list. See [docs/cli-reference.md](../cli-reference.md) for the exit-code table.

A flag transition is a reading aid. It does not show what code the flag controls in a particular function.

Sources: `src/patchtrace/cli.py` (`flags` parser, `cmd_flags`), top-level `patchtrace --help`.
