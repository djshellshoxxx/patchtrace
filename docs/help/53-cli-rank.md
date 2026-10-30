# `patchtrace rank`

Ranks the changed functions of a project by attention, a reading order based on stored change signals. A high rank means "read this first". It does not mean the function is vulnerable.

```
patchtrace rank <project> [--json] [--run RUN] [--profile NAME|FILE] [--weights JSON] [--disable DETECTOR] [--limit N] [--refresh] [--dry-run] [--cache-dir DIR]
```

- `--run RUN`: the analysis run to rank. The default is the latest completed run.
- `--profile`: a desktop analysis profile name, or a profile JSON file.
- `--weights`: a JSON object of detector weights, integers 0 to 100.
- `--limit N`: show at most N entries. `0` shows all.
- `--dry-run`: do not store the result in the project.
- `--refresh`: recompute cached stages. This does not imply network use.
- `--json`: print exactly one JSON document on stdout.

Exit codes follow [docs/cli-reference.md](../cli-reference.md). A partial result exits 0 for `rank`.

Desktop equivalent: **Analysis > Rank changes** (`Ctrl+R`).

See also: [attention ranking](35-attention-ranking-and-change-signals.md), [confidence labels](36-read-calibration-and-confidence-labels.md).

Sources: `src/patchtrace/cli.py` (`rank` parser, `cmd_rank`), top-level `patchtrace --help`.
