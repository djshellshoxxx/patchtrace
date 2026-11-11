# `patchtrace unified`

Combines the stored engine outputs into one derived, experimental result with ordinal labels. It never changes the project, the Ghidriff results, or any other stored result. Its labels are rule-based and uncalibrated.

```
patchtrace unified run <project> ...      # compute and store the unified result for this project
patchtrace unified show <project> ...     # list rows of the current result, most important first
patchtrace unified explain <project> ...  # atoms, contest, facts and provenance of one row
patchtrace unified status <project> ...   # current result, staleness, sources and recent runs
```

Useful `run` options: `--no-extract` (the only mode in this build), `--no-residual`, `--no-decompile` (skip the on-demand decompile of review pairs), `--python` and `--ghidra-dir` (both needed for that decompile), `--sources` (default `ghidriff,bindiff,rz-diff,manual`), `--timeout` (60 to 86400 seconds), `--refresh`, and `--fail-on-none`.

Exit codes: 0 ok; 2 invalid argument, environment, or nothing runnable; 3 runtime failure or partial result; 4 for `show` with no row listed (and `run --fail-on-none`); 5 cancelled. With `--json`, stdout carries one `enrichment-cli/1` document, including on failure.

Desktop equivalent: the [Unified panel](22-unified-panel.md) (`Ctrl+Shift+U`, run with **Run unified**).

Sources: `src/patchtrace/unified/cli.py`, `src/patchtrace/unified/panel.py`, top-level `patchtrace --help`.
