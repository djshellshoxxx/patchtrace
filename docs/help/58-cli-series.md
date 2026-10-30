# `patchtrace series`

Compares an explicitly ordered set of builds as adjacent pairs. Each adjacent pair is an ordinary comparison project. The series file records the order you chose. File names and timestamps do not set the order.

```
patchtrace series create ...   # create or reuse the adjacent pair projects and write series.json
patchtrace series chains ...   # list the chain hypotheses in series.json
```

- `create` builds the pair projects and writes `series.json`. It reuses a pair project that already exists.
- `chains` lists how functions link across adjacent pairs. Only one-to-one links extend a chain. Split, merged, ambiguous and unmatched events end it.

A chain is an inference from adjacent pairs. A direct first-to-last comparison is a separate check. See [Series panel](32-series-panel.md).

Desktop equivalent: **Project > Series window…** opens a `series.json`.

Sources: `src/patchtrace/cli.py` (`series` parser, `cmd_series`), `src/patchtrace/nway/`.
