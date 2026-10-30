# `patchtrace cache`

Inspects or maintains the global derived-stage cache. The cache holds recomputable intermediate results. It is not your evidence, and deleting cache entries does not change a project.

```
patchtrace cache {status,verify,prune} --cache-dir DIR [--target-bytes N] [--json]
```

- `status`: report what the cache holds.
- `verify`: check the stored entries.
- `prune`: remove entries to reduce the cache. `--target-bytes N` sets the size to aim for.
- `--cache-dir DIR` is required. There is no default location.

If the cache cannot be used, the command exits 2 and says so. Check the path and its permissions.

Sources: `src/patchtrace/cli.py` (`cache` parser, `cmd_cache`), top-level `patchtrace --help`.
