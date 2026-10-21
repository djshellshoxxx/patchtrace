# `patchtrace secondary`

Brings second-opinion match sets into a project: BinDiff results, rz-diff, and validated `.BinExport` files. These sets are compared with the primary Ghidriff matches. Agreement between tools that read the same disassembly is not independent confirmation.

```
patchtrace secondary import-bindiff ...      # import a genuine .BinDiff result for this exact pair
patchtrace secondary run ...                 # run secondary engines on the project artifacts
patchtrace secondary rzdiff ...              # alias for: secondary run --engine rz-diff
patchtrace secondary reconcile ...           # compare stored secondary match sets with Ghidriff
patchtrace secondary binexport-check ...     # validate a user-supplied .BinExport for one artifact
```

- `import-bindiff` accepts only a result for the exact pair in the project.
- `binexport-check` runs its validation in an isolated worker process.
- `run` starts the engines you select. Opening a result does not start them.

Desktop equivalent: the **Engines** tab of the [Engine evidence panel](21-engine-evidence-panel.md).

Sources: `src/patchtrace/cli.py` (`secondary` parser, `cmd_secondary`), `src/patchtrace/secondary/cli_*.py`, top-level `patchtrace --help`.
