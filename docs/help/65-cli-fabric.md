# `patchtrace fabric`

Reads the anchors a project already holds: stable identities for functions, strings, imports and other evidence that other views link to. The command is read-only. Producers write anchors. This command never changes them.

```
patchtrace fabric list ...      # list the anchors of a project in canonical order
patchtrace fabric show ...      # show one anchor with its witnesses
patchtrace fabric resolve ...   # resolve a value to one anchor: found, ambiguous or unknown
patchtrace fabric stats ...     # count the anchors and list the stored batches with their flags
```

Missing evidence is reported as unknown, never as a negative result. An `ambiguous` answer means more than one anchor matches, so pick one by its identity rather than by its name.

Sources: `src/patchtrace/fabric/cli.py`, `src/patchtrace/cli_commands/fabric.py`, top-level `patchtrace --help`.
