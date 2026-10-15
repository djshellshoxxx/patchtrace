# `patchtrace graph`

A call-graph explorer over the call lists stored in a project. It is read-only. Static call lists can be incomplete, so a missing edge does not prove that a function cannot be reached.

```
patchtrace graph neighbours ...   # callers and callees around one function
patchtrace graph delta ...        # callee changes of modified pairs
patchtrace graph leads ...        # ordinal graph signals per changed function
patchtrace graph paths ...        # observed call paths over the stored call lists
patchtrace graph export ...       # write one match neighbourhood as DOT or JSON
patchtrace graph series ...       # how a function neighbourhood changes across a series
```

Read the direction of each edge: a caller calls the function, and a callee is called by it. Do not infer call counts, execution order or runtime coverage from a static list.

Desktop equivalent: the [Calls panel](24-call-graph-panel.md).

Sources: `src/patchtrace/callgraph/cli.py`, `src/patchtrace/cli_commands/graph.py`, top-level `patchtrace --help`.
