# `patchtrace pilot`

Produces ordered, explained leads for changed function pairs. A lead is a place to look. The order follows explainable rules, not likelihood. A lead does not show that a function contains or fixes any CVE. The command reads stored results and sends nothing.

```
patchtrace pilot leads ...    # compute, store and list the leads of the project
patchtrace pilot why ...      # explain one lead from the stored result
patchtrace pilot review ...   # pin, dismiss or annotate a lead (append only)
```

Useful `leads` options include `--cve`, `--class` (`fit`, `review`, `partial`, `code`, `queue`), `--limit`, `--no-unified`, `--show-dismissed` and `--export`.

`review` appends a decision. It does not delete the lead or rewrite earlier evidence. Dismissing a lead does not mean its code was validated.

Desktop equivalent: the [Leads panel](31-leads-panel.md) (`Ctrl+Shift+L`).

Sources: `src/patchtrace/pilot/cli.py`, `src/patchtrace/cli_commands/pilot.py`, top-level `patchtrace --help`.
