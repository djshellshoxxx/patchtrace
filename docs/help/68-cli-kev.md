# `patchtrace kev`

Works with CISA's Known Exploited Vulnerabilities (KEV) catalog. A catalog is a saved snapshot with a date and a source. KEV membership is exploitation context about a CVE. It is not a property of a function.

```
patchtrace kev status ...   # show the catalog in use and its age (no network)
patchtrace kev plan ...     # show the exact request a fetch would send (no network)
patchtrace kev fetch ...    # download the catalog after you name the host (one GET)
patchtrace kev import ...   # read a KEV JSON file you saved (no network)
patchtrace kev lookup ...   # look up CVE IDs in the catalog (no network)
patchtrace kev diff ...     # show what changed between two stored catalogs (no network)
patchtrace kev prune ...    # delete old stored catalogs (the only deletion)
```

- `plan` shows the request before any `fetch`. Read it first.
- `fetch` needs `--consent-hosts` with the host named in `plan`.
- A missing or old catalog cannot support a current negative answer. "Not listed" applies only to the snapshot you checked.

Desktop equivalent: the [Exploitation context panel](30-kev-context-panel.md), with **Update from CISA...** and **Import file...**.

Sources: `src/patchtrace/kev/cli.py`, `src/patchtrace/cli_commands/kev.py`, `src/patchtrace/ui_kev.py`, top-level `patchtrace --help`.
