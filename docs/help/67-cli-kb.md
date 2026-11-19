# `patchtrace kb`

Correlates Microsoft KB numbers and CVE identifiers with advisory documents and file pairs. `index sync` fetches monthly advisory metadata with consent for the exact hosts and request plan. `acquire` downloads file pairs with consent for the exact hosts. `inventory fetch` is an optional remote request with its own exact-plan consent; the other inventory operations use local data. Coverage is stated with every answer: a "not found" applies only to the documents that were checked.

```
patchtrace kb index ...         # offline index: import, status, verify, plan (see "kb index --help")
patchtrace kb index sync --help # monthly metadata fetching and its consent flags
patchtrace kb search ...        # find the CVEs and products of a KB or CVE in loaded documents
patchtrace kb attach ...        # finish or inspect the context attach of a project
patchtrace kb explain ...       # show a project's advisory context
patchtrace kb export ...        # write the advisory context as JSON or escaped Markdown
patchtrace kb products ...      # list the product scopes of an investigation
patchtrace kb products --all --query 24H2 # browse active stored products without creating an investigation
patchtrace kb components ...    # component hints (analyst names and advisory title names)
patchtrace kb inventory ...     # import, retain, inspect and select file-list metadata; optional consented fetch
patchtrace kb pairs ...         # pair candidates from the saved Winbindex records
patchtrace kb import-pair ...   # compare two files you hold: create and attach a project
patchtrace kb plan ...          # preview what a file-index pair needs; makes no request
patchtrace kb leads ...         # group the changed functions by CVE (run "rank" first)
patchtrace kb acquire ...       # download, verify and compare a file-index pair (needs consent)
```

Check the product and architecture before you read an association. An advisory mention, a vendor remediation statement and a disputed applicability are different things.

## Saved file inventories

`kb inventory import FILE --kb KB` retains a saved CSV for offline inspection. Use `list` to find its import ID and `show IMPORT_ID` to inspect rows, original metadata, counts and conflicts. Add `--workspace DIR` and `--json` after the subcommand when needed. These actions work without a comparison project. Local file lists remain unverified source claims and cannot establish binary identity or a CVE fix.

`kb inventory retain IMPORT_ID --architecture amd64 --page 1` reads a source page from the saved raw CSV and returns a new import ID. It preserves the earlier import and its original limits. Source pages are one-based; `show --limit/--offset` pages the rows already retained. An incomplete source scan cannot feed filename selection.

Use `kb inventory select IMPORT_ID ENTRY_ID --investigation ID --product ID --expected-revision N` only after inspecting the row and the investigation's current product scope and revision from `kb products`. An unmapped source also needs `--assert-scope`; known product, architecture and build conflicts still refuse selection. The chosen row must be an eligible AMD64 PE filename with a known version. Stale selections leave the existing revision and decisions unchanged.

`kb inventory links HTML --page-url URL` inspects saved support links without following them. `plan URL --kind file-inventory --json` previews a request without fetching. For an optional remote fetch, save and review that plan, then supply `fetch --plan-file FILE --consent-plan SHA --consent-host HOST`, repeating the host flag for every planned host. CSV fetching also requires `--kb`. An unexpected redirect needs a new preview and fresh consent; `--offline` refuses requests even with consent. Advisory or symbol-server consent does not authorize this operation.

The [file-inventory guide](kb-file-inventory.md) gives complete examples, source-page bounds and exit-code remedies. Desktop equivalent: **File inventories…** in the [KB and CVE panel](29-kb-and-cve-investigation-panel.md).

## Continue a retained investigation

After attaching context and completing a comparison, continue with
[retained KB/CVE patch-intent leads](70-cli-pilot.md#continue-a-retained-kbcve-investigation).
Eligible CVRF fields retain their source bindings and unknown applicability;
overlapping CSAF statements take precedence. Saved leads and report exports
check for changed evidence before presenting them as current.

`search --kev-dir DIR` uses a local KEV catalogue (the default is the catalogue
used by `patchtrace kev`). Search JSON includes CVE-level status, listing date,
snapshot identity and catalogue provenance. No catalogue means not loaded;
absence from a loaded snapshot says nothing about exploitation. KEV does not
change advisory edges or the order of functions.

Desktop equivalent: the [KB and CVE panel](29-kb-and-cve-investigation-panel.md).

Sources: `src/patchtrace/kbcorrelation/cli.py`, `cli_online.py`, `cli_index.py`, `cli_acquire.py`, `cli_pairs.py`, `cli_leads.py`, `cli_inventory.py`, `src/patchtrace/cli_commands/kb.py`, top-level `patchtrace --help`.
