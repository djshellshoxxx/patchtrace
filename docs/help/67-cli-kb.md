# `patchtrace kb`

Correlates Microsoft KB numbers and CVE identifiers with advisory documents and file pairs. Everything except `acquire` is offline. `acquire` is the only verb that downloads, and it needs consent for the exact hosts. Coverage is stated with every answer: a "not found" applies only to the documents that were checked.

```
patchtrace kb index ...         # offline index: import, status, verify, plan (see "kb index --help")
patchtrace kb search ...        # find the CVEs and products of a KB or CVE in loaded documents
patchtrace kb attach ...        # finish or inspect the context attach of a project
patchtrace kb explain ...       # show a project's advisory context
patchtrace kb export ...        # write the advisory context as JSON or escaped Markdown
patchtrace kb products ...      # list the product scopes of an investigation
patchtrace kb components ...    # component hints (analyst names and advisory title names)
patchtrace kb pairs ...         # pair candidates from the saved Winbindex records
patchtrace kb import-pair ...   # compare two files you hold: create and attach a project
patchtrace kb plan ...          # preview what a file-index pair needs; makes no request
patchtrace kb leads ...         # group the changed functions by CVE (run "rank" first)
patchtrace kb acquire ...       # download, verify and compare a file-index pair (needs consent)
```

Check the product and architecture before you read an association. An advisory mention, a vendor remediation statement and a disputed applicability are different things.

Desktop equivalent: the [KB and CVE panel](29-kb-and-cve-investigation-panel.md).

Sources: `src/patchtrace/kbcorrelation/cli.py`, `cli_online.py`, `cli_index.py`, `cli_acquire.py`, `cli_pairs.py`, `cli_leads.py`, `src/patchtrace/cli_commands/kb.py`, top-level `patchtrace --help`.
