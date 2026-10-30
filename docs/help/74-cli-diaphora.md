# `patchtrace diaphora`

Imports an existing Diaphora comparison database as **optional, secondary match evidence**. PatchTrace does not launch IDA or Diaphora, and the imported result cannot overwrite the primary Ghidriff matches or analyst corrections. You must provide the database yourself; this command does not extract or execute target binaries.

```
patchtrace diaphora inspect RESULT.diaphora
patchtrace diaphora import PROJECT --diff RESULT.diaphora --manifest MANIFEST.json
patchtrace diaphora import PROJECT --diff RESULT.diaphora --user-attest-pair
patchtrace diaphora show PROJECT
```

- `inspect` reads a result without a project, reporting match and unmatched counts. It does **not** bind the result to a binary pair.
- `import` verifies the supplied result and binds it to the chosen project's older/newer pair. Use `--manifest` for the `diaphora-diff/1` sidecar. If there is no manifest, `--user-attest-pair` explicitly records the analyst's assertion that the exact ordered pair was used; an assertion is **not cryptographic verification**.
- `show` displays stored Diaphora match sets and their reconciliation with existing Ghidriff matches.
- Every subcommand accepts `--json` to emit the `enrichment-cli/1` output envelope.

A Diaphora match score or a high similarity is not evidence of a confirmed CVE or exploitability. Engine agreement over common disassembly is not independent proof. This integration is an optional import workflow, not a live adapter; ordinary PatchTrace analysis requires neither IDA nor Diaphora.

Sources: `src/patchtrace/diaphora/cli.py`, `src/patchtrace/diaphora/service.py`, and `src/patchtrace/cli_commands/diaphora.py`.
