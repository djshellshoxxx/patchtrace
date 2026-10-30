# `patchtrace diaphora`

Read and import an **existing** Diaphora comparison result as optional function-matching evidence. The current Mode A commands do not launch Diaphora, IDA, or the analysed binaries; the Ghidriff result remains primary. This capability is experimental, and the source's Diaphora result format has not yet been confirmed against real Diaphora 3.4.3 output.

```
patchtrace diaphora inspect RESULT.diaphora [--json]
patchtrace diaphora import PROJECT --diff RESULT.diaphora [--manifest FILE] [--user-attest-pair] [--json]
patchtrace diaphora show PROJECT [--json]
```

- `inspect` checks the supplied Diaphora SQLite result without a project and reports its table counts and detected version; it does not establish pair provenance.
- `import` associates an existing `.diaphora` result with a project. Provide a binding manifest using `--manifest` when available. Without one, `--user-attest-pair` records an explicit lower-trust assertion that the supplied result belongs to exactly this older/newer binary pair. Imported evidence is stored separately from Ghidriff matches and does not overwrite analyst corrections.
- `show` lists stored Diaphora result sets and their reconciliation with the primary Ghidriff matches. No Diaphora result in the project is a no-results state, not evidence that no functions match.
- `--json` prints a structured `enrichment-cli/1` response rather than human-readable text.

Exit statuses follow the usual CLI convention: 0 complete, 2 invalid input or environment, 3 runtime or partial failure, 4 no results, 5 cancelled. Import can exit 4 when a valid result contains no matches.

These commands only support **import of an existing result**. Export-database comparison, automated Diaphora/IDA execution, additional signals and GUI integration remain unimplemented; see [optional Diaphora engine specification](../specs/diaphora-optional-engine.md) and [secondary engine configuration](44-configure-secondary-engines.md).

Sources: `src/patchtrace/diaphora/cli.py`, `src/patchtrace/cli_commands/diaphora.py`, and `docs/specs/diaphora-optional-engine.md`.
