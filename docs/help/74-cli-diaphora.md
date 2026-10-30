# `patchtrace diaphora`

Import and review an **existing** Diaphora comparison as optional evidence for a PatchTrace project. This command does not start Diaphora or IDA, execute the target binaries, or replace the primary Ghidriff results.

```text
patchtrace diaphora inspect RESULT.diaphora [--json]
patchtrace diaphora import PROJECT --diff RESULT.diaphora [--manifest MANIFEST.json | --user-attest-pair] [--json]
patchtrace diaphora show PROJECT [--json]
```

- `inspect` reads a supplied result database without opening a project and reports version, tables, match counts, and unmatched records.
- `import` binds an existing result to the project's older/newer pair. Prefer a `diaphora-diff/1` manifest with provenance and pair identity. Without one, `--user-attest-pair` records an explicit analyst attestation; it does not independently verify the original binary pair.
- `show` lists imported result sets and their reconciled relationship to the primary Ghidriff matches.
- `--json` writes an `enrichment-cli/1` JSON envelope; it does not make the evidence more authoritative.

Only Mode A (result import and display) is supported. PatchTrace does not launch an IDA/Diaphora analysis here. Treat matches as tool-supplied hypotheses, not proof of a vulnerability or patch effectiveness. Use `patchtrace diaphora --help` and each subcommand's `--help` for current arguments.

See [secondary comparison engines](59-cli-secondary.md) and `docs/specs/diaphora-optional-engine.md`.
