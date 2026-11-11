# `patchtrace diaphora`

Import an existing Diaphora comparison as optional, separately attributed matching evidence. This is **Mode A import**, not a way to launch IDA or Diaphora. PatchTrace does not run an analysed binary.

```text
patchtrace diaphora inspect RESULT.diaphora [--json]
patchtrace diaphora import PROJECT --diff RESULT.diaphora [--manifest SIDECAR.json | --user-attest-pair] [--json]
patchtrace diaphora show PROJECT [--json]
```

- **inspect** reads the existing result database and reports its version, match counts and unmatched counts. It does not bind evidence to a project.
- **import** stores the result for the chosen project pair and compares it with stored Ghidriff matches. Supply a `diaphora-diff/1` manifest to bind the result to the exact older/newer binaries, or explicitly attest the pair with `--user-attest-pair` if a manifest is unavailable. Review the evidence provenance before trusting any relationship.
- **show** summarizes previously imported Diaphora results and their reconciliation with Ghidriff. It does not run a new comparison.

`--json` prints a machine-readable `enrichment-cli/1` document. Exit status is 0 on success, 2 for invalid input/environment, 3 for runtime failure, 4 if there are no results, and 5 if cancelled.

The Diaphora match set remains a separate evidence source; it does not silently replace Ghidriff or unified-engine matches. Missing or unverified provenance must not be described as verified identity.

See `src/patchtrace/diaphora/cli.py`, `docs/specs/diaphora-optional-engine.md`, and `patchtrace diaphora --help`.
