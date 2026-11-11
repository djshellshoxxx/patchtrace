# `patchtrace inspect`

Reads static version, manifest and embedded-signature facts from the saved older and newer project artifacts. The command does not execute either binary or assert that a signature is trusted merely because it exists.

```text
patchtrace inspect <project>
patchtrace inspect <project> --side older
patchtrace inspect <project> --side newer --json
```

Use `--side older|newer|both` (default: `both`). The default `--trust offline` examines local structures and digests only; it does not perform chain-trust or revocation checks. Results identify unreadable and non-PE inputs rather than inventing missing facts.

`--trust cache|online` refers to Windows catalog/revocation functionality **not implemented in this build**. Both return `PT-PE-TRUST-UNAVAILABLE` (exit 3). Online checking additionally requires `--consent-online`; without it the command rejects the request with `PT-PE-CONSENT-REQUIRED` (exit 2). Consent alone does not enable an unavailable feature.

`--json` emits one `enrichment-cli/1` document with a `pe-inspect/1` result. Exit codes: 0 completed; 2 invalid arguments or project; 3 failed or partial inspection; 4 only non-PE inputs; 5 cancelled. The result does not include absolute input paths.

Desktop equivalent: the project inspection and signing information view (where built). Do not confuse embedded-signature presence with verification of current trust or revocation status.

Sources: `src/patchtrace/cli_commands/inspect.py`, `src/patchtrace/pe_overview/{cli,metadata,signature}.py`.
