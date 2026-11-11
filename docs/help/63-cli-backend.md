# `patchtrace backend`

Checks the analysis runtime that ships in an offline bundle next to PatchTrace. Use it to confirm the bundle before you compare anything.

```
patchtrace backend status ...      # report the bundle after a fast file check (starts no process)
patchtrace backend verify ...      # verify the bundle files against backend/manifest.json
patchtrace backend selftest ...    # run a real comparison through the bundled runtime and check the result
patchtrace backend diagnose ...    # run the backend dependency diagnosis with the bundled runtime
```

- `status` is the quick check. It starts no process.
- `verify` hashes the bundle files. A matching manifest shows integrity, not who published the files.
- `selftest` runs a real comparison, so it needs a complete runtime and time to finish.
- `diagnose` checks dependencies. A passing check does not prove that every file pair compares.

Desktop equivalents: **Verify bundle files** and **Diagnose dependencies** in **Setup**. Error codes are listed in [troubleshooting](52-troubleshooting.md#bundle-verification-errors).

Sources: `src/patchtrace/backend_cli.py`, `src/patchtrace/backend_bundle.py`, `src/patchtrace/ui_bundle_setup.py`, top-level `patchtrace --help`.
