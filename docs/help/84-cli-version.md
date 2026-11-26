# `patchtrace version`

Shows the installed PatchTrace version and available **local** source/build observations.
It is a read-only, headless command. It does not run an analysis engine or contact a network.

```console
patchtrace version
patchtrace version --json
patchtrace version --help
```

In text mode it reports the package version, Python version, source/build basis,
Git commit and description, checkout cleanliness, and a source SHA-256 fingerprint.
Optional information may be **unknown**; this is not a failure or proof of an
unchanged, trusted or authenticated installation. A normal source checkout
always reports Git cleanliness as unknown.

With `--json`, standard output contains one `enrichment-cli/1` envelope for
command `version` and a `build-info/1` result. Its `basis` is `source-tree`
or `packaged-record`. The result also includes `frozen`, optional
`pyinstaller` and `pyside6` versions, and `built_utc` when available.

## What the observations mean

- **Git commit and description:** From fixed, bounded, read-only local Git
  commands when Git and the selected repository root are available. The tool
  avoids worktree status checks, which could run repository-configured filters.
  Tags and descriptions are observations, not signed release attestations.
- **Source SHA-256:** A bounded hash of the available Python source files in
  the `patchtrace` package. It is not the identity of running bytecode or
  native tools, nor an authenticity signature.
- **Frozen package:** Reads a strictly validated `build-info.json` record
  only when the builder supplied one. Current builders may not include that
  record; absent or invalid metadata is reported as unknown with a warning.

Missing Git, an invalid source root, changing files or exceeded inspection
budgets also produce warnings and unknown fields. Do not replace unknown
values with guesses or infer `dirty: false` from an absence of evidence.

The Git subprocess uses a minimal environment allow-list and a three-second
timeout, with no inherited API credentials, proxy settings or loader hooks.
Its output is limited to 4096 bytes; no native memory-cap guarantee is made.
Running this command does not establish dependency compatibility, test results,
release readiness, signing integrity or publisher identity.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The observation completed; individual optional fields may be unknown. |
| 2 | Invalid command-line arguments. |
| 5 | Cancelled. |

There is no single matching desktop control. For installation diagnostics,
see [`patchtrace doctor`](82-cli-doctor.md). For release and provenance
limitations, see [the version/source contract](../specs/version-provenance.md).
