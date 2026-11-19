# Pydantic security pin upgrade, 2026-11-19

This slice changes the direct runtime pin from Pydantic 2.13.5 to 2.14.2 on
`codex/patchtrace-pydantic-security-20261119-81e4`, based on
`f114eb96c392d97ad88ddbbc0bda55c159b92559`. The owned checkout is
`/tmp/pt81-test-harness`. No production Python module, Qt dependency, historical
receipt, frozen diagnostic candidate, or remote branch is changed here.

## Reason and advisory scope

The maintainer's four advisories place 2.13.5 in affected version ranges. The
selected 2.14.2 pin includes all four fixes. These are dependency findings;
application reachability has not been established.

| Maintainer advisory | Affected versions stated by the advisory | First fixed version | Relevant precondition |
|---|---|---|---|
| [GHSA-qpmf-fgh3-ff25](https://github.com/pydantic/pydantic/security/advisories/GHSA-qpmf-fgh3-ff25) | `>=2.13.0, <2.14.2` | 2.14.2 | JSON validation with allowed extras and a constrained extra-key type |
| [GHSA-3r8g-cqwr-jr29](https://github.com/pydantic/pydantic/security/advisories/GHSA-3r8g-cqwr-jr29) | `>=2.0, <2.14.2` | 2.14.2 | Aliased TypedDict/dataclass fields with allowed extra data |
| [GHSA-955g-x97g-8mcp](https://github.com/pydantic/pydantic/security/advisories/GHSA-955g-x97g-8mcp) | `2.0.0, <2.14.0` | 2.14.0 | Untrusted multi-host URLs with resource-expensive prefixes/host counts |
| [GHSA-gj4f-r7mf-jjxh](https://github.com/pydantic/pydantic/security/advisories/GHSA-gj4f-r7mf-jjxh) | `>=2.10.0, <2.14.0` | 2.14.0 | Fraction validation of exponent-form strings |

The [2.14.2 release notes](https://github.com/pydantic/pydantic/releases/tag/v2.14.2)
also describe JSON alias/extra-field handling becoming consistent with Python
validation. That behavior merits compatibility checks even where an application
forbids extras. The source search found the core and enrichment record bases
forbid extras, and the N-way contract uses an alias with `populate_by_name=True`.
This limited inspection is not a proof that every advisory path is unreachable.

`rg` found the active install pin in `pyproject.toml`. The current packaging guide
and notices table are updated with it. Dated research plans, measurements, and
audit receipts retain their original dependency versions. No wire-contract
change or schema migration is introduced; schema regeneration below found no
byte differences, so model specifications and committed schemas stay unchanged.

## Exact environment and wheel inputs

Python is 3.12.14 on Linux x86-64. The private symlink venv is
`/tmp/pt81-pydantic-venv`; editable PatchTrace metadata and the five validation
packages are installed in its own site-packages. Installs used the existing
wheel directory with `--no-index --no-deps --ignore-installed`, without a shared
package uninstall or a network fetch. Other dependencies are read from the
existing shared environment. Isolated `-I` import checks confirmed the owned
source path and the private compiled pydantic-core extension.

| Distribution | Before | Tested after |
|---|---|---|
| Pydantic | 2.13.5 | 2.14.2 |
| pydantic-core | 2.46.5 | 2.50.2 |
| annotated-types | 0.8.0 | 0.8.0 |
| typing-extensions | 4.16.0 | 4.16.0 |
| typing-inspection | 0.4.5 | 0.4.5 |
| PySide6 / shiboken6 | 6.12.0 / 6.12.0 | Unchanged versions and import origins |
| protobuf | 7.36.2 | Unchanged version and import origin |

The supplied Pydantic wheel requires core 2.50.2, annotated-types at least 0.6.0,
typing-extensions at least 4.16.0, and typing-inspection at least 0.4.4. The three
supporting package versions already met those requirements before this slice.

| Exact wheel | SHA-256 |
|---|---|
| `pydantic-2.14.2-py3-none-any.whl` | `7efbf7507b937931cd32a5755acb00ea1cf5ccb1d4e8067a5850d5069e382118` |
| `pydantic_core-2.50.2-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` | `9667637665acba166a7dbbc786f14c50512d3a01f7199e0e1a13b929e92d7c7a` |
| `annotated_types-0.8.0-py3-none-any.whl` | `f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0` |
| `typing_extensions-4.16.0-py3-none-any.whl` | `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8` |
| `typing_inspection-0.4.5-py3-none-any.whl` | `bc210535442b39e1bf2805e0c7a17dfd6a4ace760c84c7f7d16245d23a6b1c39` |

## Validation evidence

The new dependency test verifies the direct pin and installed Pydantic/core
versions. Bounded constructed types check constrained extra keys in Python/JSON
mode, alias/name collisions for TypedDicts and dataclasses in both modes, and
Fraction exponents immediately around the documented 4,300 bound. The positive
controls retain valid values and unrelated allowed extras. These upstream
controls do not assert a reachable application exploit. The multi-host URL fix
is supported by the upstream advisory; local controls do not benchmark its
asymptotic behavior.

| Check | Recorded result |
|---|---|
| New controls on Pydantic 2.13.5/core 2.46.5 | 8 failed, 1 passed in 1.24 s |
| Identical controls on Pydantic 2.14.2/core 2.50.2 | 9 passed in 0.96 s |
| All 16 repository schema generators under each version | Both phases succeeded; all 301 files under `docs/schemas` and the generated CSAF table remained byte-identical |
| Whole configured Ruff (`src tests tools`) | Passed |
| Private environment `pip check` | Passed |
| Compatibility selections | 79 distinct files in 28 batches: 2,903 passed, 1 existing strict xfail, no skipped tests/failures/errors; summed batch wall time 195.955 s |

The selection includes 1,341 passing model/contract controls; 136 schema/packaging
passes and the expected failure; 328 strict JSON, cache and storage-boundary
passes; 390 feature-store and N-way persistence passes; 630 CLI passes; and 78
report/fingerprint passes. The existing strict xfail is
`test_codex_pkg_packaging.py::test_linux_package_runs_full_cli_smoke` (`CODEX-14`).
No marker was added or relaxed. The new nine dependency controls are included in
the 2,903 total; the separate nine-test green run is not added to that total.

The first combined 16-file model/contract selection was terminated by SIGKILL
after 9.573 s. It has no completed pytest summary or JUnit and is not a pass.
The next apparent case, the enrichment ordering property test, passed alone on
2.14.2 in 3.36 s. The termination's cause is not established. The same selected
compatibility files then completed in batches of at most three, preserving all
assertions and the incomplete first attempt. No golden or fixture was rebaselined.

## Receipts and reproduction

Receipts are under `/workspace/scratch/81e4938f4a3a/verification`:

- `pydantic-upgrade-versions-before.json` and `pydantic-upgrade-versions-after.json`
  record exact versions, import origins, wheel hashes/metadata, and the compiled
  extension path. `pydantic-upgrade-shared-unchanged.json` confirms all eight
  original package versions and import origins stayed unchanged.
- `pydantic-upgrade-install.log`, `pydantic-upgrade-editable.log`,
  `pydantic-upgrade-pip-check.log`, and `pydantic-upgrade-ruff.log` retain setup and
  static-check output.
- `pydantic-security-{red,green}.{log,xml}` retain the controlled version comparison.
- `pydantic-schema-compare.{py,json,log}` records all generator commands and file
  hashes before and after both phases.
- `pydantic-compatibility-{run.py,run.log,results.json}` retains the interrupted
  grouped attempt. `pydantic-compatibility-bounded-{run.py,run.log,results.json}`
  records the smaller batches, exact file selection, commands, exits, and skips;
  each batch has its own `pydantic-compatibility-<group>-<part>.{log,xml}`.
  `pydantic-compatibility-summary.json` aggregates the completed JUnit results and
  distinguishes the existing expected failure from ordinary skips.

The bounded runner uses the private interpreter, `QT_QPA_PLATFORM=offscreen`,
`PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`, an explicit per-batch basetemp,
and `tmp_path_retention_policy=failed`. Reproduce its exact selection with:

```bash
/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12 -B \
  /workspace/scratch/81e4938f4a3a/verification/pydantic-compatibility-bounded-run.py
```

Native Windows wheels/builds and remote CI remain separate gates. This report
does not declare the entire dependency closure free of advisories, supply a
complete lock/SBOM, or qualify a release.
