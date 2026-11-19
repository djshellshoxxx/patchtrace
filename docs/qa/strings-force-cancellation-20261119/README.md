# Forced strings export cancellation — 2026-11-19

## Outcome

The selected PR #308 repair introduced an additional cleanup regression: it broadened forced-export staging cleanup from `OSError` to `BaseException`. A `KeyboardInterrupt`, `SystemExit`, or other non-I/O failure could therefore remove a foreign replacement at the staging pathname. Original main and #317 retained that pathname for cancellation. The no-force recovery at `6e0342ff5217552e14fb37739a4e529ca5db089b` inherited the broadened force cleanup.

The bounded correction restores the original exception boundary. It still closes a descriptor owned by the attempt, but only an `OSError` enters the existing forced pathname cleanup. Non-I/O failures propagate without unlinking that name. Random exclusive staging, JSON/CSV output, ordinary force replacement, and the new owned-source no-force route remain available.

- Regression/specification commit: `03f23f515e2433cb6442d7c18395be02115598b4`.
- Corrected source: `14f0e2c973dc5a9f6025aa6fa98138b1efe07023`.
- Source tree: `df1d30e643bbce570d1e2089c391146e22c00c43`.
- Source parent: `6e0342ff5217552e14fb37739a4e529ca5db089b`.

The earlier forced-publication and ordinary I/O cleanup races remain **BLOCKED**. This correction does not claim full forced-export source ownership, and it does not remove Linux `--force` functionality. Non-I/O interruption can leave a staging entry for inspection, matching the original exception behavior.

## Independent controls

Six new controls interrupt the publication seam after the source stream closes. They cover `KeyboardInterrupt`, `SystemExit`, and `RuntimeError`, each with either the owned stage still present or a foreign replacement placed at its name. The prior destination and, for substitution, the moved original stage must remain unchanged; the identical exception must propagate.

All six controls failed on the pre-correction runtime because its cleanup removed the staging name. After correction, the expanded export/CLI/shared-publication selection passed **53 tests in 4.36 seconds**, with no failures, errors or skips. Existing normal forced-replacement and ordinary I/O failure behavior checks still pass. Whole-tree Ruff and whitespace checks passed.

The retained `strings-source-ownership-20261119/force_source_probe.py` was rerun unchanged. Its twelve rows preserve exact source hashes and show:

| Source | Forced success under substitution | Forced OSError under substitution | Forced Ctrl+C under substitution |
|---|---|---|---|
| Main `9c411ca3` | Foreign bytes published; blocked | Foreign stage removed; blocked | Foreign stage preserved |
| #317 `88b0b522` | Foreign bytes published; blocked | Foreign stage removed; blocked | Foreign stage preserved |
| Selected #308 on `d436a7ec` | Foreign bytes published; blocked | Foreign stage removed; blocked | Foreign stage removed; introduced regression |
| Corrected source `14f0e2c9` | Foreign bytes published; still blocked | Foreign stage removed; still blocked | Foreign stage preserved; original boundary restored |

These are authored temporary-file probes on Linux, not native Windows qualification. The success/OSError rows remain failures of the broader ownership invariant and were not relabelled as passing acceptance. The proof command exits normally because it records observations; its JSON status remains `BLOCKED`.

## Evidence

`manifest.json` records commands, exact source identities, counts, limits and SHA-256 hashes of the red/green logs, JUnit, Ruff output and the complete baseline proof. The original red pytest log and JUnit contain pytest-emitted trailing whitespace and are preserved byte-for-byte in `raw-failures.zip`; their result text was not normalized. The source-authored no-force evidence and its older force observations are preserved without modification. The original source history distinguishes inherited defects from this introduced regression.

No remote ref, protection, PR, or issue was changed. Full combined hosted checks and native Windows remain the integration owner's qualification gates.
