# Retained CVRF SQLite storage-class repair — 2026-11-18

## Outcome and source

Malformed selected `kb-context` rows now withhold CVRF context before the shared enrichment reader loads their bodies. The adapter returns a deterministic unavailable snapshot, a plain warning, and no trusted cards. Named collection returns the existing `PT-PILOT-STALE` / `advisory-context-unavailable` failure instead of leaking a Python decoding or identity exception. Valid retained context behavior and identity are preserved.

Spec and red controls: `e1b161fdd1dd64a09379f9ca98bfdec4cc1ca428`. Source: **`423a4fc00599cd085ac4a3b95db3e164071f4d79`**; tree: `ea6dbeaf67441c8ae2d7a2d7f08bcd603966e5c3`. Both append to the original bridge and QA history ending at `7cc6a0392c9af5844f226deadcf20ff16f4dc96c`; the original implementation is `353902677e6d59961e808a90b2a3dd96d2b43269`.

Only `pilot/sources/kb_context.py` changes in production. The shared enrichment reader, project schema, collector, advisory adapter, and separately owned current-input freshness hook remain unchanged.

## Confirmed failure and correction

The independent review wrote SQLite BLOB values into `body`, `body_sha256`, and `id`. BLOB bodies reached the shared reader's string `.encode()` call and raised `AttributeError`. BLOB IDs/checksums survived into the failure-path identity payload, where the canonical identity encoder rejected bytes and raised `TypeError`. The existing fallback therefore could itself crash while trying to mark a malformed context unavailable.

The metadata query retains its row-count limit and bounded ID/checksum prefixes, and now requests SQLite `typeof` values for all selected row text/integer fields. It checks these primitive/storage classes before calling `EnrichmentStore.entries()`. BLOB, NULL, integer, and real values in incompatible columns fail at this preflight. Only safe bounded primitives enter the metadata identity; bytes and real values use explicit deterministic type-tagged text encodings. Valid rows keep the original identity payload, preserving existing digests.

The change does not coerce malformed rows into valid evidence or select older contexts after refusal. It adds no source acquisition, second project open, network access, native analysis, or target execution.

## Evidence and chronology

| Stage | Result | Meaning |
| --- | --- | --- |
| Original independent reproducers against original bridge | **3 failed in 0.70 s** | Preserved unchanged probe and raw log/XML; actual BLOB crashes |
| New spec/control stage before repair | **24 failed, 1 passed in 1.66 s** | 22 new local cases plus the same three independent probes; the existing NULL-body path already withheld context |
| Focused repaired candidate | **25 passed in 1.45 s** | Primitive-type refusals, deterministic snapshot, no named leads, restoration, and unchanged original probes |
| Exact source `423a4fc0` affected suite | **1,558 passed in 35.92 s, no skips** | Every `test_pilot*.py`, field provenance, no-double-count lineage, Leads UI, intelligence explain/CLI, fabric adoption, and the three independent probes |
| Exact-source whole Ruff and diff check | **Passed** | Raw outputs retained |
| Real authored retained-project compatibility | **Byte-identical before/after snapshot** | The previously retained import/pair/analysis/rank project was read before and after the fix; its CVEs, admitted bundles, warnings, and digest did not change |

The 25 focused cases are included in the 1,558-case affected result; they are not additive coverage. This is a bounded source qualification, not a full test-suite or completion percentage.

The malformed-row controls exercise actual SQL storage classes, asserting `typeof` at the read boundary. A deliberately weakened test table permits NULL and numeric neighbors that a healthy table's normal constraints/affinity would prevent or coerce. These changes exist only in disposable fixture databases; no product schema is migrated. The controls replace the shared `entries` method with a refusal sentinel and prove body loading is not reached. A separate restoration control repairs the original checksum and observes the original valid snapshot and normal unverified CVRF advisory context.

The retained authored project's context digest remains **`2b81eea4d485ae8372c7c6239898a0accf7c0897ee5ae0801ac65e4f61331123`**. Both complete serialized snapshots and their hashes are retained, rather than inferring identity compatibility from source inspection alone.

## Reproduction and limits

Commands use `/workspace/scratch/3a6632a6e5ff/venv/bin/python`, `QT_QPA_PLATFORM=offscreen`, and absolute `/workspace/scratch/c7a9e8d98848/cvrf-pilot/src` plus that worktree's `tests` in `PYTHONPATH`. The packet records the complete expanded affected selection, source/import paths, Python/platform details, source file hashes, and original independent evidence hashes. Source pinning avoids the shared environment's older editable checkout.

This repair handles malformed primitive/storage types in selected retained-context rows. It does not qualify arbitrary concurrent database mutation, unlimited metadata in other channels, all SQLite corruption modes, or the separate current-input hook. Root owns independent review of the combined CVRF/freshness slice before publication. Exact combined/full/platform gates, native Windows behavior, frozen builds, external-engine/native data, and manual desktop acceptance remain separate. Synthetic local fixtures and offscreen tests do not satisfy those gates.

## Retained packet

`pilot-cvrf-storage-classes-20261118/manifest.json` binds all **19** receipts in `raw-evidence.zip`: original independent source/log/XML; pre-fix and fixed raw logs/XML; Ruff/diff output; valid before/after snapshots and capture script; provenance; and receipt-building script. ZIP size: **45,328 bytes**. SHA-256: **`e0c3e45738e5a3cd7b5910c38a1a009f29058aca0e3df37be484ba54f57effdf`**. CRC, member digests, original probe/log copies, before/after snapshot equality, and exact source/tree hashes were checked before this QA commit.
