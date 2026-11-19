# Retained CVRF complete-row byte budget — 2026-11-18

## Outcome and source

The 16 MiB retained-context budget now covers the combined stored-field bytes of **all 12 columns across all selected rows**, before the shared enrichment reader loads any complete row. Oversized guard, ID, timestamp, status, or checksum text can no longer bypass a body-only limit. Refusal withholds the complete CVRF channel with a deterministic unavailable snapshot and a plain byte-limit warning. The valid context identity payload is unchanged.

Spec and red controls: `91a96acdf9f2c610d650af1a238e46ace5d0d2c3`. Source: **`8e368dd88c3ad65726d84701219942ff38c6c2cd`**; tree: `ab751b5ae29a69cb8bbf100c6efefda935bd9ca8`. This appends to storage-class source `423a4fc00599cd085ac4a3b95db3e164071f4d79` and its QA `3897d2ab63cc77d7146dba0835d37f301f730245`. Earlier source and results remain historical evidence; they do not qualify this later repair.

Only `pilot/sources/kb_context.py` changes in production. Shared enrichment storage/schema, other source adapters, collector semantics, and the separately owned freshness hook are unchanged.

## Confirmed gap and contract change

Root's independent controls increased real SQLite `created`, `project_id`, and `input_digest` text beyond a small authored `MAX_BYTES`. The bounded metadata scan counted only body bytes, then called the shared reader, which loads all row fields. All three probes failed at a sentinel for this over-budget full-row allocation.

The preflight now obtains a scalar sum of `length(CAST(column AS BLOB))` for every selected column, validates storage types as before, and adds these byte counts across the selected rows before calling `entries()`. The existing 1,001-row metadata scan / 1,000-row admission limit remains. Every UTF-8 byte and every byte after an embedded NUL contributes to the budget. Integer metadata contributes its SQLite text-form length. The fixed `kind` text and checksum are included even though they are small in healthy rows.

This is a **stricter combined 16 MiB allowance** than the previous body-only cap. A valid body near the old limit can now be refused when its other row fields are included. There is no separate per-row allowance and no truncation or prefix selection. The original valid-row identity fields are retained exactly, so ordinary admitted contexts keep their digests.

## Evidence and chronology

| Stage | Result | Meaning |
| --- | --- | --- |
| Original independent metadata-budget probes at `423a4fc0` | **3 failed in 0.65 s** | Actual oversized SQLite text reached shared full-row loading; unchanged source/log/XML retained |
| New specification and controls before implementation | **15 failed, 1 passed in 1.11 s** | 13 new local cases plus the same three probes; the existing oversized-body case already passed |
| Repaired focused candidate | **41 passed in 2.09 s** | Both local regression groups and all six original independent storage-class/budget probes |
| New exact-source affected suite at `8e368dd8` | **1,574 passed in 36.27 s, no skips** | All pilot tests; field provenance and lineage counting; Leads UI; intelligence explain/CLI; fabric adoption; all six independent probes |
| Whole Ruff and diff check at this source | **Passed** | Raw logs retained |
| Existing authored retained-project compatibility | **Byte-identical before/after snapshot** | Complete admitted bundles, CVEs, warnings, and digest match across the budget repair |

The focused 41 cases are included in the 1,574-case affected run. The earlier 1,558-pass storage-class run is preserved in its own receipt and is not counted as validation of this later source. Test counts are not completion or accuracy percentages.

The new field controls cover every variable text column (`id`, project/run guard fields, status, creation text, body, checksum) with UTF-8 payloads whose character count fits but whose byte count exceeds the budget. A separate embedded-NUL case prevents SQL character-length truncation from hiding the suffix. The multiple-row control keeps each row and all bodies individually within the cap while exceeding it in aggregate with metadata; no full-row load is allowed. One- and two-row positive controls accept the complete selected-row total exactly, preserve the prior valid snapshot, then refuse when the limit is lowered by one byte. These boundary controls also verify inclusion of fixed `kind` and integer fields.

The previously retained authored import/pair/analysis/rank project's context digest remains **`2b81eea4d485ae8372c7c6239898a0accf7c0897ee5ae0801ac65e4f61331123`**. Full serialized snapshots, their hashes, and the capture script are retained.

## Source pinning and remaining limits

Tests use `/workspace/scratch/3a6632a6e5ff/venv/bin/python`, `QT_QPA_PLATFORM=offscreen`, and absolute `/workspace/scratch/c7a9e8d98848/cvrf-pilot/src` plus that worktree's `tests` in `PYTHONPATH`. The packet records exact expanded commands, imports, Python/platform details, source hashes, and original-probe hashes. The shared environment's older editable install is not treated as the tested source.

The cap bounds selected stored-field bytes admitted to the full shared-row reader. It is not a guarantee on SQLite's internal working memory, total database I/O/latency, Python object overhead, or arbitrary concurrent database replacement. The existing decoded-structure and cancellation checks remain separate. Root owns independent combined CVRF/freshness review before publication. Exact combined/full/platform gates, native Windows, frozen builds, live/native-engine data, target execution, and manual desktop acceptance were not performed here.

## Retained packet

`pilot-cvrf-metadata-budget-20261118/manifest.json` binds all **20** receipts in `raw-evidence.zip`: original metadata-budget probe/log/XML, unchanged storage-class probe source, pre-fix and fixed raw logs/XML, Ruff/diff output, valid before/after snapshots, compatibility script, provenance, and receipt-building script. ZIP size: **44,526 bytes**. SHA-256: **`22ff6b1660ba36568a9bac3824cad68c16dcac24eaae99e6d01fefb0bdce5695`**. CRC, every member hash, original-probe equality, before/after snapshot equality, and exact source/tree hashes were verified before this QA commit.
