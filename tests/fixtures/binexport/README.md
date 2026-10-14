# BinExport2 test fixtures (SPEC-10b §10.1)

## What is here

All `.BinExport` files in this directory are **synthetic**. They are produced by `tools/gen_binexport_fixtures.py` from `tests/binexport_builder.py`, using the runtime class built from the checked-in descriptor. They are serialized deterministically. No BinExport plugin, Ghidra or IDA was involved, so they are **not live-compatibility evidence** (AGENTS.md). Use them for format, pair, orientation and address-basis tests.

| File | Bound to | `executable_id` | Address basis |
|---|---|---|---|
| `synthetic-older.BinExport` | `patchtrace.sample.synthetic_pe(0)` | SHA-256 of that PE | VA (image base 0x180000000) |
| `synthetic-newer.BinExport` | `synthetic_pe(1)` | SHA-256 | VA |
| `synthetic-newer-rva.BinExport` | `synthetic_pe(1)` | SHA-256 | RVA (as if "Subtract Imagebase") |
| `synthetic-older-md5id.BinExport` | `synthetic_pe(0)` | MD5 of that PE (IDA-style fallback) | VA |

`PROVENANCE.json` (strict JSON) has one record per file: hashes, source PE SHA-256, origin, tool, options, license, observed id, expected id binding and address basis. `tests/test_binexport_fixtures.py` checks four things. Every `.BinExport` here has a record. The hashes match. Each id equals the source PE's SHA-256 (or its MD5 for the md5 case). Regenerating the files reproduces the committed bytes.

## Regenerating

```
python tools/gen_binexport_fixtures.py          # rewrite files + PROVENANCE.json
python tools/gen_binexport_fixtures.py --check  # exit 1 on drift
```

Regenerate only in a PR that explains why the bytes changed: a builder change, a `synthetic_pe` change, or a protobuf re-pin.

## Real-plugin goldens: OPEN, manual (C3-7)

These need a human or a CI step with Ghidra and the BinExport extension, or a licensed IDA 9.4+.

1. Compile `tests/fixtures/old.c` / `new.c` (project-owned) to small PEs with clang-cl or mingw, and record the compiler and flags.
2. Import each PE into Ghidra from that exact path, so that `executable_id` is the SHA-256 of the file.
3. Export with the BinExport extension:
   - GUI: File > Export > "Binary BinExport (v2) for BinDiff".
   - Headless: `analyzeHeadless <proj> <name> -process <file> -preScript BinExport.java <out.BinExport> -noanalysis` after a prior `-import`, or use `-propertiesPath` with a `BinExport.properties` file.
4. Make the same "Subtract Imagebase" choice for both files.
5. Add each file as `ghidra-<name>.BinExport`, at most 256 KiB each and 2 MiB in total.
6. Add a PROVENANCE record with the real tool and version, the options, the date and OS, and who produced it. Set `live_compatibility_evidence: true`.
7. Never commit exports of Microsoft or other third-party binaries. Larger corpora stay outside git: point `PATCHTRACE_BINEXPORT_CORPUS` at them.

Any strict-rule rejection of a real export is a validator bug (spec U3). Downgrade that rule to a warning and add a regression test.
