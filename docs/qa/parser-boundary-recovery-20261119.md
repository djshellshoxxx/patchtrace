# Parser boundary recovery — November 19, 2026

This selective recovery starts at **`e59e9fce81416c543aa09117e620f7db45b5effd`** and takes seven existing-parser changes from immutable completion head **`2511301fc26bf0e039f54828959c422b4ff761a2`**, pull request #322. It does not adopt that branch's overlapping evidence UI, KB service, scoring or BinDiff schema changes. Each affected specification and the module index were updated before the runtime port.

## Recovered behavior

| Consumer | Accepted change |
| --- | --- |
| Winbindex raw/import parser | Check the decoded byte cap before UTF-8 decoding or JSON allocation, including the uncompressed entry points. Exactly the cap remains eligible. |
| CVE normalization and freshness | Admit exact finite tenths under a local Decimal context; reject unsupported exponents and UTC-overflow timestamps through the established typed errors. Preserve valid score identities and original timestamp provenance. |
| CSAF transport | Treat malformed redirect joins as typed configuration failures; close the response and avoid dispatch/cache publication. Existing host, scheme, port and consent checks remain in force. |
| N-way pair reader and staleness | Classify per-pair resolution/stat failures without leaking the operating-system path text or discarding a healthy hop. |
| BinExport validation | Apply existing UTF-8 and string-byte budgets to expression symbols and mnemonic, library and module names, with the existing work-budget ticks. |
| rz-diff interpreter | Keep malformed fallback UTF-8 inside typed failures. Nonzero exits remain run failures with bounded display diagnostics; successful output identities still describe the original eligible UTF-8 bytes. |

Seven additional rz-diff controls demonstrated limits missing from the source snapshot: a replacement character could expand a tail beyond its byte budget when truncation split UTF-8, and diagnostic conversion or successful-text sizing could allocate from an already oversized complete value. The recovery selects a bounded diagnostic suffix before conversion, discards an incomplete UTF-8 prefix at the final byte boundary, and rejects a successful string whose character count already exceeds its byte budget before encoding it. Smaller successful strings still undergo exact encoded-length validation.

The source's small N-way test-isolation change is also retained: global `os.open`/`fstat`/`fdopen` failure injection is scoped to the attempted operation and restored before checking that the descriptor was closed. The descriptor postcondition is unchanged.

## Evidence

On the unchanged runtime baseline, the six recovered boundary files produced **89 failures and 38 passes in 10.30 s**. The executor connection was interrupted after that run; on recovery, its complete pytest summary was present and the parser runtime diff was still empty. The scoped source port then passed 127 controls. The seven extra rz-diff controls each failed before their repair. These red logs are retained and their passing controls are not added to final totals.

The exact final source passed **602 checks, with no failures, errors or skips**, in nine sequential bounded subprocess groups:

| Group | Passed | Pytest duration |
| --- | ---: | ---: |
| New boundary controls | 134 | 4.48 s |
| Existing Winbindex consumers | 35 | 2.74 s |
| Existing CVE consumers | 75 | 3.45 s |
| Existing CSAF transport | 23 | 0.97 s |
| Existing series storage/tolerance | 29 | 4.51 s |
| Existing N-way view and recovery-copy controls | 33 | 2.90 s |
| Existing BinExport checks | 48 | 1.35 s |
| Existing BinExport pipeline | 26 | 1.42 s |
| Existing rz-diff interpretation and I/O evidence | 199 | 3.70 s |

Each group selects disjoint test files. Scoped Ruff and `git diff --check` passed. The [source-and-evidence manifest](parser-boundary-recovery-20261119/source-and-evidence.json) binds exact source, tests, specifications, index rows and raw logs/XML by SHA-256.

These checks use authored/redacted provider fixtures, synthetic projects, protobuf wire records, parser workers and process controls. They establish the stated parsing and error boundaries; they do not qualify a live provider, native analysis engine, native exporter, Windows platform or entire repository. Independent review is requested separately from this author gate.
