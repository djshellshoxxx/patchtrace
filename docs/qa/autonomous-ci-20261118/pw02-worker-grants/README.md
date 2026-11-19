# PW-02 portable serial worker accounting — exact-source candidate

This packet qualifies the bounded accounting interface at
`eb50b0283cf7a46e7bd25ffc23cd78b18dfeb2e0` only. All **441 affected cases passed**
in 1.65 seconds, with no attempted socket or child creation during pytest. Normal
Ruff across `src`, `tests` and `tools`, the package schema check, and the complete
candidate whitespace check passed. The source remains a candidate for independent
review. No worker process, native decoder, package extraction, held-file reader,
project admission, Windows runtime or frozen executable was exercised here.

## Exact history and ownership

| Role | Exact commit |
| --- | --- |
| Parent-approved base | `068513a72e8a1412ce3960d3024c462d68d51376` |
| First specification and failing controls | `a522e275ddeedc25bfb2b06fd01b20ec7caef1d7` |
| Explicit envelope and entry-capacity specification / failing controls | `4474686899318efb57dac683e66c3e07f99dcf87` |
| Production and generated schemas | `eb50b0283cf7a46e7bd25ffc23cd78b18dfeb2e0` |
| Production tree | `e21808397bab4269ed3bf878989816b885e2755e` |

Branch: `codex/pw02-worker-contracts-20261118`. The existing
`pw02-local-packages` worktree was reused. Earlier pure contracts, the ASCII
selection repair, original review failures and the sealed native design remain
on their retained branch and in their separate packets. They were not rewritten
or relabeled as this source.

Twelve paths differ from the approved base: `package_budget.py`, the new
`package_worker_contracts.py`, the package schema generator, three additive worker
schemas, the specification/module row, a shared authored fixture helper and
three focused test files. Existing package schema bytes are unchanged. This slice
does not edit the process supervisor, native publication, FDI, KB/core services,
ingestion or persistence. The separately owned neutral `HeldInput` /
`PairInputReaders` interface retains the planned provider/core split; no native
values or core read-work ledger were added to these wire records.

## Implemented contract

`PackageWorkerBinding` captures exact operation, request and attempt identities
and the complete package source record. `PackageWorkerGrant` captures that
binding, an opaque fresh parent nonce, limits, the original monotonic start and
absolute deadline, issuance time and a quiescent cumulative usage baseline. A
canonical digest binds those fields. Grant and receipt envelopes require the
literal protocol name and integer version. Strict parsing rejects unknown
fields, duplicate keys, coercion, nonfinite numbers and oversized raw JSON,
including whitespace. The hard worker wire ceiling is 1 MiB; a captured lower
operation JSON limit still applies.

One parent budget can have one outstanding grant. The exact returned object is
its local control token; a parsed, copied or foreign object cannot act as that
token. The private serialized capture protects receipt comparison against an
unsafe mutation of the returned frozen object. A parent may inspect cancellation,
time and snapshots while a grant is outstanding, but counter mutation fails.
Issuance requires no open entry, pending write or live allocation and consumes
one original work unit. The operation identity stays fixed and attempt IDs never
repeat. A derived worker retains the same original start, deadline and all prior
usage; it cannot delegate another grant.

A terminal receipt repeats the full ownership binding and grant digest, reports
cumulative counters and the last observed monotonic time, and identifies complete
or failed accounting. Complete requires no unfinished resources and equal
reserved/confirmed output. Known partial counters remain available in a failed
receipt. The worker emits one terminal record and cannot resume productive work.
Only cleanup of its own live allocations remains possible.

Parent reconciliation validates the whole receipt before changing usage: exact
ownership, captured limits, monotone counters/peak, original clock basis and
issuance-to-parent observation bounds. New reserved bytes cannot exceed newly
reported entries times the captured per-entry limit, and reported open entries
cannot reuse previously closed baseline entries. The parent retains its own
current clock. A valid receipt's known consumption is recorded before a later
parent cancellation/deadline is surfaced. A failed, missing, malformed,
mismatched, replayed or overspent response permanently refuses further grants;
there is no refund or retry. Missing or unusable worker consumption is marked
unknown while retaining known parent counters; it is not fabricated as zero or
as a fully consumed reservation.

These are accounting and protocol consistency checks. Valid JSON does not prove
that native reads or writes occurred, that the reported counts are truthful, that
handles name the expected files, or that any decoder/process exited successfully.
Those checks remain the future native adapter and parent admission obligations.
The grant digest is an identity binding, not a secret authenticator or signature.

## Preserved red-to-green evidence

| Receipt | Source interpretation | Result |
| --- | --- | --- |
| `red.log`, `red.xml`, `red-provenance.json` | Exact first spec/test commit; worker API/schema absent | 149 expected failures / 111 registry positives |
| `green.log`, `green.xml`, `green-provenance.json` | Initial uncommitted implementation over `a522e275`; exact changed bytes in `green-source/` | 431 passed in 1.47 s |
| `edges/red.log`, `edges/red.xml`, `edges/red-provenance.json` | Edge spec/test commit plus the preserved initial uncommitted implementation | 9 expected failures / 112 positives in 0.56 s |
| `final.log`, `final.xml`, `final-provenance.json` | Clean exact committed source `eb50b028` | 441 passed in 1.65 s |

The initial 149 failures were 119 missing-budget-API errors, 29 missing-worker-
module errors and one absent-additive-schema assertion. The additional nine
failures demonstrated omitted protocol envelopes being inferred, impossible
issuance/entry baselines, new output using no new entry capacity, and failed
receipts reopening previously closed baseline entries. One positive edge control
proved that an unsafe public-token mutation did not alter the private capture.
All authored assertions remained unchanged through their respective green gate.

Each pytest receipt records the interpreter, command, imported source paths,
source hashes, exit status and attempted network/child operations. No such test
attempts occurred. Canonical Git source reads for provenance run before the audit
hook and use replacement-disabled Git with file-only protocol policy; they are
not native worker launches. Authored data never invokes a package or target.

The final command was:

```text
PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/3a6632a6e5ff/venv/bin/python \
  /workspace/scratch/c7a9e8d98848/qa/pw02-local-packages/worker-grants/run_final.py final
```

The wrapper sets the exact worktree `PYTHONPATH`, denies socket/process creation
during pytest, disables the pytest cache and uses a fresh system-temporary
directory outside any Git tree. It runs the three new worker test modules, the
seven existing package contract/path/budget/platform/schema/edge/ASCII modules,
and the specification registry. The complete argv is in the provenance file.
The broad runner and full suite were not resumed; parent scope required this
affected gate. Static commands and raw output hashes are in `static-checks.json`.

## Packet verification and limits

`source-provenance.json` records canonical final Git blobs for the changed paths,
imported package sources, affected test inputs, schemas and configuration.
`capture_sources.py` compares them with the clean checkout and final test
snapshots. `manifest.json` lists every retained payload's size and SHA-256 plus
the archive size/hash. `seal_packet.py` verifies ZIP member uniqueness, CRCs,
byte-for-byte hashes and canonical source equality before declaring success.
Temporary Python caches are excluded; no original red/green receipt is replaced.

This packet supplies portable authored evidence only. Actual Windows monotonic
clock sharing, suspended parent-directed handle transfer, explicit inherited
handles, verified process termination, independent rooted read-open while
retaining original share locks, FDI callback output, nesting/discard behavior,
owned cleanup, PE verification, durable provenance and the frozen native journey
remain unqualified. No source authenticity, observed SHA/header certainty,
implicit retrieval, target execution or PW-02 completion is claimed.
