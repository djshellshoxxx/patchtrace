# Cache, full Linux smoke and publication import purity — 2026-11-18

## Qualified bounded source

Exact clean candidate `f3b7a0e895c3b9928e08f93ac77d2afda5c56dd8`, tree `de56f481ed4d18c196f6b069860d3f11035e375e`, passes **1,028 tests** with
**two explicit skips and one existing expected failure**, zero failures/errors,
in **22.89 seconds**. The 30-file selection is the union of all three author
affected scopes plus independent cache and publication probes. All 221 imported
PatchTrace modules match this commit's Git bytes, with no foreign imports or
drift. All ten changed source/test/tool/workflow files since `12f5ff324572afdd039e7a55515c9d3ade001340` exactly
match reviewed author bytes. No production conflict required manual resolution.

Normal `ruff check src tests tools` passes. The isolated, ignore-noqa strict S
scan still fails on **80 unchanged path/code/selected-statement sites**. These
are scoped regression results; full Linux/Windows/Qt/native/frozen/package,
dependency/security and reproducibility acceptance remain incomplete.

## Integrated changes and independent review

| Slice | Behavior | Reviewed source / retained evidence |
| --- | --- | --- |
| Corpus archive cache | Cache original Rizin/Ghidra archives; validate pin syntax, type and SHA on both cache hits and cold paths; extract into an exclusively fresh runtime directory. Corrupt archives, symlinks, FIFOs and preexisting runtime objects refuse without running payloads. | `451e463d25e625c55344ac232fd9de90275b9013`; 54-member author packet and independent 26-pass shell control. Cooperative CI workspace boundary, without an active-writer race claim. |
| Full Linux frozen smoke | Invoke the existing complete `tools/frozen_smoke.py` harness against the new frozen executable before archive/digest creation, with a 900-second timeout. | `2a7e3147abda0450840e885dc075cf319a59ccaa`; 56-member author packet. Author gate's preexisting IR import-purity failure is preserved. This local gate exercises builder controls and source CLI smoke, not a new frozen build. |
| Publication import purity | Load Linux ctypes only when Linux native publication is actually dispatched. Windows/unsupported dispatch and pure IR imports no longer import ctypes. | `73bd7eadd1fa279cd1f7ea6887029b85e6c55430`; 40-member packet. Native move logic, ownership checks and all 32 existing publication assertions remain unchanged. |

The coordinator verified all 96 smoke/purity archive members and 43 canonical
Git snapshots, and the cache packet's 54 members and 22 Git snapshots. The
smoke harness AST is unchanged after its documentation string; the purity
production AST is unchanged after moving the ctypes import. Original failed
assertions, intermediate fixture/lint/collection errors and original author
results remain attributed to their own source and are not relabeled.

The independent archived publication probe formerly patched private
`publisher.ctypes`. A fresh replay copy changes exactly two injection targets to
the same already imported `ctypes` module. Every assertion and all other AST
nodes are identical; the original probe file remains byte-for-byte unchanged.
This adaptation is explicit in `external-probe-adaptation.json`.

The two skips require native Windows junction creation and host-denied AF_UNIX
socket creation. CODEX5 dependency hash closure is the sole remaining expected
failure in this scope. Cache verification and full-smoke policies are now normal
required assertions. The duplicate-ZIP fixture emits its expected warning.

Execution installs the retained Linux network-denial filter before collection,
rejects inherited sockets, restricts Git to local files and uses an owned system
temporary directory outside any repository. The audit saw 190 hostname events,
one denied AF_UNIX creation and 254 inspected local fixture/CLI/Git subprocess
invocations. The temporary directory was removed after success. This execution
guard is not a native product sandbox qualification.

## Preceding publication and fresh hosted evidence

At `2026-11-18T21:07:18.298Z`, main remained `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` and PR316 remained open at
`f3f4492981f2c76c8d461d6a6d3eb1ac682fb996`. The preceding 45-commit append was
independently reread and published with a non-force expected-head lease. Its
tree `e49299eabe4cff2304d9dbe15f94c3c79566af44` equals local `12f5ff324572afdd039e7a55515c9d3ade001340`. Preview
`a94495abb6117400c138eaaa0127d260c3010094` has main and actual f3 head as parents
and that same tree. Original publication receipts are retained here.

New hosted observations belong to that **preceding f3/preview tree**, not this
new local CI follow-up. Four downloaded artifacts match both API SHA-256 and
byte size; all member CRCs/hashes are retained. Native binaries in the BinDiff
artifact were read only as evidence and were not executed locally.

- Windows BinDiff now builds the native helper and passes six authored controls,
  including its 20/21-function synthetic end-to-end pair. Its no-network control
  fails: restricted control process chain exit125. Actual pytest and `bindiff.json`
  fail despite the job-level success status. There is no Windows no-network or
  representative-binary accuracy acceptance. Detailed diagnosis is assigned.
- Windows runtime and packaging dependency profiles get past source verification
  and scanner installation, then `python -I -m pip inspect --local` exits2 with
  a CP1252 UnicodeEncodeError for U+1F44B. This is a new, retained downstream
  failure; neither profile reaches product dependency-audit acceptance.
- Hosted static scanning reaches its strict scan and fails. Its artifact now
  retains `bootstrap-pip.txt`, establishing delivery of that prior upload repair.
  The complete hosted diagnostic/site comparison remains a separate review.

Job badges are not acceptance. Other hosted full/platform/native jobs are not
qualified by this packet. The old f3 gate remains 6,356 passed /18 skipped /three
expected failures at its own source; this later result does not alter it.

## Remaining work and release state

No PR has been merged or closed, no branch deleted, and no main/tag/release/
deployment ref changed. The 12 local follow-up commits retain `[no release]`;
their append-only remote publication and readback are separate receipts.

Portable serial worker grants and neutral held-input/core checkpoints are under
independent review. A persisted-signal navigation defect has preserved original
failures and an isolated repair in progress. Native worker transfer, rooted
stage/FDI, KB propagation, durable package provenance and a real frozen intake
journey remain open. Dependency hash closure and the newly observed Windows
encoding/native control failures continue independently. Whole PW02 and beta
readiness are not established. Frozen L1/L2/L3 outcomes remain unchanged.

## Sealed archive

70 verified payloads; 718,877 bytes. SHA-256 `3eda6ae51107d721b6122998cb55d343d6d3d3d8c1f1756de617ff36f48b07ed`.
