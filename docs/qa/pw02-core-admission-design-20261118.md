# Core package-admission design observations — 2026-11-18

This is a **read-only proposal**, not an implemented package route. Frozen source
`9ad2ec5cdbde85155fdca3cdd88804fd8b2e1a53` (tree `db005f5ede44b60fa2cf92581ac7dd685b087d99`) remains unchanged in production,
tests, tooling and workflows. The five relevant core files equal reviewed source
`9740860928c7911e6fa975528db1f7fa5ca1940b`.

The [complete proposal](../plans/package-core-admission-seams-20261118.md) recommends
only an optional preallocated project ID on existing create, and explicit
recovery/checkpoint forwarding through existing open/load. It identifies all
durable facade/held-origin/provenance prerequisites that remain unimplemented.
Root must review the proposal before any source work; meaningful failing
integration controls must precede that future implementation.

## Current observations

Ten bounded controls pass, zero skips, in 0.43 seconds, with 60 exact-source
project/test-support imports and no drift. Eight new authored PE/real SQLite
controls are joined by the unchanged two earlier public KB controls. No network,
child process, native worker, target or compiler was executed. Counts describe
current behavior, not proposed capability acceptance.

The existing model/store can commit a caller-chosen ID without schema changes.
Two projects can share an ordered binary pair but have different IDs; orientation
can change under one ID. Therefore the later verifier must compare the actual
committed ID and ordered hashes before adoption or publication, while retaining
existing create refusal and destination ownership checks.

Explicit `load(recover_interrupted=False)` preserves queued state, database bytes
and history in the authored healthy case. `open(maintenance=False)` intentionally
retains startup recovery and adds a history row. This flag is not an application
read-only identity check. The lock holder record remains the documented exception
to unchanged project bytes; SQLite still opens through the current mode=rw path.

Fresh reopen after held creation performs 12 project-copy reads / 2,316 bytes
without the original callback in the authored example. The proposed per-call
checkpoint reaches existing full hash/PE/cache verification. It must not become
a persisted callback, reset the original operation, consume extraction output,
invoke creation rollback or recover queued/running records during reconciliation.

Save-return and constructor exceptions after a real commit both retain the
actual project and verified copies. The unchanged public fault still leaves a
committed project while its attachment says intent/project_id=None; generic
reader-less recovery then tries the original sources and records interruption.
That behavior is retained explicitly and is not qualified as safe package
recovery. Core preallocation alone does not supply a durable lease marker,
package lineage, or guarded metadata reconciliation.

## Exact evidence and limits

`source-provenance.json` contains 74 canonical Git snapshots and seven exact
reference snapshots, including the approved KB propagation plan from
`8b376a7bf4cbe2603958b5c596619849d363d828` (absent from this frozen base).
`source-seams.json` binds 43 complete source spans/signatures. Three full caller
searches, exact argv/environment/import manifests, current observations and the
original public probe/source receipts are retained. No original probe changed.

New current-observation probe SHA-256:
`a9a78c027c7afbd839dfc22e4aa7f27ad5b4b24ab37908ff3bd98106603fa87d`.
Unchanged prior public probe SHA-256:
`43bd6974c6c65cb9a2a7788f7cb2bd35b8d8b9a18e0cf3c476136c37dc40d31c`.

Portable POSIX observations do not qualify native sharing, FDI/process handoff,
package exposure, durable recovery, arbitrary namespace resistance or frozen
acceptance. The core remains Qt-free/synchronous with caller-thread SQLite.
The plan explicitly distinguishes known commit, unknown result and missing
association, and never authorizes deleting or adopting a foreign project.

## Sealed packet

The [archive](pw02-core-admission-design-20261118.zip) contains 107 verified payloads
(1,637,765 uncompressed bytes; 561,595 ZIP bytes).
Archive SHA-256: `2360724532d6bd77c73b1f52ef8640b80ea279dfc78ff3a1f7afdfe60ac5ec5a`.
The [manifest](pw02-core-admission-design-20261118.manifest.json) records every payload hash and size.
Raw observations remain in `qa/pw02-core-admission-design`.
