# Internal KB held-input propagation

This is an additive internal capability seam over the existing KB import path.
It implements the reviewed `kb-held-reader-propagation-20261118` plan and reuses
`core-held-inputs.md`. It is not a package import entry point.

**No CLI, GUI or package entry point may expose a held-origin operation until
the separate durable facade prevents reader-less recovery from reopening its
stored package paths.** Generic recovery, package provenance, expected project
identity and native Windows admission remain outside this slice.

## Same operation, same admission

`KbService.import_pair(..., input_readers=None)` optionally accepts the existing
`PairInputReaders`. Both readers and the exact original checkpoint remain owned
by the caller for the entire synchronous import. The path asserts the provider's
captured binding; it is never permission for a pathname fallback. The KB service
checks the operation and both bindings before inspection and again before any
approval or successful dry-run return. Inspection, the pre-intent hashes, the
pre-create hashes and core ingestion all read the corresponding held side.

The current expected revision, ordered advisory snapshot, product/architecture,
expected pair, full-global index and finite saved-scope checks remain unchanged.
No reduced index, source-digest shortcut, package-derived advisory fact or new
confidence is introduced. Before intent publication, the attachment rechecks the
same operation/bindings after its ordinary source-object and destination checks.

`Env` inspector/factory protocols document optional keywords. The real inspector,
both factories, `RealProjectPort` and `ProjectAttachment` accept the additive
capability. When it is absent, all existing injected calls retain their old
arguments: no unnecessary `reader=None` or `input_readers=None` keyword is passed.
There is no catch-TypeError retry with ordinary path I/O. Default reuse and
desktop create-only policies keep their existing meanings. `ProjectPort`,
`AttachRequest`, journal bodies and every persisted or user-facing record keep
their existing shapes.

## Bounded reads and stops

Held inspection and hash loops request exact finite integer chunks no larger
than 1 MiB. A returned value must be exactly `bytes` and no longer than the
requested chunk. Nonbytes, oversized or otherwise invalid results raise the
existing fixed `InputReadError('invalid')` before digest/size progress is recorded;
they must not silently compare equal to the EOF sentinel, spin or be credited.
Empty bytes is EOF. Short successful reads are valid: inspection accumulates the
first at most 4096 bytes across blocks, while hashing and counting the complete
input. The existing 4096-byte inspection limit does not increase; a PE header
beyond that prefix is still refused. Ordinary inspection and held inspection of
the same bytes must retain the same basename, architecture, hash and size.

The provider alone accounts positive held-read byte counts. KB boundary checks
use zero, and the unchanged core accounts its project-owned verification reads.
No new clock, read-work counter, output reservation, retry or side-specific
budget is created. Context exit closes the borrowed stream, never the original
capability. All store work stays on the synchronous caller thread.

`InputReadError` identity/reason must propagate through the KB route, including
the existing generic creation exception wrapper. Ordinary OSError/storage
mapping stays unchanged. The caller retains original-handle cleanup ownership.

## Committed boundary and qualification limits

The reviewed core checks before COMMIT and performs no checkpoint after a
successful first save inside creation rollback scope. KB adds no operation
checkpoint between the real project port returning and the attachment recording
the committed project's `created` journal identity. Late failures cannot delete
committed evidence. Stops before approval add no investigation/decision/journal
or project; later stops may retain earlier approval or intent, as before.

Reader-less generic repair cannot recreate a lost held capability. Postcommit
context writes still reopen immutable copies through ordinary project loading,
outside the creation checkpoint. This internal propagation does not claim safe
durable package recovery or a fully interruptible/read-accounted association.
Those protections must precede any exposed package route. Portable descriptor
tests are not native sharing, worker/FDI, frozen-package or Windows acceptance.

## Exact shared-reader import boundary

The internal capability above reuses the standard-library-only `input_readers`
module. The KB architecture guard permits these explicit relative imports:

| KB module | Allowed symbols from `..input_readers` |
| --- | --- |
| `service.py` | `HeldInput`, `PairInputReaders` |
| `store.py` | `HeldInput`, `InputReadError`, `PairInputReaders` |
| `wiring.py` | `HeldInput`, `PairInputReaders` |

These are per-file, per-symbol exceptions, not permission to import the whole
module or its other exports. Aliases, wildcard imports, absolute imports,
submodule imports and mixed approved/unapproved symbols must fail the guard.
Other KB domain modules have no shared-reader import exception. Existing Qt,
network, database, persistence and other sibling-module restrictions remain in
force, including when a permitted reader import appears in the same file.

The guard must accept the actual reviewed reader declarations and reject
authored forbidden-import variants. This specification records the already
implemented capability boundary; it introduces no new runtime dependency,
reader behavior, persisted field or externally available route.
