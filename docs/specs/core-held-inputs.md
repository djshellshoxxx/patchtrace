# Core held inputs and operation read checkpoints

Status: neutral core implementation candidate. Supports the later PW-02 route;
native Windows sharing, KB propagation and package provenance remain separate.
Parent contracts: `architecture.md`, `local-package-intake.md`.

## Runtime capability

`input_readers.py` is Qt-free and standard-library-only. `HeldInput.check(path)`
and `open_reader(path)` are an operation-owned source capability; the path asserts
its captured binding and does not authorize a new caller-selected open. A frozen
`PairInputReaders(older, newer, checkpoint)` requires both readers and one callable
checkpoint. It hides those values from its representation and refuses pickling.
No native handles or acquisition types cross this core interface.

The provider owns native identity, anchored name binding, byte bounds, a read-only
independent cursor, one borrower per object, and checks before/after and during
read/seek operations. It closes its borrowed stream without closing the retained
original. `read(-1)`, oversized reads and out-of-range seeks are unsupported.
The core additionally checks regular-file type, 1 GiB size limit, same-descriptor
state, complete copy length, full SHA-256 and existing AMD64/PE32+ structure rules.
Provider assertions never replace hashing or PE validation. Errors preserve the
neutral reasons `cancelled`, `limited`, `changed`, `unavailable`, `invalid` through
`InputReadError`, a ValueError with fixed bounded PT-INPUT text.

`ProjectService.create(..., input_readers=None)` keeps ordinary callers unchanged.
An explicit pair is checked before creating/opening a project store; each reader
is passed to `inspect_artifact(..., reader=..., checkpoint=...)`. Held sources do
not use pathname opens or pathname fingerprints. Ordinary sources keep their
existing path/descriptor/fingerprint comparisons. Both modes share immutable
copy, complete validation, exclusive publication and the creation ownership
ledger. Package inputs never become project rollback-owned objects.

`validate_pe(path, *, reader=None, checkpoint=None)` can inspect a held input.
It reads exact bounded headers/sections and refuses truncated/short data. Its
ordinary pathname mode remains available for project-owned copies. `sha256_file`
and `verify_artifact` accept an optional checkpoint; no digest supplied by a
caller can authorize skipping their existing verification.

## Read work and checkpoint lifetime

`ReadCheckpoint = Callable[[int], None]`: zero checks the original operation;
positive values record bytes actually read and perform that same check. Calls
occur before and after bounded reads and around relevant metadata/verification
boundaries. Path reads request at most 1 MiB. Held providers account their own
reads: their callers must not charge them again. This includes held PE parsing.
The callback can reject deadline, cancellation or work exhaustion by raising.

Core code does not create a timer, output allowance or new operation. Positive
counts describe read work, including PE headers; they do not redefine native
hashed-input counters or consume/refund extraction output reservations. A later
adapter binds the callback to the original operation's finite read-work ledger,
work allowance, deadline and cancel token. This slice introduces no aggregate
read-byte cap beyond source-size/chunk bounds and the supplied callback.

`ProjectStore._verify_files(..., checkpoint=None)` preserves all existing hash,
PE, fingerprint and verification-cache checks, including a checkpoint on cached
verification. `save(..., checkpoint=None)` checks before verification, after
serialization before its transaction, and inside the transaction immediately
before COMMIT. A raising precommit checkpoint rolls back the save. Creation
rollback preserves preexisting/reused/foreign databases and files and removes
only exclusively created objects according to the existing ledger.

No checkpoint may raise after successful commit inside creation rollback scope.
There are no callback calls after `store.save` returns in `ProjectService.create`.
Later cancellation/timeout belongs to an outer retained-project outcome; it
cannot delete committed evidence. OS calls/SQLite COMMIT remain cooperative
boundaries, not exact-time preemption. Existing defensive committed-snapshot
preservation in `_rollback_creation` remains in place.

## Compatibility and qualification

New arguments are keyword-only. When absent, callers invoke existing injected
functions with their old argument shapes; they do not pass unnecessary None
keywords. Callback failures are propagated with their original type/reason.
Ordinary paths, project schema, verification cache, locks and cleanup policy are
unchanged. This slice does not alter KB Env/import/attachment, native readers,
jobs, package budget/schema or durable package recovery.

Tests use authored PE bytes, operation-owned POSIX descriptors and real project
SQLite. Required controls deny selected-source pathname reopening, verify copy
and reopened ordered hashes, reject descriptor drift/truncation/oversized or
malformed PE data, preserve original descriptors, count read work without double
charging, and cancel during copying, stage validation, save verification and
immediately before COMMIT. Brand-new cleanup, preexisting empty/zero-byte retry,
foreign-file preservation, cached verification and ordinary call shapes remain
positive controls. Portable descriptor tests are not Windows sharing or frozen
package qualification.
