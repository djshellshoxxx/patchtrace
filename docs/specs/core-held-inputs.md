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
keywords. Operation stops use `InputReadError`, whose original object/reason propagates;
unrelated `OSError`/SQLite failures retain the existing storage-error mapping.
If removal of this attempt's temporary input raises `OSError` while a primary
operation exception is propagating, cleanup preserves that original exception
object and appends a fixed bounded note that temporary bytes may remain. The
note contains no raw secondary exception text or path. It does not claim cleanup
succeeded, retry unrelated paths, or authorize deleting an unowned file. A
cleanup failure without a primary operation failure remains observable; it
cannot turn an unsuccessful removal into a returned artifact. Ordinary input
and storage-error mapping remains in place.
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

## Preallocated creation identity and postcommit reads

`ProjectService.create(..., project_id=None)` optionally commits a caller-chosen
ID through the existing project model. Validate a supplied value with the strict
bounded `Record.id` contract before store creation, source I/O or held-reader
checks. Omission retains default UUID generation and existing injected call
shapes. This does not tighten historical IDs to UUIDs, add a project/schema field,
authorize reuse of a committed database, or bypass full input/aggregate/ownership
validation. Eligible empty/zero-byte retries retain their existing rules.

The returned identity must come from the actual saved/validated project. An
exception after COMMIT is not proof that no project exists: keep the existing
committed/unknown-outcome retention policy. A caller's expected ID, equal pair
hashes or directory existence does not grant deletion or adoption authority.
Later package composition must durably bind the expected ID before create and
compare the actual ID and side-keyed ordered hashes before association; those
durable fields and the held-origin recovery marker are outside this core slice.

`ProjectStore.load(..., checkpoint=None)` carries an explicitly supplied original
operation callback through snapshot validation and `_verify_files`. Checks occur
before reading and around payload/aggregate verification. Existing path reads
charge actual bytes; cache hits still check without positive-byte charges.
If interrupted-run recovery remains enabled, its existing save receives the same
callback and existing pre-COMMIT check. No callback runs after that save commits.
No callback is retained on the project/store for future unrelated operations.

`ProjectService.open(..., maintenance=True, recover_interrupted=True,
checkpoint=None)` forwards explicit nondefault options to the existing load.
With a callback, check it before acquiring the store. When options are omitted,
preserve the current `load()` and verification call shapes, including legacy
injected functions without new keywords. `maintenance=False` skips legacy raw
cleanup; `recover_interrupted=False` skips application recovery writes. Both are
required for the package verifier's non-mutating read. Such a read changes no
healthy project snapshot/history/raw bytes; the existing lock-holder record is
still written, and this is not a new physically read-only SQLite mode.

A failed open closes only the store acquired by that invocation, including when
the primary failure is `KeyboardInterrupt` or `SystemExit`. If that close also
fails, preserve the original failure object and add a fixed bounded note that
resources may remain open. Do not echo secondary exception text, claim successful
close, invoke creation rollback or delete project data. A close failure on an
otherwise successful path remains observable through the existing close API.
Neutral cancellation/limit reasons remain intact. Unknown committed results and
foreign/preexisting projects remain retained.

Postcommit reads use the same deadline/cancel/read-work callback, without new
allowances or extraction-output charges. SQLite work, JSON validation and OS
calls remain cooperative boundaries. This hook does not checkpoint legacy raw
maintenance, enrichment backup/publication, package provenance or generic KB
recovery. KB/facade propagation and held-origin CLI/GUI/native exposure remain
separate, explicitly unqualified work.

Required new controls precede implementation: real preallocated create/reopen;
invalid-ID refusal before I/O; ordinary call compatibility; foreign/reused create
refusal; first-save cancellation and after-commit retention; explicit no-recovery
open with queued/running records; exact checkpoint and positive-byte propagation
through artifact/raw/PE/cache reads; neutral-stop identity and connection closure;
secondary-close masking; no callback retention; full corrupt-copy refusal; and
checkpointed default recovery without a callback after its committed save.
