# Explicit incomplete-project retry

## Purpose and authority

`ProjectService.retry_create(older, newer, name, root, checkpoint=None)` is an
explicit recovery operation for a recognized incomplete creation directory.
The ordinary New Project action keeps its absent/empty/lock-only preflight.
The new Retry incomplete project action requests bounded background validation;
it is not a repair, migration, overwrite or instruction to delete retained data.

Current `ProjectStore(create=True)` exact-schema admission, in-place reuse,
exclusive reservation for an absent database, existing artifact publication
and owned rollback remain the authorities. No historical unlink/recreate
database implementation is restored. No persisted schema changes.

## Admission and limits

Check the original absolute lexical destination components before resolving
them. Every component must be an ordinary directory; refuse symlinks and
Windows reparse points, including components preceding `..`. Record identities
and recheck them under the destination's existing exclusive kernel lock.

The destination already exists and contains an ordinary, singly linked,
4096-byte `.patchtrace.lock`. Acquire that same inode without creating or
rewriting its bytes. Lock contents and PIDs do not establish availability.
An existing live kernel lock refuses retry. Retry never creates an absent
destination or lock. The ordinary lock acquisition behavior stays unchanged.

Only `.patchtrace.lock`, optional `project.sqlite3` and optional `artifacts`
are admitted at the root. Directory enumeration is bounded by the allowed
entries and refuses an unexpected/repeated entry immediately. The artifacts
directory may contain at most the two content-addressed files corresponding
to the selected inputs; identical inputs need only one shared file. Every
present artifact must be ordinary, singly linked, match the selected input's
size and full SHA-256, and pass current PE validation. Links, reparse points,
unknown files and extra directories refuse recovery without mutation.

An existing database must pass the current store's 1 MiB bounded, exact-schema,
empty-table, immutable-read eligibility checks, followed by writable-connection
identity and schema validation inside its first-save transaction. Preserve the
current supported zero-byte retry. SQLite companions, populated snapshots,
retained sequence state, changed schema/version and invalid files remain
refusals. The validator does not introduce a second SQL acceptance policy.

## Preparation, publication and failure

Prepare both selected inputs through current creation/inspection in an owned
private staging directory before destination mutation. Preserve original input
names and metadata in the candidate project. Staging failure or cancellation
does not change the destination. Bounded input reads use the supplied neutral
checkpoint; invalid callbacks are refused before filesystem work.

Retry supplies its own finite actual-read budgets even when the caller omits
a checkpoint. Current inspection/PE reads and hash verification retain their
bounded physical chunks. Retained verification and the final save allow at
most twice the selected artifact bytes; a destination copy allows at most three
times its selected artifact bytes, accounting for copy, PE headers and an
existing-file digest. Charge and forward every actual read. Exceeding a budget
raises neutral `InputReadError('limited')`; a file growing after its initial
size check cannot keep the hash loop running indefinitely. A final physical
read may exceed the remaining allowance by at most one bounded read chunk.
Private preparation retains the core's 1 GiB per-input cap and supplies an
8 GiB aggregate actual-read allowance for the two copies and their validation.

Under the existing destination lock, validate its entries and exact retained
artifacts, then recheck captured layout and identities before store admission.
The current store validates or exclusively reserves the database. Copy from
the privately staged immutable inputs through current exclusive artifact
publication, verify each copied identity against the candidate, and record
only paths published by this attempt. Clean the private stage before the
destination save. Save the candidate through the existing pre-COMMIT callback;
no operation callback runs after a successful destination save returns.

On refusal or precommit failure, retain all preexisting destination bytes,
permissions and file identities, including the lock and any reused database
or artifact. Existing rollback removes only proven new publications; unknown
database state or uncertain ownership retains files. Secondary cleanup failures
do not replace the primary exception. Private staging cleanup failures remain
observable and cannot manufacture a completed destination receipt. A snapshot
that actually committed before a later failure remains available.

Capture the private staging directory and its ordinary lexical ancestor
identities immediately after allocation, before using it. Disable the
temporary-directory finalizer immediately: it must never later recursively
delete a substituted pathname. Recheck those captured identities before any
recursive cleanup. An observed missing, linked or replaced stage is retained
and refuses a success result; if another failure is already active, retain
that primary and add a bounded cleanup note. Do not adopt, repair, chmod or
remove the replacement. The final identity-check-to-removal interval remains
part of the noncooperating-writer limitation below.

This is the existing cooperative single-writer model. Rechecks refuse observed
changes; they do not make multi-file publication atomic or prevent a hostile
process from replacing pathnames between checks and operations. No native
Windows qualification is inferred from portable controls.

## Desktop adapter

The retry action names its recovery purpose and explains that existing files
are verified, not overwritten. Basic field validation may run on the GUI
thread; staging, hashing, SQLite inspection and publication run on the worker.
It uses the same cancellation, worker-thread close and captured-context
adoption rules as ordinary creation. A failed retry keeps the previous project
active. Cancelled or stale delivery after commit retains the created directory
without opening it. This action does not alter acquisition or KB creation.
