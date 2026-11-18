# Durable admission for held local-package inputs

**Status: read-only proposal for root review. No production, repository test,
schema, CLI or package-entry changes.** Keep the existing held-input route
internal until the durable boundary below, the separately owned core hooks and
native acquisition have their own reviewed evidence.

The recommended next boundary is one typed package-admission table in the
existing KB workspace, a strict preallocated project identity, and a package-only
mode of the existing attachment and project port. Held operations must remain
outside the legacy attachment journal. A separate explicit reconciliation may
verify an already committed project and finish metadata association; it cannot
recreate a lost reader, extract again or create another project.

## 1. Frozen authority and what exists

Frozen source: **`195e04af27f7a724c6a2037363b7fe68df418a6b`**, tree
`b976c61b0ac4ffb55b7b0e78d7a2b206742c00b1`. The source receipt retains 42 Git
snapshots, 56 complete symbol spans, five production caller searches and 16
unchanged prior design/observation files. Eleven byte-equality checks establish
the current core, KB propagation and worker authorities below. Full paths and
SHA-256 values are in the accompanying `source-provenance.json` and
`source-seams.json`; references here name the exact frozen files and symbols.

| Layer | Implemented at this base | Required later work |
|---|---|---|
| Pure package model and budget | Strict `local-package/1` records; complete source/member/ancestor/inventory identity; ASCII selected basename; bounded logical paths; global limits | No model or receipt establishes native file authority or package authenticity |
| Worker accounting | `package_budget.py` and `package_worker_contracts.py` equal `7259f86838c2181d6bdbcabe98c7a294a4499e8d`; serial once-only grant/reconciliation and terminal guards | Native stage, FDI, supervised handoff and actual Windows qualification remain separate |
| Neutral core | Five implementation/spec files equal `9740860928c7911e6fa975528db1f7fa5ca1940b`; live pair, complete copy/PE/hash verification, first-save checkpoint and committed-data retention | Public preallocated ID and non-recovering checkpointed open/load are absent here |
| KB propagation | Three source files and specification equal `d9a939911f39f3641bd5eed97a2ce067d618856b`; same live pair through inspection, both attachment hashes and core creation | No persisted held-origin discriminator, package provenance or safe reader-less recovery |
| Durable workspace | `WorkspaceStore` supports `user_version=1`; ordinary journal and source objects | No package-admission table, package schema migration or package reconciliation |
| Project association | Existing `ProjectAttachment`, `RealProjectPort`, `EnrichmentStore` | Strict expected-ID checks before directory caching, sidecars and every later open; exact idempotent package provenance |

The integrated `package-core-admission-seams-20261118.md` is a **proposal** on
this base. During this investigation its owner reported candidate source
`441c47c2262603555aa77c11e63fedcce11ba502`, based on `7b5f558f`, with the same
planned signatures. That is a subsequent, independently owned candidate pending
acceptance/integration; it does not change this design's source authority.
Root subsequently reported review of constructor-cleanup extension
`63ebc42746fbfbded311084288a339f26ed08d8c` and a 562-case author gate, with the
core chain being ported. Its inspected diff preserves the primary constructor
failure through owned cleanup; it adds no facade or durable admission authority.
Those are subsequent source/coordination facts, not tests rerun in this packet.

The dependency is explicitly:

```python
# Proposed at frozen 195e04af; separate core candidate exists.
ProjectService.create(..., *, input_readers=None, project_id=None)
ProjectService.open(root, *, maintenance=True,
                    recover_interrupted=True, checkpoint=None)
ProjectStore.load(*, recover_interrupted=True, checkpoint=None)
```

Current `ProjectStore.load` already has `recover_interrupted`; current public
`open` does not forward such an option, and neither current open nor load accepts
a checkpoint. `open(maintenance=False)` still performs startup run recovery.
The later package verifier must use explicit false/false plus its per-call
checkpoint through the accepted core hooks. No alternative core service or
project schema change is proposed here.

## 2. Concrete current gaps and the compatibility observation

These are source-proven boundaries of an unexposed capability, not claims that a
usable native package route already exists.

| Frozen entry | Consequence for durable package work |
|---|---|
| `store.py::ProjectAttachment._op_id` binds investigation/revision/pair/ordered hashes/directory only | It cannot distinguish two package intents or expected IDs. Existing ordinary operations cannot be upgraded in place |
| `_begin` stores ordinary `older_path`/`newer_path` in `journal` | Reader-less `_create` hashes those paths; a persisted pathname cannot recreate the original lease |
| `_create` uses `made.get(key, expected)` for returned hashes and coerces ID/revision | Package admission needs complete actual fields, strict types and actual side-keyed identity, with no fallback |
| `_create` faults after core creation but before the `created` journal write | A valid committed project can exist while workspace state still says `intent`; expected ID must be durable before core creation |
| `recovery.repair` calls `mark_interrupted` before its `only` predicate | A guard inside `context_for`, selected-operation filtering or `_create` is too late to prevent recovery mutation |
| `_after_create` writes sidecars before `_rows` calls the project port | Verification only inside `put_row` would permit earlier writes to an unverified destination |
| `RealProjectPort.create_project` caches the returned directory; later put/list open without expected-ID comparison | An earlier closed verification is insufficient; every later open must compare actual ID and ordered hashes before adoption/use |
| `_cas` reduces an event against the newly read current revision | Package progression must also bind the permitted revision/pair; a different current investigation must not inherit an old package association |
| `EnrichmentStore.publish` updates an existing ID on conflict; `entries` fetches a whole kind | Package idempotence needs an exact selected-row bounded read/compare, not an unchecked overwrite or all-row load |

Seven small Linux SQLite observations at **the exact frozen source** pass, with
32 exact imported project modules and no network/child attempts. They observe
existing behavior; none is a passing test of a new migration or package facade.
The original test, log, XML, command and observations are sealed unchanged.

| Authored observation | Exact scope of the result |
|---|---|
| A new v1 workspace accepts ordinary journal writes | Ordinary baseline positive |
| A quiescent v1 workspace is externally stamped v2, then freshly opened | `WorkspaceStore.read_only` is true; legacy rows are readable; public writes return nonrecoverable `PT-KBC-STORAGE`; direct SQL writes fail read-only; fixture database bytes remain unchanged |
| Fresh v2 open followed by generic repair of an unfinished row | Refuses before attempt, journal or project calls in this fixture |
| A v1 `WorkspaceStore` remains open while another connection stamps v2 | Its cached `read_only` remains false and it can still write; the version bump is not a universal barrier for already-open clients |
| Such an already-open client sees new held-looking fields in a legacy journal body | `mark_interrupted` ignores them, writes an attempt and marks the row |
| A package-looking row exists only in a separate additive table | Frozen legacy journal enumeration and marking do not visit it; this does not block that old connection from ordinary writes elsewhere |
| Authored DDL, first row and `user_version=2` share one SQLite transaction, then rollback | Table, row and version change roll back together; v1 ordinary writes still work. This establishes the tested SQLite transaction behavior, not an implemented migration |

Accordingly, **a marker added to the ordinary journal plus a version bump is
insufficient**. The proposal below isolates held progress from legacy journal
enumeration as well. Only the inspected fresh-reader implementation is shown to
open v2 read-only; no claim is made about every historical client, a preexisting
open connection, an unsupported SQLite editor or arbitrary database rewriting.

## 3. The smallest durable records

Add pure strict models under proposed
`src/patchtrace/kbcorrelation/package_contracts.py`, with a separate
`package-admission/1` discriminator. Reuse the existing package source/member/
selection/usage records; do not create alternate package identities or import
native handles. Reject duplicate JSON keys, booleans in integer fields,
nonfinite numbers, coercion, unknown fields/versions and inconsistent digests.

### Immutable admission intent

The canonical `PackageAdmissionIntent` binds these facts:

| Field group | Required content and meaning |
|---|---|
| Identity | Recomputed intent digest; separately domain-separated attachment ID; literal `input_mode='held-package'`; one newly allocated canonical expected project UUID |
| Workspace | Captured canonical selected workspace and the existing anchor's explicitly labeled identity scheme/value; compare against the live workspace before use. A persisted identity is correlation evidence, not cleanup authority or a reopened handle |
| Destination | Captured canonical project destination, parent binding and whether it was absent or an eligible existing empty retry; any available original leaf identity. Relocation/rebinding is unsupported in the first slice |
| Investigation admission | Original pre-work investigation ID/revision or explicit new-investigation request; actual admitted `BYTES_VERIFIED` revision and digest; selected pair, product/architecture and plan identity |
| Advisory scope | Exact ordered admitted SourceDoc snapshot, referenced coverage keys and strict saved coverage bodies/digests; retain finite cached document IDs including empty. Package records are not SourceDocs |
| Ordered package evidence | Exactly older and newer, each with source digest/size, original header inventory identity when applicable, separately identified materialized inventory, exact member/ancestor/ordinal/raw-name lineage, ASCII promoted basename and actual selected full-file hash/size |
| Metadata references | Bounded content-addressed references to exact canonical header/materialized inventory and worker receipt bytes; preserve original versus later inventory IDs. Complete records are revalidated and IDs recomputed before admission |
| Qualification and accounting | Decoder/parent verification observations, original operation/request/attempt labels and captured limits/known usage. Missing consumption remains unavailable; signature/applicability/product-membership uncertainty remains explicit |

Use `domain_id('kbc.package-intent', 1, canonical_payload)` and a separate
`domain_id('kbc.attach.package', 1, {intent_id, expected_project_id, input_mode})`
or equivalent reviewed domains. Do not add fields to the old `kbc.attach/1`
identity and silently reuse its operation. A collision with any incompatible
existing binding refuses. The expected UUID is newly allocated by this facade;
ordinary legacy project IDs retain the core's bounded-string contract.

Selected input paths can remain ephemeral in the live operation object. Do not
put `older_path`/`newer_path` into a legacy journal or treat a path retained for
diagnostics as resumable input. Captured FileIdInfo, roots, filenames, receipts
and hashes cannot reconstruct the original native locks or permit cleanup after
process death.

### Progress and project provenance

`PackageAdmissionProgress` contains the existing attachment phase/flags,
strict observed project ID/revision/ordered hashes when available, the permitted
current investigation revision/digest, independent package-association and KB
context states, a monotone progress generation and a fixed bounded outcome code.
The immutable intent remains unchanged. Update progress only by compare-and-swap
of generation/digest, together with any investigation revision transition.
Unsupported state combinations or missing binding fields refuse.

`PackageProjectProvenance` is an immutable documentary row keyed by intent ID.
It binds the actual expected project ID and ordered bytes to the exact package
lineage and retained metadata references. Its canonical body excludes mutable
current project revision, retry time and current investigation progress so that
repeating association after an ordinary project revision remains idempotent.
Observed project revision belongs in progress/receipt metadata; do not call a
later observed revision the creation revision. Provenance does not assert
Microsoft authenticity, upstream freshness, a verified pre/post relationship,
applicability, a CVE fix or code locality.

## 4. One workspace extension, with an explicit compatibility boundary

Proposed `package_store.py` uses the **existing WorkspaceStore connection and
owner thread**, never another SQLite file or service. Add one
`package_admissions` table containing:

`intent_id`, unique `op_id`, unique `expected_project_id`, `investigation_id`,
immutable `intent_json` and its byte hash, indexed phase, `progress_generation`,
bounded `progress_json` and its hash, and an updated timestamp.

Constraints and explicit reads check SQL primitive storage classes, lengths,
finite integer ranges and identity consistency. Immutable binding columns/body
cannot be updated or deleted through this API. The row key, recomputed intent
ID, attachment ID, body hash and progress binding must agree. Check metadata
types/byte lengths before loading full text; do not reproduce an unbounded
full-row allocation through a later model validator. Queries use fixed table/
column names and bound values.

Keep **base workspace version 1** for new ordinary workspaces, with the new
client's maximum understood version 2. Reading an old workspace does not create
the package table or change its version. At the first fully accepted package
intent, one `BEGIN IMMEDIATE` transaction installs the exact additive table,
inserts the immutable intent plus initial attachment progress, and stamps
`user_version=2`. Core creation starts only after that transaction succeeds.
Failure before commit rolls back table/row/version. Earlier legitimate approval
revisions or complete orphan metadata objects may remain; this is not a rollback
of the whole user operation. An uncertain transaction result must be resolved
by a bounded row read or reported unknown, never followed by blind creation.

All package attachment progress stays in that table. **Do not insert its
operation into the legacy `journal`, at intent, created or done.** The package
mode of ProjectAttachment uses a narrow package-specific persistence adapter
over the same workspace transaction/reducer. Extend the existing
`append_revision` transaction with one explicit package-progress participant so
that its CAS and package progress cannot diverge; do not use the twice-called
validation `guard` as a side-effect hook. Ordinary journal arguments and
ordinary `_op_id` behavior remain unchanged.

A fresh frozen v1 reader of the v2 workspace can inspect its known legacy rows
and refuses writes as observed. A v1 connection opened before the transition may
still write ordinary rows; its journal query has no package operation to resume.
It may therefore cause genuine current-revision/source conflicts, which the new
package preflight/CAS must detect. This is not an interprocess upgrade lock or a
general exclusion of older writers. The new implementation must recheck the
actual version/table contract inside package transactions; never downgrade an
unknown version or reconstruct a missing/corrupt package table from journal
fragments. Old v1 journal records remain ordinary and readable; no pathname
heuristic upgrades them to held-origin authority.

Core `project.sqlite3` stays schema 1. Add only `package-provenance` to the
existing enrichment kind registry, outside `DERIVED_KINDS`, after coordinated
review. No new project table is necessary. Existing older enrichment code
preserves unknown kinds; this fact is separate from KB workspace v2 recovery
isolation and does not promise that every historical viewer can display the row.

### Bounded metadata storage

Use existing `WorkspaceStore.write_object/read_object` for exact immutable
metadata bytes, with explicit maximum and expected size. Never pass PE payloads
through buffered gzip. Before any admission mutation, canonicalize and bound
the prospective intent, progress and metadata bytes.

Proposed first-slice caps are 1 MiB each for intent and progress and at most six
distinct full metadata objects (up to two header inventories, two materialized
inventories and two terminal worker receipts), with lower captured limits
honored. For each metadata object use the minimum of the existing 32 MiB default
object-read ceiling, captured `max_json_bytes` and `max_xml_bytes`; the last
restriction deliberately fits the current `PackageBudget.charge_metadata`
per-object API. The aggregate also spends the original remaining
`max_metadata_bytes`. This is a stricter admission envelope, not a change to the
pure inventory's 64 MiB maximum. An otherwise valid larger inventory is refused
before approval; do not split an object to evade the per-object limit or widen
the acquisition budget in this slice. Widening this envelope needs a separate
explicit metadata-budget contract.

Reference bookkeeping must recognize these objects in `unreferenced_objects`;
the current production caller only reports such objects, but new package records
must not be mislabeled orphaned. Account distinct raw metadata and typed record
bytes in the workspace budget alongside advisory and inventory data, including
the existing inventory-budget caller. Reuse one fixed-query accounting helper
rather than two conflicting totals. Enforce a proposed first-capability ceiling
of 500 package intents and 32 MiB of aggregate canonical intent/progress text per
workspace; status/reconciliation selects one intent. Validate SQL storage classes
and aggregate lengths before fetching bodies, then scan references in bounded
batches under the operation's checks. Metadata-object bytes also count toward
the existing workspace total. These proposed numerical admission
limits require specification and root review before implementation. Corrupt
budget metadata refuses a write, rather than being treated as zero. Complete
unreferenced objects after a failed transaction are retained, never removed by
invented ownership.

## 5. Existing admission path and exact write ordering

The facade is a small `package_service.py` composition over `KbService`; it is
not another approval algorithm or ProjectService. Keep native workers unable to
open SQLite. A live prepared pair must come from the separately qualified native
owner; a model, stored hash or worker receipt cannot fabricate it.

1. **Capture before work.** The first package capability requires an already
   initialized workspace opened with `create=False` and an existing ordinary
   destination parent that can be anchored; initial workspace setup remains an
   ordinary explicit operation. This keeps failed package capture from silently
   creating storage. Capture the actual selected workspace/parent,
   destination, investigation revision, ordered advisory snapshot and finite
   saved scope. Allocate the expected UUID in memory. The original extraction
   operation owns both sides, original deadline, cancellation and read-work
   callback throughout. No project intent claims a completed native result yet.
2. **Prepare and validate both sides.** The native owner reconciles the serial
   worker exactly once, verifies/promotes both selected full AMD64 PE files and
   supplies the original live `PairInputReaders`. Validate strict package and
   materialized lineage, actual hashes/sizes, metadata budgets and all captured
   bindings. Do not infer freshness, chronology or product authority from a
   local package filename.
3. **Use `KbService.import_pair`.** Add an internal optional typed package
   binding alongside `input_readers`. Preserve ordinary positional injected
   calls; omit absent keywords and never catch TypeError to retry path mode.
   Run current full-index, exact ordered source snapshot, expected revision,
   selected-product/architecture, expected-pair and saved-scope validation.
   Recheck the capture at the existing pre-approval boundary. No metadata write,
   migration, decision, investigation or project occurs on an initial refusal.
4. **Keep current approval semantics.** `_approve_pair` remains authoritative.
   Once it has produced the actual `BYTES_VERIFIED` revision, bind that exact
   revision into the intent. Earlier approved revisions may remain if a later
   storage/budget stop occurs; do not call this zero-mutation failure.
5. **Publish the durable intent before create.** The existing attachment still
   verifies both full held hashes, current admitted pair/revision, source objects
   and destination. Recheck the live pair and immutable capture. Retain bounded
   metadata, then commit the package intent/initial attachment progress/version
   transaction. No normal journal entry is created. Existing identical binding
   can be inspected; a contradictory or old ordinary operation is never upgraded.
6. **Create once through the bound real port.** A fresh package intent requires
   create-only behavior, irrespective of the ordinary default factory's reuse
   policy. Pass the expected UUID and original live pair to the accepted existing
   core API. All inspection, both attachment hashes, copying, PE validation and
   first-save verification remain real; metadata hashes cannot skip them.
7. **Record the actual committed result immediately.** Require actual project
   and store IDs to agree with the expected UUID, strict positive actual revision
   and exactly older/newer actual hashes. Compare by side; list order and an
   unordered hash set are insufficient. Missing fields, bool/numeric/string
   coercion or a fabricated expected fallback refuse. Populate `_dirs` only
   after this verification. Preserve committed bytes on every failure. Do not
   add a raising operation checkpoint between core return and the attempted
   durable `created` progress write. If that write fails, expected identity is
   already durable and the outcome remains committed/pending or unknown.
8. **Associate under a verified existing service.** Use the scope below before
   any sidecar/row write. After successful package provenance publication,
   record package association linked. KB context attached/pending remains a
   separate state. No cross-database atomicity is claimed.

Package dry-run can inspect/validate using the live pair and current admission
but may not install the table, stamp v2, publish intent or create a project.
The entry remains internal; this plan creates no `kb package` CLI or UI action.

## 6. Strict project association, including sidecars

Give the bound `RealProjectPort` a package-only association context that uses
the existing `ProjectService.open` with explicit `maintenance=False`,
`recover_interrupted=False` and the original checkpoint. On every fresh open,
load the committed aggregate using existing full verification and compare:

- actual `project.id` and `store.project_id` against the expected ID;
- both exactly labeled older/newer artifact hashes and sizes against intent;
- captured destination/workspace binding and package progress/intent identity;
- current permitted investigation revision/pair and saved source/scope admission
  before any metadata mutation.

Do this **before** caching the directory, returning a usable association port,
sidecar publication, enrichment schema/backups or row access. `_dirs` is a cache
of a verified binding, not authority for another open. A package-bound port may
not recover a directory by taking the first arbitrary journal row with that ID.
SnapshotProjectPort remains read-only and cannot authorize package admission.

Keep the existing service's normal project lock through that association's
sidecars and rows. Use that already-open service for row reads/writes rather
than recursively reopening it. The package branch of `_after_create` and
`_attach_context` enters this verified scope before `_sidecars`; ordinary
attachment keeps its existing route. Capture/check the root anchor and use the
existing anchored no-replace `publish_bytes` for package-mode sidecars and
metadata, validating exact existing content. This requires no new unrestricted
native primitive. An open-close check followed by unguarded pathname writes is
not sufficient. The normal project lock is cooperative and its holder record
changes on open; this does not claim forensic zero filesystem writes or defense
against arbitrary noncooperating database/namespace replacement.

For provenance, first read only the exact expected row ID, checking primitive
metadata types, total selected byte size, hash and strict body before loading.
An absent row may be published with the verified actual project guard. An exact
row is reused without updating its timestamp/revision/body. A different body,
guard, kind or project binding at that ID is a conflict; do not let generic
`ON CONFLICT DO UPDATE` overwrite it. This is a narrow bounded selected-row
adapter over the existing store connection, not a second enrichment service.
The ordinary complete kind APIs remain unchanged.

Package provenance is published before marking package association linked. If
publication succeeds and the workspace marker fails, retry verifies and reuses
the exact row before completing the marker. If the marker says linked but the
row or referenced object is absent, mismatched or corrupt, report damaged/pending
association; do not report success from the marker alone or manufacture lost
bytes. Project copies, valid provenance and prior attempts are retained.

## 7. Reader-less recovery refusal before mutation

The new package table is also the durable held-origin discriminator. New code
must check it before entering generic repair or direct ordinary resume. Malformed
table metadata, an unknown phase/version or an unresolved selected binding is
an explicit unavailable/unsupported result, never a reason to use legacy paths.

At the first capability, prefer this conservative rule: if a workspace has any
unresolved package operation, generic `repair`/`mark_interrupted` refuses before
marking **any** operation. Check this with bounded table metadata/existence
queries before legacy `journal_ops` parsing, context construction or attempt
writes. A per-operation `only` predicate cannot bypass the guard, including a
request that names an unrelated ordinary operation. A fully resolved package row
does not permanently disable unrelated ordinary repair. Here resolved means
attachment done, package provenance linked and KB context attached; a pending
context still needs the explicit package path. The guard refuses corrupt,
unknown or over-budget table state before falling back to legacy enumeration;
it does not call an unbounded full-row loader. An explicitly selected
package operation, including a linked one, must use the package path for status
or verification; ordinary direct resume cannot reinterpret its ID.

Both `KbService.attach(..., repair_it=True)` and `recovery.repair` enforce the
guard; direct `mark_interrupted` and `ProjectAttachment.resume` also refuse the
relevant package operation before their first mutation or source read. This
keeps the public helper boundary meaningful. No new-code caller may bypass it
by constructing a fresh reader-less attachment. A legacy client opened before
v2 cannot see package operations in its journal, though it can still change
ordinary state and cause a subsequent package CAS refusal as described above.

## 8. Bounded committed-project reconciliation

The only reader-less package continuation is an explicit **one-intent metadata
reconciliation**. It uses existing services and package state, never generic
`repair`, `_approve_pair`, an extractor, source pathname hash or create call.

1. Read/validate the selected intent and progress with primitive/size limits,
   recompute identities and validate exact metadata object bytes. Verify the
   captured workspace/destination binding. Missing or contradictory data refuses.
2. Load the full current advisory index once. Validate current revision, the
   immutable admitted revision and every selected progress-captured revision,
   including completed records when their bodies are used. Reuse
   `_checked_index`/`_saved_search`/`_stored_scope`; prebuild context before any
   progress/revision/attempt mutation. Preserve the existing product-only
   historical-source behavior and file/pair-only semantics; do not reduce the
   index and resurrect superseded, withdrawn or ambiguous sources.
3. Open the intended existing project through the non-recovering core API with
   a bounded per-call verification checkpoint. Compare actual ID, both ordered
   hashes/sizes and all binding facts before adopting it. Different ID with
   identical bytes, swapped sides under the same ID, missing/corrupt copies,
   foreign/busy/unreadable directories or unsupported identity remain retained
   conflicts/unknowns. Queued runs, history and raw evidence are not recovered.
4. If the exact project verifies but progress still says intent, record the
   actual `created` transition under generation and investigation CAS. The
   permitted current revision must be the immutable admitted revision or a
   recorded successor made by this operation. Record the expected current
   revision/digest in progress and advance it atomically with each reducer CAS.
   A different analyst revision/pair refuses; do not reduce against any fresh
   current revision merely because it is readable.
5. Enter the verified association scope, compare/publish exact idempotent
   provenance and existing KB context, then update package association/progress
   with CAS. Recheck saved-scope/source identities at the write boundary. A stop
   or conflict after project verification retains it and reports pending; no
   reconciliation deletes a project or a package source.

If no exact committed project can be verified after the live lease ends, retain
the intent and stage diagnostics. A fresh explicitly authorized package attempt
must receive a new operation/expected project ID and current admission capture;
it cannot spend, refund or revive the old extraction allowance. Matching hashes
or a directory's existence is not proof of commit or lineage. A canonical UUID
binds the expected application project; it does not authenticate arbitrary
same-user clones or edited databases.

## 9. Budget, lifetime and postcommit outcomes

The original pair, callback, cancel token, absolute deadline and serial grant
ownership remain live through synchronous create and outcome capture. A worker
receipt is accounting evidence only. Failed/missing/terminal receipts cannot
authorize retries, refunds, a new source lease or later output-token mutation.
Only cleanup of positively owned live allocations remains permitted.

Held providers own positive held-read charging; KB checks use zero. Core reads
of project copies/PE/raw files charge actual read work through the same callback.
Read-work bytes are separate from `PackageUsage.hashed_input_bytes` and extraction
output reservations; no resetting between sides or project reopens. Metadata
serialization/reads, association and backups require explicit finite caps and
checks around their existing bounded operations; SQL pages, a single OS call,
gzip/model work and COMMIT remain cooperative boundaries. No hard real-time or
complete byte-accounting claim is implied for those internals.

Never insert a raising checkpoint after a successful core save inside creation
rollback scope, or between return and the immediate created-progress capture.
Subsequent deadline/cancellation is a retained-project/pending-association
outcome. An exception before the result is observed does not prove no commit:
keep the preallocated expected identity and classify commit knowledge honestly.
The core's owned rollback policy stays unchanged; the facade cannot delete a
committed or foreign project.

A later explicit metadata reconciliation is a **new bounded verification
operation over committed copies and retained metadata**, independent of the
expired source lease. It gets its own clearly labeled verification limit and
callback, not a new PackageBudget pretending to continue extraction. It never
opens original package/member paths, refunds output or cleans a stage from
persisted file IDs. Cleanup after process death remains unavailable unless a
separately reviewed mechanism establishes live ownership.

## 10. Failure matrix and retained meaning

| Boundary / observation | Required outcome and permissible retained state |
|---|---|
| Platform/native prerequisite unavailable | Refuse before package input, stage, worker or workspace mutation; pure models do not bypass this gate |
| Captured revision/source/scope/member/metadata cap invalid before approval | Refuse without investigation/decision/journal/table/version/project writes; valid existing workspace/project stays unchanged |
| Later approval or metadata publication fails | Preserve already committed ordinary approval and complete objects; no project success or fake all-or-nothing claim |
| First-intent transaction fails before commit | No table/version/intent partial state from that transaction; ordinary prior state may remain |
| First-intent commit result uncertain | Read exact selected row within bounds or report unknown; do not call create from uncertainty |
| Live read/copy/precommit stop | Preserve typed stop; core removes only owned uncommitted outputs under existing rules; intent/approvals may remain |
| Save-return/constructor failure after actual core COMMIT | Retain project and intent; commit outcome is unknown until exact non-recovering verification |
| Core returned complete matching identity, created-progress write fails | Report retained committed project and incomplete association using actual observed facts; durable expected ID allows later reconciliation |
| Actual receipt omits a side/hash/ID/revision or contradicts intent | No directory adoption, sidecar, provenance or success; preserve any committed/foreign bytes |
| Fresh reopen sees foreign ID with equal hashes, reversed sides or corrupt files | Refuse association before project/workspace mutation; retain foreign runs/history/copies (normal lock bookkeeping is separate) |
| Original checkpoint stops a postcommit reopen or metadata step | Retain committed project; association pending, no rollback/deletion or extraction refund |
| Source/saved-scope/current revision changes after commit | Retain project and intent; refuse metadata/reducer update under the new current state |
| Provenance exists exactly, final workspace progress absent | Verify/reuse existing row, CAS the remaining metadata transition; do not duplicate or rewrite evidence |
| Existing row/reference is conflicting, corrupt or missing | Fixed bounded conflict/unavailable result; never replace conflicting evidence or infer missing native authority |
| Generic repair encounters unresolved package operation | Refuse before mark_interrupted, including mixed ordinary/package workspaces and direct helper calls |
| Lease lost and project absent/unreadable/identity unknown | Keep unresolved intent and diagnostics; no stored-path reopening, automatic retry or cleanup |
| Cleanup or process termination ownership uncertain | Retain stage evidence and report uncertainty separately from project commit/association knowledge |

## 11. Proposed file/schema ownership and implementation order

This table is an ownership request for subsequent reviewed slices, not current
authorization to edit production. Core and native owners retain their files.

| File / schema | Narrow responsibility |
|---|---|
| New `kbcorrelation/package_contracts.py` | Strict intent/progress/provenance and captured-reference models; canonical IDs and fixed limits; no I/O/native authority |
| New `kbcorrelation/package_store.py` | Bounded selected row/object codec, one additive table, first-intent transaction, immutable binding/progress CAS and exact provenance comparison over existing connections |
| New `kbcorrelation/package_service.py` | Capture/composition and explicit one-intent committed reconciliation; calls existing KB admission/attachment/core; no extraction implementation or parallel service |
| `kbcorrelation/store.py` | Base/supported workspace version split, package-aware transaction participant, current-object reference/accounting integration and narrow package mode in attachment; ordinary journal and call shapes retained |
| `kbcorrelation/service.py` | Optional internal binding, pre-approval capture check, package recovery preflight and reuse of current saved-scope/source admission |
| `kbcorrelation/wiring.py` | Bound real port, strict actual creation receipt, repeat-open identity and non-recovering association context before sidecars/rows; ordinary factory reuse and positional calls unchanged |
| `kbcorrelation/recovery.py` | Explicit bounded package refusal before mark_interrupted/ordinary resume; no package source recovery |
| `kbcorrelation/inventory_store.py` | Only coordinated reuse of the common workspace byte-accounting helper so new package references do not escape the existing budget |
| `enrichment/storage.py` | Only coordinated new non-derived `package-provenance` kind, unless a bounded selected-row seam is separately approved; generic publication/retention policy remains unchanged |
| `tools/generate_kbc_schemas.py`, `docs/schemas/kbcorrelation/` | Add the three new typed package-admission schemas after spec/models; existing core and `local-package/1` schemas retain their meanings |
| Specs, module index, registry, focused tests and QA | Amend `local-package-intake.md`, add/index a durable KB package contract, specify exact compatibility/caps before source; preserve genuine reds and original observations |
| Separately owned core service/persistence | Accepted preallocated-ID and non-recovering checkpointed open/load dependency; no facade-specific schema or expected-ID policy in the core |
| Separately owned native/jobs/acquisition | Live stage/lease/FDI/supervision and Windows evidence; no changes implied by this design |

Implement in reviewable order: **(A)** spec/pure contracts/storage compatibility
and legacy recovery isolation; **(B)** internal held admission/expected-ID binding
and strict real-port association; **(C)** explicit bounded committed reconciliation
and provenance. Keep every step internal until all dependent source and native
gates pass. There is no CLI/UI/native entry-point work in these slices. Any
additional file needed for actual source must receive explicit ownership rather
than being silently absorbed into the three-file propagation's prior authority.

## 12. Meaningful tests before each source slice

The seven current observations are retained evidence for design only. Author
genuine failing contract/integration controls before implementation, then run
the relevant existing ordinary/held/scope/recovery/ownership positives unchanged.

| Acceptance group | Required controls |
|---|---|
| Strict durable records | Key/body/digest/operation/expected-ID disagreement; SQL BLOB/NULL/numeric and overlong metadata before full loading; unsupported version; duplicate keys/nonfinite; per-object, total and exact-bound positives; original/materialized inventory distinction |
| Lazy first-intent transition | v1 read-only/status/dry-run and failed admission do not migrate; v1 ordinary writes remain; table/intent/version rollback at each precommit fault; commit-unknown retained; exact repeat versus contradictory intent; no held row in legacy journal at any phase |
| Frozen-client compatibility | Fresh frozen v1 reader refuses v2 writes; preopened v1 connection remains able to mutate ordinary state but cannot enumerate/resume held operations; current package CAS detects its actual revision/source changes. Preserve the original seven observations unchanged |
| Recovery ordering | Actual public `attach --repair`, `repair`, `mark_interrupted`, direct resume and mixed-workspace cases refuse held continuation before attempts, journal writes, source opens or create; unrelated ordinary repair works after all package associations are resolved |
| Existing admission | Deny selected-source pathname opens, use real authored PE/workspace/project; wrong expected revision/source order/pair/product, cached-empty/finite scope, selected-month drift, unreadable and current withdrawn/superseded/ambiguity conflicts refuse before initial mutation; old file/pair-only and product-only behavior stays |
| First COMMIT identity | Preallocated ID actually persists; full actual receipt required; same bytes/different ID, same ID/reversed sides and missing fields refuse; preexisting create refuses even for matching IDs; fault immediately after core COMMIT retains project while package progress is intent |
| Association before all writes | Replace destination before sidecars and between port calls; preserve foreign queued runs/history/evidence, reject before sidecar/enrichment schema/backup/provenance changes; repeat-open always verifies actual ID/side hashes; exact healthy association positive |
| Provenance idempotence | Absent row publishes once; exact row retries without rewrite; conflicting same-ID row is retained/refused; fail between project row and workspace marker, then complete through exact row reuse; linked marker with missing/corrupt row is not trusted |
| Reconciliation | Remove original inputs/close lease and reconcile only the real committed expected project; assert no extractor/create/approval/source open; actual ordinary revision with unchanged pair can be observed, while foreign ID/side change/stale investigation or scope refuses before mutation; repeat produces no duplicate records |
| Accounting and outcomes | Same pair/callback through live flow, no double charging/reset/refund; positive project-copy read work and zero-byte checks; original typed stop survives; stop after commit is pending retention; fresh later metadata verification is labeled separately and never authorizes source reads |
| State CAS and uncertainty | Valid-first/invalid-second captured records refuse before writes; concurrent analyst revision/pair and preopened legacy writer cannot be silently advanced; all fault points preserve the exact confirmed/unknown commit distinction; cleanup uncertainty never erases a committed/foreign object |
| Qualification and compatibility | Actual owner-thread SQLite; ordinary positional-only injected ports still work; no TypeError path fallback; no network/child/target work in portable controls; unchanged core/creation, KB saved-scope, inventory/source, enrichment and publication neighbors; exact-source Ruff and registry/schema checks after source |

Native Windows original-lock sharing, independent rooted name-to-object reopen,
actual FileIdInfo/rename/cleanup, FDI ABI and callbacks, Job/process handoff and
the frozen full package journey remain separate mandatory gates. Neither this
design nor a future portable facade pass completes PW-02 or authorizes release.
