# Package admission: core identity and postcommit read seams

**Status: read-only design for root review. No production or repository test
changes.** The recommended next core slice has two small additions to the
existing service/store. It does not expose a package route, add a second
admission service, implement package provenance or change generic recovery.

## 1. Frozen source and observations

Source: **`9ad2ec5cdbde85155fdca3cdd88804fd8b2e1a53`**; tree
`db005f5ede44b60fa2cf92581ac7dd685b087d99`. The five reviewed core files remain
byte-identical to `9740860928c7911e6fa975528db1f7fa5ca1940b`.
`qa/pw02-core-admission-design/source-provenance.json` retains 74 canonical
source/test/spec/config snapshots and seven reference snapshots.
`source-seams.json` binds 43 complete symbol spans by source hash and signature.

The original held-reader map, including its durable-admission section, was read
in full. The approved KB propagation plan is retained from exact Git object
`8b376a7bf4cbe2603958b5c596619849d363d828`; it is not present on this frozen base.
That separately owned three-file propagation keeps the live pair in memory and
explicitly leaves durable recovery and postcommit copy verification for later
work. Its implementation is not mixed into the source authority of this map.

Ten bounded current-behavior controls passed, with zero skips, in 0.43 seconds:
eight new observations plus the unchanged two earlier public-path controls.
All 60 loaded project/test-support modules match the frozen Git source. The
runner observed no child or network attempts. These tests use authored PE bytes
and actual temporary SQLite; they are observations of current behavior, not
passing acceptance tests for the proposed interfaces.

| Current observation | Design consequence |
|---|---|
| The existing model/store commits an explicitly supplied project ID, reopens after source removal and keeps database schema version 1. Public `create` has no corresponding keyword. | Preallocation needs an additive service argument, not a new project schema or a parallel creation path. |
| Two valid projects contain the same ordered pair but have different IDs. Recreating in the foreign project's directory refuses without changing its snapshot. | Pair hashes alone cannot establish which project an operation created. Preserve current create refusal and compare the actual project ID. |
| Orientation can reverse under the same project ID. | Project ID alone cannot establish the intended pair; compare older/newer hashes by side, not as an unordered set or artifact-list order. |
| `load(recover_interrupted=False)` leaves a queued run, database bytes and history unchanged. | Use this explicit mode for identity verification and pending-association reads. The lock file is outside the no-mutation claim. |
| `open(maintenance=False)` still changes queued to failed and adds a history row. | This is intended current startup recovery, not a defect in that option. A new explicit recovery flag must reach the existing load boundary. |
| Fresh open after held creation performs 12 copy reads, totaling 2,316 bytes in the authored pair, without the original checkpoint. | Add a per-call checkpoint to open/load and forward it to existing complete copy verification. Do not retain a global expired callback on an ordinary service. |
| Exceptions after the real save commit, both before its return and during service construction, retain the committed project and verified copies. | An exception is not proof that creation did not commit. Preserve this unknown-outcome rule. |
| The unchanged public fault at `after_project_create` leaves a usable project while the attachment remains `intent`, with `project_id=None`; reader-less repair subsequently tries the original sources. | Core preallocation is necessary, but a durable expected ID and held-origin marker outside the core are also required before a package route can be exposed. |

The last public control also retains the existing interrupted-attempt write on
generic repair. It is not evidence of mutation-free repair and is not a new
permission to invoke generic recovery for package intents.

## 2. Actual identity and mutation boundaries

All locations below are at the frozen source; full spans are in the ledger.

| Existing entry | Relevant behavior |
|---|---|
| `models.py::Record` (line 20), `ComparisonProject` (188) | Strict string ID, length 1–128, defaults to a UUID string. Legacy accepted IDs need not be UUIDs. Exactly two distinct artifacts with older/newer sides; aggregate references are validated. |
| `service.py::ProjectService.create` (87) | Checks a supplied live reader pair before opening the store, copies both inputs, constructs the project ID implicitly, then saves. The returned project is the validated result of save. |
| `persistence.py::ProjectStore.__init__` (403) | This is initialization; there is no separate `initialize` method. It owns the project lock and database admission. Existing nonempty databases refuse creation. Eligible empty/zero-byte retries are validated on the actual connection and reused without destructive recycling. |
| `persistence.py::ProjectStore.save` (535) | Validates the aggregate and complete artifact/raw files, checks reloadability, and hashes the payload. Inside its transaction it refuses a different stored project ID or a backward revision. History/current snapshot and the optional checkpoint precede COMMIT. `project_id` is assigned after the transaction; later deferred maintenance can still fail or retain history. |
| `service.py::_rollback_creation` (53) | Rolls back an outstanding transaction, then inspects whether a snapshot exists. A committed snapshot or uncertain state is retained. Only positively owned new files/database can be removed; preexisting/reused/foreign objects remain. |
| `persistence.py::ProjectStore.load` (652) | Reads and hashes the current payload, strictly validates the model/aggregate and completely verifies immutable files. It then records the actual project ID. Default interrupted-run recovery edits the model and calls save; `recover_interrupted=False` bypasses that mutation. |
| `service.py::ProjectService.open` (122) | Opens the existing store and calls default load. `maintenance=False` suppresses legacy raw cleanup only. On an ordinary loading exception it closes the store; it does not invoke creation rollback. |
| `persistence.py::_verify_files` (498) | Already accepts the neutral checkpoint and verifies full artifact/raw hashes, PE structure, path/size, file fingerprints and cache ownership. A valid cache hit still checks the operation without inventing positive read counts. |
| `kbcorrelation/wiring.py::RealProjectPort.create_project` (272) | Returns actual ID, revision and side-keyed hashes, then closes. Its existing reuse policy can open a prior project; held-reader presence does not make that project operation-owned. |
| `RealProjectPort.put_row/list_rows` (301/312) | Each call reopens and verifies project copies. At this source, both use default recovery and no operation callback. Later propagation must verify the actual identity on every owned open before publication/adoption. |
| `kbcorrelation/store.py::ProjectAttachment._begin/_create` (594/622) | Intent is written before core creation. The actual ID is written only after the real port returns and the `after_project_create` fault. Current ordinary compatibility allows missing returned hash fields through `made.get(key, expected)`; that fallback is insufficient for a new package identity receipt. |
| `ProjectAttachment._after_create` (645) | Existing CAS, sidecars and rows occur after the core snapshot is committed. Their failure must not authorize deleting that snapshot. |
| `kbcorrelation/recovery.py::repair` (45) | Constructs a reader-less attachment and calls `mark_interrupted` before its per-operation predicate. A later held-origin guard therefore must be enforced before generic repair is entered. |

The current lock is a cooperative, identity-checked kernel lock and its holder
record is rewritten on open. The SQLite constructor uses `mode=rw`; the proposed
flag controls application recovery, not a new forensic read-only SQLite mode or
protection from arbitrary concurrent filesystem replacement. Existing journal,
namespace and native-sharing limits remain. No new race-resistance claim is
made by preallocating an ID.

## 3. Recommended smallest core interfaces

Preserve positional arguments and defaults; add only keyword-only options:

```python
ProjectService.create(older, newer, name, root, *,
                      input_readers=None, project_id: str | None = None)

ProjectStore.load(*, recover_interrupted: bool = True,
                 checkpoint: ReadCheckpoint | None = None)

ProjectService.open(root, *, maintenance: bool = True,
                    recover_interrupted: bool = True,
                    checkpoint: ReadCheckpoint | None = None)
```

### Creation identity

When supplied, validate `project_id` against the existing strict bounded Record
ID contract before creating/opening a store or reading/copying inputs. Use that
same value in the existing `ComparisonProject` constructor and first save.
Do not replace an ID after save, patch the UUID generator, add a placeholder
snapshot, or add a new database field. When omitted, leave default generation
and injected call shapes unchanged. The later package facade is responsible for
allocating and durably recording a canonical UUID before admission; the core
must not tighten every historical project's existing ID contract to UUIDs.

This argument does not authorize reuse. `ProjectStore(create=True)` keeps its
actual-connection/schema/emptiness checks, exclusive creation ledger and refusal
of a committed database, even when its ID or pair happens to match. No optional
identity can bypass source hashing, PE validation, aggregate ownership or the
transaction's stored-ID check. All existing first-save checkpoints and committed
snapshot preservation remain intact.

### Actual committed identity evidence

The existing saved/loaded aggregate already supplies the minimum verified facts:
actual `project.id`, actual revision, and older/newer artifact SHA-256 values.
The store's actual `project_id` must agree. Load already validates the committed
payload digest and immutable files. A new persistent receipt schema or a second
core verification service is unnecessary for this first seam.

For a normal successful create, use the validated object returned by save. For
an uncertain result or restart, open the intended directory through the existing
core with **both** `maintenance=False` and `recover_interrupted=False`, plus the
operation checkpoint when one exists. The future bound project port must compare
the returned actual ID and side-keyed ordered hashes with the durable intent
before caching its directory, adopting it, publishing a row or updating a
journal. Return actual values, including the observed revision; never copy
expected values into missing receipt fields or infer zero revision.

An unsaved mutable `service.project`, an ID alone, matching unordered hashes or
a successful filesystem existence check is insufficient. Recheck the same
identity when reopening for a subsequent write; an earlier closed verification
is an observation, not a transferable filesystem capability. A UUID is operation
identity, not proof of package lineage or authority against deliberate same-user
cloning. Workspace/investigation ownership, the captured destination and normal
project lock still constrain the future port. Contradiction or uncertainty
retains the existing project and refuses adoption.

## 4. Postcommit copy reads keep the original checkpoint

`ProjectService.open` should check an explicit callback before acquiring a new
store, then pass it to `load`. `load` checks before the snapshot read and around
payload validation, forwards the same callback to `_verify_files`, and checks
before returning a non-recovering read. Existing bounded file reads then charge
their actual bytes through `sha256_file`, PE validation and `verify_artifact`.
No callback is fabricated and no new timer is started.

If default recovery was explicitly retained, its existing `save(project)` path
must receive that same callback when present, including the existing pre-COMMIT
check. Do not add a callback after that save commits. The package verifier uses
`recover_interrupted=False`, so it performs no recovery save, history append,
pruning or legacy raw cleanup. Cancellation while reading an already committed
project closes that owned open and propagates the original neutral failure. It
never calls `_rollback_creation`, deletes the project or marks KB recovery state.

Default calls must remain byte-for-byte equivalent at injected boundaries:
ordinary `open(root)` and `open(root, maintenance=False)` still call `load()`
with its existing defaults; omitted callbacks do not introduce redundant None
keywords into existing test ports. Only explicit nondefault values add kwargs.
The service and store must not retain the callback beyond the individual call;
future normal project use is independent of an expired package operation.

The later bound KB port can keep the original pair's checkpoint privately for
its synchronous operation and use it on each postcommit open/read. It must not
insert a new raising checkpoint between core create returning and the existing
`created` journal write. After that boundary, a stopped verification or metadata
step produces a retained-project/incomplete-association outcome. The separately
owned KB propagation does not yet implement these postcommit calls.

Positive read work remains separate from expanded-output reservations and from
hash-only worker statistics. Repeated full verifications charge real repeated
reads; cache hits charge zero bytes but still check cancellation/deadline. There
is no extraction refund, new allowance or reset between sides/reopens. SQLite
page work, an individual OS call, JSON/model validation and COMMIT remain
cooperative boundaries; this slice does not impose a new aggregate I/O cap or
make all metadata association interruptible. Sidecar publication, enrichment
backups and durable-package writes require their own later budget boundaries.

## 5. Durable binding still required before package exposure

The proposed core hooks are necessary capabilities, not a package recovery
protocol. Keep the existing internal-only held route unexposed until a separately
reviewed facade supplies all of these durable facts and guards:

1. Validate current investigation/source/saved scope and selected materialized
   members, then persist a strict bounded package intent. Bind the workspace,
   investigation/revision, source/header/member/ancestor and materialized
   identities, ordered observed hashes/sizes, pair ID, captured destination
   ownership and the preallocated project UUID. Package lineage is separate from
   advisory SourceDocs and their object/snapshot identities.
2. Before core creation, durably bind the attachment intent to the package intent,
   expected project ID and `input_mode='held'` (names remain a later contract
   decision). Those plain fields grant no reader/native authority. A pending
   held create without its live pair must refuse before source pathname access
   and before generic `mark_interrupted` writes. Legacy journals retain their
   existing meaning; do not infer a missing held marker from a pathname pattern.
3. Use the existing import/attachment/core path. The first snapshot commits the
   expected UUID. Verify complete actual ID/ordered-hash output and preserve the
   existing immediate `created` transition. No core callback or second creation
   route is added for package bookkeeping.
4. Record the observed committed identity in package state, publish the exact
   idempotent project provenance row, and only then mark package association
   linked. Existing KB context may independently be pending or complete; do not
   collapse these states. Metadata failure leaves the project and pending
   association readable. Cross-database writes are not falsely labeled atomic.

The expected ID must be durable **before** the first core save; recording it only
after create returns leaves the demonstrated gap unchanged. A package marker
alone also does not prove commit. Strict package provenance and attachment schema
ownership remain unassigned to this core slice.

### Bounded reconciliation of the demonstrated gap

| Observation after a stop | Permitted future facade behavior |
|---|---|
| A current live pair is still owned and no committed expected project exists | Revalidate current owner/scope and use the existing admission path; never bypass create refusal. |
| The live pair expired and no committed expected project can be verified | Retain unresolved intent/stage evidence. Require a fresh explicit package operation; do not reopen stored source paths to resurrect the old lease. |
| Exact committed ID and ordered copies verify, while attachment is still `intent` | A package-only reconciliation may write the guarded `created` transition and resume existing documentary association. It must not extract, reapprove, create again or invent a lease. |
| The project is known committed but the original checkpoint now stops reads | Report retained/association-pending using already observed facts, or unknown if commit identity was never observed. Do not turn timeout into evidence that creation did not occur. |
| A later explicit repair is requested | A new bounded metadata-verification operation may read committed project copies; it is not continuation of the expired extraction operation and gains no authority to reopen original package-member paths. |
| ID, ordered hashes, destination ownership, scope or durable records conflict; project unreadable | Refuse adoption/reconciliation, retain bytes and unknown outcome, and publish no success or invented provenance. |

The future `verify_created_project(...)` port and
`ProjectAttachment.reconcile_created(...)` must be narrowly guarded uses of the
current service/store and attachment state machine. Validate current and every
selected captured saved revision before any recovery mutation, as the existing
attach preflight requires. Ordinary generic `repair` is not the implementation
of this new authority check. No reconciliation may consume a different project's
queued runs, mutate an unrelated intent, or delete a committed/foreign project.

## 6. Narrow implementation ownership and tests before code

Recommended first implementation scope, only after root reviews this design:

| File | Allowed changes |
|---|---|
| `src/patchtrace/service.py` | `ProjectService.create` optional prevalidated ID and existing model construction; `ProjectService.open` explicit recovery/checkpoint forwarding and existing close-only failure path. No new rollback/deletion authority. |
| `src/patchtrace/persistence.py` | `ProjectStore.load` optional callback around existing read/validation and forwarding to `_verify_files`/authorized recovery save. Keep constructor, schema, save transaction, cache and history policy unchanged. |
| Focused new tests | Proposed `test_project_creation_identity.py` and `test_project_open_checkpoint.py`; preserve old tests/assertions. |
| Existing specification and QA | Update `core-held-inputs.md` and relevant architecture identity/read semantics before tests/source. No new schema generation, registry row or module is needed for this proposal. |

`input_readers.py`, ingestion, native/jobs/package contracts, all KB propagation
files, facade/journal/provenance schemas, generic recovery, CLI and UI stay outside
that first core implementation. The optional ID does not expose a new user flow.

Meaningful failing integration controls must precede source, followed by existing
positive controls. The ten observations in this packet do not substitute for
that red run:

| Acceptance group | Required red/positive controls |
|---|---|
| Preallocation | Actual create commits supplied ID and reopens with exact ordered hashes after source removal; default IDs remain distinct. Invalid type/empty/overlong ID refuses before store/source I/O. Preserve the existing legacy bounded-string ID contract. |
| Ownership and first COMMIT | Existing committed same-ID/same-pair or foreign-ID directories refuse unchanged; healthy empty/zero-byte retries retain behavior. Pre-COMMIT cancellation removes only owned new objects; postcommit save-return/constructor failures retain the expected committed identity and immutable copies. |
| No-recovery open | A project with queued/running runs opens with explicit false/false and leaves current/history/raw bytes unchanged except the documented lock holder record. Default opens still perform current recovery. Old injected `load()`/verify call shapes remain accepted. |
| Checkpoint forwarding | Same callback object reaches every fresh copy/raw/PE read and valid cache check. Deny original-source reopening. Compare positive read counts with actual reads; preserve original output reservations and callback state across reopens. |
| Stops after commit | Cancel/limit before store open, during either immutable copy/PE/hash/raw read, and on cache checks. Preserve the exact neutral reason/object, close the owned store, keep the prior database/history/artifacts, and permit later healthy reopen. No creation rollback or KB journal mutation. |
| Full verification | Matching IDs never bypass swapped ordered hashes, corrupt/missing copies, wrong content-addressed path/size, raw-output mismatch or aggregate ownership validation. Include healthy unchanged project positives. |
| Default recovery with callback | When recovery remains enabled, carry the original callback into its existing save/pre-COMMIT. A stop rolls back that recovery update; a successful recovery keeps ordinary behavior. No new postcommit callback is introduced. |
| Source/thread isolation | Actual authored PE/SQLite, caller-thread connections only, absolute source pin/import manifest, no network/child/native/target execution. Preserve original external observations unchanged in a fresh result directory. |

Later facade acceptance must separately test every durable intent/commit/journal/
provenance boundary, identity mismatch with equal hashes, orientation mismatch,
stale owner/revision/saved scope, lease loss before generic recovery, idempotent
metadata completion and retained unknown outcomes. Native Windows sharing,
rooted reopen, process/FDI handoff and packaged/frozen acceptance remain separate.
