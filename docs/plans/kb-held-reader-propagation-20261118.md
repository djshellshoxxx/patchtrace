# KB held-reader propagation: bounded implementation proposal

**Status: read-only design; no production edits.** Recommended next slice is the
existing KB route in three files: `kbcorrelation/service.py`, `wiring.py` and
`store.py`, with specification, module-index and focused tests. It carries an
already-owned `PairInputReaders` through the current import/attachment path.
It introduces no alternate KB service, native worker, package entry point,
durable package provenance, reconciliation protocol or schema.

## 1. Exact comparison and evidence

Frozen integrated source: **`bca79c2371dc674e1b66177e0396f10332dcf198`**, tree
`aa51e77cc9946305592866a6385b63dfb7bcdc3c`.

Five core implementation/spec files are byte-identical to reviewed core
**`9740860928c7911e6fa975528db1f7fa5ca1940b`**. Both worker implementation files
are byte-identical to **`7259f86838c2181d6bdbcabe98c7a294a4499e8d`**.
`source-provenance.json` retains all seven equality checks and 40 exact Git
snapshots. `source-seams.json` binds 51 complete symbol spans by SHA-256 and
signature. Three saved whole-production caller searches bind the current
injection and call sites. No mutable worktree source is used as authority.

The earlier `qa/pw02-kb-held-reader-design/README.md` was read in full. All 16
captured KB production files are unchanged from its exact `27e4318b` source.
Its two public-route controls remain **historical observations** at that source:
eight selected-input pathname opens across inspection, intent hash, create hash
and ingestion; seven SQLite connections on the caller thread; original-source
removal followed by successful project reopen; and a committed project retained
at the `after_project_create` fault while its journal still says `intent`.
The earlier two socket/SSL harness failures and corrected two-pass invocation
are preserved as such. They are not rerun or relabeled as a fresh integrated
held-reader test. This proposal executes no product or native code.

## 2. Existing route and the smallest change

| Current symbol at the frozen source | Existing responsibility | Proposed additive seam |
| --- | --- | --- |
| `service.py::Env` | Injected inspector and project factory | Callable protocols document optional held-reader keywords; ordinary positional call shapes remain unchanged |
| `KbService.import_pair` | Inspect both inputs, read current investigation and full advisory index, validate saved scope/product/pair, approve and attach | Keyword-only `input_readers=None`; check the original operation and ordered bindings, inspect through each reader, recheck before the first approval, then pass the same pair to factory and attachment |
| `wiring.py::inspect_local_file` | Full streamed SHA-256/size, bounded 4096-byte architecture prefix, safe basename | Keyword-only `reader=None`; held mode uses `check` and `open_reader`, never source pathname open; ordinary mode and basename hint semantics unchanged |
| `wiring.py::_project_factory/new_project_factory` | Default reuse policy versus desktop create-only policy | Optional keyword forwarding without changing either `reuse_existing` value |
| `RealProjectPort.__init__/create_project` | Own one project open/use/close per call and return actual ordered artifact hashes | Store the operation pair privately; on the existing creation branch, forward it to `ProjectService.create` only when present |
| `store.py::_file_sha` | Full independent digest before intent and again before create/resume | Optional `reader=None`; use that side's held stream and the same full digest loop |
| `ProjectAttachment.__init__/_begin/_create` | Journal idempotence, current revision, both ordered hashes, create, record `created`, then existing context/CAS path | Keep the pair in memory, use older/newer readers for the corresponding existing hash calls, and preserve typed input-stop exceptions through the generic creation wrapper |

`ProjectPort.create_project(older_path, newer_path, *, directory)` remains
unchanged: the real port instance is bound to the pair. `AttachRequest`, journal
bodies, investigation models, CLI envelopes and task requests gain no reader
field. No source digest supplied by a package receipt bypasses inspection,
either attachment hash, core copying, PE validation or initial save verification.

The route remains:

1. Check the original operation and both captured path/side bindings.
2. Inspect both held inputs through `Env.inspect`.
3. Perform the existing full-index/source/revision/saved-scope/product/pair checks.
4. Recheck the same operation and both bindings immediately before approval
   (and before returning a held dry-run preview).
5. Use the existing `_approve_pair`, admitted-index bundle and `AttachRequest`.
6. Rehash both held sides in `_begin`; preserve source-object verification and
   destination checks; recheck the same operation/bindings before writing intent.
7. Rehash both held sides in `_create`, then call the bound real project port.
8. Let the already-reviewed core perform held ingestion and checkpointed first
   save. Once it returns a committed project, retain the existing `created`
   journal transition and post-create association behavior.

The scoped implementation should preserve the existing ordering of ordinary
calls. An optional keyword is passed only when a pair was explicitly supplied.
There is no `TypeError` retry that silently changes a held request into path I/O.
An injected held inspector/factory must implement the new optional contract;
legacy path-only test ports and the desktop's current-input inspector closure
continue to receive their existing positional arguments.

## 3. Proposed signatures and file ownership

```python
KbService.import_pair(..., input_readers: PairInputReaders | None = None)
inspect_local_file(path, *, basename=None, reader: HeldInput | None = None)
_project_factory(workspace, name, *, input_readers=None)
new_project_factory(workspace, name, *, input_readers=None)
RealProjectPort(..., reuse_existing=True, input_readers=None)
ProjectAttachment(workspace, project, *, input_readers=None)
_file_sha(path, *, reader=None)
```

| Owned file | Allowed sections |
| --- | --- |
| `src/patchtrace/kbcorrelation/service.py` | Neutral input types/callable protocol annotations, `Env`, and `import_pair` optional forwarding/pre-mutation checks |
| `src/patchtrace/kbcorrelation/wiring.py` | Neutral input imports, `inspect_local_file`, the two factories, and `RealProjectPort` constructor/create branch |
| `src/patchtrace/kbcorrelation/store.py` | Neutral input imports, `_file_sha`, `ProjectAttachment` constructor and ordered `_begin/_create` checks; explicit `InputReadError` pass-through before the existing generic creation exception mapping |
| Proposed `tests/test_kbc_held_input_admission.py` | Real public KB import, ordinary call compatibility, failure/lifetime and admission controls below |
| Proposed focused attachment tests, if needed | Same-invocation intent/resume binding and typed-stop preservation; reuse existing test support without changing old expected assertions |
| Existing specifications/module index/QA | Additive propagation contract and precise qualification limits before code; no model/schema generation change |

The existing core (`input_readers`, ingestion, ProjectService, persistence),
worker/budget, index, context, saved-scope, recovery, desktop/controller, CLI
grammar and native source remain read-only in this slice.

## 4. Read ownership, cancellation and commit boundary

The actual neutral API is the frozen dataclass
`PairInputReaders(older, newer, checkpoint)`. Each `HeldInput` provides
`check(Path)` and `open_reader(Path)`. The path asserts the captured binding;
it never authorizes a new open. The provider owns each borrowed stream and
retains its original object. KB code enters/exits the borrowed contexts and
does not close, serialize, reconstruct or replace the originals.

Held read loops request finite chunks of at most 1 MiB and retain full hash/size
calculation. The provider owns positive-byte charging and per-read checks.
Neither inspection nor `_file_sha` charges those bytes again. Only zero-byte
operation checks are added around KB admission/journal boundaries. The exact
same pair/checkpoint reaches the core, which already accounts its ordinary
project-copy validation and first-save verification. No new clock, budget,
side-specific deadline, retry allowance or extraction reservation is created.

The core and CI owners confirmed this split against their final source. The
future native adapter's finite read-work ledger remains separate from
`PackageUsage.hashed_input_bytes` and output reservation/completion counters.
It uses the original parent callback/work allowance, deadline and cancel token.
Worker receipts are accounting data, not file authority. The parent must finish
its serial worker handoff before using the pair: `_local` refuses work while
a grant is outstanding, `reconcile_worker` consumes the exact grant once, and
the derived worker cannot mutate output tokens after its terminal receipt.
Actual native lock/reader construction and worker termination remain outside
this proposal.

### Preserve the original stop

`InputReadError` is a fixed-message `ValueError` with neutral reasons
`cancelled`, `limited`, `changed`, `unavailable`, `invalid`. `_file_sha` and the
inspector's existing `OSError` mapping need not swallow it. The concrete masking
point is `ProjectAttachment._create`: its generic `except Exception` currently
converts a core stop to `PT-KBC-STORAGE`. Add an explicit `except InputReadError:
raise` before that wrapper. Keep the original object/reason, including any fixed
cleanup note supplied by the core. Do not invent an `Outcome` or a native error
string here. Future package composition owns final cancellation presentation.
Ordinary storage/SQLite errors retain their existing mappings.

### Retain committed evidence

The reviewed core calls the checkpoint inside the save transaction immediately
before COMMIT, then performs no new checkpoint after `store.save` returns.
The KB propagation must not insert a raising operation check between the real
port returning the committed project and `_create` recording its `created`
journal identity. No KB catch invokes core rollback or deletes project bytes.
If failure occurs before core commit, existing creation ownership cleanup runs;
if commit has succeeded, the project remains.

The caller keeps the original stage/read capabilities until synchronous
`import_pair` returns or raises and captures the result. Cleanup remains the
caller's responsibility and must preserve the first failure. A lease that has
expired or closed refuses subsequent operations; there is no path fallback.
This is a cooperative lifetime, not hard-time interruption of an OS call or
SQLite COMMIT.

## 5. Saved scope and source admission stay authoritative

The reader pair changes how binary bytes are read, not which advisory evidence
is admissible. Preserve these current source-proven invariants:

- `import_pair` checks the expected investigation revision and compares the
  complete ordered SourceDoc serialization after the full `load_index` read.
  It retains that admitted index for the rest of the import.
- `_checked_index`/`_saved_search` validate exactly referenced coverage,
  recomputed coverage identity, unreadable-source refusal and detectable drift.
  Cached selectors keep finite recorded `doc_ids`, including the empty tuple.
- `ReverseIndex._lookup` computes `active_ids` and revision conflicts from the
  full index. Selecting older documents never resurrects superseded, withdrawn,
  ambiguous or disputed claims. Do not construct a reduced index from the
  saved selector or package members.
- `build_bundle` revalidates saved scope and keeps its selected-document key
  behavior. Package bytes/receipts do not enter advisory `docs`, SourceRefs,
  coverage records, or context provenance as vendor claims.
- The selected product, architecture and expected pair ID checks remain before
  `_approve_pair`. Manual component confirmation, identical-content refusal,
  pair grades and product membership uncertainty do not change.
- File/pair-only behavior remains distinct from saved KB/CVE searches. The
  existing basename hint is still an analyst hint, not PE OriginalFilename
  or product authority. The existing 4096-byte inspection-prefix behavior is
  retained; this slice does not broaden late-PE-header support.
- `attach --repair` still validates the current revision and every selected
  captured journal revision and prebuilds resumable context before generic
  `repair` calls `mark_interrupted`. No recovery or global admission policy
  changes are hidden in reader plumbing.

Initial stops occur before opening a workspace. Stops or admission refusal
before `_approve_pair` create no investigation/decision/attachment/project
records. Once approval has started, existing append-only decisions or intent
may remain after a later stop; tests must not label those late phases as
"nothing was imported" or require unauthorized rollback of prior records.

## 6. Concrete test-first acceptance

| Group | Red/positive controls required before source |
| --- | --- |
| Public held route | Real `KbService.import_pair` with synthetic PE files, actual workspace/project SQLite and the existing portable descriptor fixture; deny every selected-source `open`/`io.open`/`os.open`. Observe held reads at inspection, `_begin`, `_create` and ingestion; verify ordered immutable-copy hashes and reopen after input removal. No native or target execution. |
| Ordinary injection compatibility | Positional-only inspector/factory and old `_file_sha`/`ProjectService.create` test doubles still receive exact old arguments when readers are absent. Both production factories retain their existing reuse/create-only flags; the desktop current-input inspector closure is unchanged. No silent retry after a held-port `TypeError`. |
| Original lifetime/accounting | Spy the same pair and checkpoint at every held phase; all borrowed streams close on pass/failure while originals remain open. No overlapping borrow, no negative/unbounded read, no double positive-byte charge, no output-counter mutation, no reset between older/newer/hashes. |
| Pre-mutation refusal | Closed/foreign/wrong-side bindings, cancellation before inspection and binding drift during advisory-index work refuse before approval. Dry-run uses held reads, returns the existing preview only after rechecks, and invokes no project factory or attachment. |
| Admission neighbors | Wrong expected revision/source tuple/pair, malformed selected coverage, unreadable selected source, cached empty scope, later unselected documents, active/withdrawn/tied revisions and finite saved selectors retain current results. Assert no new approval/decision/journal/project writes on the pre-approval refusal cases. |
| Late reads and core errors | Stop either `_begin` hash before intent, either `_create` hash before creation, copying, first-save verification and pre-COMMIT. Verify exact original `InputReadError` identity/reason through the KB call, normal core rollback and preserved foreign/preexisting inputs. Distinguish earlier approval/intent from newly committed project state. |
| Committed boundary | Reuse the real `after_project_create` fault: the project remains valid while the original intent limitation remains visible. No new checkpoint may erase committed data or hide its existing identity transition. No new successful durable reconciliation claim. |
| Same-invocation resume | The bound attachment reuses the same live pair for an existing intent; a journal body with another path fails that capability's check before core creation. Expired/closed bound leases refuse. Ordinary generic recovery remains unchanged and separately qualified. |
| No capability persistence | Journal/request/row/CLI serialization retains its existing plain record shape; no reader, checkpoint, handle, native integer or package-private authority is serialized. |
| Thread and source isolation | All workspace/project connections are created/used/closed on the synchronous caller thread. The child/native side never receives SQLite. No target, engine, network request or new package process is run in portable controls. |

After implementing the reviewed contract, run the new file plus existing
`test_kbc_service`, `test_kbc_store`, `test_kbc_recovery`, `test_kbc_cli`,
`test_kbc_acquire_cli`, saved-scope flow/validation/revision-identity,
inventory-source-admission, investigation service, held ingestion and creation
checkpoint suites. Confirm exact existing filenames before invocation and
record source-pinned commands, real reds, fixture corrections and bounded
green results. Run the required full Ruff gate. Original assertions stay intact;
portable descriptor controls do not count as Windows sharing/FDI evidence.

## 7. Explicit boundary left for later ownership

Two reachable limits already exist and are intentionally not repaired here:

1. `recovery.repair` constructs a fresh reader-less `ProjectAttachment` and
   journals retain source paths, not a held-origin discriminator. This proposal
   cannot authorize reconstruction of a lost capability or promise safe
   package-intent resumption after process exit. The separate durable facade
   must bind package intent/expected project identity and prevent path-based
   source resurrection before a native package entry point is exposed. No
   marker/schema or `reconcile_created` API is added in this slice.
2. Post-create `RealProjectPort.put_row/list_rows` reopen the project and verify
   immutable copies through ordinary `ProjectService.open/load`, without the
   creation checkpoint. Therefore this propagation does not qualify an entirely
   interruptible or fully read-accounted postcommit association. A later facade
   must handle late deadline/cancellation as a retained-project outcome; any
   checkpoint extension into these copy reads needs separate core ownership.

The default factory's existing-directory reuse and the desktop factory's
create-only refusal both remain. A future package facade must deliberately
choose its approved creation policy and durable identity checks; held-reader
presence does not certify a foreign existing project or package provenance.
Unknown cleanup, child termination, native lock sharing, rooted rename/read-open,
FDI behavior, frozen packaging and native Windows acceptance remain explicit
unqualified gates. No whole PW-02 completion or release claim follows.
