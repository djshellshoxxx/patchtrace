# Winbindex acquisition evidence follow-up

This is a separately scoped follow-up, awaiting root independent review, to the frozen aggregate runtime
`bffcfa99d6a5044024256edbc0457ab20c92cbae`. Its worktree base is
`860fdf24d228fa49dd41d5cf7050b88048442f0e` on
`codex/acquisition-provenance-20261119-4c8d`. It does not inherit the aggregate's
full-suite acceptance. No target binary, downloaded Microsoft binary, external
provider or remote publication was used in this work.

## Concrete gap and uniqueness

The first two tests in `tests/test_kbc_acquisition_evidence.py` were run before
runtime edits. `baseline.log` and `baseline.xml` retain the **two failures**:

1. A public `kb acquire` completed and created its real comparison project but
   wrote no acquisition proposal/window/source-entry sidecar.
2. Changing one upstream entry's documentary description, while retaining the
   binary SHA-256 values, chronology, pair ID and planned URLs, still accepted the
   previous consent and created a project. The existing plan digest did not bind
   source-entry identity.

The source scan was frozen before the implementation was committed. Its complete
ref-to-object table and relevant blob/method inventories are in
`retained-scan.json`: **717 refs** (326 origin, 312 pull, 59 tags and 20 local
branches), **78 relevant unique blobs**, and **14 semantic service-method
families** when `acquire`, `import_pair` and the older `_import_pair` are included.
This is a later local-ref snapshot than the aggregate census; it is not a change
to that earlier census.

| Retained path | Unique blobs | Semantic finding |
|---|---:|---|
| `kbcorrelation/acquire.py` | 1 | `7844040814e230b7ab73f633475254e32d6a49c3` returns download provenance and explicitly documents that it is not persisted. Its consent digest binds pair/hash/request identity, not full source claims. |
| `kbcorrelation/service.py` | 35 | Current `bf574cdc825706dcdb26fc5c639744d22930c62b` and retained acquisition binding variants pass IDs/hashes through the manual import. The retained publication call arguments do not carry a full source snapshot. |
| `kbcorrelation/store.py` | 12 | `AttachRequest` and the journal/sidecar path have no acquisition snapshot field. |
| `kbcorrelation/context.py` | 15 | Advisory context does not retain the original acquisition proposal or selected delivery rows. |
| `kbcorrelation/contracts.py` | 2 | `PairProposal` describes a proposal but is not a persisted acquisition record. `SourceDoc.kind=winbindex-file` alone does not provide that pipeline; the source importer still reparses advisory documents. |
| `inventory_contracts.py`, `inventory_service.py`, `inventory_store.py` | 5 / 3 / 5 | CSV inventory/source-record work, with `CsvInventory`, page and inventory-context records. This is distinct from consented binary acquisition persistence. None was imported. |

The scan retains exact publication calls, record field lists, blob IDs and AST
family memberships. The absence of snapshot-name tokens is supporting evidence,
not the semantic conclusion by itself. Reproduce the scope with
`git rev-list --objects <the captured ref object IDs> -- src/patchtrace/kbcorrelation`
and inspect the eight listed paths with `git cat-file blob <blob>`.

The prior binding recovery from
`c3868d8335a8f32f676905032dc1a6d0e9f22fd6` was already integrated. It preserves the
approved scope and the relationship between source/manual pair IDs; this change
keeps that behavior and adds a different missing persistence boundary. No broad
PR 319/320/321 code was imported.

## Contract and implementation

The contract was updated first in
`docs/specs/kb-cve/31-F-workflow-ui-persistence.md`, under **Persisted acquisition
snapshot (2026-11-20)**, and the module was indexed in `docs/modules.md`.

`AcquisitionEvidence` is a strict frozen `kbcorrelation/1` record with an explicit
evidence version and content ID. It retains:

- The preview investigation/revision and complete original index `PairProposal`,
  including window, window completeness, reasons, source scope and pending bytes.
- Two normalized delivery rows, including their data-date labels and canonical
  upstream entry hashes. They are labelled delivery metadata and index claims.
- The approved hosts/request list and version-2 acquisition plan digest, which
  includes the full source snapshot digest.
- The complete inspected manual pair and two verified download receipts. The
  manual assessment remains grade B/tier E, user-asserted lineage, unverified fix
  boundary and an unspecified manual window.

The cap is two delivery rows, 4,096 shared-version keys per row, 514 requests
(the existing provider ceiling of 256 HEAD probes plus one GET per side), and
1 MiB of canonical evidence. Large or malformed records are refused, not
truncated. Host/request data and nested source collections are frozen before
staging. The existing three-argument import callback remains compatible; the
optional verified-receipt callback supplies provenance before import mutation.

The existing two-phase attachment carries optional evidence plus its ID in the
journal. The attach operation key includes that ID. Initial attach, resume and
interruption marking validate the record and its investigation/revision, scope,
ordered hashes, manual pair and original operation key. An internally valid
replacement receipt or source record cannot be accepted under the previous
operation key. Legacy journals and local/manual imports omit the optional record
and preserve their original operation identity and behavior.

The sidecar is `kb/acquisitions/<evidence_id>.json`; the project row is
`kb-acquisition:<evidence_id>`. The composition root's
`RealProjectPort.write_acquisition_sidecar` validates the actual project ID and
ordered artifacts under the owner service. It binds the existing
`owned_publication.publish_bytes` with an anchored project directory, bounded
exact-byte reuse and exclusive publication. Conflicting content is retained and
reported. The row is likewise validated and immutable on identical replay, using
the existing project owner and enrichment writer. No project revision, SQL
schema version or `InvestigationRevision`/`ContextBundle` shape changes.

Acquisition results report the evidence ID, relative path and attached/pending
state. Recovery replays the journal without reading the mutable Winbindex input.
Existing project backup already copies the `kb/` tree and enrichment database.
The new enrichment kind is outside derived-retention kinds.

## Validation and retained failures

- Baseline: **2 failed**, preserved before runtime changes.
- First acquisition integration: **59 passed** (new controls, CLI/workflow and
  existing approved-pair binding).
- Focused persistence integration: **223 passed**, retained in `focused.log` and
  `focused.xml`; this preceded the final port and operation-key refinements.
- Expanded intermediate run: **1 failed, 1,542 passed, 1 skipped**, retained as
  `affected-before-port.log` and `.xml`. The failure was the architecture guard
  rejecting a direct `store.py` sibling import. The binding was moved into
  `wiring.py`; store/domain did not receive an exception.
- The following contract/recovery run exposed the composition root's older
  finite whitelist as well: **1 failed, 205 passed** (tool output). The guard now
  permits exactly `OwnedPublicationError`, `directory_anchor` and `publish_bytes`
  only in `wiring.py`, matching the new explicit port contract. The broader
  sibling restrictions remain in place.
- Final expanded affected run: **1,547 passed, 1 skipped in 97.16 seconds**,
  retained in `affected.log` and `affected.xml`. The skipped control requires
  native Windows held-source replacement. It is not a live-provider or Windows
  qualification result.
- Successor validation: whole-repository `ruff check src tests tools` passes;
  `generate_kbc_schemas.py --check` passes with no drift. The final test selection,
  source hashes and retained-log digests are recorded in `completion-receipt.json`.

The parent aggregate on the earlier `bffcfa99` runtime ended with SIGKILL after
1,729.332 seconds, without a final JUnit report. Its incomplete qualification is
separate from these affected tests and provides no acceptance for this follow-up.

To replay the final affected selection (all test classes in `affected.xml`):

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_kbc*.py tests/test_acquisition_workflow.py \
  tests/test_kb_acquire_lifecycle_20261105.py tests/test_kb_product_start_20261106.py \
  tests/test_owned_publication.py tests/test_owned_publication_integrity.py \
  tests/test_owned_publication_replace.py
PYTHONPATH=src python tools/generate_kbc_schemas.py --check
python -m ruff check src tests tools
```

The authored controls exercise public acquire/attach CLI paths, real SQLite
stores, project creation, ownership checks, source-consent invalidation before
staging/mutation, altered staged bytes, post-create interruption, journal repair,
byte-identical replay, backup, malformed/foreign records, immutable row and
sidecar conflict refusal, the existing owned publisher, and read-only snapshot
ports. Network access is denied; provider responses and PE bytes are synthetic.

The independent review worker ended before completing its runtime controls or
report. Its preliminary source observation about named-temp publication was
addressed by reusing the existing owned publisher. No completed peer-review
acceptance is claimed. Its isolated review worktree was clean when checked;
there was no review test change available there to import. Root review of a
stable candidate remains required.

## Deliberate limits and successor work

This preserves the original proposal and normalized endpoint delivery metadata.
It does **not** retain raw complete Winbindex entries or the full index/timeline
needed to rerun every resolver decision. Upstream entry hashes are source claims,
not authentication. A separately scoped successor can capture bounded raw entry
or whole-index bytes and explicit resolver input membership without treating the
advisory-only importer as a generic Winbindex store.

The advisory JSON export and UI remain unchanged; the new sidecar and result
reference are the reviewable persisted deliverable. Historical acquisitions do
not receive fabricated snapshots. No live-provider, target-execution, native
Windows publication or aggregate full-suite qualification is claimed here.
