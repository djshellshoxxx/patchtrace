# KB source-admission provenance repair — 2026-11-06

## Finding and exact baseline

The [Qodo finding on #244](https://github.com/djshellshoxxx/patchtrace/pull/244#discussion_r4489325824)
is valid. Baseline #244 commit `5347ccfd206f37fc6c5f531614ac051221bc470a`
contains source-owner [#242](https://github.com/djshellshoxxx/patchtrace/pull/242)
service blob `910f31ebd6b4d6740b1e5ba8b852789cd61f7dbc`.
`import_pair` checked `expected_source_snapshot`, then independently reloaded
the advisory index for selected-product validation and for context creation.
A cooperative source import between that check and either read could replace
the admitted advisory source in a successfully saved ContextBundle.

The existing admission-check qualification did not prevent this provenance
drift. A held WorkspaceStore context closes its connection on exit; it does
not lock the document set for the entire import operation.

## Repair and preserved boundaries

[SPEC-31-D](../specs/kb-cve/31-D-acquisition-packages.md) was amended before the
production edit. When an expected source snapshot is supplied, `import_pair`
builds one index, compares the current ordered source records with that
snapshot after the read, and reuses the admitted index for selected-product
validation and `_bundle`. Existing manual callers with no expected source
snapshot retain their previous index-loading behavior.

The ordering relies on the cooperative store contract already implemented:

- `WorkspaceStore.sources()` materializes ordered immutable SourceDoc records;
  `add_document` only adds records and content-addressed objects. An addition
  before or during the index read therefore makes the following comparison
  stale. There is no cooperative source-update or source-delete path.
- A successful comparison admits the already-built index. Later document
  additions cannot enter scope lookup, lead lookup, card facts, source digests
  or the edge-set digest through a subsequent index reload.
- `_lead_cves` reads search coverage only by the captured revision's coverage
  IDs. `put_coverage` uses `INSERT OR IGNORE`, so later searches do not replace
  the coverage attached to those IDs.
- Attachment retains its existing journal and revision compare-and-swap
  behavior. Its sidecar writer looks up records by SHA but iterates only the
  request's captured `source_shas`; later additions cannot add sidecars.

No public argument, model, schema or storage format was added. No transaction
was introduced across download, approval or project attachment. Cancellation,
exact consent, binary verification and conservative pairing labels remain
unchanged.

## Deterministic real-store regressions

Both controls use the existing authored CVRF/PE fixtures, real acquisition,
verification, project persistence and a second real WorkspaceStore connection.
The injected writer imports a valid newer advisory revision and asserts that
the document was added without changing the current investigation revision.
Sockets and DNS are denied by the existing fixture; the transport opener serves
authored bytes and never contacts a provider. The completed-project fixture
also checks that its prior database remains byte-identical.

1. **Source committed during the import index call:** the real loader finishes
   reading its materialized source set, then the second writer commits before
   the loader returns to admission. The operation must raise `PT-KBC-STALE`,
   preserve the investigation revision and added workspace source, create no
   project, and remove owned staging.
2. **Source committed after admission:** the real `_approve_pair` finishes,
   then the second writer commits before context construction. Acquisition
   may complete, but the saved ContextBundle's sources, card facts, edge-set
   digest and search coverage must remain bound to the admitted source. The
   new source remains readable in the workspace, source sidecars contain only
   admitted bytes, both artifact hashes match the verified inputs, and staging
   is empty. The test asserts the writer ran, so eliminating a later loader
   cannot silently turn the timing control into a no-op.

## Results

Environment: local Linux, existing Python virtual environment, `PYTHONPATH=src`,
`QT_QPA_PLATFORM=offscreen`, sockets denied by the KB test fixtures.

| Check | Actual result |
|---|---|
| Both new tests against unchanged #244 production source | **2 failed, 9 deselected in 1.41 s**. Build-time addition did not raise; post-admission addition saved newer source SHA `ca98fe45b199a2c0f01c768961fcae833350be69531d2faf8ffdadfd0a33c05c` instead of admitted SHA `bb24994065736ce59444bdcaf39dc0cfee8b5b3dc6f23d5ec245d52f6a1154d8`. |
| Both new tests after repair | **2 passed, 9 deselected in 1.37 s**. |
| Lifecycle, acquisition CLI, service and crash-recovery selection | **75 passed in 10.56 s**. Includes the two new tests; counts overlap. |
| `python -m ruff check src tests tools` | **Passed**. |
| `git diff --check` | **Passed**. |

Commands:

```text
python -m pytest -q tests/test_kb_acquire_lifecycle_20261105.py -k 'source_added_during_import_index_build or source_added_after_admission'
python -m pytest -q tests/test_kb_acquire_lifecycle_20261105.py tests/test_kbc_acquire_cli.py tests/test_kbc_service.py tests/test_kbc_recovery.py
python -m ruff check src tests tools
git diff --check
```

## Limits and remaining gates

These tests demonstrate real local store interleavings under cooperative,
append-only source imports. They do not establish a transaction over the
whole acquisition, protection from direct database tampering, live provider
compatibility, native Windows acceptance or a complete exact-head suite pass.
The repair is pending independent integration review. Existing hosted,
scanner, Windows and release gates remain open; this receipt does not qualify
the broader branch for main or release.

## Independent integration review

Independent review of local commit `c93bbe1d85e9069b7443a594a298bcf70dba7da6`
found no blocking or nonblocking findings and independently ran the two new
regressions: **2 passed in 1.28 s**. The coordinator reviewed the same production
delta and integrated its exact non-ledger blobs with the recovery prerequisite.
The combined source tree is `3e5276d6643d784e459264d6cb213082b812c8d4`, published
as `a502c9c241d855dba530160e19215d802ebaf90f`. Its broader affected selection
passed **774 tests in 37.31 s**; whole-tree Ruff and schema drift checks passed.
These results overlap the author checks. Hosted, Windows and main/release
acceptance remain separate gates.
