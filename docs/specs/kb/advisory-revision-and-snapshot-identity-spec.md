# Advisory revisions, snapshot identity, staleness and cache keys (KBF-03)

Status: draft, developer-ready design. Date: 2026-10-15. Base commit: `54fd085`. Proposed alias: KBF-03. Owner packages: `enrichment/{cve,contracts,storage}.py`, `intelligence/{storage,explain}.py`, `intelligence/csaf/applicability.py`, `kbcorrelation/{index,context,leads}.py`, `kev/store.py`. Reads with KBF-01, KBF-02, SPEC-07 s8, SPEC-35 section I, KB plan s7.4.

## 1. Purpose and non-goals

Purpose: say precisely how a revised advisory, a re-fetched CVE record, a second KEV catalog or a replaced CVRF month changes what the product shows, which identifier changes when, and when a stored result is declared stale instead of silently recomputed or silently reused.

Non-goals: changing any persisted field (additive only; no migration); a version-control history browser; automatic refresh; merging two revisions into one claim.

## 2. Identity rules (all BUILT unless marked)

| Object | Identity | Inputs (and what is deliberately NOT an input) | Code |
|---|---|---|---|
| `CveSnapshot.snapshot_id` | `domain_id('cve-snapshot', 1, {cve_id, normalization_version, response_digests{provider: sha256}})` | NOT `retrieved_at`: re-fetching identical bytes later yields the same id with a different `retrieved_at` | `enrichment/cve.py:183` (`_snapshot_id`) |
| imported snapshot (`correlate --snapshot FILE`) | must equal the recomputed id, `retrieved_at` must parse as ISO 8601 with offset | the digests inside the file are CLAIMED; an attacker can forge a consistent id, so the file stays `unverified` (ACQ-10 fix checks consistency, not authenticity) | `cve.py:175-178`; `tests/test_enrichment_cve.py::test_acq10_*` |
| merged snapshot (`select_latest`) | same recipe over the per-provider chosen digests; `retrieved_at` = OLDEST contributor (conservative) | order of arrival | `cve.py:402-459` |
| CVRF/CSAF/KEV document | `doc_id = domain_id('kbc.source', 1, {kind, sha256 of decompressed bytes})` | URL, retrieval time (a fetched and an imported copy of the same bytes are ONE document) | `kbcorrelation/contracts.py:SourceDoc` |
| CSAF facts | `facts_id` from source sha + `NORMALIZER_VERSION` | retrieval time | `intelligence/csaf/normalize.py` |
| CSAF retrieval | `retrieval_id` per acquisition; many per source sha | - | `intelligence/storage.py:add` |
| KB context row | `context_key = domain_id(..., {inv, base_revision, edge_set_digest, csaf_source_shas, rules_digest, lexicon_digest, kev_snapshot_sha (always None today), older, newer, scope_id})` | KEV: the field exists but is `None` until KBF-06 binds KEV | `kbcorrelation/context.py:86-93` |
| Leads result (`pilot`) | `result_id` over every input digest + config + limits + rules + tiers | clock | `pilot/keys.py` |
| Search index | `index_key = domain_id('search-index', 1, [(group, digest16)...])[:16]` | cache location | `search/build.py:BuildRequest.index_key` |

Invariant I1: an id never depends on wall-clock time, absolute path, thread, locale or argument order. Invariant I2: a record with an unknown newer major is read-only and never downgraded.

## 3. Revision semantics per source

1. CVRF month (`kb index`): a revised month has different bytes -> a new `SourceDoc`; per release month the revision with the newest `current_release_date` (tie: `doc_id`) is ACTIVE; older ones stay in the index, are listed `superseded` and never deleted (`index.py:111-166,299-300`). Coverage has two axes: the document ids, and `watermark_current_release_date` with the fixed sentence "Revised CVEs may sit in earlier documents." (`scope.py:24-25,189-193`).
2. CSAF (`intelligence`): `supersession(facts)` marks a document superseded when a newer revision of the same `tracking_id` exists. `AdvisoryStore.applicability()` resolves OLD/NEW over EVERY stored document, so a newer revision that no longer lists the CVE supersedes the older claims (audit C-03 fix). KNOWN OPEN DEFECT: `intelligence/explain.py:151` still filters to documents that list the CVE (`unique = {... if a.facts.vulnerability(cve) is not None}`) before calling `resolve`, so `intelligence explain` (and `IntelligenceAdvisory.report_for`) can show an older claim as current. Fix specified in section 5.
3. SUG / NVD snapshots: no upstream revision field is stored; a changed body is a new `response_digests` entry and so a new `snapshot_id`; `select_latest` picks, per provider, the newest `retrieved_at` (ties: smallest `snapshot_id`), earlier snapshots are reported as `ignored`, never deleted (`cve-snapshot` rows are never evicted, `storage.py` retention).
4. KEV: each catalog is a snapshot named by its raw SHA-256; a pointer file names the current one; `prune` keeps the snapshot the pointer names even if its description is damaged (INT-1 fix). Drift between two snapshots is `kev diff`.
5. Winbindex record: `<name>@<data_date>.json[.gz]`; the newest data date wins for a name; older files stay on disk.

## 4. Staleness: what is stale, who says so, what the user sees

| Stored thing | Becomes stale when | Mechanism | User text |
|---|---|---|---|
| `kb-context` row | project revision, older/newer sha, run, rules/lexicon digest changes | enrichment `Guard` + fingerprint; link state `stale` requires `stale_reasons` (`contracts.py:498-503`) | KB14 "This context was prepared for a different file pair, analysis run or advisory revision. It is shown for reference; navigation is off." |
| `kb-context` row | a NEWER CVRF/CSAF revision for the same CVE is imported AFTER the attach | NOT DETECTED today (`edge_set_digest` is computed at attach and never re-checked against the workspace); specified in section 6 | proposed: "A newer revision of {document} is loaded (revised {date}). Refresh the context." |
| Leads result | the stored `PilotInputs` differ from `known` in any NAMED field. The Leads dock names only four: `older_sha256`, `newer_sha256`, `ghidriff_run_id`, `raw_sha256` (`ui_leads.known_inputs`). `PilotInputs` also holds `advisory_facts_ids`, `kev_snapshot_id`, `kb_link_digest`, `tool_keys`, `unified_result_id`, `secondary_set_ids`, but the dock does not pass them, so importing or revising an advisory AFTER leads were prepared does not mark the leads stale (by reading `pilot/store.py:284-287`; UNVERIFIED by a running test) | `pilot.store.load` -> `_changed` | L6 "These leads are out of date: {changed}. They are shown for reference only." Proposed in KBB-18: pass `advisory_facts_ids` (and later `kev_snapshot_id`, `kb_link_digest`) in `known_inputs` |
| Search index segment | its group digest changes (inputs pinned in `SourceSpec.inputs`) | per-group `digest16`; unchanged groups are reused | coverage status `stale` / `missing` |
| Derived enrichment cache | any stage input digest or algorithm digest | `tests/…/algorithm_digests.json` | cache miss |

Rule S1: stale data is shown for reference with navigation disabled; it is never silently recomputed in the GUI and never deleted. Rule S2: "no newer revision is loaded" is not "this is the latest revision" - coverage text must say what was checked (KBF-01 coverage words).

## 5. Fix for the explain path (KBB-03)

```
build_report(cve, advisories, older, newer):
    all_unique   = {a.source.sha256: a for a in advisories}          # EVERY stored advisory
    relevant     = sorted([a for a in all_unique.values() if a.facts.vulnerability(cve)], key=_order)
    if not relevant: raise PT-INTEL-NOTFOUND
    applicability = resolve(cve, [a.facts for a in all_unique.values()], older, newer)   # all documents
    superseded_map = supersession([a.facts for a in all_unique.values()])
    current = [a for a in relevant if not superseded_map[a.facts.facts_id]] or relevant
    ...rest unchanged
```
Red test: two documents with one `tracking_id`; r1 lists the CVE as `known_affected` for the product; r2 (newer) omits the CVE. Expected `applicability.older.resolution` is `unknown` with a `superseded` limitation, and `sources[0].superseded is True`. Today the CVE-listing filter hides r2 and yields `affected`.

## 6. Staleness for a later-loaded revision (KBB-03 part 2)

Add (additive, no persisted field changes): `kb explain` and `kb leads` compute `current_edge_set_digest` from the CURRENT workspace index for the context's lead and compare with `bundle.edge_set_digest`; if different the report gets state `stale-advisory` (a new value of the existing free-text `stale_reasons`, not a new enum) and the sentence above. Algorithm:

```
def advisory_drift(bundle, workspace):
    index = load_index(workspace, ports)
    now = edge_set_digest(index.edges_for(bundle.lead, scope_id=bundle.scope_id))   # same function as at attach
    return None if now == bundle.edge_set_digest else StaleReason('advisory-revision', newest_doc_date(index))
```
Cost: one index load (bounded by KbcLimits) on the worker thread; the GUI never calls it directly.

## 7. Cache keys (single table; every derived cache must name these)

parse = `{doc_sha256, dialect, parser_version, alias_catalog_version}`; context = section 2 row; leads = `{context_key, run_id, raw_sha256, ranking_config_digest, unified_result_id, secondary_set_ids}`; search segment = `(group, table_sets, inputs)`; tool evidence = tool version + binary sha + rule pack + options; derived enrichment = stage inputs + algorithm digest. A digest that cannot be computed makes the cache MISS, never a hit.

## 8. Error codes

`PT-KBC-STALE`, `PT-PILOT-STALE`, `PT-TOOL-STALE`, `PT-SEARCH-STALE`, `PT-FAB-STALE`, `PT-ENRICH-STALE` already exist; no new code. `PT-INTEL-NOTFOUND` stays "no stored advisory lists {cve}". Imported-snapshot errors: `PT-ENRICH-INPUT` with the text `snapshot {n} snapshot_id does not match its provider digests` or `snapshot {n} retrieved_at is not ISO 8601 with a timezone` (BUILT, real strings).

## 9. Security and privacy invariants

Imported snapshots and documents are `unverified-local-file`; no consistency check is called verification. No revision is deleted by sync, refresh, prune or retention. No result is recomputed behind the user's back. Revision text (titles, notes) is untrusted.

## 10. Budgets

`select_latest` over 5,000 snapshots in under 1 s; `advisory_drift` over a 60-document index in under 250 ms on the worker; no GUI-thread index load.

## 11. Test plan

New (red first): `tests/test_intel_explain_supersession.py` (section 5); `tests/test_kbc_advisory_drift.py` (import r2 after attach -> `kb explain --json` carries the stale reason; unchanged index -> no reason); `tests/test_enrichment_snapshot_identity.py` (same bytes at two times -> same id; one changed digest -> different id; merged id equals fresh id over identical responses - the docstring promise at `cve.py:403`); existing `test_kbc_*` index revision tests stay green.

## 12. Open questions

Q1 Should `snapshot_id` ever include `retrieved_at`? Default no (additive-only, and identical bytes are identical evidence). Q2 Show the number of loaded revisions in `kb index status`? Default yes (cheap). Q3 Should the Leads dock offer "refresh advisory context" or only point to the KB dock? Default point.

## 13. Acceptance

Sections 5 and 6 tests green; `grep -n "vulnerability(cve) is not None" src/patchtrace/intelligence/explain.py` shows the filter applies only to the `relevant` display list, never to the argument of `resolve`.
