# Advisory revisions, snapshot identity, staleness and cache keys (KBF-03)

Status: draft, developer-ready design; s5.1 and s5.2 BUILT 2026-11-04. Date: 2026-10-15. Base commit: `54fd085`. Proposed alias: KBF-03. Owner packages: `enrichment/{cve,contracts,storage}.py`, `intelligence/{storage,explain}.py`, `intelligence/csaf/applicability.py`, `kbcorrelation/{index,context,leads}.py`, `kev/store.py`. Reads with KBF-01, KBF-02, SPEC-07 s8, SPEC-35 section I, KB plan s7.4.

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
| KB context row | `context_key = domain_id(..., {inv, base_revision, edge_set_digest, csaf_source_shas, rules_digest, lexicon_digest, kev_snapshot_sha (always None today), older, newer, scope_id[, csaf_applicability]})` | KEV: the field exists but is `None` until KBF-06 binds KEV; `csaf_applicability` is present only when a CSAF claim reached a card (s5.2) | `kbcorrelation/context.py:context_key` |
| Leads result (`pilot`) | `result_id` over every input digest + config + limits + rules + tiers | clock | `pilot/keys.py` |
| Search index | `index_key = domain_id('search-index', 1, [(group, digest16)...])[:16]` | cache location | `search/build.py:BuildRequest.index_key` |

Invariant I1: an id never depends on wall-clock time, absolute path, thread, locale or argument order. Invariant I2: a record with an unknown newer major is read-only and never downgraded.

## 3. Revision semantics per source

1. CVRF month (`kb index`): a revised month has different bytes -> a new `SourceDoc`; per release month the revision with the newest `current_release_date` (tie: `doc_id`) is ACTIVE; older ones stay in the index, are listed `superseded` and never deleted (`index.py:111-166,299-300`). Coverage has two axes: the document ids, and `watermark_current_release_date` with the fixed sentence "Revised CVEs may sit in earlier documents." (`scope.py:24-25,189-193`).
2. CSAF (`intelligence`): `supersession(facts)` marks a document superseded when a newer revision of the same `tracking_id` exists. `AdvisoryStore.applicability()` resolves OLD/NEW over EVERY stored document, so a newer revision that no longer lists the CVE supersedes the older claims (audit C-03 fix). KNOWN OPEN DEFECT: `intelligence/explain.py:151` still filters to documents that list the CVE (`unique = {... if a.facts.vulnerability(cve) is not None}`) before calling `resolve`, so `intelligence explain` (and `IntelligenceAdvisory.report_for`) can show an older claim as current. Fix specified in section 5. (2026-11-04: `report_for` is built over every document it is given, section 5.1.)
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

### 5.1 `IntelligenceAdvisory.report_for` (KB context adapter; BUILT 2026-11-04, slice kbc-report-for)

`AdvisoryPort.report_for(cve, facts, older_sha256, newer_sha256)` restates CSAF applicability for the two files of a KB context. It is pure over its arguments (no store read, no network) and bound in `kbcorrelation/wiring.py`. `build_bundle` uses it to fill `CveCard.applicability` (s5.2).

Input: `facts` is EVERY loaded CSAF document as `AdvisoryFacts` JSON (the `parse_csaf` output), not only those that list the CVE, so a newer revision that dropped the CVE supersedes the older claims (section 5). Each mapping is validated strictly (`PT-KBC-SOURCE` when it is not `AdvisoryFacts`); the same facts given twice count once; two different facts for one `source_id` are `PT-KBC-SOURCE`; a malformed CVE id is `PT-KBC-INPUT`. The SHA-256 values are recorded identities (`facts_state = record-only`): an advisory file-hash match is a `candidate` mapping, never `verified`.

Output: a JSON object with `contract = "kbc-csaf-applicability/1"`.

| field | meaning | provenance |
|---|---|---|
| `cve`, `older_sha256`, `newer_sha256` | the question | caller |
| `assessment` | `advisory-claim` when at least one side restates a vendor status, else `unknown` | the `applicability` sides |
| `applicability` | the `intelligence/1` `ApplicabilityReport` of `resolve` over every document; `null` when no document lists the CVE or a SHA-256 is missing | every mapping names `source_id`, `basis`, `detail`; every status names `source_id`, `tracking_id`, `revision`, JSON `pointer`, `superseded` |
| `sources` | every document that lists the CVE, plus the current revisions that dropped it: `source_id, facts_id, tracking_id, revision, current_release_date, document_category, lists_cve, superseded`, sorted by `source_id` | content address; every `source_id` used elsewhere in the object is listed here |
| `withdrawn` | per `(publisher_namespace, tracking_id)` whose current revisions no longer list the CVE: `listed_in` and `current` source ids | `sources` |
| `unknowns`, `limitations` | fixed sentences naming at most the CVE id and a side; the `intelligence` limitations follow when `applicability` is present | - |

Rules: R1 unknown stays unknown: no listing document, a missing SHA-256 or an unmapped side is `unknown`, never `not_affected` or `fixed`, and never a negative vote. R2 a superseded revision is listed with `superseded: true` and its statuses are marked superseded; a withdrawn entry appears in `withdrawn` and its side resolves `unknown`, never as still affected. R3 no field names a function, RVA or match; a fixed limitation says applicability does not show that a changed function addresses the CVE. R4 the object depends only on the input set (order and repetition of `facts` do not change it). Tests: `tests/test_kbc_report_for.py`.

### 5.2 Use in `build_bundle` (BUILT 2026-11-04, slice D-kb-1-kbc-applicability)

Caller: `KbService._bundle`, shared by `kb import-pair` (attach) and `kb attach --repair` (`_rebuilt_rows`), so an attach and its repair write the same bytes. It parses every CSAF document of the loaded KB index once (`parse_csaf` over the stored bytes, including superseded revisions and documents of other products) and calls `report_for(cve, facts, older_sha, newer_sha)` for each CVE of the lead that fits the card `CveId` (at most 24 characters); with no CSAF document loaded, or no such CVE, it calls nothing. A longer `kb-syntax/1` CVE (up to 19 digits) can have no card, so it gets no report and the attach completes as it did before s5.2. `build_bundle` receives the results as a plain `applicability: Mapping[cve, report]` and imports no `intelligence` behaviour.

| report | `CveCard.applicability` | context unknowns |
|---|---|---|
| absent, or `applicability` null (no loaded document lists the CVE, a SHA-256 is missing) | `APPLICABILITY`, exactly as before (R1) | unchanged |
| `applicability` present | `{assessment}: older file {older.resolution}, newer file {newer.resolution}; any file-hash mapping is a candidate, not verified; restated from CSAF {sources}` through `clean_text(..., 1000)`, with `{assessment}` and each resolution cut to 40 characters and `{sources}` to 600, so the fixed qualifier ends within the first 200 characters and survives the 500-character Leads applicability chip; `{sources}` is the sorted, de-duplicated `{tracking_id} revision {revision}` of the report's `sources`, with ` (superseded)` after a superseded one | each report unknown once, as `{cve} (CSAF): {unknown}` through `clean_text(..., 1000)` |

A withdrawn CVE therefore reads `unknown: older file unknown, newer file unknown; any file-hash mapping is a candidate, not verified; restated from CSAF ... revision 1 (superseded), ... revision 2` with the withdrawn sentence among the unknowns, never `affected` (R2). The text names no function, RVA or match (R3); the bundle limitation already says so.

Key rule: `context_key` adds `csaf_applicability = domain_id('kbc.csaf-applicability', 1, {cve: report})` over the reports that reached a card, and only when at least one did. Every bundle without a CSAF claim (CVRF only, no CSAF loaded, an unlisted CVE, a missing SHA-256) keeps its key and its bytes (pinned in the tests). `CONTEXT_KEY_VERSION` stays 3: no existing payload changes, and a payload with the field cannot equal one without it. A report for a CVE that has no card does not change the key (R4 holds for the bundle too).

Not changed: no persisted field (the `CveCard.applicability` field exists; it is not in `card_provenance.FIELDS`, so no field reference is added), no schema, the Leads applicability chip state stays `unknown` (only its text changes), and the CSAF documents used here are not added to `ContextBundle.sources`. Tests: `tests/test_kbc_context_applicability.py`.

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
