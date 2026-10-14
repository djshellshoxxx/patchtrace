# SPEC-31-B: MSRC Sources, KB Reverse Index, Coverage and Product-Scoped Remediation

Status: developer-ready sub-specification; provider implementation/research required. Parent: [SPEC-31](../kb-cve-correlation-and-acquisition.md). Depends on SPEC-31-A. Owner: metadata source worker. No project mutation, Qt or binary acquisition.

## B1. Verified source entrypoints and deferred assumptions

Repository already supports per-CVE SUG requests using https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{CVE} and NVD CVE API 2.0 through enrichment.intelligence. Reuse those exact contracts and session-only consent. Microsoft's public MSRC Security Updates API example module documents Get-MsrcSecurityUpdate and Get-MsrcCvrfDocument / monthly releases, not a verified universal public KB->CVE query endpoint. Its published Get-MsrcCvrfAffectedSoftware and KBArticle examples establish a document-oriented extraction strategy. Live availability/schema of individual endpoints MUST be probed and recorded against real captures before enabling any new network route.

CSAF provider URL discovery uses the publisher's well-known provider metadata and official index/rollup service only after validating the discovery chain and profile; no guessed filenames. CSAF is optional until SPEC-28 implemented. Never infer that SUG, CVRF and CSAF are independent confirmations; group by common MSRC advisory/release revision.

Sources are divided:
1. MSRC per-CVE: authoritative for the record's stated remediation/products, if explicitly present; CVE-first.
2. Official release/CVRF feed: creates a bounded searchable index of contained vulnerabilities/remediation rows; KB-first reverse query after indexed coverage.
3. CSAF: product status/remediation and revised advisory context; use validated import first, fetched provider later.
4. NVD: vulnerability/CWE corroboration, not automatic Microsoft KB evidence.
5. Winbindex: candidate file metadata, never adds CVE facts.
6. Official KB support article: product/build and supplemental stated facts; no automated HTML extraction in first release.

## B2. Discovery and sync plan: no invented API

Define SourceDiscoverySnapshot {index_uri, retrieved_at, source_kind, raw_sha, discovered_document_ids, covered_date_start/end, pagination_complete, errors}. The user must specify a date window or accept last 24 months; max span 60 months per request. Never claim a complete index of all historical KBs. For KB search, first query locally accumulated remediation links; if coverage insufficient, present exactly which months/documents could be fetched, sizes if known, hosts/URLs, and estimated document count, then request consent for the enumerated operations.

Use a two-stage sync:
- Stage 1: fetch and validate official release identifiers from a documented updates/release index (or load a signed/locally provided index); persist pending IDs and release metadata.
- Stage 2: fetch a bounded page/batch of release documents with cancellation and per-document size/time limits; normalize to edges; atomic checkpoint each completed document and record failed IDs.
Resume by skipping exact {URI,ETag or raw digest, parser version} snapshots. Conditional GET is allowed only when HTTP metadata is present and well formed; 304 means reuse the verified cache, not source revalidation. Any change creates a new immutable revision. Cursor is a pure key {window, ordered_release_id, source_version} and can be resumed after crash.

For one KB, searching the reverse index is constant work relative to advisory corpus using SQLite indexed fields; do not fan out into all CVE requests blindly. When only per-CVE API is configured, an uncached KB query reports 'index unavailable/insufficient coverage', not zero results. Never manufacture a KB GET endpoint.

## B3. Parsing pipelines and edge policy

Network boundaries use existing HTTPS allowlist, exact template and per-operation consent. Strict JSON: duplicate object keys rejected, non-finite numbers rejected, UTF-8 decoded only, size/depth/item count limited, clock metadata validated, unknown required schema versions rejected. Keep raw compressed representation separately from decoded SHA when appropriate. Reject zip bombs, pointer collisions and unexpected remediation shapes with a typed partial/error, not silent fallback.

Normalize a claimed remediation only when all necessary facts occur in the same vulnerability/product scoped record:
- CVE ID validated and present in vulnerability node;
- KB article or remediation reference is structurally linked to that CVE;
- product(s) in remediation resolve through the current document product tree/product groups to concrete ids;
- remediation kind is a vendor fix or explicitly documented security update, not generic mitigation/workaround;
- evidence locator points at exact structured record;
- revised/vex product 'not affected' conflicts stay flagged as current contradiction, never overwritten.

Separate relation outputs: vendor-remediation, vendor-association, mention-only, package-contains, analyst-asserted, disputed. Text grep matching digits is never a verified remediation. A product group with several architectures must expand into per-product rows without erasing distinctions. If a remediation names 'All Windows' with no resolvable product identity, keep a group-scoped claim and mark applicability unknown; no fabricated product rows.

Example synthetic normalized claim:

~~~json
{
  "kb": "KB5000001",
  "cve": "CVE-2099-10001",
  "product_scope_id": "synthetic-client-amd64",
  "semantics": "vendor-remediation",
  "document_id": "sug-fixture-sha",
  "pointer": "/vulnerabilities/0/remediations/2",
  "source_release_id": "2099-Feb",
  "status": "resolved",
  "coverage_id": "coverage-fixture-id"
}
~~~

CVE count is counted per distinct canonical CVE and product row, while records from different months/revisions remain separately visible. Do not collapse a KB mentioned by a revision into a new vendor-remediation edge without checking the kind.

## B4. Source conflict and update semantics

Advisory revision ordering is defined by provider tracking revision sequence and issued/updated fields when available; raw retrieval timestamp is NOT a substitute for advisory revision. Handle revocation: latest vendor revision may withdraw or narrow earlier product applicability; mark affected earlier links 'superseded' and retain source snapshot.

Conflicts requiring review: same product ID mapped to incompatible releases; latest revisions with differing fixed build; vendor-remediation in one source and current known-not-affected in another; unparseable product groups; mismatched KB/article link type. Do not simply majority-vote three MSRC representations. Preserve source-lineage-group and conflict description.

Absence cases:
- known-no-links: only when all required source release documents in declared window fetched, parsed and indexed; label "No KB/CVE link observed in scanned scope" even then.
- index-partial: missing/rejected releases or active rate limit.
- provider-unavailable: network or schema unsupported.
- no-per-CVE-remediation: CVE exists but source did not explicitly include KB.
- not-observed: applicable when no source confirms a link, never a global negative assertion.

## B5. Reverse index SQLite materialization

Tables (cache-level, separate from project):
source_documents(doc_id PK, source_kind, uri, raw_sha, fetch_ts, schema_ver, parser_ver, revision, artifact_path, validation_state)
source_segments(segment_id PK, source_id, window_start, window_end, completed_at, release_count, processed_count, failure_count, resumable_cursor, query_digest)
products(product_scope_id PK, full canonical JSON, source_doc_id)
remediation_edges(edge_id PK, kb, cve, scope_id, semantics, source_doc_id, source_pointer, revision, release_id, release_ts)
edge_conflicts(edge_id, conflict_id, code, details)
Each raw source and normalized row immutable. Use a separate active-view table or query to select current vendor revision by source lineage; NEVER delete historical facts while representing latest state. Unique constraint on exact evidence identity and index on (kb,scope_id,cve), (cve,scope_id,kb), (source_doc_id,source_pointer), (release_id,revision). SQLite migrations are single-writer, explicitly versioned with backup. Source snapshots may be cached outside project as planned in 31-A.

## B6. Pure algorithm and complexity gates

~~~python
def reverse_lookup(kb, indexed_edges, coverage):
    claims = [e for e in indexed_edges if e.kb == kb]
    claims = resolve_current_vendor_revisions(claims)
    # Never convert a partial search's empty list to "KB has no CVEs".
    return LookupResult(edges=sorted(claims, key=stable_key),
                        coverage=coverage, status=derive_status(claims, coverage))
~~~

Bound parsing to 16 MiB per per-CVE body unless existing adapter cap is smaller (existing MSRC/NVD enrichment cap 4 MiB and remains unchanged); large monthly release bodies use a separate 64 MiB maximum pending verified fixture benchmarking. Maximum 600 vendor documents per initiated scan, max two concurrent metadata requests, response/body limit enforced while streaming, parser normalized object count cap 250k, recursion/depth cap 64, 30s individual request deadline and 15 minute single-scan budget; these are provisional budgets that require performance fixtures. Rate limiting/retry defaults must not weaken existing enrichment safeguards.

## B7. Acceptance examples and tests

Positive: same KB repairs two CVEs for product A, one of them repairs product B via a different KB. Query KB returns only linked product rows. Same product revision has duplicate exact source rows -> dedupe once; two vendor revisions -> retain both, newest active.

Negative: KB appears in advisory unrelated text only -> mention-only; NVD matching product CPE -> no KB edge; missing group identity -> unresolved scope; one monthly CVRF download fails -> partial coverage; unparseable month -> partial coverage; conflict across revs -> disputed; 304 with missing cached bytes -> error; provider 404 -> source missing, not an empty complete index; cancellation mid-window -> resumable cursor, no false completeness.

Offline replay: exact raw source snapshots and parser pins produce identical edge IDs/order and source pointers; verify no network module is invoked. Domain tests block PySide6 and urllib imports. Integration runs with recorded public official samples but CI does not depend on live vendor endpoints.

## B8. Research and handoff evidence

Before implementation: record MSRC endpoints discovered (URL/path, schema version, update method and date), at least one CVE with structured KB remediation, one multi-product example, one withdrawn/revised advisory, one large monthly document, and an explicit negative/unavailable case. Store trimmed licensed-safe fixture shapes without claiming full vendor coverage. Sources: https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API , https://msrc.microsoft.com/csaf , https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html .
