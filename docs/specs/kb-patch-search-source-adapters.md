# SPEC-32A: Microsoft Patch Search Data Sources and Correlation Contracts

Status: expanded developer specification (2026-10-14). Docs-only. Schema/API behavior is a validation gate, not a claim of current live availability.
Parent: docs/specs/kb-patch-search-and-pair-resolution.md.
Scope: KB query -> source document -> exact per-product CVE association, with full evidence lineage. No binary download or Qt code in this module.

## 0. Explicit engineering decisions

- Authoritative association for MVP: a valid MSRC CVRF remediation of KB type 2 scoped to product ID(s) and the enclosing CVE. Retain the CVRF issuer identity, source document ID and revision; unknown ProductID is an error in mapping, not proof.
- The MSRC Security Update Guide REST API accepts CVRF document IDs by month; do not assume it offers a general KB reverse-lookup endpoint. Search either a bounded downloaded CVRF document set or an indexed corpus. An input KB without a configured corpus/date scope returns SEARCH_SCOPE_REQUIRED rather than silently searching one month and calling results exhaustive.
- CSAF 2.0 import is a separate adapter to the SPEC-28 normative parser. It MUST NOT reuse CVRF's integer remediation Type 2 rule: CSAF remediation categories use strings such as vendor_fix. Any association to a numeric KB has to be evidenced by the actual CSAF remediation/reference text/URL and bound to specific products, with a versioned extractor and status "candidate" unless source semantics support "confirmed".
- Data from NVD is allowed as additional CVE context; never an authoritative KB-remediation join solely on publication date.
- Microsoft Update Catalog is not assumed to expose a supported public arbitrary-KB search JSON API. A browser link and source-attributed manually imported package metadata are v1 fallbacks. WUA searches are host/service applicability views, not historical universe-wide KB indexes.
- Source revisions are never silently overwritten. A KB-CVE edge's validity is derived from (snapshot SHA, CVE ID, product ID, remediation pointer, KB).
- Standard used for CSAF: OASIS CSAF 2.0 **OASIS Standard**, not committee-spec draft: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html ; official schema: https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json .
- A source snapshot is "origin-verified" only if its network endpoint was validated against an approved provider with TLS and fetched through the authorized adapter; a local JSON file with a Microsoft field is "locally imported / authenticity not established".

## 1. Provider discovery and transport strategy

### 1.1 Source families

| Adapter ID | Acquisition / import | Unit searched | Known scope limit | MVP |
|---|---|---|---|---|
| msrc-cvrf/1 | Official MSRC API + pinned offline files | One monthly CVRF document, not KB reverse index | Retrieval window; document revisions | yes |
| msrc-csaf/1 | Microsoft-published CSAF directory and local import | Advisory document + product graph | Index discovery and multiple CVEs | offline adapter after SPEC-28 |
| msrc-sug/1 | Existing per-CVE MSRC vulnerability API | Selected CVE ID | CVE context, not KB inversion | reuse |
| nvd-cve/1 | Existing NVD endpoint | Selected CVE ID | Not an authoritative patch package map | reuse |
| winbindex-file/1 | Existing Winbindex filename index | File basename | x64 selection in SPEC-08; no KB->all files query | reuse after filename chosen |
| microsoft-catalog-manual/1 | Browser/manual package selection | Analyst-selected update | Metadata alone not verified until validated | v1 fallback |
| wua-local/1 | Windows Update Agent user-consented local service query | Host-applicable update | OS/service dependent | future opt-in |

### 1.2 Scope contract before network I/O

SearchScope:
- document_ids: explicit, finite validated MSRC CVRF IDs; OR
- release_month_start and release_month_end with upper bounded count (proposed max 24 months, decision configurable); OR
- cached_corpus_id + digest, including offline mode.
- ScopeKind is explicit: selected_months | cached_corpus | provided_files | mixed.
- SearchCompleteness is explicit: COMPLETE_WITHIN_DECLARED_SCOPE / PARTIAL_SOURCE_FAILURE / SCOPE_UNKNOWN / STALE_CACHE / NOT_SEARCHED.
- A negative match is never "no CVEs for this KB" without showing exactly which documents/revisions were searched.
- A provider plan contains exact host, method, URL and estimated requests; implicit fallback to a different host is denied.
- Source network consent is per operation/plan, does not persist silently and may be revoked by cancellation.
- All HTTP parsers use injected clients with explicit content byte/deadline caps, redirect checks and Retry-After; never rely on ambient environment proxies.

Suggested source discovery pseudocode:

    def search(query: KbSearchQuery, scope: SearchScope, provider: AdvisoryProvider):
        ids = select_document_ids(scope)             # pure, bounded, deterministic
        if not ids and scope.kind != "provided_files":
            return SearchOutcome(status="scope_required", inspected=())
        outputs = []
        for doc_id in ids:
            raw = provider.get_snapshot(doc_id)      # explicit consent or local cache
            parsed = validate_and_normalize(raw)     # strict boundary
            outputs.append(index_cvfr_kb(parsed, query.kb))
        return combine_edges_preserving_lineage(outputs, scope)

The example's index_cvfr_kb name should be spelled index_cvrf_kb in actual code.

### 1.3 MSRC API shape validation gate

Reference OpenAPI document:
https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/main/docs/swagger.json
The published contract includes GET /cvrf/{id}, with id identified as yyyy-mmm. It contains further endpoints, but availability, auth requirements and paging must be confirmed with a real opted-in probe before freezing source transports.

DO NOT:
- send guessed /kb/<digits> calls,
- declare a complete history of KB matches after examining only the month's most recent CVRF,
- use a CVE search response's text mention of KB to substitute for a product-bound remediation,
- bundle Microsoft source data or third-party Winbindex indexes without licensing review.

## 2. CVRF parser normalization algorithm

The official PowerShell Get-MsrcCvrfAffectedSoftware function provides the mapping precedent:
https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/main/src/MsrcSecurityUpdates/Public/Get-MsrcCvrfAffectedSoftware.ps1

The official reference filters remediation Type == 2 against the vulnerability's ProductID. Build fixtures from official source responses; the following is **language-neutral pseudocode**, not a byte-accurate sample of all CVRF response dialects.

    products = index_product_tree(source.ProductTree)
    for vi, vuln in enumerate(source.Vulnerability):
        cve_id = validate_cve_id(vuln.CVE)
        statuses = index_statuses(vuln.ProductStatuses)
        for ri, rem in enumerate(vuln.Remediations):
            if normalize_remediation_type(rem.Type) != KB_ARTICLE_TYPE_2:
                continue
            kb = extract_kb_exactly(rem.Description.Value)
            if kb is None:
                record_unparsed_remediation(vi, ri)
                continue
            for product_id in validated_product_ids(rem.ProductID):
                if product_id not in products:
                    add_mapping_problem("UNKNOWN_PRODUCT_ID", vi, ri, product_id)
                    continue
                # Verify this product belongs to the vulnerability context where
                # the published dialect constrains vulnerability applicability.
                relationship = reconcile_product_status(
                    product_id=product_id, statuses=statuses, remediation=rem
                )
                emit_edge(
                    kb=kb, cve=cve_id, product_id=product_id,
                    association=relationship.association,
                    source_pointer=f"/Vulnerability/{vi}/Remediations/{ri}",
                    product_pointer=products[product_id].pointer,
                    remediation_url=rem.URL if valid_reference(rem.URL) else None
                )

Hard requirements:
1. Convert upstream product IDs to canonical strings, preserving the original typed representation and upstream ID. Never match product by display name only.
2. A single Type-2 remediation may list multiple ProductID values. Generate separate records for each, with one shared source lineage.
3. Parse KB IDs from exact supported forms (e.g., KB1234567 or a bare numeric article value if the field is demonstrably the KB-article field), not arbitrary digits extracted from prose, URL query strings, version numbers or CVE numbers.
4. Preserve the raw remediation description and pointer. When the published field differs in a current API revision, adapt at the edge, never silently skip an unfamiliar structure.
5. The original CVRF source may have ProductStatuses status groups with numeric Type values and product member lists. Validate the dialect with real snapshots. A remediation mapping alone can support a "KB remediation for this product" fact, but positive/negative product vulnerability status must be surfaced separately.
6. If CVE is absent, malformed or duplicated ambiguously, do not create a confirmed edge. Record validation diagnostics, retain untouched good records and mark a partial source.
7. A product ID in a remediation but not in the ProductTree is not a wildcard; keep the unresolved raw record and mark mapping invalid.
8. Article 'KB' may represent more than one actual update package; this parser must not assign update architecture, update ID, file list or package URL without independent evidence.
9. Document release/update timestamps are not substitute fields for the KB's package release time.
10. Unknown or conflicting statuses never coerce into "known affected".

### 2.1 Golden fixture schema (illustrative test-owned adapter input)

    {
      "DocumentTitle": {"Value": "synthetic document"},
      "ProductTree": {"FullProductName": [
        {"ProductID": "P-CLIENT", "Value": "Fixture Client x64"},
        {"ProductID": "P-SERVER", "Value": "Fixture Server x64"}
      ]},
      "Vulnerability": [
        {
          "CVE": "CVE-2024-12345",
          "ProductStatuses": [{"Type": 1, "ProductID": ["P-CLIENT"]}],
          "Remediations": [
            {"Type": 2, "ProductID": ["P-CLIENT"],
             "Description": {"Value": "5012345"}, "URL": "https://example.invalid/kb"},
            {"Type": 2, "ProductID": ["P-SERVER"],
             "Description": {"Value": "5012346"}, "URL": "https://example.invalid/kb2"}
          ]
        }
      ]
    }

This is intentionally SYNTHETIC. Do not claim the status Type values demonstrate real MSRC values; confirm all literal enums against pinned real API fixtures. A parser can normalize varying field casing/nesting only if it has a precise tested dialect version. The cross-product edge above should be flagged for status review if the status set covers P-CLIENT only.

### 2.2 Product-specific remediation edge invariant

For every confirmed KbCveEdge:
- its advisory_snapshot_id exists and raw digest verifies,
- exact source vulnerability contains its CVE ID,
- exact remediation record has KB type 2 and normalized KB value,
- exact remediation product list contains product_id,
- product_id exists in that document's product index,
- contradictory explicitly negative vulnerability status is not hidden,
- the edge is not inferred from neighboring remediations, CVEs, products or bulletin timestamps.

Edge key:
  domain_id("kb-cve-product-edge", 1, [source_snapshot_sha, cve_id, product_id, remediation_pointer, kb])

Two occurrences from one monthly record may be deduplicated for display, but *never* stripped of separate remediation source references.

## 3. CSAF adapter, product groups, and VEX

SPEC-28 owns the actual CSAF schema validation and normalization. The patch-search adapter receives normalized CSAF claims with:
- document identity, tracking ID, revision, publisher and SHA-256;
- product_tree concrete product IDs, version ranges, nested branches and graph relationships;
- product_groups resolved to their member IDs (must reject unknown and cyclic relationships);
- each vulnerability's CVE, product_status, remediations (category, details, product_ids, group_ids, URL), references and JSON pointers;
- explicit VEX known_not_affected vs known_affected vs fixed/first_fixed vs unknown.

Mapping rule: remediation vendor_fix category is NOT necessarily a KB article. Only derive a KB association when there is a verified exact KB identifier in relevant structured source content (typically vendor_fix details/url/reference), the product/group relation is resolvable, and the adapter records method and limitation. Name-based/date-based association remains "proposed" not confirmed.

Cross-revision conflicts:
- retain every immutable snapshot with revision/tracking timestamp;
- select a UI-preferred current source using explicit revision ordering but do not destroy alternate claims;
- if an older version says known_affected and newer says fixed, show timeline, not arbitrary "conflict";
- if two current overlapping records disagree about known_not_affected, mark product-vulnerability status disputed;
- preserve the provenance of group expansion.
- CSAF validation must use OASIS Standard profile rules and official JSON schema; do not treat a generic valid JSON document as a validated CSAF advisory.

## 4. Merge and search result semantics

Do not collapse "official Microsoft source" and "Winbindex source" into a single trust score. Define:
- SourceOrigin: provider_allowlisted_tls | locally_imported | third_party_index | analyst;
- SourceIntegrity: digest_verified | digest_mismatch | unavailable;
- AssociationBasis: cvrf_type2_product | csaf_explicit_kb_product | csaf_textual_hint | manual | date_only;
- AssociationStatus: confirmed | proposed | conflicting | rejected | unknown;
- SearchCoverage: complete_in_scope | partial_in_scope | stale_cache | unknown_scope.

For "confirmed", both a well-formed source assertion AND correct product linkage are required; the word confirmed means "advisory association confirmed", not "vulnerability fixed" or "file modified".

Example result:
  KB5012345 selected, product=P-CLIENT,
  CVE-2024-12345 => confirmed KB remediation association (one CVRF record),
  filename => unknown,
  fixed binary => unknown,
  current source coverage => complete within selected month range only.

If no matched edges:
- NO_ASSOCIATIONS_IN_SCOPE if sources successfully scanned and scope declared;
- SOURCE_UNAVAILABLE if no sources were obtainable;
- PARTIAL_ASSOCIATIONS_IN_SCOPE if some scanned and others failed;
- SCOPE_REQUIRED if user did not choose dataset/time span;
- AMBIGUOUS_PRODUCT when edges exist but product is not selected.

Never say "no CVEs associated with KB" without the scoped qualifier.

## 5. Caching, transport, and failure details

### 5.1 Source transport port

    @dataclass(frozen=True)
    class HttpFetchPlan:
        provider_id: str
        method: Literal["GET"]
        url: str
        requested_document_id: str
        max_response_bytes: int
        max_redirects: int
        deadline_seconds: float

    class SourceFetcher(Protocol):
        def execute(self, plan: HttpFetchPlan, consent: ConsentToken,
                    cancel: CancellationToken) -> SourceFetchOutcome: ...

Verified origins are provider-specific. Do not use a global regex like *.microsoft.com. If a request redirects outside its approved providers, require an explicit supported redirect policy, never trust an arbitrary 302. Record immutable final nonsecret source URI, not transient auth/SAS query strings. Retry bounds independent of huge scope.

### 5.2 Source blob handling

- Capture bytes (bounded) -> SHA256 -> strict duplicate-key rejecting JSON -> schema/dialect validation -> normalized snapshot.
- Store raw source bytes under private SHA-keyed objects, stage+atomic replace only after digest validation. Never replace last-good on parsing failure.
- Canonical normalization cannot silently reinterpret booleans as integer Type values.
- Negative cache entries have an expiry; no-result must not persist forever across new monthly advisories.
- Cache refresh must never silently connect to Internet; UI/CLI explicitly says which sources will be contacted.
- Offline results can show last retrieved UTC and stale status; freshness threshold is a user-visible policy, not source credibility.
- Never put API keys in exported source refs or stored request URLs.
- Limit decompression, JSON nesting, URL text length, number of CVEs, product nodes, KB references and total per-run items. Refuse massive input with typed RESOURCE_LIMIT failure, not process exhaustion.

## 6. Required source test suite

S01: One KB matches CVE A in product P1 but not P2.
S02: CVE A maps to different KBs per product; do not cross-join.
S03: Same month unrelated CVE B is excluded.
S04: KB remediation references multiple product IDs; produce multiple edges retaining one source.
S05: Duplicate KB remediation entries preserve separate pointers while display deduplicates.
S06: Invalid/unknown ProductID does not produce confirmed edge.
S07: CVRF Type 5 Known Issue does not count as KB patch.
S08: Product negative status contradicting remediation is surfaced for review.
S09: Type 2 description contains unrelated number, not a valid KB => reject.
S10: One document 404, others successful => partial-in-scope, never "no CVEs".
S11: API fields move or format changes => adapter version rejects unknown dialect explicitly.
S12: CSAF vendor_fix with no KB => no KB association.
S13: CSAF group expands correctly; unknown group/cycle rejected.
S14: CSAF VEX known_not_affected disallows an affected assertion.
S15: Same CVE+product across revisions retains both source snapshots and UI timeline.
S16: Locally forged "Microsoft" JSON does not become verified-origin.
S17: Offline search has no DNS/network calls even if cache missing.
S18: Negative result includes searched document IDs and last retrieved date.
S19: Malicious source string is rendered plain and not used to construct a URL.
S20: Golden official fixture from captured opt-in response matches expected exact pointer and product scope.

## 7. Research and validation checklist

Pin and preserve:
- Official MSRC OpenAPI revision/hash and actual /cvrf/{id} response dialect.
- Reference PowerShell remediation traversal against fixture corpus.
- OASIS CSAF 2.0 Standard schema and product graph validation rules.
- Provider content licensing / cache retention and required notices.
- Provider response headers/rate limitations, documented retry rules, redirects and max sizes.
- Live URL behavior must be measured before claiming production adapter support.
- Test fixture documents must be scrubbed of transient tokens and carry SHA256+retrieval UTC.
