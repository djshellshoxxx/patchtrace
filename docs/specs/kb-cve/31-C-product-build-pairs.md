# SPEC-31-C: Product/Build Lineage, Supersedence and Pair Resolution

Status: developer-ready deterministic design; implementation pending. Parent [SPEC-31](../kb-cve-correlation-and-acquisition.md). Requires 31-A; consumes 31-B and existing Winbindex BuildCandidate. No I/O, Qt, network.

## C1. The product key is multi-dimensional

A Microsoft KB number is not a unique product/build/file tuple. Require distinct normalized dimensions: publisher product id (if available), OS family (client/server), release (e.g. 24H2), architecture, channel (GA/preview/Insider/LTSC), edition/locale/optional component where material, and full build+UBR. Normalize aliases through curated versioned mapping tables with source/effective dates. A descriptive string match is only a candidate and must not set mapping=verified. Full dotted builds compare as parsed integer tuples ONLY within an already verified Windows build family. FileVersion is NOT proof of Windows build; PE timestamps and update KB numbers are not chronology.

Define ProductScopeRef as (ProductScopeId, verification_state, evidence_ids, conflict_ids). User selections persist an assertion (may lower ambiguity) but do not change vendor verification status. A file present across Windows client/server with identical SHA may be reused as the *same bytes*, not evidence the Windows products are equivalent.

Known Windows client generations must remain distinct even when release labels coincide (Windows 10 22H2 and Windows 11 22H2). Their scope identity uses `kbc.scope` version 2 with the derived `winbindex_key` (`10-22H2` versus `11-22H2`) alongside the existing dimensions. Scopes without a known client key retain the version 1 formula. This is an identity correction, not a claim of verified product mapping.

Compatibility: immutable stored contexts, pair records, decisions and investigation history retain their original identifiers; a legacy scope ID must never be guessed or rebound to one of the new generations. The reverse index is rebuilt from retained raw advisory bytes. An investigation whose selected product is absent from that rebuilt index must refuse index pairing with an explicit instruction to repeat the search and select the product again. Existing context exports remain historical records. The persisted SQL edge dictionaries remain historical ingestion data; current correlation uses the reparsed reverse index. No destructive migration or implicit historical-context rewrite occurs.

## C2. Partial-order update graph

Represent product-specific release instances, not global KB nodes:
- UpdateNode: release_instance_id, kb, product_scope_id, full_os_build?, published_at?, category (security/preview/feature/checkpoint/out-of-band), source_ids.
- Edge: before|supersedes|requires-checkpoint|replaces|included-in, origin and semantic strength.
- BuildNode: OS build+UBR with release/arch channel and official date/version evidence.
- ContentObservation: file SHA first/last observed in a source-backed build and package identity where available.

Only insert graph edge from explicit vendor metadata or reliably parsed same-lineage build chronology, with reason code. A directed edge does not imply a binary was changed. Missing edge = unknown ordering, not no relationship. Topological sort must detect cycles and contradictory source claims; on cycle mark component unavailable for automatic pair orientation and expose affected IDs.

Checkpoint updates: Windows 11 24H2+ and Server 2025+ may need preceding checkpoints for manually acquired Catalog MSUs. This is a prerequisite DAG, not merely previous KB numeric sequence. Source update graph edges must preserve whether a node is dependency for package reconstruction vs chronology for interpretation; do not convert needs-checkpoint into 'fix introduced here'. Windows Update/WSUS workflows can handle checkpoint content automatically, but offline package extraction/reconstruction must account for exact prerequisites.

## C3. Candidate filtering versus ranking

Phase 1 hard filters for AUTO_VERIFIED pairs:
- same normalized basename and supported PE AMD64 machine 0x8664;
- SHA known, distinct, correct full-final-PE bytes;
- both candidates in exactly the same verified ProductScope lineage or a declared compatible branch mapping corroborated by official release/build evidence;
- two verifiable source-backed build nodes with older strictly before newer;
- newer association with selected target product/update, or explicit analyst-selected wider window with a label;
- no product/build/arch conflict, revision conflict or pending authenticity verification required by local policy.

Failing a hard filter emits reason codes instead of dropping row. USER_ASSERTED is allowed as separate lower-assurance mode for offline investigations: record full reason and never call it AUTO_VERIFIED. No auto-pick with more than one equally valid top pair. A SHA match against Winbindex record is a metadata consistency check only.

Phase 2 stable preference tuple for compatible candidates:
1. directly bracket target patch release with no known intervening updates;
2. source-backed narrower build window;
3. verified per-product package or build mapping;
4. complete SHA metadata;
5. local verified bytes, then direct-download, then delta, then package, then unavailable;
6. deterministic stable IDs as final sort.

This ordering must not be exposed as a vulnerability probability. If a newer version is shared across multiple KBs, attribution window is ambiguous even if the pair is otherwise compatible.

## C4. Formal interval algorithm

Target update T on the selected product lineage; let valid old/new build observations o,n have o < n. Seek the nearest verified predecessor o to T and earliest verified new build n at/after T with no known intermediate security or preview updates. A cumulative update may include other fixes even at one step: indicate multi-CVE-confounded. If any build branch changes across T, do not treat it as an adjacent pair. Unknown intervening releases result in coverage_unknown=true and do not qualify the label 'isolates target update'.

~~~python
def classify_pair(target, older, newer, graph):
    reasons = []
    if older.sha == newer.sha: return NoChangeForFile(...)
    if older.basename != newer.basename: reasons.append("DIFFERENT_FILE")
    if not same_supported_arch(older, newer): reasons.append("ARCH_MISMATCH")
    relation = graph.compare_builds(older.build_node, newer.build_node)
    if relation in ("unknown","cycle","incomparable"):
        reasons.append("CHRONOLOGY_UNVERIFIED")
    if relation != "older_before_newer":
        reasons.append("ORIENTATION_INVALID")
    scope = compare_product_scope(older, newer, graph.alias_rules)
    if scope != "verified-same-lineage":
        reasons.append("PRODUCT_LINEAGE_UNVERIFIED")
    window = graph.enumerate_known_updates(older.build_node, newer.build_node)
    unknown_coverage = not graph.coverage_complete_for_window(window)
    return PairProposal(
        eligibility=auto_verified_if_no_blockers(reasons),
        intervening_updates=window.without_target(target),
        multi_fix_possible=True,
        unknown_coverage=unknown_coverage,
        reason_codes=tuple(reasons)
    )
~~~

A valid 'no change for file' assessment may use an equal-hash pair for metadata inspection but cannot be sent to the modified-function correlation engine. A pair from before and after many cumulative updates remains eligible for manual analysis with 'wide-window' warning. Metadata missing on either side returns needs_older or needs_newer; it is not evidence of absence of a security fix.

## C5. Identity fusion: evidence examples

Synthetic:
- KB5000001 fixes CVE-2099-10001 on Client/Release A/build 26000.101; Server/Release B has a different KB. Candidate driver from Client build 26000.100 and 26000.101 => compatible after verified package/source lineages.
- Same basename+FileVersion on Client and Server, different SHA => product mismatch, do not auto-select.
- Client 26000.100 -> 26000.107 with known intermediary builds 101 and 105 => 2+ confounders; show each source and offer SPEC-09 version series.
- Filename appears in KB manifest but hash unchanged => zero observed change for that file, do not infer all CVE remediations absent.
- PE timestamp decreases on the newer package because of reproducible builds => chronology still based on product/build graph.
- Two identical newer hashes appear in distinct subsequent LCUs => first observed no later than earliest source-backed build, not proof it was introduced there.
- Unknown UBR or package identity => pair unresolved unless analyst explicitly asserts, recorded as low-assurance.

## C6. Implementable interfaces

~~~python
class ProductResolver(Protocol):
    def resolve(self, raw_product_claims: tuple[RawProductClaim,...],
                catalog: ProductAliasCatalog) -> tuple[ProductScopeRef,...]: ...
class UpdateGraph(Protocol):
    def compare_builds(self, a: BuildRef, b: BuildRef) -> BuildRelation: ...
    def window(self, a: BuildRef, b: BuildRef) -> UpdateWindow: ...
class PairResolver(Protocol):
    def resolve(self, *, target: RemediationLink,
                candidates: tuple[BinaryCandidate,...],
                graph: UpdateGraphSnapshot,
                policy: PairPolicy) -> PairResolution: ...
~~~

PairResolution contains proposals + rejected proposals + status + ambiguity counts + missing evidence + stable explanation paths, never silently discards candidates. Accept cancellation only at orchestration boundary; pure calculations deterministic. Bound graph size (100k nodes, 500k edges per indexed coverage), cycle detection O(V+E), pairing via indexed filename/product buckets and at most 1000 enumerated pairs with truncation flagged. Never hide truncation.

## C7. Acceptance and golden tests

- Same KB across client/server/arm64: produce separate scopes, only amd64 supported for binary comparison.
- Decimal component build parsing: .9 is before .10; unparseable parts remain unknown.
- Cross branch same file version: rejected; exact-sha same cross scope: byte identity but product equivalence unknown.
- Cyclic supersedence: auto-selection blocked; stable conflict diagnostics.
- Checkpoint requires two prior packages: dependency plan includes both in DAG order; chronological interpretation does not claim either contained target fix.
- Equal hashes: no-code-change state, not analysis failure.
- Multi-update window: UI warning and reports retain all known intervening KBs.
- Product alias rule upgraded between snapshots: prior pair marked stale and selection reevaluated, analyst note kept.
- Deterministic candidate order under reversed input permutation.
- Property-based tests enforce no pairs with cross product or reverse chronology tagged AUTO_VERIFIED.

Release gate: 100% blocking-condition tests; manual user-asserted workflow remains possible, labelled and replayable.
