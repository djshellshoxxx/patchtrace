# SPEC-31-C: Product/Build Lineage, Supersedence and Pair Resolution

Status: developer-ready deterministic design; implementation pending. Parent [SPEC-31](../kb-cve-correlation-and-acquisition.md). Requires 31-A; consumes 31-B and existing Winbindex BuildCandidate. No I/O, Qt, network.

## C1. The product key is multi-dimensional

A Microsoft KB number is not a unique product/build/file tuple. Require distinct normalized dimensions: publisher product id (if available), OS family (client/server), release (e.g. 24H2), architecture, channel (GA/preview/Insider/LTSC), edition/locale/optional component where material, and full build+UBR. Normalize aliases through curated versioned mapping tables with source/effective dates. A descriptive string match is only a candidate and must not set mapping=verified. Full dotted builds compare as parsed integer tuples ONLY within an already verified Windows build family. FileVersion is NOT proof of Windows build; PE timestamps and update KB numbers are not chronology.

Define ProductScopeRef as (ProductScopeId, verification_state, evidence_ids, conflict_ids). User selections persist an assertion (may lower ambiguity) but do not change vendor verification status. A file present across Windows client/server with identical SHA may be reused as the *same bytes*, not evidence the Windows products are equivalent.

Known Windows client generations must remain distinct even when release labels coincide (Windows 10 22H2 and Windows 11 22H2). Their scope identity uses `kbc.scope` version 2 with the derived `winbindex_key` (`10-22H2` versus `11-22H2`) alongside the existing dimensions. Scopes without a known client key retain the version 1 formula. This is an identity correction, not a claim of verified product mapping.

Compatibility: immutable stored contexts, pair records, decisions and investigation history retain their original identifiers; a legacy scope ID must never be guessed or rebound to one of the new generations. The reverse index is rebuilt from retained raw advisory bytes. An investigation whose selected product is absent from that rebuilt index must refuse index pairing with an explicit instruction to repeat the search and select the product again. Existing context exports remain historical records. The persisted SQL edge dictionaries remain historical ingestion data; current correlation uses the reparsed reverse index. No destructive migration or implicit historical-context rewrite occurs.

Product listing must also refuse a stale investigation with that refresh instruction when any stored scope no longer exists in the rebuilt index, including a mixed list with surviving server scopes. It must not claim that a legacy mapping loss means the lead has no products or that a partial surviving list is complete.

Implied-release amendment (2026-11-11, audit KBA-08, alias catalog version 2): a client product name without a release token names the first release of its generation only in the exact vendor form `Windows 10|11 for x64-based|32-bit|ARM64-based Systems` (the whole normalised name): Windows 10 gets release `1507` and key `10-1507`, Windows 11 gets release `21H2` and key `11-21H2`, so the release-less Windows 11 name shares the scope of the later spelling `Windows 11 version 21H2 for ...` of the same architecture. `Version 2004` is a release token like `1507` to `1909` (client key `10-2004`; `Windows Server, version 2004` gains release `2004` and stays without a key, as the 1903 and 1909 server names do). Any other wording without a release token (LTSC/LTSB, IoT or another edition, extra words, a family hint that contradicts the client family) keeps an unknown release and gets no key. `winbindex_key` is the scope-identity key, not the file index's spelling: the resolver asks the index for `10-<release>` and for the bare `<release>` that Winbindex uses for Windows 10 (audit KBA-01). Compatibility: scope ids change only for names that carry the token `Version 2004` or have the exact release-less client form (version 1 name-keyed to keyed for the client names); every other name derives the attributes and the id it had under catalog version 1. An investigation stored on a changed name follows the refusal rule above (repeat the search and select the product again) and its stored records keep their identifiers; a pending product-start selection recorded under catalog version 1 is refused by full scope equality. The mapping stays `candidate`. Evidence: the Windows 10 form occurs in the committed MSRC factual projection (`tests/fixtures/kbcve/msrc`); MSRC use of the `Version 2004` and release-less Windows 11 forms is unverified offline.

Local product-start amendment (2026-11-06): a product catalogue may be built
without a KB/CVE lead from the active documents of a captured local reverse
index. Merge their source product references with the existing scope rules;
retain tied/ambiguous active revisions and their mapping states. A superseded
document alone must not keep a removed product selectable. Selection records
the complete ProductScope and its source identities, and a new local pair is
bound to that scope only after source-snapshot admission and full scope equality
are checked. This establishes an analyst-selected scope, not binary product
membership, affectedness or a fix attribution. Source digests/raw sidecars may
support that selection without adding any CVE cards to its saved context.

Unreadable stored documents make current product activity uncertain, including
same-month tied native revisions and CSAF groups whose tracking identity cannot
be recovered. Product-only listing/admission therefore refuses conservatively
when any source cannot be read or parsed; it must not revive an older definition
from the remaining documents. Existing partial KB/CVE lookup behavior is unchanged.

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

The existing index-row proposal seam must enforce the component and orientation checks even when called directly, outside the filename-filtered resolver. Distinct normalized basenames carry the existing NAME_MISMATCH hard block. The timeline's KB identifier, SHA-256 and BASE-row ordering are deterministic display tie-breakers only; they cannot establish temporal order when both rows have equal release date and numeric build/UBR. Such proposals retain their rows with ORDER_UNVERIFIED, incompatible lineage and grade X. This does not change manual pair selection or imply verified product mapping, complete update coverage or a vulnerability probability.

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

Reverted-content amendment (2026-11-11, audit KBA-06): the older side of a resolver proposal never carries the target build's SHA-256. When a file's bytes return to an earlier value across a row of another update class (timeline Z, A, B(preview), A with target the last A), the backward search passes over every row holding the target's own bytes as well as the rows of the other class, and takes the nearest earlier admissible row with different bytes (Z). Every row passed over stays in the window, so the proposal is named WINDOW_CONFOUNDED. Nearest wins: for Z, A, Y, B(preview), A the older side is Y, not Z. When no such row exists the answer is NO_OLDER, never an equal-hash pair. Proposal identifiers of timelines without such a reversion are unchanged. The equal-hash 'no change for file' assessment above remains available to a direct caller of the proposal seam (grade X, IDENTICAL_CONTENT); the resolver does not offer it as a candidate pair.

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
