# SPEC-32 Implementation Guide: KB Patch Search

Status: implementation plan, 2026-10-14. This document is NOT a claim that code exists.
Depends on: docs/specs/kb-patch-search-and-pair-resolution.md.
Cross-references: SPEC-08, SPEC-07, SPEC-28, SPEC-30, current C6 evidence UI, SPEC-31 unified-engine plans.

## 1. Guardrails and first action

Before editing:
1. Read AGENTS.md, CLAUDE.md, docs/modules.md, tasks/todo.md, docs/specs/acquisition.md, docs/specs/enrichment.md, docs/specs/csaf-cve-interpretation-engine.md and docs/plans/spec-decisions-20261014.md.
2. Check main and all active patchtrace PRs/branches. Do not implement a duplicate CSAF parser if SPEC-28 is in flight, do not modify the unified engine's matcher or rebase over someone else's work without coordination.
3. Establish baseline tests: python -m pytest tests/test_acquisition_winbindex.py tests/test_acquisition_transport.py tests/test_ui_acquisition.py tests/test_enrichment_cve.py tests/test_enrichment_intelligence.py tests/test_cli.py -q. Record environment and all results. Tests requiring binaries/Windows may need CI.
4. Agree file ownership per worktree/agent. One integration owner controls CLI parser, main UI seam, module index and changelog. Avoid concurrent writes to src/patchtrace/ui.py and tasks/todo.md.
5. Create smallest test-first implementation PRs; each must merge cleanly and leave default offline/product behavior unchanged.

## 2. Recommended package layout

Add new code under src/patchtrace/patch_search/:

    __init__.py             # stable facade export, no side effects
    contracts.py            # strict Pydantic patch-search/1 records
    kb.py                   # canonical KB validation
    errors.py               # typed PT-PATCH-* exceptions, result status
    ids.py                  # canonical content identity, versioning
    sources.py              # source protocol, snapshot verification, store interfaces
    cvrf.py                 # pure CVRF parser: KB remediation/product graph and pointers
    csaf_adapter.py         # adapter to SPEC-28 when available; no second CSAF parser
    catalog.py              # catalog metadata/manifests as optional provider only
    discovery.py            # search coordinator + dedup + partial source outcomes
    components.py           # component hint provenance/quality
    versions.py             # compatibility and fix-boundary checks
    pairs.py                # pure pair candidates, deterministic ordering and blockers
    acquiring.py            # ONLY SPEC-08 acquisition composition / local import
    hypotheses.py           # adapter to SPEC-28 rule pack, fallback contextual text
    correlate.py            # read-only join to enrichment & multi-engine evidence
    persistence.py          # versioned append-only session/snapshot repository
    service.py              # orchestration facade; no Qt import
    cli_patch.py            # parser/handler isolated from main cli.py
    report.py               # safe export transformations

GUI additions outside package:
    src/patchtrace/ui_patch_search.py        # PatchSearchDialog, table models, controller
    src/patchtrace/ui_patch_intelligence.py   # optional dock, pure view-model consumer
    src/patchtrace/tooltips.py               # add tooltip templates/keys only
    src/patchtrace/ui.py                     # minimal menu action + open callback + dock seam
    src/patchtrace/cli.py                    # one additive top-level command delegation

Tests:
    tests/test_patch_kb.py
    tests/test_patch_cvrf.py
    tests/test_patch_sources.py
    tests/test_patch_products.py
    tests/test_patch_pairs.py
    tests/test_patch_acquiring.py
    tests/test_patch_service.py
    tests/test_patch_cli.py
    tests/test_patch_correlate.py
    tests/test_ui_patch_search.py
    tests/test_patch_state.py
    tests/test_patch_security.py
    tests/fixtures/patch_search/{manifest.md,cvrf,csaf,winbindex,pe,golden}...

Docs:
    docs/modules.md (new module registry row after integration)
    docs/specs/kb-patch-search-and-pair-resolution.md
    docs/plans/kb-patch-search-implementation.md
    docs/plans/kb-patch-search-integration-notes.md
    docs/qa.md; tasks/todo.md; release notes at release gate only

Naming note: existing enrichment/intelligence.py is an MSRC/NVD network client, not the SPEC-28 future intelligence package. Do not overload it with KB-specific search logic.

## 3. Dependency direction and public seam

The dependency arrows are one-way:

    ui_patch_search / cli_patch
                    |
           patch_search.service
                    |
       discovery --- pairs --- hypotheses --- correlate
          |          |            |             |
     CVRF/CSAF     versions     SPEC-28       SPEC-07
     source data     |          optional     + engines
          |          v
     source store  acquisition facade  -> SPEC-08 transport/quarantine
                    |
           ProjectService.create
                    |
           existing project & report storage

Pure modules (kb, contracts, cvrf, components, versions, pairs, hypotheses) cannot import Qt, urllib, requests, filesystem mutation, subprocess, ProjectStore or engine executables. Source fetch is behind a Protocol; pair materialization is behind a narrow verified-artifact port; artifact inspection delegates to existing ingestion. Import graph contract tests enforce these boundaries.

External adapter Protocol interfaces (proposed, semantic; concrete types defined before production implementation):

    class AdvisoryProvider(Protocol):
        provider_id: str
        def search_kb(self, query: KbSearchQuery, context: FetchContext) -> SourceSearchResult: ...

    class BinaryIndex(Protocol):
        def find(self, filename: str, variant: UpdateVariant, context: LookupContext) -> CandidateIndexResult: ...

    class VerifiedPairAcquirer(Protocol):
        def materialize(self, plan: PairAcquisitionPlan, context: AcquisitionContext) -> MaterializedPair: ...

    class PatchEvidenceReader(Protocol):
        def for_pair(self, project, older_sha, newer_sha, run_id) -> EvidenceSnapshot: ...

    class PatchSessionStore(Protocol):
        def append_snapshot(self, snapshot: SourceSnapshot, raw: bytes) -> str: ...
        def commit_session(self, session: PatchSearchSession, expected_revision: int) -> str: ...

Defaults should be stateless/adaptable for fake providers in CI. Freeze DTOs at the boundary. Use result objects for no association/partial provider failures, typed exceptions for malformed input or unexpected runtime failure. No exception object leaks unredacted URL or local path in user-facing text.

## 4. Development slices and ownership

### Slice P0: baseline, fixtures, contracts (easy, 1 PR)

Files: contracts.py, errors.py, ids.py, kb.py, fixtures, test_patch_kb.py, test_patch_service.py.
- Start with red tests for KB canonicalization including whitespace, Unicode, slash, newline, oversized and leading zero semantics; decide whether leading zero is allowed as a preserved upstream value (default: preserve digits exactly, no numeric coercion).
- Strict Pydantic records, JSON Schema generation pinned to the existing Pydantic major version. Domain-separated deterministic IDs with canonical serialized field order. Consistent source status "confirmed/candidate/conflicting/unknown".
- Build 20 golden fixtures in a corpus manifest: actual MSRC CVRF structure for a known CVE+KB+ProductID; multi-product same KB; CVE absent; Type-2 remediation not related; dates but no remediation link; 0..many CVEs; component hint absent; mixed architectures; stale source; corrupted JSON. Record URL, retrieval UTC, upstream revision, SHA256, redacted fixture content and reuse terms.
- Adopt fake sources, no network in deterministic unit tests. Tests import core modules in a headless Python process without PySide6 loaded.
Gate: schema roundtrip, determinism, negative matrix pass.

### Slice P1: offline KB/CVRF discovery (medium, 1 PR)

Files: cvrf.py, sources.py, discovery.py, persistence.py, test_patch_cvrf.py.
- Map CVRF /Vulnerability entries by the exact associated ProductID in Remediations.Type == 2 records and matching KB article description. Normalize CVE identity separately from product graph. Retain source record position and exact pointer.
- In multi-product arrays, create edges only when remediation targets include the specific product. Product name lookup must use ProductTree and surface unknown IDs as mapping problems, not bogus names.
- Search one or more imported source documents, return deduplicated update variants and edges. For records without authoritative updateID, generate a source-qualified synthetic ID; distinguish from a real Microsoft update identity.
- Conflicting source revisions become parallel claims with a conflict status. Do not hide older source silently.
- Snapshot raw content atomically and generate content-addressed local objects; no automatic network or project writes.
Gate: examples with known-affected and known-not-affected statuses, multiple KBs per CVE, one KB addressing multiple CVEs, mixed products and missing ProductID.

### Slice P2: MSRC source network adapters (medium, 1 PR)

Files: sources_msrc.py (or under providers/), discovery.py, test_patch_sources.py.
- Extend existing enrichment/intelligence.py patterns (static host allowlist, opt-in plan/consent, no ambient proxy, bounded response/redirect/retry, clock/transport injection, cancellation); do not copy/paste a forked HTTP implementation if composition suffices.
- For CVRF, use the official MSRC Security Update Guide API contract, first verified with a pinned fixture. The public API supports CVRF documents identified by period such as YYYY-Mmm; searching a KB therefore requires a bounded local corpus/index of documents, not assuming a direct /kb/{id} official endpoint. Limit initial discovery horizon by a user-selected period or cached metadata; do not automatically request all historical monthly files.
- Microsoft CSAF directory adapter is deferred to SPEC-28, but its provider interface must fit. Discovery must inspect actual published index/listing; never guess advisory filenames.
- Rate limiting, retries, ETag/Last-Modified where supported, immutable raw digests, source age. Return partial results for intermittent provider failures.
- No scraping of Microsoft Update Catalog's DOM or undocumented postback endpoints as a release dependency. Offer a documented launch URL / manual package import while assessing a supported programmatic metadata source.
Gate: unit tests with fake opener; explicit live opt-in probe with a fixture captured+reviewed; offline test sends 0 packets.

### Slice P3: product/component hint and pair resolver (medium/hard, 1-2 PRs)

Files: components.py, versions.py, pairs.py, Winbindex adapter, test_patch_pairs.py.
- Component hint precedence: verified manifest or explicit binary input > source-linked module reference > curated component registry > free-text term. Keep every hint's exact origin and confidence category.
- A KB with no source-linked filename presents input request, not arbitrary Windows DLL guesses. Curated mappings are versioned data; each requires maintainer-reviewed upstream citations.
- Query current Winbindex by filename; use existing parse() output BuildCandidate with release/KB metadata. DO NOT modify BuildCandidate semantics in place.
- Filter exact PE machine, product release branch and version compatibility; sorted suggestions are just suggestions. Choose baseline by proven fixed-release boundary where possible, otherwise source-supported/analyst override explicitly.
- Adversarial tests: superseded update, newer date with older code branch, two identical hashes, x86 vs x64, Windows 10 vs 11 same filename, different cumulative update with same CVE, Winbindex record never downloadable.
- Return explicit blocker codes: NO_COMPONENT, PRODUCT_AMBIGUOUS, NO_PRE_FIX_PAIR, NO_NEW_PE, WRONG_MACHINE, UNSUPPORTED_PAYLOAD, HASH_UNAVAILABLE, UNVERIFIED_BOUNDARY.
Gate: cannot mark a pair "verified_pre_post" without the required metadata evidence. Prefer exploratory/manual classification.

### Slice P4: acquisition reuse and project creation (medium, 1 PR)

Files: acquiring.py, test_patch_acquiring.py, tiny ProjectService boundary.
- Reuse current acquisition.Transport, consent preview, quarantine.make_plan, quarantine.acquire and quarantine.promote. Existing SPEC-08 requires exact same basename, SHA mismatch, known sizes, Microsoft symbol-server URL and hashes; pass through these validations.
- For already present full PEs, use existing ingestion/ProjectService path with verified local hashes, PE parsing and matching identity instead of a second quarantine implementation.
- One operation-private staging area; all or nothing project adoption. No project created until both verified PEs are present and project location validated.
- New session/provenance stored separately, append only; artifact identity is computed by the original service. Preserve exact pair hashes and source refs.
- Delta-only and PSFX-only entries return blocked/capability status, not a corrupted PE project.
Gate: SPEC-08 regression suite all green; hash mismatch/cancel/partial download/proxy redirect tests; no project on failure.

### Slice P5: CLI-first end-to-end flow (easy/medium, 1 PR)

Files: cli_patch.py and minimal dispatch changes in cli.py; test_patch_cli.py.
- Define --offline, --snapshot, --fetch-metadata, --consent-hosts, --product-id, --file, --pair-id, --project, --json semantics with parser tests.
- CLI defaults are local-only. No "search" command should fetch without explicit --fetch-metadata.
- Implement plan-only/--dry-run that prints exact source requests and download plan without modifying project.
- JSON errors emit standard envelope; exit statuses consistent with existing CLI. Progress and consent summary go to stderr, bounded.
- End-to-end golden: imported CVRF fixture -> product -> typed filename -> Winbindex fixture -> pair selection -> mock verified local PE pair -> new project -> explain without network.
Gate: headless import, golden JSON hash stability and process exit codes.

### Slice P6: expectation and localization adapter (medium/hard, 1-2 PRs)

Files: hypotheses.py, correlate.py, report.py, test_patch_correlate.py.
- First pass: derive deterministic "what to look for" from explicitly available CWE/type/component; include counterexamples, unknowns and sources. Do not invent affected functions.
- Reuse SPEC-07 contextual ranking only as a pointer to potential changed functions; preserve original score and record it as attention, never vulnerability probability.
- For SPEC-28/30 readiness: plug into a versioned evidence-reader interface. Correlate matched functions on verified run+hash+orientation IDs, not names or display labels. Cross-engine match contradictions are first-class statuses.
- Existing partial match override and evidence panel data must not be rewritten. No changes to engine scoring or unified matching algorithm.
- Always retain unclassified changed functions, even when a CVE hypothesis generated 0 ranked candidates. Generic bounds-check additions must not auto-label the actual CVE site.
- If SPEC-28/30 implementations do not exist, render "contextual suggestions only", and keep deeper localization feature-flagged.
Gate: no source facts promoted to observed evidence; stale engine report => no localization; no "vulnerability fixed" assertions.

### Slice P7: GUI wizard and dock (medium, 1-2 PRs)

Files: ui_patch_search.py, ui_patch_intelligence.py, tooltips.py, minimal ui.py seam.
- Qt model/view for long tables (QAbstractTableModel), not populating thousands of QTableWidgetItem instances.
- Use Worker(QThread) precedent with cancellable tasks. Data returned to GUI by signal, and project/persistence writes on owning GUI thread (the existing AcquisitionDialog documents why).
- Search/product/components/pairs as progressive steps. Disabled controls explain prerequisites in adjacent status text, not tooltips alone.
- Source inspector always shows exact facts/provenance and limitations. Pre-run expectations available after project attachment; post-run dock attaches only to matching completed run.
- Preserve New, Open, Run Comparison, Cancel and existing AcquisitionDialog actions. Use one new action and short controller hook; avoid editing giant ui.py beyond boundary seam.
- Add QSettings namespace patch_search/1 without colliding with UI profile/enrichment keys. Do not persist host consent as permanent global approval.
- Add tooltips to registry, tests for coverage and objectName accessibility fields.
Gate: Qt offscreen tests, cancellation, selection resets, rapid window close, no cross-thread SQLite, manual Windows DPI/screen-reader smoke.

### Slice P8: supported package fallback feasibility (separately gated, optional)

Files: package_adapters/ module added only if verified; fixtures and WIndows CI.
- First analyze whether MSU/CAB manifest extraction can produce a full binary or requires PSFX hydration. Windows newer LCUs are commonly forward/reverse deltas relative to RTM and component state. Generic extract-all-file commands cannot promise hydrated PE files.
- Optional supported path: take a known genuine baseline image (with build provenance) and Microsoft update package, mount offline into disposable scratch directory, apply update using supported DISM servicing and extract older/newer versions from separate before/after images. Requires image compatibility, prereqs and adequate disk budget.
- Never use DISM /Online. Never execute update package inside current runtime. No silent admin elevation.
- Verify expected PE SHA-256, machine, version, product lineage and safe copy; always clean up/retry idempotently. Do not store EULA-restricted binaries in test repos.
- Reuse current acquisition.delta only for supported PA30 cases with independently established exact base and exact expected target hash. Do not treat its existence as universal PSFX support.
Gate: native Windows CI virtualized/disposable fixture, no changes to host, unsupported gracefully; only then expose the adapter.

### Slice P9: release verification and documentation (1 PR)

- Update docs/modules.md, docs/qa.md, README and tasks/todo.md with precise statuses; synchronize with integration owner to avoid lost writes.
- Test all Windows packaging modes used by tools/build_windows.py (PyInstaller hidden imports, local data files, cert validation libs, optional package binaries) and verify EXE starts fully offline.
- Run Linux type/format/unit/static smoke if required by existing workflows; native Windows PySide6 GUI acceptance and actual pair acquisition with a user-consented non-sensitive sample.
- Prove disconnected mode on real Windows with network disabled, not just mocked requests.
- Check report reproducibility, source revision staleness and cancellation, then release only after baseline and new gates pass.

## 5. Division of labor, complexity and dependencies

| Work | Complexity | Can proceed independently | Blocker |
|---|---|---|---|
| P0 contracts/fixtures/KB validator | easy | yes | none |
| P1 offline CVRF parser | medium | after P0 | official sample schema |
| P2 MSRC transport | medium | after P0, parallel P1 | live provider behavior |
| P3 component/pair resolver | hard | after P0, parallel P1 | reliable product-lineage and fix boundary |
| P4 acquisition/project adapter | medium | after P0, parallel P1 | explicit single-session ownership |
| P5 CLI | medium | after P1+P3+P4 | facade stable |
| P6 hypotheses/contextual findings | hard | after P1 + current analysis evidence | deep localization gated on SPEC-28/30 |
| P7 wizard | medium | after P5 facade | GUI thread/persistence seam |
| P8 package/hydration | very hard | after P4 | Windows servicing images and supporting evidence |
| P9 QA/packaging | medium | after core features | Windows real release gate |

Suggested initial MVP = P0 + P1 + P3 (manual filename) + P4 (direct symbol/local PE) + P5 + P7 minimal. Provide CVE facts + "what to look for" text from P6 minimal in MVP, but do not claim strong automated localization. P2 official live lookup can follow once a reliable fixture corpus validates the discovery horizon. Keep P8 out of initial critical path.

## 6. Code implementation notes

### 6.1 Avoid circular imports

- Patch-search domain modules import src/patchtrace/models.py only via protocols or narrow ID types, not entire service/UI.
- ui.py imports ui_patch_search lazily from new action; no import from patch_search into ui.py during module discovery when avoidable.
- patch_search.acquiring imports SPEC-08 facade, NEVER the acquisition UI class.
- patch_search.correlate imports read-only evidence conversion and enrichment view-models; do not make enrichment import patch_search.
- Dedicated adapters own transformations between schema versions, with unit-tested mapping and no implicit positional field reinterpretation.

### 6.2 Errors and status

Use PT-PATCH-INPUT / PT-PATCH-CONFIG / PT-PATCH-PROVIDER / PT-PATCH-LIMIT / PT-PATCH-CANCEL / PT-PATCH-MISMATCH / PT-PATCH-UNSUPPORTED / PT-PATCH-STATE / PT-PATCH-STORAGE. Provider failure must be separable from no exact KB match. Unsupported package cannot be returned as generic "download failure". Error summaries redact private URLs and paths; full user-controlled diagnostic context remains local only.

### 6.3 Atomicity and idempotency

- Metadata fetch: cache a full validated snapshot or none.
- Binary acquisition: hash during streaming, fsync/rename into private final storage, verify again when reading cache; remove only operation-owned temp files.
- Project creation: check empty/nonexistent destination, store two files with existing service, attach session source refs transactionally. Crash recovery identifies orphaned private staging without deleting user files.
- Acquire/session idempotency key derives from selected KB + product + filename + ordered pair hashes + snapshot IDs; repeated request can reuse verified cache but must not silently overwrite a different project.
- Revision guard is an atomic check-and-commit under the existing ProjectStore ownership model; do not do a separate check then overwrite without locking.

### 6.4 Performance and resource bounds

- Paginate source/search results and lazily populate Qt table models.
- Put metadata/symbol-network work on background workers; progress per stage and byte.
- Cap candidates, source-documents per batch, file bytes, decompressed bytes and concurrent probes with explicit config and documented defaults.
- Cache source bytes by SHA, derivative by parser+rule version, binaries by their verified hash; never duplicate full binary per CVE reference.
- Do not invoke Ghidriff/BinDiff/rizin during KB lookup; Run Comparison stays a separate user action.
- Use immutable snapshots to prevent UI refresh from changing a running analysis context.

### 6.5 License and provenance

- No bundled Microsoft binaries, Winbindex dataset, or symbol downloads.
- Review license and attribution for all imported code/data. Current SPEC-08 notes runtime Winbindex third-party GPL-3 metadata; do not copy GPL components into PatchTrace's MIT source without a license decision.
- Prefer open documented wire protocols, new adapters and original code, not wholesale upstream reimplementation.
- SHA-256 validates the candidate against the index; optional Authenticode verification has separate status and must not be conflated.

## 7. TDD test matrix and fixture recipes

Synthetic fixture builder should produce:
- fake ProductTree entries P-WIN11-X64 and P-SERVER-X64;
- CVE-A affecting P-WIN11-X64, with KB-1 Type-2 remediation;
- CVE-B affecting both products, with distinct product-specific KB-1/KB-2 relationships;
- CVE-C published same month but not remediated by KB-1;
- source revision 1 and revision 2 with changed product status;
- a fake Winbindex file-name index with three hashes: old full PE x64, new full PE x64, and newer PA30-only; one x86 candidate;
- minimal valid synthetic PE test fixture (reuse tests/pe_builder.py) signed state may be "not checked";
- golden change signals only when bound to the exact SHA/run and intentionally labelled as synthetic.

Test cases:
 T01 Search normalizes KB, rejects malformed input; no stdout secrets.
 T02 Source parser per-product association and JSON pointer correctness.
 T03 CVE search no-result vs provider-unavailable distinction.
 T04 Multiple variants and ambiguous product correctly require selection.
 T05 Manual component input not auto-verified as CVE affected.
 T06 Pair resolver rejects same hashes / mismatched arch / cross-version family.
 T07 Version/date sorting does not claim pre-fix unless proper source supports boundary.
 T08 Full-PE symbol download passes existing checks; PA30-only blocked unless valid reconstruction.
 T09 HTTP redirect allowlist and no env proxy; repeated transient 429, 5xx and timeout.
 T10 Consent denial yields no fetch and no project.
 T11 Cancellation at every boundary leaves no orphaned incomplete project.
 T12 Source revision or matching override invalidates derived suggestions.
 T13 Malicious CVRF strings and bogus external links never execute/click automatically.
 T14 Existing acquire and correlate behavior unchanged; no Qt in patch_search pure imports.
 T15 Offline native Windows end-to-end fixture; frozen exe import path.
 T16 Adverse evidence: ordinary guard change reported as possible only, not vulnerability verified.
 T17 One CVE with two files and one file with multiple CVEs never double-counts evidence.
 T18 Large source documents/decompression bombs/10k variants meet caps and benchmark.
 T19 Two simultaneous workers cannot attach two sessions to the same project revision.
 T20 Primary source unavailable with cached snapshot retains stale but inspectable last good evidence.

## 8. Test/build command recommendations

On supported development environment:

    python -m pip install -e ".[dev]"
    python -m pytest tests/test_patch_kb.py tests/test_patch_cvrf.py tests/test_patch_pairs.py -q
    python -m pytest tests/test_acquisition_winbindex.py tests/test_acquisition_transport.py tests/test_ui_acquisition.py -q
    python -m pytest tests/test_enrichment_cve.py tests/test_enrichment_intelligence.py -q
    python -m pytest -q
    python tools/build_windows.py --help

Confirm actual pyproject extras and build command flags before running; the snippets above are illustrative, not verified CI logs. Use repository-pinned dependencies, not unsolicited unpinned upgrades. Native Windows build and GUI verification are required; Linux success alone is insufficient.

## 9. Definition of done for the MVP

A new user on an offline Windows executable can import a verified CVRF snapshot, enter a KB, choose a product, view its associated CVEs, specify the binary if needed, see compatible candidate versions, select/import two full PEs, create a project, read the advisory-derived hypotheses, run comparison, and inspect run-bound candidate changes and unresolved facts. With separate explicit consent, supported MSRC metadata and Microsoft symbol-server fetches work and are logged with immutable provenance. Missing data and unsupported package formats produce clear recovery options. Old acquisition/comparison functionality remains intact. All test gates documented in docs/qa.md with exact runner/date/results. 
