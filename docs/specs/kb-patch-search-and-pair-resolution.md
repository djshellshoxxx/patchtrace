# SPEC-32: KB Patch Search, CVE Resolution, and Verified Binary Pair Selection

Status: developer-ready design, 2026-10-14. Implementation: NOT STARTED by this documentation change.
Contract: patch-search/1. Owner: PatchTrace acquisition/intelligence integration.
Related: SPEC-08 acquisition, SPEC-07 enrichment, SPEC-28 CSAF, SPEC-30 patch-intent localization, SPEC-09 N-way, current multi-engine evidence and unified-engine plans.
Companion: docs/plans/kb-patch-search-implementation.md and docs/plans/kb-patch-search-integration-notes.md.


## Implementation precedence and detailed annexes (2026-10-14)

The following companion documents are normative refinements of this feature and supersede conflicting shorthand in the original broad SPEC-32 text:

1. [SPEC-32A: Provider and source correlation contracts](kb-patch-search-source-adapters.md) fixes the MSRC CVRF Type-2 per-product join, bounded CVRF search scope, CSAF mapping distinctions and provenance.
2. [SPEC-32B: Pair lifecycle and crash recovery](kb-patch-search-pair-lifecycle.md) fixes the old/new identity decision table, companion SQLite sidecar and post-project-create recovery protocol. The previous phrase "all-or-nothing project creation" applies to both binary inputs before ProjectService.create; attachment to the companion database is separately recoverable.
3. [SPEC-32C: GUI/CLI contract](kb-patch-search-ui-cli-contract.md) fixes concrete CLI syntax, no-network defaults, wizard state invalidation and GUI-thread database ownership.
4. [SPEC-32D: QA and fixtures](kb-patch-search-qa-and-fixtures.md) fixes deterministic positive/negative cases, offline integration, crash injection and Windows release gates.
5. [SPEC-32E: Python contract blueprint](kb-patch-search-contract-blueprint.md) fixes strict Pydantic DTO examples, truth-preserving validators, versioned result semantics, service ports, and a reproducible synthetic end-to-end scenario.

Engineering defaults approved for initial MVP: x64 complete PE inputs, MSRC CVRF official-source corpus with explicit finite scope, one product variant, one analyst-selected file pair, offline-first, consented source/download operations, a separate optional project sidecar, and conservative contextual vulnerability hypotheses. Windows update-package/PSFX reconstruction remains a separately gated future feature. Source-derived KB/CVE association is never proof of a vulnerable function or definitive fixed binary.

## 1. User story and business outcome

An analyst searches for a Microsoft KB, selects the actual affected product/build/architecture, reviews the associated CVEs, identifies a plausible pre-fix and post-fix pair of the same binary, downloads or imports both with verification, creates a normal PatchTrace comparison project, and sees a concise advisory-derived "What to look for" explanation before analysis and an evidence-linked candidate-changes explanation after analysis.

The feature must always distinguish:
- A: KB publication / product association (vendor advisory or catalog fact).
- B: KB-to-CVE association for a specified product (source-backed).
- C: CVE-to-binary association (often only a candidate until independently evidenced).
- D: exact older/newer binary identity, origin, version and file integrity.
- E: observed code changes that are compatible with a CVE-related hypothesis.
- F: actual vulnerability/fix verification (not claimed automatically).

A valid KB search does not imply a downloadable binary or a unique CVE. No source maps every KB to every modified PE or every CVE to one function.

## 2. Existing verified PatchTrace reuse

The repository (main inspected 2026-10-14) already provides:
- src/patchtrace/acquisition/{contracts,winbindex,transport,quarantine,delta}.py: filename-based Winbindex metadata, Microsoft symbol-server retrieval with consent, streaming SHA-256 verification, staging, PE identity, optional Windows delta reconstruction.
- src/patchtrace/ui.py AcquisitionDialog: filename search, explicit older/newer selection, worker cancellation and progress, GUI-thread project creation.
- src/patchtrace/cli.py: acquire search/fetch, correlate --cve/--fetch, JSON CLI result/error conventions.
- src/patchtrace/enrichment/{cve,intelligence,pipeline,storage}.py: source-specific CVE enrichment, bounded opt-in fetch, baseline contextual ranking.
- src/patchtrace/service.py ProjectService.create, immutable artifact hashes, revisioning, project ownership.
- docs/specs/csaf-cve-interpretation-engine.md and patch-intent-localization-engine.md: deferred advanced evidence interpretation.
- docs/specs/unified-engine/*: upcoming analysis evidence fusion, not a prerequisite for basic KB lookup.

SPEC-32 MUST NOT reimplement these parts or silently broaden SPEC-08 acquisition/1 contracts. Add composition and adapters, then optionally extend through versioned and additive interfaces.

## 3. Functional requirements (normative)

### 3.1 KB search and product disambiguation

F01. Accept KBNNNNNN or NNNNNN input, uppercase canonicalize as KB plus digits, preserve original query; reject letters embedded in digits, Unicode lookalikes, excessive length, paths, URLs and control characters. Suggested canonical range: 4-9 digits, configurable only by validation-version change. Never derive fetch URLs by concatenating unchecked input.

F02. Show ALL found product/architecture/channel variants with their exact upstream source IDs, package/update identifiers where available, title, source release/revision dates, release type and supersedence/applicability metadata if proven. Show multiple versions rather than quietly selecting a single match.

F03. Resolve CVE associations from official MSRC advisories. For CVRF monthly documents, interpret per-vulnerability, per-product Remediations where Type 2 KB article records have a valid normalized KB identifier; map ProductID to the CVRF ProductTree. Do not infer universal KB-to-CVE association from a monthly bulletin. Keep source document ID, product ID, remediation index/JSON pointer and retrieval digest.

F04. Also support SPEC-28 CSAF advisory/VEX source import and discovery once implemented. Preserve product_tree relationships, group references, per-CVE product_status, remediations and revisions. No guess that CSAF filename equals a CVE. CVRF and CSAF are independent observation families, not automatically independent corroborating evidence.

F05. Present CVE ID, title, CWE if stated, CVSS and impact as context, affected product, KB association source and status (confirmed / candidate / conflicting / unknown). A KB returned without CVEs is a legitimate result.

F06. If search yields no exact KB-to-product-to-CVE matches, present "No confirmed association found in checked sources" and allow manual CVE input/import. Do not match by publication date alone. Dates may be shown as a lead with a distinct speculative classification only.

F07. Support an offline import of an analyst-supplied, source-attributed normalized snapshot or source CVRF/CSAF JSON. Require strict schema/source labeling; treat claimed "Microsoft" origin as unverified if the source has no independently established provenance.

### 3.2 Component identification and candidate pair selection

F08. Selecting a product reveals affected component hints separately from proven changed files. Hints may come from advisory wording, curated auditable rules, source-backed file manifests, an analyst-supplied filename, or independently verified binary metadata. Product-level advisories often lack filenames. Never fabricate a DLL from a CVE title.

F09. If no specific binary can be identified, require the analyst to enter/select a filename or import a known pair. No "automatic complete" claim.

F10. For each selected filename, reuse the existing Winbindex filename lookup and filter its build entries on declared Windows release, product family, machine type, KB and version evidence. Warning: Winbindex data may include KB entries but is not an authoritative vulnerability mapping; retain its index revision/digest and per-build provenance.

F11. Pair orientation: older is a build proven or reasonably supported to precede the relevant fix; newer is a build containing or associated with that fix. The nearest lower chronological KB is not a proof of pre-fix state. Enforce same filename, compatible PE machine/OS lineage and distinct SHA-256. Record how the fix boundary is inferred. If status is unknown, ask analyst for explicit override; label pair exploratory.

F12. Preferred acquisition tiers:
  A. Both full PE binaries downloadable and SHA-256 matched through current Microsoft symbol-server route: offer automatic import.
  B. One or both binaries obtainable from locally provided files, offline image, ISO, mounted component store or package: offer verified import.
  C. Vendor update package supplied or catalog page opened externally: list package verification/extraction prerequisites; do not assert that CAB/MSU always contain directly extractable full PEs.
  D. Only PA30/PA31/delta/PSFX payloads, missing baseline, file absent or not supported: mark blocked with specific reason, offer manual pair import.

F13. If update packages are used, a future optional package adapter may inspect manifests and use trusted Windows DISM on a disposable offline image or supported Windows delta APIs where verified. Never run update installers on the analyst host. A reconstruction must verify exact expected output hash and PE identity before adoption. Unsupported format => honest abstention.

F14. Downloads require the exact list of hosts/requests to be presented before consent. Reuse existing acquisition transport where origin, redirect and signed SAS URL handling match; new hosts require separately audited allowlists. No binary uploads.

F15. The system may offer several candidate files/pairs. Bulk mode is opt-in, bounded, deduplicated by hash and ordered deterministically. Default: one explicitly selected pair and one project; never silently compare incompatible cross-product binaries.

### 3.3 Analysis and advisory intelligence

F16. Before Run Comparison, present "What to look for": advisory-backed affected component, stated weakness/impact, likely patch motifs as hypotheses, counterexamples and source URLs/JSON pointers. Expected patch motifs use versioned deterministic rules, not LLM-generated certainty. If evidence is only generic wording, show generic investigation themes as low specificity.

F17. After the comparison completes, show a separate, non-blocking "Patch search findings" pane or summary dialog. Preserve the standard diff, engines, project handling and ranking semantics. Link candidate claims to exact current run ID, binary SHA-256 pair, function match ID, code address/range, observed change kind and advisory claim. Never overlay unrelated CVEs as fact.

F18. The appearance of guard, branch, length check, memcpy or authorization change is suggestive only. Ghidriff and any optional engines may disagree; contested function matches stay contested. Shared-origin Ghidra-derived observations must not be counted twice as independent votes. Missing signal is not evidence of absence.

F19. Provide per-CVE triage status: no analysis / candidate evidence / conflicting evidence / no localized evidence / source unavailable / not applicable / manually reviewed. Do not use "fixed" or "verified exploit mitigated" unless based on explicit manual/evidence workflow beyond this feature.

F20. Persist immutable search snapshots, provenance, analyst pair selection and interpretations separately from base Ghidriff output. Re-evaluate or stale-out derived judgments when advisory rev, selected product, artifact hash, orientation, analysis run, matching override or ruleset changes. Keep historical comments/notes.

F21. Reports and JSON exports carry raw source references, versioned rule IDs, unresolved questions and explicit limitations. Keep report text escaped, no active HTML, no arbitrary external URLs embedded as executable actions.

### 3.4 User experience

F22. Add an entry "Search Microsoft KB / patch…" near the existing New > Download from Microsoft symbol server action. Use a separate PatchSearchDialog/Controller to avoid bloating the ~3K-line src/patchtrace/ui.py. Add tab/dock "Patch intelligence" only when search context is attached to a project. Existing AcquisitionDialog must continue to work unchanged.

F23. Guided steps: KB input -> update/product variant -> CVEs/advisory -> choose candidate component -> choose old/new pair -> consent/download or import -> project -> expected signatures -> run -> findings. Expose manual/offline branches at each step.

F24. Present source confidence independently from pair readiness. Example: "KB-CVE association: confirmed (MSRC CVRF ProductID X)"; "file association: unknown"; "pair: hash-verified, pre-fix classification unverified"; "analysis: not yet run."

F25. Every new control except established New/Open exemptions gets concise explanation of what it does, what data source it uses and whether it contacts a network. Follow tooltips.py and accessibility naming, keyboard tab order, screen-reader statuses, high-DPI rules and background worker conventions.

F26. Network disabled by default. Cache-only and offline-import modes must remain first-class. Consent is separate for metadata fetch and binary fetch; refusal cannot create a partial project. Allow visible cancellation and reattempt.

## 4. Source/provider truth table

| Data | Primary route | Fallback | Hard boundary |
|---|---|---|---|
| KB-to-CVE and product | MSRC CVRF / Security Update Guide (official) | imported official CSAF/VEX, explicit user association | per-product records, not monthly/date proximity |
| CVE weakness / impact | MSRC advisory, NVD as contextual second source | local source snapshots | descriptions do not prove patch mechanism |
| Product/update package list | Microsoft Update Catalog interactive listing; source-backed local/WUA metadata where available | user-imported package manifests | do not assume documented public Catalog JSON search API |
| Binary versions | Winbindex index metadata, files served by Microsoft symbols endpoint | verified local files / offline image | Winbindex is third-party metadata, not authoritative KB-CVE mapping |
| Authenticity | exact expected hash and, if supported, Windows trust/catalog-signature validation | explicit unverified state | hash matches the metadata, not necessarily vendor signing |
| PSFX/full-file reconstruction | documented Windows servicing applied to disposable offline image, or separately tested msdelta for supported formats | user supplies already materialized PE pair | not generically extractable from CAB |
| Diff signals | present artifact-matched comparison engine outputs | manual annotation | no CVE localization without evidence |

MSRC Security Updates API OpenAPI: https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/tree/main/docs
MSRC reference PowerShell KB extraction: https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/main/src/MsrcSecurityUpdates/Public/Get-MsrcCvrfAffectedSoftware.ps1
MSRC CSAF directory: https://msrc.microsoft.com/csaf
OASIS CSAF 2.0: https://docs.oasis-open.org/csaf/csaf/v2.0/cs01/csaf-v2.0-cs01.html
Microsoft Update Catalog: https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/manage/wsus-and-the-catalog-site
PSFX design: https://learn.microsoft.com/en-us/windows/deployment/update/psfxwhitepaper
Winbindex: https://github.com/m417z/winbindex

## 5. Contracts (new, additive, Pydantic strict/frozen)

All exported records carry contract="patch-search/1", schema version, source/evidence status and stable IDs. Reuse canonical SHA-256 and timestamp rules from src/patchtrace/enrichment/contracts.py. Never loosen that existing schema.

KbSearchQuery:
  kb: normalized KB identifier
  product_filter?: exact analyst-supplied product hint
  architecture?: x64 | x86 | arm64 | unknown
  mode: cache_only | offline_import | consented_online
  source_ids?: immutable permitted source IDs

SourceSnapshot:
  snapshot_id: SHA-256 domain-separated content identity
  provider: msrc-cvrf | msrc-csaf | msrc-sug | microsoft-catalog | local-manifest | winbindex | analyst
  origin_uri?: exact approved URL (no SAS, credentials, secrets)
  response_sha256: SHA-256 of raw bytes
  retrieved_at: UTC
  source_release?: date
  revision?: string
  validation: verified_origin | parsed_unverified | failed
  raw_object_ref?: local cache key
  parser_version: semantic revision
  upstream_record_pointer?: JSON pointer or record ID

UpdateVariant:
  variant_id: stable digest (provider, updateID/revision if present, product ID, architecture, channel)
  kb: KB
  update_id?: upstream ID
  title
  product_ids: tuple
  architecture?: enum
  os_build?: version/build
  classification?: string
  released_at?: date
  supersedes: tuple of source-backed variant IDs
  source_refs: tuple of SourceRef

KbCveEdge:
  edge_id: SHA-256 of canonical source binding
  kb, cve_id, product_id
  association: confirmed | proposed | disputed
  remediation_type?: upstream type
  source_refs: tuple[SourceRef]
  caveats: tuple[str]

ComponentHint:
  hint_id, binary_name?, module?, product_id
  origin: vendor_file_manifest | vetted_rule | advisory_text | analyst_input
  status: evidenced_file | suspected_file | unknown_file
  basis: source references (advisory text alone cannot set evidenced_file)

PairCandidate:
  pair_id, filename, product_variant_id, architecture
  older: BinaryRef, newer: BinaryRef
  boundary: verified_pre_post | source_supported | analyst_selected_exploratory | unknown
  old_fix_status: known_vulnerable | possible_vulnerable | unknown
  new_fix_status: fixed_by_advisory | possible_fixed | unknown
  blockers: tuple[str]
  provider_methods: tuple[direct_symbols | local_file | offline_image | package_pending]
  selection_reason: str with source_refs

BinaryRef:
  sha256, file_name, version?, machine?, size?, product_identity?, kb_membership?
  source_ref, access: downloaded_full_pe | supplied_full_pe | delta_only | missing
  integrity: hash_matched | supplied_hash_only | unchecked
  signature: trusted | valid_untrusted | invalid | unsigned | not_checked | indeterminate

PatchSearchSession:
  session_id, query, update_variant_ids, selected_variant_id?
  edges, component_hints, selected_pair_id?, source_snapshot_ids
  state: draft | ready_to_acquire | downloaded | project_attached | analysis_pending | analyzed | partial | cancelled
  project_id?, pinned_project_revision?, analysis_run_id?
  warnings, errors

PatchHypothesis (reuse/extend SPEC-28/30 with adapters, avoid duplicate domain objects):
  hypothesis_id, cve_id, cwe_id?, rule_id?, rule_version
  expectation, discriminators, negative_evidence_hints, advisory_source_refs
  evidence_strength: contextual | speculative
  never contains an automatic "proven fixed" boolean

PatchLocalization (view/read model):
  session_id, analysis_run_id, pair_id, cve_id, match_id?
  finding_status, observations: immutable evidence references
  alternatives, counterevidence, unknowns, quality_flags, staleness_reason?

SourceRef (normalized):
  source_snapshot_id, pointer, upstream_uri?, field, assertion_kind
  assertion_kind: advisory_fact | binary_observation | rule_hypothesis | analyst_statement

Identifiers: domain_id(namespace, revision, canonical JSON) per existing identity pattern; sorting and serialization deterministic. No naked broad object references or absolute user file paths in exported reports.

## 6. Pure service interface and state transitions

Expose one facade src/patchtrace/patch_search/service.py:

  search_kb(query, sources, cancel) -> SearchOutcome
  describe_cves(variant, snapshots) -> tuple[KbCveEdge, ...]
  suggest_components(variant, edges, known_components) -> tuple[ComponentHint, ...]
  resolve_pairs(filename, variant, index, local_inputs) -> tuple[PairCandidate, ...]
  plan_acquisition(pair, consent_preview) -> AcquisitionDecision
  materialize_pair(decision, transport, cancel) -> MaterializedPair
  attach_to_project(session, project_service) -> AttachedSearch
  build_expectations(session, ruleset) -> tuple[PatchHypothesis, ...]
  interpret_comparison(session, project_snapshot, engine_reports) -> TriageOutcome
  explain(session_id, cve_id?) -> EvidenceReadModel

All service methods must take validated typed inputs, not UI widgets, and produce structured partial results on recoverable provider failure. Only materialize_pair has binary network side effects; attach_to_project is the only project mutation. No direct Qt imports. Never silently trigger Run Comparison. The existing ProjectService remains the authority for artifact import, file identity and SQLite ownership.

State machine:
  draft -> discovered -> product_selected -> pair_selected
       -> acquired -> project_attached -> analysis_pending -> analyzed
  offline/manual recovery exists from discovered, product_selected or blocked acquisition
  cancellation retains valid immutable cache/snapshots but does not commit an incomplete project
  alternative pairs become explicit separate sessions/projects rather than overwrite current pair

Pair approval gates:
 G1 same basename, PE type and machine family.
 G2 SHA-256 differ, older/newer order source-backed or deliberately overridden.
 G3 selected product variant compatible with both binary identities, else exploratory with explicit limitations.
 G4 hashes verified against declared expected metadata; no quarantine bypass.
 G5 project path available and write transaction atomic.
 G6 pre-fix/fixed status remains an independent advisory-vs-binary judgment.

## 7. UI view-model (not a proposed screenshot)

The top-level dialog has three master areas:
  left: numbered steps and search query
  center: product/update table; CVE list; component candidate table; pair options
  right: fact/provenance inspector and "What we might look for" text

Toolbar: Search; Import saved advisory; Offline only; Open Microsoft Catalog page; Select product; Refresh sources; Cancel.
Pair editor: older/newer version+SHA+size+arch+source+status; swap; manual file import; acquire verified pair.
Project handoff: create project (not overwrite), show preflight, Run Comparison (existing action).
Post-run: Patch Intelligence dock with per-CVE status, top changed-function candidates, observed signal, raw/source excerpt, alternatives, unresolved queue and "Open diff at finding". Pinned analysis-run selector if more than one exists.

Visible status wording examples:
  "CVE mapped to this KB for Windows product X (official MSRC remediation)"
  "Filename candidate only. Advisory does not identify the file."
  "Hash matched Winbindex metadata; signature was not validated."
  "Post-update binary available. Pre-fix status of older binary is not established."
  "Change is consistent with a bounds-check hypothesis; CVE attribution unverified."
  "No supported reconstruction path. Import older/newer PE files manually."

## 8. Network, archive, and execution boundaries

Offline default. Show exact requested providers/hosts and anticipated payload sizes where known before consent. Use static host allowlists, HTTPS, bounded redirect handling and real content/time/record caps. For new source adapters, propose: advisory max 32 MiB compressed / 128 MiB expanded, maximum 25,000 parsed nodes, nesting max 64, 30 s request deadline, no more than 3 retries; revise by fixture evidence before shipping. Reuse existing stricter policy when applicable. No session IDs, local file paths or project content in URLs or headers. Ignore ambient proxy settings consistently with current transports. Never keep Azure blob SAS URLs.

Package handlers: require non-executable extraction, central directory/entry count caps, size/ratio caps, path traversal + symlink rejection, no writes outside operation-private staging, disk budget; never execute supplied installer binaries, MSU, CAB scripts, or extracted PE. Disable autoplay/installer invocation. Third-party binary acquisition adapters must pass origin trust review. Windows-only DISM/servicing experiments MUST target a disposable mounted offline image, not /Online. A failed reconstruction must never be promoted.

Verification: SHA-256 of full bytes, parsed PE signature + machine, expected version/product checks, optional Authenticode/catalog signing with explicit result and offline revocation limitation. Metadata hashes are not proof of provenance when provider data is third-party; keep verification layers distinct.

No data from a low-trust advisory, catalog title, downloaded manifest or filename is ever passed as shell text, a generated executable command or a prompt instruction. Network data is displayed as escaped plain text; all background tasks cancellable.

## 9. Reporting, cache, and staleness

**Storage clarification:** The optional `patch_search.sqlite3` companion store is separate from `project.sqlite3` because current `ProjectStore` strictly validates its schema version. Existing ComparisonProject remains unchanged. Two-phase attach and idempotent recovery in SPEC-32B supersede any implied cross-database atomic transaction here. A successful project create cannot be deleted or declared corrupt merely because attaching patch context failed; display CONTEXT_PENDING and provide retry.

Persist an append-only reference to SourceSnapshot and PatchSearchSession in a separate versioned table/namespace; do not modify ComparisonProject.artifacts shape or its exactly-two-artifact constraint. Write per-operation source/object bytes atomically with a bounded content-addressed cache and verification on read. Record actual source digest, parser and rule versions, selected product, exact filename and pair hashes. Do not persist signed redirect URLs, private tokens or full absolute paths in exports.

Dependency fingerprint for a localization result:
  project revision + ordered older/newer SHA-256 + analysis run digest
  + advisory snapshot digests + product mapping/variant
  + engine evidence digest(s) + matching override revision + ruleset version

When any dependency changes: mark localization stale, keep audit history, compute replacement only on request/approved background task. Source fetch failure must leave last known good source marked stale, not erase it. Swapping orientation invalidates boundary claims and expectations.

## 10. CLI contract, additive

CLI syntax, defaults, error codes and exact JSON envelopes are now fixed in [SPEC-32C](kb-patch-search-ui-cli-contract.md). The earlier placeholder command list has been superseded.

Illustrative valid end-to-end commands: local `patchtrace patch search KB5012345 --scope-file corpus.json --json`; `patchtrace patch pairs --session session.json --product-id P-CLIENT --file clfs.sys --json`; `patchtrace patch fetch --session session.json --pair-id ID --project DIRECTORY --consent-hosts winbindex.m417z.com,msdl.microsoft.com --json`; and offline `patchtrace patch explain DIRECTORY --cve CVE-2024-12345 --json`. Any actual fetched source requires an explicit scope, consent and validated supported origin. Bare search never connects to a network.

Existing `acquire` and `correlate` subcommands and global `enrichment-cli/1` outer JSON envelope stay backward compatible.

## 11. Acceptance criteria (hard gates)

A01. KB variants are not mixed across product/architecture; a single KB with 2 products and 3 CVEs yields only source-supported product edges.
A02. Known CVRF fixture Type-2 KB association parses per ProductID and pointer; unrelated vulnerability from the same monthly bulletin is excluded.
A03. Source revision conflicts, supersedence, many-to-many KB/CVE relationships and CVE with no KB are represented without data loss.
A04. KB search by itself uses cache only; consent test verifies no hidden network.
A05. Pair decision never claims pre-fix from date sorting or same filename alone.
A06. Realistic no-filename advisory supports manual filename/PE import without fake candidate.
A07. Existing SPEC-08 acquire search/fetch and UI paths pass unchanged.
A08. Valid full-PE pair downloads, hashes, architecture and quarantine checks, creates ordinary project, attaches source provenance.
A09. Hash mismatch, PA30-only, PSFX-only, product mismatch, same hashes, no baseline and wrong architecture each fail closed with distinct recoverable status.
A10. Cancellation during metadata, download, extraction and project creation does not leave incomplete project or corrupt cache.
A11. CSAF/CVRF and manual source strings containing HTML/script injection are displayed escaped and never executed.
A12. Offline imported snapshot -> manual pair -> comparison -> explanation succeeds without DNS/network.
A13. Stale localization detection on swap, file replacement, new run, source revision and analyst match correction.
A14. Real Windows frozen EXE GUI test, 125/150/200% DPI, Narrator, tab order, tooltips and worker-connection ownership.
A15. Reference golden corpus of ≥20 source/product cases incl. at least 5 adversarial mismatches; no unsupported "vulnerability proven" assertions.
A16. Bench budgets: pure cached search <500 ms for 1K edges on developer baseline, UI thread <100 ms blocking per action, sustained 10k rows via paged/model-backed tables, no unbounded memory/CPU amplification. Measure and publish actual results rather than assume compliance.

## 12. Explicit out-of-scope in v1

Guaranteed fully automatic CVE-to-file reverse mapping; every Windows/Office/Edge product; undocumented Catalog web scraping as sole data source; installing KBs on host; universal PSFX hydration; bypassing protected update downloads; exploit generation; claiming a CVE is fixed based on binary heuristics; ML "probabilities" without held-out calibration; changing existing comparison engines.

## 13. Implementation and open product decisions

Follow the companion implementation plan and integration notes. Default unresolved decisions for a v1 prototype: x64 Windows kernel/user-mode PE first; MSRC CVRF first, CSAF next; one analyst-selected pair; Windows MSI/PSFX package reconstruction deferred; offline/manual mode mandatory; ordinal hypothesis descriptions only; separate New patch-search wizard and post-run dock; branch/PR independently from ongoing unified-engine work.

Before shipping, record approved decisions on:
 D1. Microsoft Update Catalog automation policy: official/supportable metadata adapter vs manual browser-assisted import.
 D2. Optional supported Windows package servicing in an isolated image; OS/privilege requirements.
 D3. Canonical KB matching scope (MSRC CVRF only first, then CSAF, WUA metadata).
 D4. Product identity baseline verification rules and responsibility for reviewed mappings.
 D5. Source caching retention and licensing terms for third-party index data.
 D6. Whether bulk candidate project creation is offered behind an advanced toggle.

## 14. Source review and caveats

Specifications were cross-checked with the repo and the following source documentation on 2026-10-14; external API schemas and provider behavior must be pinned and verified with real fixtures before code is released:
- https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API
- https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/main/src/MsrcSecurityUpdates/Public/Get-MsrcCvrfAffectedSoftware.ps1
- https://msrc.microsoft.com/csaf
- https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/manage/wsus-and-the-catalog-site
- https://learn.microsoft.com/en-us/windows/deployment/update/psfxwhitepaper
- https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesearcher
- https://github.com/m417z/winbindex
