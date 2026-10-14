# SPEC-31-A: Canonical Contracts, Identity, Provenance and Compatibility

Status: developer-ready sub-specification; design only. Parent: [SPEC-31](../kb-cve-correlation-and-acquisition.md). Contract: kbcorrelation/1. Owner: contracts worker. No network, Qt or project writes.

## A1. Scope and implementation decisions

Build an immutable, import-safe domain layer before any provider/UI work. Reuse existing enrichment.identity.domain_id, enrichment.intelligence.validate_cve_id and acquisition.contracts records at their respective boundaries. Do not alias/redefine the existing BuildCandidate, CveSnapshot, Project or Finding models. SPEC-31 adapters must transform them, recording source version and transformation errors. All output JSON has explicit contract and revision; unknown future major versions fail closed. Additive optional fields require defaults and migration tests.

Persist four independent truths: documented KB/CVE/product association, estimated build/product applicability, acquired artifact identity, and code-change hypothesis. No field called confidence can silently combine these dimensions. Do not give one object simultaneous mutable source claims and analyst annotations.

Source bytes, canonical normalized facts, derived selection and user decision are separate records. A source digest cannot imply cryptographic authenticity of publisher. Generated schema files are built from Pydantic, checked into docs/schemas/kbcorrelation, and compared byte-for-byte in CI.

## A2. Frozen value types

KB normalization at the untrusted boundary: trim Unicode whitespace, case-insensitive leading KB prefix optional in UI only, ASCII digits only, 4..10 digits per SPEC-31 syntactic policy; normalize as KB + digits without numeric casting (do not drop leading zero unless evidence shows canonical equivalence). Reject signs, separators, exponent notation, bidi controls and embedded whitespace. For CLI, permit an explicit alternate numeric mode only behind separately tested option. CVE: delegate to current validate_cve_id and require exact uppercase spelling. Pydantic models must be strict, frozen, extra forbid. Use Annotated validators for Hash, KB, CVE and UTC time, and a TypeAdapter for input discriminated unions.

Typed identities, string serializations:
- SourceDocumentId: domain_id('kbc.source', 1, {kind, body_sha256, canonical_source_uri_or_local_origin}). The same bytes from different URLs remain separately sourced.
- ProductScopeId: domain_id('kbc.product',1,{authoritative_product_id, family, release, arch, channel, edition, build, locale}); omit null only through canonical serializer, not falsy filtering.
- EdgeId: domain_id('kbc.edge',1,{kb,cve,product_scope_id,semantics,source_document_id,locator,release_revision}); never reuse across differing provenance.
- CandidateId: domain_id('kbc.binary',1,{sha256,basename,variant_scope_id}); if sha unknown use 'unresolved candidate' ID scoped to origin and do not promote to concrete artifact ID.
- PairId: domain_id('kbc.pair',1,{older_sha,newer_sha,product_scope_id,window_id}); ordered side is identity.
- InvestigationId: persistent UUID assigned once at initial search; deterministic derived IDs may not replace persistent project links.

SHA-256 must be exactly 64 lowercase hexadecimal characters. PDB GUID+age is optional and is not interchangeable with file SHA. Artifact byte digest always refers to the final complete PE, not compressed transport bytes.

## A3. Required persisted aggregates

Implement separate Pydantic records and generated JSON schemas:
- SourceDocument: id, source_kind, source_uri?, acquisition_mode (consented|offline-imported), fetched_at?, sha256, bytes, schema_id/version?, revision?, publisher_claim?, authenticity_state, raw_blob_ref, parser_version, validation_warnings.
- SourceCoverage: query_id, source_id, scope_start?, scope_end?, completed_segments[], failed_segments[], observed_documents, succeeded_documents, parsed_documents, partial_reason?, is_exhaustive_for_scope boolean, query_params_digest. A zero-result partial scan must never become NOT_FOUND.
- ProductScope: id, issuer_identifier?, canonical/display names, family, release, architecture, servicing_channel, edition, locale?, full_build?, mapping_state, evidence_ids.
- RemediationLink: edge_id, kb, cve, product_scope_id, document_id, pointer, remediation_kind, vendor_relation, explicit_fix_state, release_id?, fixed_build?, effective_date?, conflict_ids. Document membership and remediation are distinct relation kinds.
- BinaryCandidate: id, basename, proposed_product_scope_id, sha256?, size?, file_version?, pdb_signature?, machine?, package_identity?, update_associations[], availability, source_ids[], authenticity_state.
- PairProposal: id, old/new candidate IDs, source/target release, product_scope_id, update_window[], asserted_lineage boolean, ordinal_pair_grade, hard_blocks[], warnings[], provenance_ids[]; reason codes are machine readable.
- InvestigationRevision: revision_id, investigation_id, parent_revision_id?, selected_product_id?, selected_pair_id?, source_ids[], coverage_ids[], status, created_at, selection_assertions[], warnings[].
- ProjectLink: project identity, investigation/revision ID, old/new SHA, current project revision, active_run_id?, attach_time, stale_reasons[].
- AnalystDecision: separate append-only record: operation, exact prior->next value, user reason, timestamp, referenced evidence, current/stale state.

Use immutable tuple arrays for canonical lists. Store null for unknown, do not use absent array for unknown (empty means searched and none found only when coverage is complete).

## A4. Exact public interfaces

~~~python
from dataclasses import dataclass
from typing import Generic, Literal, Protocol, TypeVar
T = TypeVar('T')
Stage = Literal['ok','partial','unknown','unsupported','cancelled','error']
@dataclass(frozen=True)
class OperationResult(Generic[T]):
    status: Stage
    value: T | None
    errors: tuple['KbError', ...]
    warnings: tuple[str, ...]
    provenance_ids: tuple[str, ...]
class KbError(Exception):
    code: str
    safe_message: str
    details: dict[str, str]  # redacted structured values only
    recoverable: bool
class CancelToken(Protocol):
    def raise_if_cancelled(self) -> None: ...
~~~

Invariants: ok requires value and no blocking errors; partial requires value plus incompleteness; cancelled cannot persist a new committed result; error must not claim success. If a missing optional provider returns unsupported, other providers may still produce ok/partial. A transport exception is mapped once at provider boundary, retaining original typed PT-ACQ / PT-ENRICH code as a safe nested detail.

Facade public commands must accept a validated immutable request plus source/cache/cancel context; return OperationResult. No direct writer access is exposed through read-only methods. Define a stable Protocol and compatibility tests for each adapter. Keep domain modules fully usable with imports blocked for PySide6, urllib, subprocess and sqlite3.

## A5. Referential integrity

Every evidence_id points to an existing source document + JSON pointer/record locator or to a verified binary/run function record. A normalized claim must be recoverable from immutable input bytes under its recorded parser revision. Reject mismatched source digest and dangling links. Content deduplicate only exact bytes; do not dedupe semantics across advisory revisions. The current view can choose the latest revision, but must retain earlier contradictory revisions as evidence.

Verify cross-record constraints:
- selected_product_id must exist in the referenced investigation revision;
- selected_pair belongs to same product scope or records explicit user assertion;
- any ready_for_comparison pair has known distinct hashes, same basename and valid final PE on both sides;
- attached project old/new hash and orientation match exactly;
- a different run_id cannot inherit earlier evidence references;
- provider strings are data, rendered escaped/plain text in UI and exports.

## A6. Migration and compatibility protocol

A newly created project contains no KB records by default. No changes to the existing Project v1 JSON shape are required for the first slice. Use the existing service-owned extension/auxiliary storage mechanism after inspection: if unavailable, add migration v2 with transactional copy-and-verify backup and keep v1 readable. Never write SQLite from a Qt worker or a provider. Store investigation snapshots externally in content-addressed cache until they are attached to a project.

Version policy: old major is explicitly migrated; same major with unsupported required fields is rejected; future major is not downgraded. Serialize with stable key ordering and explicit UTF-8, and compute derived identifiers only from stable normalized fields. Protect against path escape and unsafe bytes in exported source references.

## A7. Tests and freeze gate

Tests first: KB validation including Unicode/full-width digits, whitespace and 00001234; CVE delegation; null/empty semantics; source duplication across URLs and revisions; canonical IDs stable across insertion order and locale; SHA mismatch; product alias not promoted to equality; unknown JSON fields rejected; schema files regenerated deterministically; foreign project or function ID refused; missing optional provider; future major version rejected; existing projects still open without migration. Golden fixtures contain no Microsoft binaries.

Freeze gate: schemas, errors, IDs, import paths and adapter Protocol signatures approved and committed before parallel 31-B/C/D/E. Once frozen, changes require explicit versioned migration and integrator review.
