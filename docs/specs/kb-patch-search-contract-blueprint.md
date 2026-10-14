# SPEC-32E: Python Contract Blueprint, Result Shapes, and Integration Examples

Status: detailed examples for implementers (2026-10-14). NOT runtime code; copy snippets only after aligning with actual module naming and CI.
Related: SPEC-32 master and annexes A-D.
Reason for this annex: the previous design named DTO fields but did not prescribe all type boundaries and incompatibility semantics. This document closes those integration gaps while preserving existing enrichment/1, acquisition/1 and ComparisonProject schemas.

## 1. Pydantic conventions

Repository pyproject.toml pins Pydantic 2.13.5 and Python >=3.12. Use frozen, strict models with extra fields forbidden, matching current src/patchtrace/enrichment/contracts.py. Reuse its identity.domain_id or an agreed local wrapper; do not create incompatible random IDs.

Use persisted JSON enums with lower_snake_case exact values and define model/contract version explicitly. Unknown upstream fields are never silently retyped inside the normalized DTO; the *provider parser* must explicitly map them, with dialect-version tests.

Illustrative example code:

~~~python
from __future__ import annotations

import re
from typing import Literal, Annotated
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from patchtrace.enrichment.identity import domain_id

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Kb = Annotated[str, Field(pattern=r"^KB[0-9]{4,9}$")]
Cve = Annotated[str, Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]

class PatchRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    contract: Literal["patch-search/1"] = "patch-search/1"

class SourceReference(PatchRecord):
    snapshot_sha256: Sha256
    pointer: str = Field(min_length=1, max_length=1024)
    assertion: Literal[
        "advisory_fact", "binary_observation",
        "rule_hypothesis", "analyst_statement",
    ]
    field: str = Field(min_length=1, max_length=128)

class KbQuery(PatchRecord):
    kb: Kb

    @field_validator("kb", mode="before")
    @classmethod
    def canonical_kb(cls, value: object) -> str:
        if type(value) is not str:
            raise ValueError("KB must be a string")
        s = value.strip(" \t")
        if not re.fullmatch(r"(?:KB)?[0-9]{4,9}", s, re.IGNORECASE):
            raise ValueError("expected KB1234567 or 1234567")
        s = s.upper()
        return s if s.startswith("KB") else "KB" + s

class KbCveEdge(PatchRecord):
    edge_id: Sha256
    kb: Kb
    cve: Cve
    product_id: str = Field(min_length=1, max_length=256)
    association: Literal["confirmed", "proposed", "conflicting", "unknown"]
    basis: Literal[
        "cvrf_type2_product", "csaf_explicit_product",
        "csaf_textual_hint", "analyst", "date_only",
    ]
    sources: tuple[SourceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_truth(self):
        if self.association == "confirmed" and self.basis not in (
            "cvrf_type2_product", "csaf_explicit_product",
        ):
            raise ValueError("unattributed source cannot confirm KB/CVE")
        return self

def edge_id(source_sha: str, cve: str, product_id: str,
            pointer: str, kb: str) -> str:
    return domain_id("kb-cve-product-edge", 1, {
        "snapshot_sha256": source_sha, "cve": cve,
        "product_id": product_id, "pointer": pointer, "kb": kb,
    })
~~~

Notes:
- This example intentionally allows a bare numeric input only through a validator, never stores numbers as integers. Pydantic strict mode applies to output after conversion. Write tests for whitespace/newline and Unicode lookalikes.
- Accepted CVE ID length and regex should use the existing validate_cve_id in enrichment/intelligence.py or an equivalent shared canonical validator, not ship divergent two-regex validation.
- A CSAF "confirmed" explicit KB/product association requires a stronger normalized source proof than mere lexical KB occurrence. Never label a textual hint confirmed.
- A Pydantic-generated JSON Schema is part of a versioned, checked-in artifact; generate from code and compare against fixture to avoid drift.
- A field named sha256 never means a generic cache object ID unless bytes being hashed are explicitly stated.

## 2. Discriminated results and partial-state model

Do not expose unchecked Exception instances across GUI/CLI boundaries. Typed error objects:

~~~python
class PatchIssue(PatchRecord):
    code: Literal[
        "PT-PATCH-INPUT", "PT-PATCH-SCOPE", "PT-PATCH-SOURCE",
        "PT-PATCH-PRODUCT", "PT-PATCH-PAIR", "PT-PATCH-VERIFY",
        "PT-PATCH-CONSENT", "PT-PATCH-CANCEL", "PT-PATCH-STATE",
        "PT-PATCH-STORAGE", "PT-PATCH-UNSUPPORTED", "PT-PATCH-LIMIT",
    ]
    message: str = Field(min_length=1, max_length=500)
    recoverable: bool = False
    source_id: str | None = None

class SearchCoverage(PatchRecord):
    state: Literal[
        "complete_in_scope", "partial_in_scope",
        "stale_cache", "unknown_scope", "not_searched",
    ]
    inspected_document_ids: tuple[str, ...] = ()
    failed_document_ids: tuple[str, ...] = ()
    requested_document_ids: tuple[str, ...] = ()

class SearchOutcome(PatchRecord):
    status: Literal[
        "complete", "partial", "scope_required",
        "source_unavailable", "cancelled",
    ]
    query: KbQuery
    coverage: SearchCoverage
    edges: tuple[KbCveEdge, ...] = ()
    variant_ids: tuple[str, ...] = ()
    issues: tuple[PatchIssue, ...] = ()

    @model_validator(mode="after")
    def prevent_false_complete(self):
        if self.status == "complete":
            if self.coverage.state != "complete_in_scope":
                raise ValueError("cannot claim complete with incomplete scope")
            if (not self.coverage.inspected_document_ids
                    and not self.coverage.requested_document_ids):
                raise ValueError("complete search requires explicit evaluated corpus")
        return self
~~~

Semantics:
- "No confirmed edges in a finite evaluated scope" is a valid complete outcome with empty edges.
- Provider errors yield partial/source_unavailable, never empty complete result.
- CANCELLED is not a source failure; preserve prior immutable successful cache results, with no session attachment side effects.
- Product mismatch is not interpreted as provider failure.
- A partial source result can still return useful edges, even when the CLI returns a nonzero partial exit depending on selected policy.

## 3. Pair contracts and source-proof categories

Suggested DTOs:

~~~python
class BinaryIdentity(PatchRecord):
    sha256: Sha256
    basename: str
    size: int = Field(gt=0)
    machine: int = Field(ge=0, le=65535)
    file_version: tuple[int, int, int, int] | None = None
    product_id: str | None = None
    product_identity_status: Literal[
        "source_verified", "analyst_claimed", "unknown", "contradictory",
    ] = "unknown"
    format: Literal["pe", "pa30", "pa31", "psfx", "unknown"] = "unknown"
    acquisition_method: Literal[
        "symbol_server", "local_pe", "offline_image", "package_pending",
    ]

class PairDecision(PatchRecord):
    pair_id: Sha256
    old: BinaryIdentity
    new: BinaryIdentity
    compatibility: Literal[
        "verified", "exploratory", "blocked",
    ]
    fix_boundary: Literal[
        "source_supported", "unverified", "contradicted",
    ]
    blockers: tuple[str, ...] = ()
    analyst_override: bool = False
    source_refs: tuple[SourceReference, ...] = ()

    @model_validator(mode="after")
    def basic_pair(self):
        if self.compatibility == "verified":
            if self.old.format != "pe" or self.new.format != "pe":
                raise ValueError("automatic verified pair requires full PE")
            if self.old.sha256 == self.new.sha256:
                raise ValueError("identical content is not a patch pair")
            if self.old.machine != self.new.machine:
                raise ValueError("machine mismatch")
            if self.old.basename != self.new.basename:
                raise ValueError("file component mismatch")
        return self
~~~

A syntactically valid PairDecision does not replace the real acquisition/quarantine integrity tests. The validator above checks only necessary pair invariants; the separate service policy must verify bytes, product lineage and actual source facts before using compatibility="verified". Do not grant truth via a caller-supplied enum string.

Pair decision examples:
- Same PE hashes and same filename => compatibility blocked, blocker IDENTICAL_CONTENT.
- Distinct verified full PE hashes but unknown update fix boundary => compatibility verified or exploratory depending on lineage, fix_boundary unverified.
- New file PA30 and no exact base => compatibility blocked; no project create.
- Product data conflicting across two sources => compatibility exploratory/manual only, fix_boundary unverified or contradicted.
- Post-update build from source-supported fixed release with pre-update baseline verified => fix_boundary source_supported, but evidence localization remains not-run.

## 4. Component and candidate evidence joining

A component hint carries:
  filename (optional), product_id, hint_origin, source_refs, hint_status, rationale and unresolved.
Hint statuses are evidenced_file, suspected_file, analyst_selected, unknown_file.

Algorithm:
- Exact source-file manifest plus product identity can yield evidenced_file.
- Advisory mentions a subsystem like kernel memory manager; it cannot automatically map to ntoskrnl.exe or any specific driver.
- Analyst-typed clfs.sys is a selection, not evidence that CVE modifies clfs.sys.
- Winbindex filename index records build SHA/version/KB, but its KB presence alone is not official CVE-to-file mapping.
- Link possible filenames to CVEs via an explicit hypothesis graph, not by guessing file names from CVE title.
- Explain all negative candidates and alternate versions rather than silently pruning novel fixes.
- Duplicate two tool observations with shared Ghidra lineage are one correlated evidence group, not two votes.

## 5. Pure service ports

Define dependency inversion so test fixtures can replace each external service:

~~~python
from typing import Protocol

class AdvisoryCorpus(Protocol):
    def search(self, query: KbQuery, scope: object,
               cancel: object) -> SearchOutcome: ...

class BinaryCandidateIndex(Protocol):
    def find(self, basename: str, product_variant_id: str,
             cancel: object) -> object: ...

class PairPlanner(Protocol):
    def propose(self, older: BinaryIdentity, newer: BinaryIdentity,
                context: object) -> PairDecision: ...

class VerifiedPairMaterializer(Protocol):
    def acquire(self, plan: object, consent: object,
                cancel: object) -> object: ...

class ProjectAttacher(Protocol):
    def attach(self, session: object, project_id: str,
               revision: int, ordered_shas: tuple[str, str]) -> object: ...

class EngineEvidenceReader(Protocol):
    def read(self, project_id: str, run_id: str,
             ordered_shas: tuple[str, str]) -> object: ...
~~~

This sketch uses object placeholders intentionally; replace them with exact DTOs in P0 before coding and compile mypy/pyright or other repository-approved type validation when available. The rule is that source fetching, pair planning, project mutation and UI never share mutable state or implicit global singletons.

One composition root (patch_search/service.py) binds the implementations. Pure parser/decision modules have no Qt, network or file-system mutation imports. Don't add reverse imports from acquisition/enrichment/engines into patch_search just to call helpers. Keep engine evidence read-only.

## 6. Schema/version upgrade and persisted view

External contract names:
- patch-search/1 (source/session/read model)
- patch-pair-plan/1 (exact verified acquisition plan)
- patch-triage/1 (run-linked interpreted findings)
- patch-search-sidecar/1 (companion schema marker, independent of core project database)

Rules:
- Changes to a serialized enum's meaning or a required field need a new contract version and a migration read adapter. Additive optional fields with default may remain on version 1 if JSON representation preserves compatibility.
- Core project schema stays at existing supported version. Old PatchTrace can ignore optional sidecar file without data loss.
- Do not treat absolute file paths, signed SAS URLs or API keys as immutable source facts.
- Select exactly one stable ID approach per object class and unit test that sorting and locale do not change it.
- Use strict round-trip fixture tests: model_validate_json, model_dump(mode=json), generated JSON Schema, and rejected wrong-types/extra-fields.

## 7. CLI scenario expected result, synthetic

Given:
- imported fixture CVRF monthly source lists P-CLIENT, CVE-2024-12345 and KB5012345 under Type 2;
- a separate same-month CVE unrelated to this KB;
- no filename in advisory;
- offline-only source corpus selected.

Expected patch search result (schematic):
    status = complete
    coverage = complete_in_scope, inspected=one pinned monthly CVRF
    product variant = P-CLIENT
    edges = one confirmed KB5012345/CVE-2024-12345/P-CLIENT source-bound edge
    component hints = none
    pair candidates = none before analyst selects filename
    UI text = "CVE association confirmed for selected product; affected binary unknown"
    network requests = 0

After analyst supplies two synthetic verified PE files:
    pair compatibility = verified or exploratory by available lineage
    fix boundary = unverified (because sample advisory lacks exact file/build mapping)
    project created = ordinary two-artifact project
    sidecar attached = record project ID/ordered hashes and source snapshot
    analysis = not automatically started
    pre-run rule output = source-linked hypothetical code motifs
    post-run = only those function observations attached to correct hash+run IDs

Negative expected: the application NEVER turns this into "CVE-2024-12345 verified fixed by modifying function X" without independent actual evidence.

## 8. Contract-focused implementation acceptance

E01 All Pydantic models frozen/strict and reject unknown fields.
E02 Canonical KB IDs preserve string digits and reject Unicode/confusables.
E03 Remediation source refs and product IDs required for confirmed edges.
E04 Unbounded/no-source query cannot return complete coverage.
E05 Pair model blocks full-PE-required failures and identical hashes.
E06 Product and pre-fix boundary remain independent from basic PE verification.
E07 Current project/analysis run pairing and source digests validated before triage.
E08 Repo-wide imports remain acyclic and headless pure-models import without PySide6.
E09 JSON schema generated from typed models and drift regression checked.
E10 Old acquisition/1, enrichment/1 and project snapshot schemas remain unmodified.
