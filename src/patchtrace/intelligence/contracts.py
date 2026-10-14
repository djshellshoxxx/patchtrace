"""Strict, frozen ``intelligence/1`` records (SPEC-28a/b, csaf-cve-interpretation-engine.md section B).

Pure: no Qt, network or I/O. Every record forbids extra fields and coerces nothing (strict mode),
and every collection is a tuple in a canonical order, so a dump is deterministic. Records loaded
from storage must be parsed with ``model_validate_json`` (JSON arrays become tuples there).

Vocabulary that keeps claims honest: ``advisory-claim`` (what a vendor document states, with its
JSON pointer), ``rule-hypothesis`` (PatchTrace's curated interpretation), ``search-hint`` (an anchor)
and ``unknown``. Nothing in this contract can express "vulnerability verified in a function".
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CONTRACT = 'intelligence/1'
MAX_TEXT = 1_048_576  # matches the validator's string cap
MAX_PRODUCTS = 100_000
MAX_VULNERABILITIES = 10_000

Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
# RFC 6901 JSON pointer; "" addresses the whole document.
Pointer = Annotated[str, Field(max_length=4096, pattern=r'^(/([^/~]|~[01])*)*$')]
CveId = Annotated[str, Field(max_length=24, pattern=r'^CVE-[0-9]{4}-[0-9]{4,19}$')]
CweId = Annotated[str, Field(pattern=r'^CWE-[1-9][0-9]{0,5}$')]
Timestamp = Annotated[str, Field(max_length=40, pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
                                                       r'(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$')]
Text = Annotated[str, Field(max_length=MAX_TEXT)]
Short = Annotated[str, Field(min_length=1, max_length=1000)]
Version4 = Annotated[str, Field(pattern=r'^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$')]
Side = Literal['older', 'newer']

ErrorCode = Literal['PT-INTEL-INPUT', 'PT-INTEL-FORMAT', 'PT-INTEL-LIMIT', 'PT-INTEL-VALIDATE',
                    'PT-INTEL-UNSUPPORTED', 'PT-INTEL-CONFIG', 'PT-INTEL-NETWORK', 'PT-INTEL-PROVIDER',
                    'PT-INTEL-INTEGRITY', 'PT-INTEL-NOTFOUND', 'PT-INTEL-CANCEL', 'PT-INTEL-STORAGE']
ProductStatus = Literal['first_affected', 'first_fixed', 'fixed', 'known_affected', 'known_not_affected',
                        'last_affected', 'recommended', 'under_investigation']
PRODUCT_STATUSES: tuple[str, ...] = ('first_affected', 'first_fixed', 'fixed', 'known_affected',
                                     'known_not_affected', 'last_affected', 'recommended', 'under_investigation')
StatusClass = Literal['affected', 'not_affected', 'fixed', 'under_investigation']
# CSAF 2.0 §6.1.6 contradiction groups; `recommended` belongs to none of them.
STATUS_CLASS: dict[str, str] = {
    'first_affected': 'affected', 'known_affected': 'affected', 'last_affected': 'affected',
    'known_not_affected': 'not_affected', 'first_fixed': 'fixed', 'fixed': 'fixed',
    'under_investigation': 'under_investigation'}
Resolution = Literal['affected', 'not_affected', 'fixed', 'under_investigation', 'contradictory', 'ambiguous',
                     'unknown']
MappingStatus = Literal['verified', 'candidate', 'unknown']
BranchCategory = Literal['architecture', 'host_name', 'language', 'legacy', 'patch_level', 'product_family',
                         'product_name', 'product_version', 'product_version_range', 'service_pack',
                         'specification', 'vendor']
NoteCategory = Literal['description', 'details', 'faq', 'general', 'legal_disclaimer', 'other', 'summary']
CweBasis = Literal['explicit-csaf-cwe', 'cwe-id-in-text', 'curated-vocabulary']
LexiconScope = Literal['weakness', 'effect', 'component', 'primitive']


class IntelError(Exception):
    """Typed failure. ``message`` is user-safe (no local paths, no advisory text beyond a short excerpt)."""

    def __init__(self, code: ErrorCode, message: str, *, recoverable: bool = False, pointer: str | None = None):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message
        self.recoverable = recoverable
        self.pointer = pointer


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Contract(Record):
    contract: Literal['intelligence/1'] = CONTRACT


def _sorted(values, key=None) -> bool:
    items = list(values)
    keyed = [key(v) for v in items] if key else items
    return keyed == sorted(keyed)


# ---------------------------------------------------------------------------------------------- validation

class Finding(Record):
    """One validation result. ``test`` is a CSAF 2.0 section id (``6.1.1``), ``schema``, ``json`` or ``limit``."""
    test: str = Field(min_length=1, max_length=32)
    severity: Literal['error', 'warning']
    pointer: Pointer
    message: str = Field(min_length=1, max_length=500)


class ValidationReport(Contract):
    validator_version: int = Field(ge=1)
    document_category: str = Field(max_length=1000)
    errors: tuple[Finding, ...] = ()
    warnings: tuple[Finding, ...] = ()
    tests_run: tuple[str, ...] = ()
    tests_not_implemented: tuple[str, ...] = ()
    truncated: bool = False

    @property
    def valid(self) -> bool:
        return not self.errors


# ---------------------------------------------------------------------------------------------- sources

class AdvisorySource(Contract):
    """One acquisition of exact bytes. ``source_id`` is the content SHA-256; ``retrieval_id`` the event."""
    source_id: Sha256
    retrieval_id: Sha256
    origin: Literal['local-import', 'https-fetch']
    uri: str | None = Field(default=None, max_length=2048)
    file_name: str = Field(min_length=1, max_length=255)
    retrieved_at: Timestamp
    sha256: Sha256
    size: int = Field(ge=1, le=16 * 1024 * 1024)
    tracking_id: Short
    revision: Short
    tracking_status: Literal['draft', 'final', 'interim']
    initial_release_date: Timestamp
    current_release_date: Timestamp
    schema_version: Literal['2.0']
    document_category: Short
    publisher_name: Short
    publisher_namespace: str = Field(min_length=1, max_length=2048)
    publisher_category: Literal['coordinator', 'discoverer', 'other', 'translator', 'user', 'vendor']
    authenticity_state: Literal['unverified-local-file', 'tls-allowlisted-host', 'tls-allowlisted-host-hash-match']
    signature_state: Literal['not-checked'] = 'not-checked'
    self_urls: tuple[str, ...] = Field(default=(), max_length=64)
    filename_matches_tracking_id: bool | None = None
    raw_path: str = Field(min_length=1, max_length=255, pattern=r'^intelligence/csaf/sources/[0-9a-f]{64}\.json$')

    @model_validator(mode='after')
    def _consistent(self):
        if self.source_id != self.sha256:
            raise ValueError('source_id must equal the content SHA-256')
        if self.raw_path != f'intelligence/csaf/sources/{self.sha256}.json':
            raise ValueError('raw_path must name the content-addressed sidecar')
        if self.origin == 'local-import':
            if self.uri is not None or self.authenticity_state != 'unverified-local-file':
                raise ValueError('a local import has no URI and is unverified')
        elif self.uri is None or not self.uri.startswith('https://') or \
                self.authenticity_state == 'unverified-local-file':
            raise ValueError('a fetched source needs its https URI and a TLS authenticity state')
        if '/' in self.file_name or '\\' in self.file_name:
            raise ValueError('file_name is a base name, never a path')
        return self


# ---------------------------------------------------------------------------------------------- products

class BranchStep(Record):
    category: BranchCategory
    name: Short


class FileHash(Record):
    file_name: Short
    sha256: Sha256


class Identification(Record):
    cpe: str | None = Field(default=None, max_length=10_000)
    purl: str | None = Field(default=None, max_length=10_000)
    sha256_hashes: tuple[FileHash, ...] = Field(default=(), max_length=10_000)


class RelationshipRef(Record):
    category: Literal['default_component_of', 'external_component_of', 'installed_on', 'installed_with',
                      'optional_component_of']
    product_reference: Short
    relates_to_product_reference: Short


class Product(Record):
    product_id: Short
    name: Short
    definition: Literal['branch', 'full_product_name', 'relationship']
    pointer: Pointer
    branch_path: tuple[BranchStep, ...] = Field(default=(), max_length=64)
    version: str | None = Field(default=None, max_length=1000)
    version_range: str | None = Field(default=None, max_length=1000)
    group_ids: tuple[str, ...] = ()
    relationship: RelationshipRef | None = None
    identification: Identification = Identification()

    @model_validator(mode='after')
    def _shape(self):
        if (self.definition == 'relationship') != (self.relationship is not None):
            raise ValueError('only relationship-defined products carry a relationship')
        if self.definition != 'branch' and self.branch_path:
            raise ValueError('only branch-defined products have a branch path')
        if not _sorted(self.group_ids) or len(set(self.group_ids)) != len(self.group_ids):
            raise ValueError('group_ids must be sorted and unique')
        return self


class ProductGroup(Record):
    group_id: Short
    product_ids: tuple[str, ...] = Field(min_length=2)
    summary: str | None = Field(default=None, max_length=10_000)
    pointer: Pointer


# ---------------------------------------------------------------------------------------------- vulnerability facts

class Note(Record):
    category: NoteCategory
    title: str | None = Field(default=None, max_length=1000)
    audience: str | None = Field(default=None, max_length=1000)
    text: Text
    pointer: Pointer


class CweRef(Record):
    id: CweId
    name: Short
    pointer: Pointer


class StatusClaim(Record):
    product_id: Short
    status: ProductStatus
    pointer: Pointer


class _Scoped(Record):
    """Shared shape of remediations, threats and flags: direct ids, group ids and the expansion."""
    product_ids: tuple[str, ...] = ()
    group_ids: tuple[str, ...] = ()
    via_groups: tuple[str, ...] = ()  # product ids reached only through group_ids
    date: Timestamp | None = None
    pointer: Pointer


class Remediation(_Scoped):
    category: Literal['mitigation', 'no_fix_planned', 'none_available', 'vendor_fix', 'workaround']
    details: Text
    url: str | None = Field(default=None, max_length=20_000)
    restart_required: str | None = Field(default=None, max_length=50)


class Threat(_Scoped):
    category: Literal['exploit_status', 'impact', 'target_set']
    details: Text


class Flag(_Scoped):
    label: Literal['component_not_present', 'inline_mitigations_already_exist',
                   'vulnerable_code_cannot_be_controlled_by_adversary', 'vulnerable_code_not_in_execute_path',
                   'vulnerable_code_not_present']


class Score(Record):
    """Severity context only (never a vulnerability probability). The score is kept as a decimal string."""
    cvss_version: Literal['2.0', '3.0', '3.1']
    base_score: str = Field(pattern=r'^(10(\.0)?|[0-9](\.[0-9])?)$')
    base_severity: str | None = Field(default=None, max_length=50)
    vector: str | None = Field(default=None, max_length=1000)
    products: tuple[str, ...] = Field(min_length=1)
    pointer: Pointer


class VulnerabilityId(Record):
    system_name: Short
    text: Short
    pointer: Pointer


class CVEFact(Contract):
    """One ``/vulnerabilities[]`` item exactly as the vendor states it (an advisory claim, never verified)."""
    source_id: Sha256
    cve: CveId | None = None
    pointer: Pointer
    title: str | None = Field(default=None, max_length=1000)
    cwe: CweRef | None = None
    notes: tuple[Note, ...] = ()
    product_status: tuple[StatusClaim, ...] = ()
    remediations: tuple[Remediation, ...] = ()
    threats: tuple[Threat, ...] = ()
    scores: tuple[Score, ...] = ()
    flags: tuple[Flag, ...] = ()
    ids: tuple[VulnerabilityId, ...] = ()
    assessment: Literal['advisory-claim'] = 'advisory-claim'

    @model_validator(mode='after')
    def _ordered(self):
        if not _sorted(self.product_status, key=lambda c: (c.product_id, c.status, c.pointer)):
            raise ValueError('product_status must be sorted by product id, status and pointer')
        return self


class AdvisoryFacts(Contract):
    """Normalized, content-derived view of one accepted CSAF document (same bytes, same facts)."""
    facts_id: Sha256
    normalizer_version: int = Field(ge=1)
    source_id: Sha256
    tracking_id: Short
    revision: Short
    current_release_date: Timestamp
    document_category: Short
    publisher_namespace: str = Field(min_length=1, max_length=2048)
    title: Short
    document_notes: tuple[Note, ...] = ()
    products: tuple[Product, ...] = Field(default=(), max_length=MAX_PRODUCTS)
    groups: tuple[ProductGroup, ...] = ()
    vulnerabilities: tuple[CVEFact, ...] = Field(default=(), max_length=MAX_VULNERABILITIES)
    validation: ValidationReport

    @model_validator(mode='after')
    def _ordered(self):
        ids = [p.product_id for p in self.products]
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            raise ValueError('products must be sorted by product_id and unique')
        if any(v.source_id != self.source_id for v in self.vulnerabilities):
            raise ValueError('every vulnerability fact must name this source')
        if not self.validation.valid:
            raise ValueError('facts exist only for documents that passed validation')
        return self

    def cves(self) -> tuple[str, ...]:
        return tuple(sorted({v.cve for v in self.vulnerabilities if v.cve}))

    def vulnerability(self, cve: str) -> CVEFact | None:
        return next((v for v in self.vulnerabilities if v.cve == cve), None)

    def product(self, product_id: str) -> Product | None:
        return next((p for p in self.products if p.product_id == product_id), None)


# ---------------------------------------------------------------------------------------------- identity

class PdbIdentity(Record):
    name: str = Field(min_length=1, max_length=260)  # base name only; build paths are never kept
    guid: str = Field(pattern=r'^[0-9A-F]{32}$')
    age: int = Field(ge=0, le=0xFFFFFFFF)


class ArtifactIdentity(Contract):
    """Identity facts for one side. Bytes-derived fields come only from verified bytes; the file name is
    never an identity fact. ``asserted_product_ids`` are analyst input and stay labelled as such."""
    side: Side
    sha256: Sha256
    file_version: Version4 | None = None
    product_version: Version4 | None = None
    pdb_identity: PdbIdentity | None = None
    asserted_product_ids: tuple[str, ...] = Field(default=(), max_length=64)
    facts_state: Literal['verified-bytes', 'record-only']
    notes: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode='after')
    def _state(self):
        if self.facts_state == 'record-only' and (self.file_version or self.product_version or self.pdb_identity):
            raise ValueError('bytes-derived identity facts require verified bytes')
        if list(self.asserted_product_ids) != sorted(set(self.asserted_product_ids)):
            raise ValueError('asserted_product_ids must be sorted and unique')
        return self


# ---------------------------------------------------------------------------------------------- applicability

class ProductMapping(Record):
    source_id: Sha256
    product_id: Short
    product_name: Short
    status: Literal['verified', 'candidate']
    basis: Literal['advisory-file-hash', 'relationship-from-verified-component', 'asserted-product-id',
                   'file-version-equals-product-version', 'same-product-name']
    detail: str = Field(max_length=500)


class StatusEvidence(Record):
    source_id: Sha256
    tracking_id: Short
    revision: Short
    document_category: Short
    product_id: Short
    product_name: Short
    status: ProductStatus
    status_class: StatusClass | None  # None for `recommended`
    pointer: Pointer
    superseded: bool
    assessment: Literal['advisory-claim'] = 'advisory-claim'


class SideApplicability(Record):
    side: Side
    identity: ArtifactIdentity
    product_mapping_status: MappingStatus
    mappings: tuple[ProductMapping, ...] = ()
    resolution: Resolution
    recommended: bool = False
    statuses: tuple[StatusEvidence, ...] = ()
    why: tuple[str, ...] = Field(min_length=1)
    assessment: Literal['advisory-claim', 'unknown']

    @model_validator(mode='after')
    def _abstain(self):
        if self.product_mapping_status == 'unknown' and (self.resolution != 'unknown' or self.mappings):
            raise ValueError('an unmapped side always abstains')
        if (self.resolution == 'unknown') != (self.assessment == 'unknown'):
            raise ValueError('assessment must be unknown exactly when the resolution is unknown')
        return self


class Contradiction(Record):
    kind: Literal['cross-revision', 'vex-vs-advisory', 'cross-document', 'orientation']
    product_name: str | None = Field(default=None, max_length=1000)
    claims: tuple[StatusEvidence, ...] = ()
    explanation: str = Field(min_length=1, max_length=1000)


class ApplicabilityReport(Contract):
    cve: CveId
    older: SideApplicability
    newer: SideApplicability
    contradictions: tuple[Contradiction, ...] = ()
    sources: tuple[Sha256, ...] = ()
    superseded_sources: tuple[Sha256, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode='after')
    def _sides(self):
        if self.older.side != 'older' or self.newer.side != 'newer':
            raise ValueError('older/newer sides are swapped')
        return self


# ---------------------------------------------------------------------------------------------- lexicon

class TermHit(Record):
    term_id: str = Field(min_length=1, max_length=64)
    phrase: str = Field(min_length=1, max_length=200)
    cwe_ids: tuple[CweId, ...] = ()
    scope: LexiconScope
    strength: Literal['strong', 'weak']
    negated: bool = False
    negation_cue: str | None = Field(default=None, max_length=40)
    pointer: Pointer
    excerpt: str = Field(max_length=300)


class CweClassification(Record):
    cwe_id: CweId
    family: str = Field(min_length=1, max_length=40)
    basis: CweBasis
    confidence: Literal['explicit', 'phrase-match', 'weak']
    hits: tuple[TermHit, ...] = ()
    pointers: tuple[Pointer, ...] = ()
    assessment: Literal['advisory-claim', 'rule-hypothesis']

    @model_validator(mode='after')
    def _honest(self):
        claim = self.basis in ('explicit-csaf-cwe', 'cwe-id-in-text')
        if claim != (self.assessment == 'advisory-claim'):
            raise ValueError('only vendor-stated CWEs are advisory claims; vocabulary matches are hypotheses')
        if (self.basis == 'explicit-csaf-cwe') != (self.confidence == 'explicit'):
            raise ValueError('confidence "explicit" is reserved for the CSAF cwe field')
        return self


class CweProfile(Contract):
    cve: CveId
    lexicon_version: str = Field(min_length=1, max_length=40)
    lexicon_digest: Sha256
    status: Literal['explicit', 'derived', 'weak', 'vague', 'none']
    classifications: tuple[CweClassification, ...] = ()
    negated_hits: tuple[TermHit, ...] = ()
    effect_hits: tuple[TermHit, ...] = ()
    disagreements: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode='after')
    def _status(self):
        confident = [c for c in self.classifications if c.confidence != 'weak']
        if self.status in ('vague', 'none') and confident:
            raise ValueError('vague or empty text never carries a confident classification')
        if self.status == 'explicit' and not any(c.basis == 'explicit-csaf-cwe' for c in self.classifications):
            raise ValueError('status explicit requires the CSAF cwe field')
        return self


# ---------------------------------------------------------------------------------------------- rules / hypotheses

Phrases = Annotated[tuple[str, ...], Field(max_length=64)]


class Rule(Contract):
    id: str = Field(pattern=r'^R-[A-Z0-9-]{1,40}$')
    revision: int = Field(ge=1)
    family: str = Field(min_length=1, max_length=40)
    cwe_patterns: tuple[CweId, ...] = Field(min_length=1)
    negations: Phrases = ()
    required_observations: Phrases = ()
    contradictions: Phrases = ()
    expected_operations: Phrases = Field(min_length=1)
    sources: Phrases = ()
    sinks: Phrases = ()
    guards: Phrases = ()
    api_hints: tuple[Annotated[str, Field(pattern=r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')], ...] = Field(default=(), max_length=64)
    counterexamples: Phrases = Field(min_length=1)
    caveat: str = Field(min_length=1, max_length=500)


class PatchHypothesis(Record):
    hypothesis_id: Sha256
    cwe_id: CweId
    family: str = Field(min_length=1, max_length=40)
    rule_id: str = Field(pattern=r'^R-[A-Z0-9-]{1,40}$')
    rule_revision: int = Field(ge=1)
    basis: CweBasis
    expected_operations: Phrases
    sources: Phrases = ()
    sinks: Phrases = ()
    guards: Phrases = ()
    api_hints: tuple[str, ...] = Field(default=(), max_length=64)
    counterexamples: Phrases
    required_observations: Phrases = ()
    contradictions: Phrases = ()
    caveat: str = Field(min_length=1, max_length=500)
    assessment: Literal['rule-hypothesis'] = 'rule-hypothesis'


class HypothesisSet(Contract):
    cve: CveId
    rules_version: str = Field(min_length=1, max_length=40)
    rules_digest: Sha256
    hypotheses: tuple[PatchHypothesis, ...] = ()
    unknowns: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode='after')
    def _explicit_unknown(self):
        if not self.hypotheses and not self.unknowns:
            raise ValueError('an empty hypothesis set must say why (explicit unknown)')
        return self


# ---------------------------------------------------------------------------------------------- anchors

class Anchor(Record):
    anchor_id: Sha256
    kind: Literal['module', 'api', 'string', 'feature', 'component', 'pdb']
    value: str = Field(min_length=1, max_length=512)
    source: Literal['csaf-title', 'csaf-note', 'csaf-product', 'csaf-remediation', 'hypothesis-rule',
                    'artifact-identity']
    pointer: Pointer | None = None
    quality: Literal['explicit', 'derived', 'rule', 'verified-bytes']
    label: str = Field(min_length=1, max_length=300)
    assessment: Literal['search-hint'] = 'search-hint'


class AnchorSet(Contract):
    cve: CveId
    anchors: tuple[Anchor, ...] = ()
    limitations: tuple[str, ...] = ()


# ---------------------------------------------------------------------------------------------- report

class SourceSummary(Record):
    source: AdvisorySource
    facts_id: Sha256
    superseded: bool
    cves: tuple[CveId, ...] = ()
    validation_warnings: int = Field(ge=0)


class IntelligenceReport(Contract):
    """``intelligence explain`` result: claims with provenance, hypotheses and explicit unknowns."""
    cve: CveId
    sources: tuple[SourceSummary, ...] = Field(min_length=1)
    facts: tuple[CVEFact, ...] = Field(min_length=1)
    applicability: ApplicabilityReport
    cwe_profile: CweProfile
    hypotheses: HypothesisSet
    anchors: AnchorSet
    unknowns: tuple[str, ...] = ()
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode='after')
    def _same_cve(self):
        parts = (self.applicability.cve, self.cwe_profile.cve, self.hypotheses.cve, self.anchors.cve)
        if any(c != self.cve for c in parts) or any(f.cve != self.cve for f in self.facts):
            raise ValueError('every part of the report must describe the same CVE')
        return self
