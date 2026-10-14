"""Strict, frozen ``kbcorrelation/1`` records (KB-integration-plan section 7.2).

Pure: no Qt, network, urllib or sqlite3. Every record forbids extra fields and coerces nothing (strict mode), every
collection is a tuple in a canonical order, so a dump is deterministic. Records loaded from storage must be parsed
with ``model_validate_json`` (JSON arrays become tuples there).

Vocabulary that keeps claims honest: ``advisory_fact`` and ``index_claim`` are what a document states (with its JSON
pointer), ``binary_observation`` is a hash match against an index row, ``rule_hypothesis`` is a curated
interpretation. Nothing here can express "confirmed", "trusted", "signed" or "vulnerability verified in a function".
"""
from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..acquisition.contracts import validate_file_name
from ..enrichment.identity import domain_id
from ..intelligence.contracts import CveId, CweId, IntelligenceReport, Pointer, Sha256, Timestamp
from .ids import KB_PATTERN, is_cve
from .limits import MAX_SEARCH_MONTHS

CONTRACT = 'kbcorrelation/1'

Short = Annotated[str, Field(min_length=1, max_length=1000)]
Reason = Annotated[str, Field(max_length=500)]
Text = Annotated[str, Field(max_length=64 * 1024)]
KbId = Annotated[str, Field(pattern=KB_PATTERN)]
ReleaseId = Annotated[str, Field(pattern=r'^[0-9]{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$')]
BuildUbr = Annotated[str, Field(pattern=r'^[0-9]{1,6}\.[0-9]{1,6}$')]
FileVersion = Annotated[str, Field(pattern=r'^[0-9]{1,5}(\.[0-9]{1,5}){3}$')]
Uuid = Annotated[str, Field(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
ErrorCodeText = Annotated[str, Field(pattern=r'^PT-KBC-[A-Z]{3,12}$')]

SourceKind = Literal['cvrf-month', 'csaf', 'sug-cve', 'winbindex-file', 'kev', 'local-note']
Origin = Literal['local-import', 'https-fetch']
Authenticity = Literal['unverified-local-file', 'tls-allowlisted-host', 'tls-allowlisted-host-hash-match']
Lineage = Literal['msrc', 'winbindex', 'nvd', 'cisa', 'analyst']
Assertion = Literal['advisory_fact', 'index_claim', 'binary_observation', 'rule_hypothesis', 'analyst_statement']
CoverageState = Literal['complete_in_scope', 'partial_in_scope', 'stale_cache', 'unknown_scope', 'not_searched']
Family = Literal['windows-client', 'windows-server', 'other', 'unknown']
Arch = Literal['amd64', 'arm64', 'x86', 'unknown']
Mapping = Literal['verified', 'candidate', 'unknown', 'conflicted']
Relation = Literal['vendor-remediation', 'vendor-association', 'mention-only', 'package-contains', 'analyst-asserted',
                   'disputed']
HeadingClass = Literal['standard', 'preview', 'out-of-band', 'expired', 'none']
Variant = Literal['full', 'delta+', 'delta', 'raw']
BinaryAuthenticity = Literal['hash-matched-to-index', 'signature-unknown', 'embedded-signature-valid',
                             'unverified-local-file', 'hash-mismatch']
Availability = Literal['local', 'direct', 'candidates', 'delta-only', 'unavailable']
BytesState = Literal['verified', 'pending', 'mismatch', 'incompatible']
LineageState = Literal['index-adjacent', 'compatible-branch', 'user-asserted', 'unverified', 'incompatible']
FixBoundary = Literal['source-supported', 'unverified', 'contradicted']
Grade = Literal['A', 'B', 'X']
ReasonCode = Literal['IDENTICAL_CONTENT', 'DELTA_ONLY', 'ARCH', 'CROSS_PRODUCT', 'ORDER_UNVERIFIED', 'DIGEST_MISMATCH',
                     'NO_OLDER', 'NO_NEWER', 'WINDOW_CONFOUNDED', 'SERVER_NOT_COVERED', 'NAME_MISMATCH', 'INDEX_GAP']
HARD_BLOCKS = frozenset({'IDENTICAL_CONTENT', 'DELTA_ONLY', 'ARCH', 'CROSS_PRODUCT', 'DIGEST_MISMATCH', 'NO_OLDER',
                         'NO_NEWER', 'SERVER_NOT_COVERED', 'NAME_MISMATCH'})
STATES = ('NEW', 'LEAD_PARSED', 'SEARCHED', 'METADATA_READY', 'METADATA_PARTIAL', 'NOT_OBSERVED', 'SCOPE_REQUIRED',
          'PRODUCT_SELECTED', 'NEEDS_PRODUCT', 'COMPONENTS_READY', 'NEEDS_FILENAME', 'PAIR_PROPOSED', 'NEEDS_OLDER',
          'NEEDS_NEWER', 'LINEAGE_BLOCKED', 'NEEDS_PAIR_SELECTION', 'PAIR_APPROVED', 'PLAN_READY', 'ACQUIRING',
          'BYTES_VERIFIED', 'PROJECT_CREATED', 'CONTEXT_PENDING', 'CONTEXT_ATTACHED', 'COMPARISON_PENDING', 'ANALYZED',
          'LEADS_READY')
State = Literal['NEW', 'LEAD_PARSED', 'SEARCHED', 'METADATA_READY', 'METADATA_PARTIAL', 'NOT_OBSERVED',
                'SCOPE_REQUIRED', 'PRODUCT_SELECTED', 'NEEDS_PRODUCT', 'COMPONENTS_READY', 'NEEDS_FILENAME',
                'PAIR_PROPOSED', 'NEEDS_OLDER', 'NEEDS_NEWER', 'LINEAGE_BLOCKED', 'NEEDS_PAIR_SELECTION',
                'PAIR_APPROVED', 'PLAN_READY', 'ACQUIRING', 'BYTES_VERIFIED', 'PROJECT_CREATED', 'CONTEXT_PENDING',
                'CONTEXT_ATTACHED', 'COMPARISON_PENDING', 'ANALYZED', 'LEADS_READY']
NEXT_HOOKS = ('kb.next.import_documents', 'kb.next.choose_product', 'kb.next.enter_filename', 'kb.next.supply_pair',
              'kb.next.run_comparison', 'kb.next.review_lead', 'kb.next.widen_window')
MEANING_HOOKS = ('kb.meaning.coverage', 'kb.meaning.relation', 'kb.meaning.tier', 'kb.meaning.grade',
                 'kb.meaning.kev', 'kb.meaning.hypothesis')
HOOKS = NEXT_HOOKS + MEANING_HOOKS
Hook = Literal['kb.next.import_documents', 'kb.next.choose_product', 'kb.next.enter_filename', 'kb.next.supply_pair',
               'kb.next.run_comparison', 'kb.next.review_lead', 'kb.next.widen_window', 'kb.meaning.coverage',
               'kb.meaning.relation', 'kb.meaning.tier', 'kb.meaning.grade', 'kb.meaning.kev',
               'kb.meaning.hypothesis']
Channel = Literal['documentary', 'applicability', 'exploitation', 'hypothesis', 'binary-identity', 'code-change',
                  'anchor']
ChipState = Literal['supports', 'neutral', 'contradicts', 'unknown', 'not-run']


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Contract(Record):
    contract: Literal['kbcorrelation/1'] = CONTRACT


_HTTPS = re.compile(r'https://([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::[0-9]{1,5})?(?:[/?][^\s#]*)?')


def https_host(url: str) -> str | None:
    """Lower-cased host of a plain ``https://host[:port][/path]`` URL (no userinfo, no spaces), else None."""
    match = _HTTPS.fullmatch(url)
    return match.group(1).lower() if match else None


def _name(value: str) -> str:
    try:
        return validate_file_name(value)
    except Exception:
        raise ValueError('file name must be a lowercase PE basename of [a-z0-9._-]') from None


def _canonical(values, name: str, key=None) -> None:
    items = list(values)
    keyed = [key(v) for v in items] if key else items
    if keyed != sorted(keyed) or len(set(keyed)) != len(keyed):
        raise ValueError(f'{name} must be sorted and unique')


# ---------------------------------------------------------------------------------------------- sources

class SourceDoc(Contract):
    """One document's exact bytes (``sha256`` is of the decompressed bytes). ``doc_id`` derives from kind and hash."""
    doc_id: Sha256
    kind: SourceKind
    sha256: Sha256
    size: int = Field(ge=0)
    origin: Origin
    uri: Annotated[str, Field(min_length=1, max_length=2048)] | None = None
    retrieved_at: Timestamp
    release_id: ReleaseId | None = None
    current_release_date: Timestamp | None = None
    dialect: Short
    parser_version: Annotated[int, Field(ge=1)]
    authenticity: Authenticity
    lineage: Lineage
    object_path: Annotated[str, Field(min_length=1, max_length=512)]

    @model_validator(mode='after')
    def _consistent(self):
        if self.doc_id != domain_id('kbc.source', 1, {'kind': self.kind, 'sha256': self.sha256}):
            raise ValueError('doc_id does not derive from kind and sha256')
        if self.origin == 'local-import' and (self.uri is not None or self.authenticity != 'unverified-local-file'):
            raise ValueError('a local import carries no URI and is unverified-local-file')
        if self.origin == 'https-fetch':
            if self.uri is None or https_host(self.uri) is None:
                raise ValueError('a fetched document needs an https URI')
            if self.authenticity == 'unverified-local-file':
                raise ValueError('a fetched document cannot be unverified-local-file')
        parts = self.object_path.split('/')
        if '\\' in self.object_path or self.object_path.startswith('/') or '..' in parts or '' in parts \
                or ':' in parts[0]:
            raise ValueError('object_path must be a relative POSIX path inside the workspace')
        if self.kind == 'cvrf-month' and self.release_id is None:
            raise ValueError('a CVRF month document needs release_id')
        return self


class SourceRef(Record):
    doc_id: Sha256
    pointer: Pointer
    assertion: Assertion


class SearchScope(Record):
    kind: Literal['selected_months', 'cached_corpus', 'provided_files', 'mixed']
    months: tuple[ReleaseId, ...] = Field(default=(), max_length=MAX_SEARCH_MONTHS)
    doc_ids: tuple[Sha256, ...] = ()
    corpus_digest: Sha256 | None = None

    @model_validator(mode='after')
    def _consistent(self):
        _canonical(self.months, 'months')
        _canonical(self.doc_ids, 'doc_ids')
        if self.kind == 'selected_months' and not self.months:
            raise ValueError('selected_months needs at least one month')
        if self.kind == 'provided_files' and not self.doc_ids:
            raise ValueError('provided_files needs doc_ids')
        if self.kind in ('cached_corpus', 'mixed') and self.corpus_digest is None:
            raise ValueError('a cached corpus scope needs corpus_digest')
        if self.kind in ('selected_months', 'provided_files') and self.corpus_digest is not None:
            raise ValueError('corpus_digest belongs to cached_corpus or mixed scopes')
        return self


class Failure(Record):
    id: Short
    reason: Short


class Coverage(Contract):
    """What was actually inspected. ``exhaustive_for_history`` is the constant False: a scope is never all of history."""
    coverage_id: Sha256
    source_kind: SourceKind
    scope: SearchScope
    state: CoverageState
    requested_ids: tuple[Short, ...] = ()
    inspected_ids: tuple[Short, ...] = ()
    failed: tuple[Failure, ...] = ()
    unfetchable_ids: tuple[Short, ...] = ()
    watermark_current_release_date: Timestamp | None = None
    retrieved_at: Timestamp
    exhaustive_for_history: Literal[False] = False

    @property
    def is_complete(self) -> bool:
        return (bool(self.requested_ids) and set(self.requested_ids) == set(self.inspected_ids) and not self.failed
                and not self.unfetchable_ids)

    @model_validator(mode='after')
    def _consistent(self):
        _canonical(self.requested_ids, 'requested_ids')
        _canonical(self.inspected_ids, 'inspected_ids')
        _canonical(self.unfetchable_ids, 'unfetchable_ids')
        _canonical([f.id for f in self.failed], 'failed')
        requested = set(self.requested_ids)
        failed = {f.id for f in self.failed}
        if not set(self.inspected_ids) <= requested or not failed <= requested \
                or not set(self.unfetchable_ids) <= requested:
            raise ValueError('inspected, failed and unfetchable ids must be requested ids')
        if set(self.inspected_ids) & failed:
            raise ValueError('an id cannot be both inspected and failed')
        if self.state == 'complete_in_scope' and not self.is_complete:
            raise ValueError('complete_in_scope needs requested == inspected, nothing failed or unfetchable, '
                             'and at least one requested id')
        if self.state == 'partial_in_scope' and (self.is_complete or not self.requested_ids):
            raise ValueError('partial_in_scope needs requested ids and something left unchecked')
        if self.state == 'not_searched' and self.inspected_ids:
            raise ValueError('not_searched cannot have inspected ids')
        return self


# ---------------------------------------------------------------------------------------------- products, edges

class ProductRef(Record):
    doc_id: Sha256
    product_id: Short


class ProductScope(Contract):
    scope_id: Sha256
    family: Family
    release: Short | None = None
    architecture: Arch
    channel: Short | None = None
    edition: Short | None = None
    build: Short | None = None
    display_name: Short
    source_product_ids: tuple[ProductRef, ...] = ()
    winbindex_key: Short | None = None
    mapping: Mapping
    alias_catalog_version: Annotated[int, Field(ge=0)]

    @model_validator(mode='after')
    def _consistent(self):
        _canonical([(p.doc_id, p.product_id) for p in self.source_product_ids], 'source_product_ids')
        if self.mapping == 'verified' and (self.winbindex_key is None or not self.source_product_ids):
            raise ValueError('a verified mapping needs a winbindex_key and source product ids; '
                             'string-derived scopes are candidates')
        return self


class ProductStatus(Record):
    value: Short
    pointer: Pointer


class KbCveEdge(Contract):
    edge_id: Sha256
    kb: KbId
    cve: CveId
    scope_id: Sha256
    relation: Relation
    ref: SourceRef
    release_id: ReleaseId | None = None
    fixed_build: BuildUbr | None = None
    supersedes: tuple[KbId, ...] = ()
    sub_type: Short | None = None
    product_status: ProductStatus | None = None
    conflict_ids: tuple[Sha256, ...] = ()
    lineage: Literal['msrc'] = 'msrc'

    @model_validator(mode='after')
    def _consistent(self):
        key = {'kb': self.kb, 'cve': self.cve, 'scope_id': self.scope_id, 'relation': self.relation,
               'doc_id': self.ref.doc_id, 'pointer': self.ref.pointer}
        if self.edge_id != domain_id('kbc.edge', 1, key):
            raise ValueError('edge_id does not derive from kb, cve, scope, relation and reference')
        _canonical(self.supersedes, 'supersedes')
        _canonical(self.conflict_ids, 'conflict_ids')
        if self.kb in self.supersedes:
            raise ValueError('a KB cannot supersede itself')
        if self.relation == 'vendor-remediation' and self.ref.assertion != 'advisory_fact':
            raise ValueError('vendor-remediation must cite an advisory_fact')
        if self.relation == 'analyst-asserted' and self.ref.assertion != 'analyst_statement':
            raise ValueError('analyst-asserted must cite an analyst_statement')
        if self.relation == 'disputed' and not self.conflict_ids and self.product_status is None:
            raise ValueError('a disputed edge needs conflict_ids or a product_status')
        return self


class ComponentHint(Contract):
    hint_id: Sha256
    basename: Short
    scope_id: Sha256
    tier: Literal['A', 'B', 'C', 'D', 'E']
    reasons: tuple[Short, ...] = ()
    claim_refs: tuple[SourceRef, ...] = ()
    changed_in_kb: Literal['yes', 'no', 'unknown'] = 'unknown'

    @model_validator(mode='after')
    def _consistent(self):
        _name(self.basename)
        return self


class BuildRow(Contract):
    file_name: Short
    sha256: Sha256
    version_key: Short
    kb: KbId | None = None
    release_date: Timestamp | None = None
    release_version: Short | None = None
    heading_class: HeadingClass
    shared_with: tuple[KbId, ...] = ()
    variant: Variant
    download: Annotated[str, Field(min_length=1, max_length=2048)] | None = None
    record_sha256: Sha256
    data_date: Timestamp | None = None

    @model_validator(mode='after')
    def _consistent(self):
        _name(self.file_name)
        _canonical(self.shared_with, 'shared_with')
        if self.download is not None and https_host(self.download) is None:
            raise ValueError('download must be an https URL')
        return self


# ---------------------------------------------------------------------------------------------- binaries, pairs

class BinaryRef(Contract):
    sha256: Sha256
    size: int = Field(ge=0)
    basename: Short
    machine: Arch
    file_version: FileVersion | None = None
    build_ubr: BuildUbr | None = None
    origin: Literal['index-row', 'local-file', 'download']
    availability: Availability
    authenticity: BinaryAuthenticity

    @model_validator(mode='after')
    def _consistent(self):
        _name(self.basename)
        if self.origin == 'local-file' and self.availability != 'local':
            raise ValueError('a local file is available locally')
        return self


class PairProposal(Contract):
    """A proposed older/newer pair. Three orthogonal proofs (bytes, lineage, fix boundary) plus reason codes; the
    grade is derived from them and never exceeds what they support."""
    pair_id: Sha256
    older: BinaryRef
    newer: BinaryRef
    scope_id: Sha256
    window_id: Short
    bytes_state: BytesState
    lineage_state: LineageState
    fix_boundary: FixBoundary
    window: tuple[KbId, ...] = ()
    window_complete: bool | None = None
    reason_codes: tuple[ReasonCode, ...] = ()
    grade: Grade
    tier: Literal['A', 'B', 'C', 'D', 'E']

    @model_validator(mode='after')
    def _consistent(self):
        key = {'older': self.older.sha256, 'newer': self.newer.sha256, 'scope_id': self.scope_id,
               'window_id': self.window_id}
        if self.pair_id != domain_id('kbc.pair', 1, key):
            raise ValueError('pair_id does not derive from older, newer, scope and window')
        _canonical(self.reason_codes, 'reason_codes')
        _canonical(self.window, 'window')
        hard = bool(HARD_BLOCKS & set(self.reason_codes)) or self.bytes_state in ('mismatch', 'incompatible') \
            or self.lineage_state == 'incompatible'
        if self.older.sha256 == self.newer.sha256 and 'IDENTICAL_CONTENT' not in self.reason_codes:
            raise ValueError('identical content must carry IDENTICAL_CONTENT')
        if hard and self.grade != 'X':
            raise ValueError('a hard block forces grade X')
        if not hard and self.grade == 'X':
            raise ValueError('grade X needs a hard block')
        if self.grade == 'A' and (self.lineage_state != 'index-adjacent' or self.bytes_state not in
                                  ('verified', 'pending')):
            raise ValueError('grade A needs index-adjacent lineage and verified or pending bytes')
        if self.grade == 'B' and self.bytes_state != 'verified':
            raise ValueError('grade B needs verified bytes')
        return self


class PlanRequest(Record):
    method: Literal['GET', 'HEAD']
    url: Annotated[str, Field(min_length=1, max_length=2048)]
    bytes: Annotated[int, Field(ge=0)] | None = None
    why: Short

    @model_validator(mode='after')
    def _https(self):
        if https_host(self.url) is None:
            raise ValueError('plan requests must be https URLs')
        return self


class ExpectedFile(Record):
    sha256: Sha256
    size: int = Field(ge=0)


class PairPlan(Contract):
    """The exact request preview a consent is bound to. Absent for local files."""
    plan_sha: Sha256
    pair_id: Sha256
    requests: tuple[PlanRequest, ...] = Field(min_length=1)
    hosts: tuple[Short, ...]
    expected: tuple[ExpectedFile, ...] = ()
    destination_policy: Short
    acquisition_plan_sha: Sha256 | None = None

    @model_validator(mode='after')
    def _consistent(self):
        _canonical(self.hosts, 'hosts')
        if tuple(sorted({https_host(r.url) for r in self.requests})) != self.hosts:
            raise ValueError('hosts must equal the hosts of the planned requests')
        return self


class Attempt(Contract):
    """Consent record and recovery journal entry."""
    op: Short
    plan_sha: Sha256 | None = None
    stage: Short
    result: Literal['ok', 'partial', 'cancelled', 'error']
    code: ErrorCodeText | None = None
    created_at: Timestamp

    @model_validator(mode='after')
    def _consistent(self):
        if self.result == 'error' and self.code is None:
            raise ValueError('an error attempt needs a code')
        if self.result == 'ok' and self.code is not None:
            raise ValueError('an ok attempt carries no code')
        return self


class AnalystDecision(Contract):
    """Append-only: product choice, pair approval, orientation override, name-mismatch confirmation."""
    op: Short
    prior: Short
    next: Short
    reason: Reason
    created_at: Timestamp
    refs: tuple[SourceRef, ...] = ()


class Lead(Record):
    kind: Literal['kb', 'cve', 'file', 'pair']
    value: Short
    raw: Annotated[str, Field(max_length=200)]


class InvestigationRevision(Contract):
    investigation_id: Uuid
    revision: int = Field(ge=1)
    parent: int | None = Field(default=None, ge=1)
    lead: Lead
    state: State
    scope_ids: tuple[Sha256, ...] = ()
    coverage_ids: tuple[Sha256, ...] = ()
    selected_scope_id: Sha256 | None = None
    selected_pair_id: Sha256 | None = None
    plan_sha: Sha256 | None = None
    warnings: tuple[Reason, ...] = ()

    @model_validator(mode='after')
    def _consistent(self):
        if (self.parent is None) != (self.revision == 1) or (self.parent is not None and self.parent >= self.revision):
            raise ValueError('revision 1 has no parent; later revisions point to an earlier one')
        if self.selected_scope_id is not None and self.selected_scope_id not in self.scope_ids:
            raise ValueError('selected_scope_id must be one of scope_ids')
        return self


class ProjectLink(Contract):
    project_id: Short
    project_revision: int = Field(ge=0)
    older_sha: Sha256
    newer_sha: Sha256
    investigation_id: Uuid
    revision: int = Field(ge=1)
    pair_id: Sha256
    state: Literal['attached', 'context-pending', 'stale']
    stale_reasons: tuple[Short, ...] = ()

    @model_validator(mode='after')
    def _consistent(self):
        if (self.state == 'stale') != bool(self.stale_reasons):
            raise ValueError('stale_reasons are required exactly when the link is stale')
        return self


# ---------------------------------------------------------------------------------------------- context, leads

class CveCard(Record):
    cve: CveId
    source_kind: Literal['cvrf', 'csaf']
    title: Short | None = None
    stated_cwe: CweId | None = None
    severity_context: Short | None = None
    kev: Literal['listed', 'not-in-snapshot', 'not-loaded'] = 'not-loaded'
    applicability: Short | None = None


class ContextReport(Contract):
    """Documentary context per CVE; ``intelligence`` embeds the reused ``intelligence/1`` report where CSAF exists."""
    cards: tuple[CveCard, ...] = ()
    intelligence: tuple[IntelligenceReport, ...] = ()
    coverage: tuple[Coverage, ...] = ()
    unknowns: tuple[Short, ...] = ()
    limitations: tuple[Short, ...] = ()
    hooks: tuple[Hook, ...] = ()

    @model_validator(mode='after')
    def _consistent(self):
        _canonical([c.cve for c in self.cards], 'cards')
        _canonical(self.hooks, 'hooks')
        return self


class Chip(Record):
    channel: Channel
    state: ChipState
    text: Short
    ref: SourceRef | None = None


class LeadNav(Record):
    match_id: Short | None = None
    project_revision: int = Field(ge=0)
    run_id: Short | None = None


class LeadRow(Contract):
    lead_id: Sha256
    level: Literal['component', 'function']
    group: Short
    subject: Short
    chips: tuple[Chip, ...] = ()
    rank_basis: Short
    nav: LeadNav
    stale: bool = False
    hooks: tuple[Hook, ...] = ()

    @model_validator(mode='after')
    def _consistent(self):
        _canonical(self.hooks, 'hooks')
        channels = [c.channel for c in self.chips]
        if len(set(channels)) != len(channels):
            raise ValueError('one chip per channel; channels are listed in words, never counted')
        if self.group not in ('unattributed', 'not-applicable'):
            if not is_cve(self.group):
                raise ValueError("group is a CVE id, 'unattributed' or 'not-applicable'")
        return self
