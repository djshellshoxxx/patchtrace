"""Strict, frozen ``pilot/1`` records (PIL-integration-plan.md s7; SPEC-30 as amended). Persisted contracts are
additive only from here on: a new optional field is appended with a default, nothing is removed, renamed or retyped.

Pure: pydantic + stdlib; no Qt, I/O, sqlite, network or other feature. Every record forbids extra fields, coerces
nothing (strict mode) and is frozen; every set-like collection is a tuple in canonical order and the contract has no
float, so a dump is deterministic. Stored JSON is revalidated in JSON mode (``model_validate_json``).

Vocabulary that keeps claims honest: a lead is an ordinal, explainable *fit* of observed change evidence to an
advisory's weakness hypothesis (``rule-hypothesis``) or ``unknown``. Nothing here can express a probability, a
confidence, or "vulnerability verified in this function", and the mechanism ``strong`` is reserved: it is part of the
vocabulary but unreachable until a typed dominance or dataflow channel exists (``STRONG_REACHABLE``).
"""
from __future__ import annotations

import re
from datetime import date
from types import MappingProxyType
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

from .limits import DEFAULT_LIMITS, ERROR_CODES, EXIT_CODES, PilotError  # noqa: F401 - re-exported

_L = DEFAULT_LIMITS
CONTRACT = 'pilot/1'
MAX_NOTES = 64
MAX_LIMITS_HIT = 32
MAX_ORIGINS = 8
MAX_COMPONENT_TAGS = 32
MAX_OBLIGATIONS = 16
MAX_ANCHORS = 16
MAX_FACETS = 16
MAX_SOURCES = 64
MAX_SIDE_FUNCTIONS = 256
MAX_WINDOW_CVES = 1024
MAX_CWE_IDS = 16
MAX_SECONDARY_SETS = 16
MAX_TOOL_KEYS = 6
MAX_CONTEXTS = _L.p03_cves + 1  # CVE contexts plus the code-only context
MAX_LEADS = MAX_CONTEXTS * (_L.p04_leads_per_context + _L.p04_queue_rows_per_context)
MAX_POOL = MAX_LEADS * _L.p02_observations_per_lead

# --- vocabulary (frozen; s7) --------------------------------------------------------------------------------------

Channel = Literal['advisory', 'code', 'calls', 'strings', 'capa', 'build', 'pairing']
Role = Literal['shape', 'local', 'counter', 'conflict', 'context']  # only shape and local can raise a tier
Verification = Literal['verified-bytes', 'tool-reported', 'label-only', 'advisory-claim', 'rule-hypothesis',
                       'analyst-assertion']
Mechanism = Literal['strong', 'moderate', 'tentative', 'unexplained', 'contested', 'not-assessed']
AssignedMechanism = Literal['moderate', 'tentative', 'unexplained', 'contested', 'not-assessed']
LeadClass = Literal['fit', 'review', 'partial', 'code', 'queue']
Identity = Literal['corroborated', 'contested', 'unassessed']
CveGate = Literal['applies', 'asserted', 'unverified', 'conflict', 'not-applicable', 'none']
ContextGate = Literal['applies', 'asserted', 'unverified', 'conflict', 'not-applicable']  # a CVE context has an advisory
LeadGate = Literal['applies', 'asserted', 'unverified', 'conflict', 'none']  # not-applicable produces no leads
ChannelState = Literal['available', 'partial', 'not-run', 'unsupported', 'failed', 'stale']
Depth = Literal['typed', 'lexical', 'none']
ChangeState = Literal['met', 'not-observed', 'unknown', 'contradicted']
Basis = Literal['explicit-csaf-cwe', 'cwe-id-in-text', 'curated-vocabulary']  # as intelligence/1 CweBasis
Cap = Literal['confounded-window-needs-locality', 'toolchain-changed-lexical-only', 'cve-unverified', 'cve-conflict']
AssessmentKind = Literal['rule-hypothesis', 'unknown']
RunStatus = Literal['complete', 'partial', 'abstained']
Side = Literal['older', 'newer']
ReviewAction = Literal['pin', 'unpin', 'dismiss', 'restore', 'note']
KevState = Literal['listed', 'not-in-snapshot', 'unknown']
WindowState = Literal['yes', 'no', 'unknown']
CweStatus = Literal['explicit', 'derived', 'weak', 'vague', 'none']  # as intelligence/1 CweProfile.status
Resolution = Literal['affected', 'not_affected', 'fixed', 'under_investigation', 'contradictory', 'ambiguous',
                     'unknown']  # as intelligence/1
MappingStatus = Literal['verified', 'candidate', 'unknown']  # as intelligence/1
Engine = Literal['capa', 'floss', 'diec']

MECHANISMS: tuple[str, ...] = get_args(Mechanism)
ASSIGNABLE_MECHANISMS: tuple[str, ...] = get_args(AssignedMechanism)
STRONG_REACHABLE = False  # `strong` needs a typed dominance/dataflow channel that no PatchTrace component produces
LEAD_CLASSES: tuple[str, ...] = get_args(LeadClass)
CHANNELS: tuple[str, ...] = get_args(Channel)
# Class = f(mechanism) (s7: fit = moderate, review = contested, partial = tentative, code = no advisory plus change
# evidence, queue = the rest).
CLASS_MECHANISMS = MappingProxyType({'fit': ('moderate',), 'review': ('contested',), 'partial': ('tentative',),
                                     'code': ('not-assessed',), 'queue': ('unexplained', 'not-assessed')})
CLASS_RANK = MappingProxyType({name: index for index, name in enumerate(LEAD_CLASSES)})
# Caps of tier derivation step 4: they hold a lead at tentative, so it can be neither a fit nor "needs review".
TIER_CAPS = frozenset({'confounded-window-needs-locality', 'toolchain-changed-lexical-only'})
# Observation kind prefix -> the channel it belongs to; `die` and `str` observations never raise a tier.
KIND_CHANNEL = MappingProxyType({'adv': 'advisory', 'b1': 'code', 'cf': 'code', 'call': 'calls', 'str': 'strings',
                                 'capa': 'capa', 'die': 'build', 'pair': 'pairing'})
CONTEXT_ONLY_KINDS = frozenset({'die', 'str'})

# --- plain text and identifier shapes -----------------------------------------------------------------------------
# The unsafe sets contain everything `secondary.evidence_view.sanitize_text` removes (C0 except tab/newline, DEL and
# C1, LRM/RLM, line/paragraph separators, bidirectional embeddings and isolates); a line also rejects tab and newline.
_UNSAFE_LINE = re.compile('[\x00-\x1f\x7f-\x9f‎‏ -‮⁦-⁩]')
_UNSAFE_TEXT = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏ -‮⁦-⁩]')
_UNSAFE_ANY = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏ -‮⁦-⁩\ud800-\udfff]')


def _encodable(value: str) -> str:
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('text must be UTF-8 encodable') from None
    return value


def plain_line(value: str) -> str:
    """Validator: single-line plain text (what adapters store after sanitising untrusted text)."""
    _encodable(value)
    if _UNSAFE_LINE.search(value):
        raise ValueError('text must be a single line of plain text (no control, bidirectional or separator characters)')
    return value


def plain_text(value: str) -> str:
    """Validator: plain text that may span lines (tab and newline allowed; analyst notes)."""
    _encodable(value)
    if _UNSAFE_TEXT.search(value):
        raise ValueError('text must be plain text (tab and newline only; no other control or bidirectional characters)')
    return value


def clean_line(value: object, limit: int = _L.p05_text_chars) -> str:
    """Untrusted text -> a value `plain_line` accepts: unsafe characters and lone surrogates removed, tabs and
    newlines become spaces, capped at `limit` characters with an ellipsis (same cap rule as `sanitize_text`)."""
    text = '' if value is None else str(value).replace('\n', ' ').replace('\t', ' ')
    text = _UNSAFE_ANY.sub('', text)
    return text if len(text) <= limit else text[:max(0, limit - 3)] + '...'


def _line(max_length: int, min_length: int = 0):
    return Annotated[str, AfterValidator(plain_line), Field(min_length=min_length, max_length=max_length)]


def _real_date(value: str) -> str:
    try:
        date.fromisoformat(value)
    except ValueError:
        raise ValueError('date must be a real calendar date YYYY-MM-DD') from None
    return value


PlainLine300 = _line(_L.p05_text_chars, 1)
PlainLine256 = _line(256, 1)
PlainLine200 = _line(200, 1)
PlainText = Annotated[str, AfterValidator(plain_text), Field(max_length=_L.p11_review_text_bytes)]
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Rva = Annotated[int, Field(ge=0, le=2**32 - 1)]
Count = Annotated[int, Field(ge=0)]
Rank = Annotated[int, Field(ge=1)]
Line = Annotated[int, Field(ge=1)]
Slug = Annotated[str, Field(pattern=r'^[a-z0-9-]{1,48}$')]
# The next three shapes are identical to intelligence/1 (parity is tested); duplicated so no feature is imported.
CveId = Annotated[str, Field(max_length=24, pattern=r'^CVE-[0-9]{4}-[0-9]{4,19}$')]
CweId = Annotated[str, Field(pattern=r'^CWE-[1-9][0-9]{0,5}$')]
Pointer = Annotated[str, Field(max_length=4096, pattern=r'^(/([^/~]|~[01])*)*$')]
Utc = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(\+00:00|Z)$')]
IsoDate = Annotated[str, Field(pattern=r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$'), AfterValidator(_real_date)]
OriginTag = Annotated[str, Field(pattern=r'^D_[a-z0-9_]{1,32}$')]
ObsKind = Annotated[str, Field(pattern=r'^[a-z][a-z0-9]{0,11}:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')]
EvidenceClass = Annotated[str, Field(pattern=r'^E-[A-Z][A-Z0-9]{1,11}$')]
AnchorId = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,15}:[\x21-\x7e]{1,200}$')]
Ident = Annotated[str, AfterValidator(plain_line), Field(min_length=1, max_length=256)]
ProjectId = Annotated[str, Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
RunId = ProjectId
TeachId = Annotated[str, Field(pattern=r'^pilot\.[a-z]+\.[a-z0-9-]{1,48}$')]
RuleId = Annotated[str, Field(pattern=r'^R-[A-Z0-9-]{1,40}$')]


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


def _sorted_unique(values, what: str, key=None):
    items = list(values)
    keyed = [key(v) for v in items] if key else items
    if keyed != sorted(set(keyed)):
        raise ValueError(f'{what} must be sorted and unique')
    return values


# --- observations -----------------------------------------------------------------------------------------------

class FunctionRef(_Strict):
    """One function of a candidate side: module-relative address and display name (untrusted, sanitised)."""
    rva: Rva
    name: PlainLine256 | None = None


class Nav(_Strict):
    """Where to look: a side, a module-relative address and optional 1-based inclusive lines."""
    side: Side
    rva: Rva
    start_line: Line | None = None
    end_line: Line | None = None

    @model_validator(mode='after')
    def _lines(self):
        if self.end_line is not None and self.start_line is None:
            raise ValueError('end_line needs start_line')
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError('end_line must not precede start_line')
        return self


class ObsRef(_Strict):
    """What the observation was read from: a source kind and id, an optional RFC 6901 pointer and content digest."""
    kind: Slug
    id: Ident
    pointer: Pointer | None = None
    sha256: Sha256 | None = None


class Observation(_Strict):
    """One flat ledger entry; `obs_id` is the content id (keys.observation_id), so duplicates collapse."""
    obs_id: Sha256
    channel: Channel
    kind: ObsKind
    role: Role
    verification: Verification
    origins: tuple[OriginTag, ...] = Field(min_length=1, max_length=MAX_ORIGINS)
    evidence_class: EvidenceClass
    obligations: tuple[Slug, ...] = Field(default=(), max_length=MAX_OBLIGATIONS)
    anchor_ids: tuple[AnchorId, ...] = Field(default=(), max_length=MAX_ANCHORS)
    ref: ObsRef
    nav: Nav | None = None
    detail: PlainLine300

    @field_validator('origins', 'obligations', 'anchor_ids')
    @classmethod
    def _canonical(cls, value, info):
        return _sorted_unique(value, info.field_name)

    @model_validator(mode='after')
    def _consistent(self):
        prefix = self.kind.split(':', 1)[0]
        channel = KIND_CHANNEL.get(prefix)
        if channel is not None and self.channel != channel:
            raise ValueError(f'kind prefix {prefix} belongs to channel {channel}')
        if prefix in CONTEXT_ONLY_KINDS and self.role != 'context':
            raise ValueError(f'{prefix} observations are context only: they never raise a tier')
        return self


# --- leads ------------------------------------------------------------------------------------------------------

class ExpectedChange(_Strict):
    """One change a weakness rule expects (e.g. a guard added) with its three-valued state."""
    id: Slug
    state: ChangeState
    required: bool
    observation_ids: tuple[Sha256, ...] = Field(default=(), max_length=_L.p02_observations_per_lead)
    teach_id: TeachId

    @field_validator('observation_ids')
    @classmethod
    def _canonical(cls, value, info):
        return _sorted_unique(value, info.field_name)

    @model_validator(mode='after')
    def _evidence(self):
        if self.state in ('met', 'contradicted') and not self.observation_ids:
            raise ValueError('a met or contradicted expected change needs observations')
        return self


class HypothesisFit(_Strict):
    """How one weakness hypothesis (K rule id and revision) fits a candidate."""
    hypothesis_id: Sha256
    rule_id: RuleId
    rule_revision: int = Field(ge=1)
    cwe_id: CweId
    basis: Basis
    expected_changes: tuple[ExpectedChange, ...] = Field(min_length=1, max_length=_L.p07_changes_per_rule)
    met: Count
    total: Count

    @model_validator(mode='after')
    def _counts(self):
        ids = [c.id for c in self.expected_changes]
        if len(set(ids)) != len(ids):
            raise ValueError('expected change ids must be unique')
        if self.total != len(ids):
            raise ValueError('total must equal the number of expected changes')
        if self.met != sum(1 for c in self.expected_changes if c.state == 'met'):
            raise ValueError('met must equal the number of met expected changes')
        return self


class LeadComponents(_Strict):
    """Independent origin components behind a lead: `tags` holds the smallest origin tag of each component."""
    count: Count
    tags: tuple[OriginTag, ...] = Field(default=(), max_length=MAX_COMPONENT_TAGS)

    @field_validator('tags')
    @classmethod
    def _canonical(cls, value, info):
        return _sorted_unique(value, info.field_name)

    @model_validator(mode='after')
    def _count(self):
        if self.count != len(self.tags):
            raise ValueError('components.count must equal the number of tags')
        return self


class Tie(_Strict):
    """Leads with equal evidence share a tie group: positions `first`..`last`, shown as "n-m (tie)"."""
    size: Rank
    first: Rank
    last: Rank

    @model_validator(mode='after')
    def _span(self):
        if self.last < self.first or self.size != self.last - self.first + 1:
            raise ValueError('tie size must equal last - first + 1')
        return self


def _ready(fit: HypothesisFit) -> bool:
    return fit.met >= 1 and all(c.state == 'met' for c in fit.expected_changes if c.required)


class Lead(_Strict):
    """One candidate function pair assessed in one context (a CVE, or `cve` null for code evidence only).

    `rank` is the display position within the context; `fits` lists every hypothesis, best first. The four id lists
    reference the assessment's observation pool: `support_ids` back the listing, `counter_ids` hold counter and
    conflict evidence, `unknown_ids` record evidence that could not be assessed, `alternative_ids` favour another
    explanation (for example a toolchain change)."""
    candidate_key: Sha256
    cve: CveId | None = None
    lead_class: LeadClass
    mechanism: AssignedMechanism
    identity: Identity
    gate: LeadGate
    depth: Depth
    fits: tuple[HypothesisFit, ...] = Field(default=(), max_length=_L.p07_rules)
    components: LeadComponents
    local_hits: Count = 0
    caps: tuple[Cap, ...] = Field(default=(), max_length=len(get_args(Cap)))
    support_ids: tuple[Sha256, ...] = Field(default=(), max_length=_L.p02_observations_per_lead)
    counter_ids: tuple[Sha256, ...] = Field(default=(), max_length=_L.p02_observations_per_lead)
    unknown_ids: tuple[Sha256, ...] = Field(default=(), max_length=_L.p02_observations_per_lead)
    alternative_ids: tuple[Sha256, ...] = Field(default=(), max_length=_L.p02_observations_per_lead)
    rank: Rank
    tie: Tie
    assessment: AssessmentKind
    older: tuple[FunctionRef, ...] = Field(default=(), max_length=MAX_SIDE_FUNCTIONS)
    newer: tuple[FunctionRef, ...] = Field(default=(), max_length=MAX_SIDE_FUNCTIONS)

    @field_validator('mechanism', mode='before')
    @classmethod
    def _strong_is_reserved(cls, value):
        if value == 'strong':
            raise ValueError("mechanism 'strong' is reserved: no typed dominance or dataflow channel exists in pilot/1")
        return value

    @field_validator('caps', 'support_ids', 'counter_ids', 'unknown_ids', 'alternative_ids')
    @classmethod
    def _canonical(cls, value, info):
        return _sorted_unique(value, info.field_name)

    @field_validator('older', 'newer')
    @classmethod
    def _sides(cls, value, info):
        return _sorted_unique(value, info.field_name, key=lambda f: f.rva)

    @field_validator('fits')
    @classmethod
    def _unique_hypotheses(cls, value):
        ids = [f.hypothesis_id for f in value]
        if len(set(ids)) != len(ids):
            raise ValueError('hypothesis ids must be unique')
        return value

    @model_validator(mode='after')
    def _consistent(self):
        cls = self.lead_class
        if (self.cve is None) != (self.gate == 'none'):
            raise ValueError('gate none exactly when there is no CVE')
        if cls in ('fit', 'review', 'partial') and self.gate == 'none':
            raise ValueError(f'a {cls} lead needs an advisory (a CVE gate)')
        if cls == 'code' and self.gate != 'none':
            raise ValueError('a code-only lead has no advisory (gate none)')
        if self.mechanism not in CLASS_MECHANISMS[cls]:
            raise ValueError(f'class {cls} requires mechanism {" or ".join(CLASS_MECHANISMS[cls])}')
        if self.gate == 'unverified' and cls not in ('partial', 'queue'):
            raise ValueError('an unverified CVE gate caps a lead at partial fit')
        if self.gate == 'conflict' and cls == 'fit':
            raise ValueError('a conflicting CVE gate caps a lead at needs review')
        if self.identity == 'contested' and cls == 'fit':
            raise ValueError('a contested pairing is never a fit')
        if 'cve-unverified' in self.caps and self.gate != 'unverified':
            raise ValueError('cap cve-unverified needs gate unverified')
        if 'cve-conflict' in self.caps and self.gate != 'conflict':
            raise ValueError('cap cve-conflict needs gate conflict')
        if TIER_CAPS & set(self.caps) and cls in ('fit', 'review'):
            raise ValueError('a capped lead cannot be a fit or need review')
        if not self.tie.first <= self.rank <= self.tie.last:
            raise ValueError('rank must lie inside its tie group')
        if cls in ('fit', 'review'):  # review = a fit that a conflict or a contested pairing holds back (s7 step 5)
            if self.components.count < 2:
                raise ValueError(f'a {cls} lead needs at least two independent components')
            if self.depth == 'none':
                raise ValueError(f'a {cls} lead needs typed or lexical depth')
            if not any(_ready(f) for f in self.fits):
                raise ValueError(f'a {cls} lead needs a hypothesis fit with every required change met')
            if self.assessment != 'rule-hypothesis':
                raise ValueError(f'a {cls} lead is a rule hypothesis')
        if self.mechanism == 'not-assessed' and self.assessment != 'unknown':
            raise ValueError('a not-assessed lead has assessment unknown')
        referenced = {*self.support_ids, *self.counter_ids, *self.unknown_ids, *self.alternative_ids}
        if len(referenced) > _L.p02_observations_per_lead:
            raise ValueError(f'a lead references at most {_L.p02_observations_per_lead} observations (P-02)')
        return self


# --- CVE contexts and channels ------------------------------------------------------------------------------------

class LeadCounts(_Strict):
    fit: Count
    review: Count
    partial: Count
    code: Count
    queue: Count


class ApplicabilitySummary(_Strict):
    """What the advisory says about the two builds (from the intelligence/1 ApplicabilityReport)."""
    older: Resolution
    newer: Resolution
    older_mapping: MappingStatus
    newer_mapping: MappingStatus
    contradictions: Count = 0

    @model_validator(mode='after')
    def _unmapped_abstains(self):
        for side in ('older', 'newer'):
            if getattr(self, f'{side}_mapping') == 'unknown' and getattr(self, side) != 'unknown':
                raise ValueError('an unmapped side always abstains')
        return self


class CweSummary(_Strict):
    status: CweStatus
    ids: tuple[CweId, ...] = Field(default=(), max_length=MAX_CWE_IDS)

    @field_validator('ids')
    @classmethod
    def _canonical(cls, value, info):
        return _sorted_unique(value, info.field_name)


class Kev(_Strict):
    """CISA KEV context for a CVE: ordering of CVEs only, never evidence about a function. Absence says nothing."""
    state: KevState
    date_added: IsoDate | None = None
    snapshot_id: Sha256 | None = None

    @model_validator(mode='after')
    def _consistent(self):
        if self.state == 'listed':
            if self.date_added is None or self.snapshot_id is None:
                raise ValueError('a listed KEV entry needs its date and snapshot')
            return self
        if self.date_added is not None:
            raise ValueError('a KEV state other than listed carries no date')
        if self.state == 'not-in-snapshot' and self.snapshot_id is None:
            raise ValueError('a KEV entry absent from the snapshot needs its snapshot id')
        return self


class Confounding(_Strict):
    """Whether several CVEs are fixed on the newer build, so that shape alone cannot isolate one of them."""
    state: WindowState
    cves: tuple[CveId, ...] = Field(default=(), max_length=MAX_WINDOW_CVES)

    @field_validator('cves')
    @classmethod
    def _canonical(cls, value, info):
        return _sorted_unique(value, info.field_name)

    @model_validator(mode='after')
    def _consistent(self):
        if self.state == 'yes' and len(self.cves) < 2:
            raise ValueError('a confounded window lists at least two CVEs')
        if self.state == 'unknown' and self.cves:
            raise ValueError('an unknown window lists no CVEs')
        return self


class CveContext(_Strict):
    """Per-CVE context of an assessment: the applicability gate, CWE profile, KEV state, window and lead counts."""
    cve: CveId
    source_ids: tuple[Sha256, ...] = Field(default=(), max_length=MAX_SOURCES)
    gate: ContextGate
    applicability: ApplicabilitySummary
    cwe: CweSummary
    kev: Kev
    confounding: Confounding
    counts: LeadCounts
    limitations: tuple[PlainLine300, ...] = Field(default=(), max_length=MAX_NOTES)

    @field_validator('source_ids')
    @classmethod
    def _canonical(cls, value, info):
        return _sorted_unique(value, info.field_name)

    @model_validator(mode='after')
    def _consistent(self):
        if self.gate == 'not-applicable' and any(self.counts.model_dump().values()):
            raise ValueError('a not-applicable CVE produces no leads')
        return self


class ChannelStatus(_Strict):
    """State of one evidence channel; missing evidence is unknown, never a negative vote."""
    channel: Channel
    state: ChannelState
    reason: PlainLine200 | None = None


# --- identity payload and configuration ------------------------------------------------------------------------------

class ToolKey(_Strict):
    """The cache key of one tool result (intelligence/tools ToolRun.cache_key) for one side."""
    engine: Engine
    side: Side
    cache_key: Sha256


class PilotConfig(_Strict):
    """Knobs of the tier derivation. `limits_digest` pins the P-xx numbers the result was computed under."""
    locality_min_tokens: int = Field(default=2, ge=1, le=8)
    confounded_min_cves: int = Field(default=2, ge=2, le=MAX_WINDOW_CVES)
    lexical_moderate: bool = True
    limits_digest: Sha256


class PilotInputs(_Strict):
    """The `result_id` payload (s7), stored verbatim so the UI can name a changed input. Reviews, timestamps and
    paths are never part of it."""
    older_sha256: Sha256
    newer_sha256: Sha256
    orientation: Literal['older->newer'] = 'older->newer'
    ghidriff_run_id: RunId
    raw_sha256: Sha256
    unified_result_id: Sha256 | None = None
    secondary_set_ids: tuple[Sha256, ...] = Field(default=(), max_length=MAX_SECONDARY_SETS)
    tool_keys: tuple[ToolKey, ...] = Field(default=(), max_length=MAX_TOOL_KEYS)
    advisory_facts_ids: tuple[Sha256, ...] = Field(default=(), max_length=MAX_SOURCES)
    kev_snapshot_id: Sha256 | None = None
    kb_link_digest: Sha256 | None = None
    asserted_gates: tuple[CveId, ...] = Field(default=(), max_length=_L.p03_cves)
    lexicon_digest: Sha256
    rules_digest: Sha256
    pilot_rules_digest: Sha256
    origins_digest: Sha256
    tiers_version: int = Field(ge=1)
    config_digest: Sha256

    @field_validator('secondary_set_ids', 'advisory_facts_ids', 'asserted_gates')
    @classmethod
    def _canonical(cls, value, info):
        return _sorted_unique(value, info.field_name)

    @field_validator('tool_keys')
    @classmethod
    def _tools(cls, value, info):
        return _sorted_unique(value, 'tool_keys (by engine and side)', key=lambda k: (k.engine, k.side))


# --- the assessment -------------------------------------------------------------------------------------------------

class PilotAssessment(_Strict):
    """The persisted result of one localization run (sidecar `assessment.json.gz`), derived and never edited."""
    contract: Literal['pilot/1'] = CONTRACT
    result_id: Sha256
    project_id: ProjectId
    revision: Count
    older_sha256: Sha256
    newer_sha256: Sha256
    orientation: Literal['older->newer'] = 'older->newer'
    inputs: PilotInputs
    channels: tuple[ChannelStatus, ...] = Field(max_length=len(CHANNELS))
    cves: tuple[CveContext, ...] = Field(default=(), max_length=_L.p03_cves)
    leads: tuple[Lead, ...] = Field(default=(), max_length=MAX_LEADS)
    queue_count: Count = 0
    observations: tuple[Observation, ...] = Field(default=(), max_length=MAX_POOL)
    status: RunStatus
    limitations: tuple[PlainLine300, ...] = Field(default=(), max_length=MAX_NOTES)
    limits_hit: tuple[Slug, ...] = Field(default=(), max_length=MAX_LIMITS_HIT)
    created_utc: Utc

    def lead_counts(self) -> LeadCounts:
        """Persisted leads per class over all contexts (what the pointer and the manifest report)."""
        counts = dict.fromkeys(LEAD_CLASSES, 0)
        for lead in self.leads:
            counts[lead.lead_class] += 1
        return LeadCounts(**counts)

    @model_validator(mode='after')
    def _consistent(self):
        if (self.inputs.older_sha256, self.inputs.newer_sha256, self.inputs.orientation) != (
                self.older_sha256, self.newer_sha256, self.orientation):
            raise ValueError('inputs must match older_sha256, newer_sha256 and orientation')
        names = [c.channel for c in self.channels]
        if names != sorted(set(names), key=CHANNELS.index):
            raise ValueError('channels must be unique and in canonical order')
        cves = [c.cve for c in self.cves]
        if cves != sorted(set(cves)):
            raise ValueError('cves must be unique and sorted by CVE id')
        pool = [o.obs_id for o in self.observations]
        if pool != sorted(set(pool)):
            raise ValueError('observations must be unique and sorted by obs_id')
        self._check_leads({c.cve: c for c in self.cves}, set(pool))
        if self.status == 'abstained' and self.leads:
            raise ValueError('an abstained assessment has no leads')
        if self.status in ('partial', 'abstained') and not self.limitations:
            raise ValueError('a partial or abstained assessment names its limitations')
        return self

    def _check_leads(self, contexts: dict[str, CveContext], known: set[str]) -> None:
        seen: set[tuple[str, str]] = set()
        persisted: dict[str | None, dict[str, int]] = {}
        for lead in self.leads:
            context = contexts.get(lead.cve) if lead.cve is not None else None
            if lead.cve is not None:
                if context is None:
                    raise ValueError('lead names an unknown CVE context')
                if context.gate == 'not-applicable':
                    raise ValueError('a not-applicable CVE has no leads')
                if lead.gate != context.gate:
                    raise ValueError('lead gate must equal its CVE context gate')
            key = (lead.cve or '', lead.candidate_key)
            if key in seen:
                raise ValueError('one lead per candidate and context')
            seen.add(key)
            ids = {*lead.support_ids, *lead.counter_ids, *lead.unknown_ids, *lead.alternative_ids}
            for fit in lead.fits:
                for change in fit.expected_changes:
                    ids.update(change.observation_ids)
            if not ids <= known:
                raise ValueError('lead references an unknown observation id')
            per = persisted.setdefault(lead.cve, dict.fromkeys(LEAD_CLASSES, 0))
            per[lead.lead_class] += 1
        order = [(lead.cve or '', lead.rank) for lead in self.leads]
        if order != sorted(order):
            raise ValueError('leads must be sorted by (cve, rank)')
        if len(set(order)) != len(order):
            raise ValueError('ranks must be unique within a context')
        previous: dict[str, int] = {}
        for lead in self.leads:
            index = CLASS_RANK[lead.lead_class]
            if index < previous.get(lead.cve or '', 0):
                raise ValueError('rank order must follow class order (fit, review, partial, code, queue)')
            previous[lead.cve or ''] = index
        for cve, per in persisted.items():
            if cve is not None:
                allowed = contexts[cve].counts.model_dump()
                if any(per[name] > allowed[name] for name in LEAD_CLASSES):
                    raise ValueError('persisted leads exceed the counts of their CVE context')
            if sum(per.values()) - per['queue'] > _L.p04_leads_per_context:
                raise ValueError(f'a context persists at most {_L.p04_leads_per_context} leads (P-04)')
            if per['queue'] > _L.p04_queue_rows_per_context:
                raise ValueError(f'a context persists at most {_L.p04_queue_rows_per_context} queue rows (P-04)')


# --- review events ----------------------------------------------------------------------------------------------

class ReviewEvent(_Strict):
    """An analyst's pin, dismissal or note (own `patch-intent` rows, append only). It never changes a lead's class,
    and a note is shown as the analyst's statement, never as PatchTrace's finding."""
    contract: Literal['pilot-review/1'] = 'pilot-review/1'
    candidate_key: Sha256
    cve: CveId | None = None
    action: ReviewAction
    text: PlainText = ''
    created_utc: Utc

    @model_validator(mode='after')
    def _consistent(self):
        if len(self.text.encode('utf-8')) > _L.p11_review_text_bytes:
            raise ValueError(f'text must be at most {_L.p11_review_text_bytes} bytes')
        if self.action == 'note' and not self.text.strip():
            raise ValueError('a note needs text')
        return self


# --- sidecar manifest and enrichment pointer ----------------------------------------------------------------------

class PilotPart(_Strict):
    """`sha256` and `bytes` describe the DECOMPRESSED canonical JSON (gzip is written with mtime 0, never hashed)."""
    name: Literal['assessment.json.gz']
    sha256: Sha256
    bytes: Count


class PilotManifest(_Strict):
    """Sidecar `manifest.json`: certifies its own `result_id` (it holds the whole identity payload and the config)."""
    contract: Literal['pilot-manifest/1'] = 'pilot-manifest/1'
    result_id: Sha256
    inputs: PilotInputs
    config: PilotConfig
    status: RunStatus
    limitations: tuple[PlainLine300, ...] = Field(default=(), max_length=MAX_NOTES)
    counts: LeadCounts
    queue_count: Count = 0
    parts: tuple[PilotPart, ...] = Field(max_length=4)
    created_utc: Utc

    @model_validator(mode='after')
    def _consistent(self):
        names = [p.name for p in self.parts]
        if names != sorted(set(names)):
            raise ValueError('parts must be sorted and unique')
        if 'assessment.json.gz' not in names:
            raise ValueError('parts must include assessment.json.gz')
        if sum(p.bytes for p in self.parts) > _L.p06_sidecar_bytes:
            raise ValueError('parts exceed the sidecar limit (P-06)')
        if self.status in ('partial', 'abstained') and not self.limitations:
            raise ValueError('a partial or abstained result names its limitations')
        return self


_RELATIVE_DIR = r'^intelligence/pilot/[0-9a-f]{16}$'


class PilotResultPointer(_Strict):
    """Body of the `patch-intent` enrichment row `pilot-result:<result_id>` (tiny; the data lives in the sidecar)."""
    contract: Literal['pilot-ptr/1'] = 'pilot-ptr/1'
    result_id: Sha256
    relative_dir: str = Field(pattern=_RELATIVE_DIR)
    manifest_sha256: Sha256
    status: RunStatus
    counts: LeadCounts
    config_digest: Sha256

    @model_validator(mode='after')
    def _dir_matches(self):
        if self.relative_dir.rsplit('/', 1)[1] != self.result_id[:16]:
            raise ValueError('relative_dir must end with result_id[:16]')
        return self


# --- in-memory views used by the ports (never persisted, no schema) -----------------------------------------------

class Candidate(_Strict):
    """A function pair (or one-sided function) of the candidate universe with its pairing verdict."""
    candidate_key: Sha256
    older: tuple[FunctionRef, ...] = Field(default=(), max_length=MAX_SIDE_FUNCTIONS)
    newer: tuple[FunctionRef, ...] = Field(default=(), max_length=MAX_SIDE_FUNCTIONS)
    identity: Identity = 'unassessed'

    @field_validator('older', 'newer')
    @classmethod
    def _sides(cls, value, info):
        return _sorted_unique(value, info.field_name, key=lambda f: f.rva)

    @model_validator(mode='after')
    def _has_a_function(self):
        if not self.older and not self.newer:
            raise ValueError('a candidate needs at least one function')
        return self


class PilotAnchor(_Strict):
    """What PIL offers an anchor sink; the anchor vocabulary and keys are owned by the insight fabric."""
    anchor_id: AnchorId
    kind: Slug
    label: PlainLine300
    facets: tuple[tuple[Slug, PlainLine300], ...] = Field(default=(), max_length=MAX_FACETS)


SCHEMA_MODELS = ((PilotAssessment, 'pilot/1'), (Lead, 'pilot/1'), (Observation, 'pilot/1'), (CveContext, 'pilot/1'),
                 (ReviewEvent, 'pilot-review/1'), (PilotResultPointer, 'pilot-ptr/1'),
                 (PilotManifest, 'pilot-manifest/1'))
