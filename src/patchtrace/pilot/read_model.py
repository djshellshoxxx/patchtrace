"""What the Leads panel shows, as plain data (PIL-integration-plan.md s8 "GUI"). No Qt.

A pure function of a stored `PilotAssessment`, the analyst's review events and a few facts about the project: the
context list, the table rows of one context, the detail pane, the banners and the one state the panel is in (L0-L8).
Every string a person reads is built here from fixed words; the free text of functions, advisories and notes is
bounded and stripped first (`sanitize_text`). Enum slugs never reach a string: each is mapped to words, and the
panel's claims sweep covers this whole table. A lead is ordered by rank, never given a number that looks like a
likelihood: the only figures shown are counts, ranks and ties.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import islice
from types import MappingProxyType

from ..gui.state import ChipSpec
from ..gui.text import ClaimsProfile, sanitize_text
from .contracts import (
    CHANNELS,
    ChannelStatus,
    CveContext,
    Lead,
    Observation,
    PilotAssessment,
)
from .review import LeadReview, ReviewKey, pinned_first
from .why import CHANNEL_LABELS, FOOTER, ORIGIN_WORDS, VERIFICATION_WORDS, Explainer, kind_label

# ---- the sweep ---------------------------------------------------------------------------------------------------

CLAIMS = ClaimsProfile(
    banned_stems=('probab', 'likelihood', 'confidence', 'percent', 'vulnerab', 'exploit', 'proven', 'certain',
                  'verified', 'safe', 'secure'),
    allowed_phrases=(FOOTER, 'absence says nothing about exploitation', 'cisa kev', 'analyst statement', 'provenance',
                     'does not show that this function contains or fixes any cve'))

# ---- states (plan s8 "States": exact text) -----------------------------------------------------------------------

L0 = 'Open a project to see leads.'
L1 = 'No comparison result yet. Run the analysis first; leads are computed from stored results only.'
L1B = ('No leads have been prepared for this comparison yet. Use Prepare leads; they are computed from the stored '
       'comparison and advisories only.')
L2 = 'Preparing leads: {stage} {done}/{total}'
L2_NO_COUNTS = 'Preparing leads: {stage} (no counts available)'
L4 = 'Some evidence was not available: {channels}. Missing evidence is unknown, not a negative result.'
L5 = 'Leads could not be prepared: {code}: {message}. The stored comparison and earlier leads are unchanged.'
L6 = 'These leads are out of date: {changed}. They are shown for reference only.'
L7 = ('No advisory is loaded. Leads use code evidence only and are not matched to a CVE. Import an advisory to rank '
      'by fit.')
L8 = 'Too many rows to display ({n}). Narrow the filter.'
GATE_TEXT = MappingProxyType({
    'not-applicable': 'The advisory says these builds are not affected by {cve}, or the newer build is still '
                      'affected. No leads are produced for it.',
    'unverified': 'This advisory could not be tied to these builds; the file name is never used. Leads for it are '
                  'capped at Partial fit.',
    'conflict': 'The advisory conflicts with itself or with the build order. Leads for it are capped at Needs '
                'review.',
    'asserted': 'The analyst assumed that {cve} applies to these builds.'})
WINDOW = ('The advisory lists {n} CVEs fixed in this build. A change that fits the expected shape may belong to '
          'another CVE; only advisory-specific evidence can separate them.')
ORIENTATION = 'Older build compared with newer build'
NO_ADVISORY = 'No advisory (code evidence only)'
NO_COUNTS = 'no counts available'
NO_FITS = 'none assessed'

_INPUT_WORDS = MappingProxyType({
    'older_sha256': 'the older file', 'newer_sha256': 'the newer file', 'ghidriff_run_id': 'the Ghidriff run',
    'raw_sha256': 'the Ghidriff output', 'unified_result_id': 'the unified result',
    'secondary_set_ids': 'the second-engine results', 'tool_keys': 'the tool results',
    'advisory_facts_ids': 'the advisories', 'kev_snapshot_id': 'the CISA KEV snapshot',
    'kb_link_digest': 'the knowledge-base links', 'asserted_gates': 'the assumed applicability',
    'lexicon_digest': 'the CWE vocabulary', 'rules_digest': 'the rule table', 'pilot_rules_digest': 'the expected-change table',
    'origins_digest': 'the evidence origins', 'tiers_version': 'the ranking rules', 'config_digest': 'the settings'})

# ---- words -------------------------------------------------------------------------------------------------------

CLASS_BADGE = MappingProxyType({'fit': '(+) FITS ADVISORY', 'review': '(?) NEEDS REVIEW', 'partial': '(~) PARTIAL FIT',
                                'code': '[#] CODE CHANGE', 'queue': '[ ] CHANGED, NO FIT'})
CLASS_NAME = MappingProxyType({'fit': 'fits advisory', 'review': 'needs review', 'partial': 'partial fit',
                               'code': 'code change', 'queue': 'changed, no fit'})
CLASS_FILTER = (('all', 'All classes'), ('fit', 'Fits advisory'), ('review', 'Needs review'),
                ('partial', 'Partial fit'), ('code', 'Code change'), ('queue', 'Changed, no fit'))
PAIRING_WORDS = MappingProxyType({'corroborated': 'corroborated', 'contested': 'contested',
                                  'unassessed': 'not assessed'})
ROLE_WORDS = MappingProxyType({'shape': 'supports the change', 'local': 'name matches the advisory',
                               'counter': 'argues against', 'conflict': 'conflicts', 'context': 'context only'})
STATE_WORDS = MappingProxyType({'available': 'available', 'partial': 'partial', 'not-run': 'not run',
                                'unsupported': 'unsupported', 'failed': 'failed', 'stale': 'out of date'})
# (glyph, shape, token): a state is told apart by its word and glyph; colour is only an extra.
_CHANNEL_CHIP = MappingProxyType({
    'available': ('+', 'round', 'ok'), 'partial': ('~', 'square', 'caution'), 'not-run': ('-', 'dashed', 'muted'),
    'unsupported': ('/', 'dashed', 'muted'), 'failed': ('!', 'diamond', 'error'), 'stale': ('?', 'square', 'caution')})
KEV_TEXT = MappingProxyType({
    'listed': 'CISA KEV: listed (added {date})',
    'not-in-snapshot': 'CISA KEV: not in the loaded snapshot; absence says nothing about exploitation',
    'unknown': 'CISA KEV: unknown'})
KEV_SHORT = MappingProxyType({'listed': 'KEV', 'not-in-snapshot': '', 'unknown': ''})
NOT_UNKNOWN = frozenset({'available'})
ACTIONS = ('pin', 'unpin', 'dismiss', 'restore', 'note')
OBS_LIMIT = 256


def clip(value: object, limit: int = 200) -> str:
    return sanitize_text(value, limit)


# ---- contexts ----------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Context:
    """One entry of the context combo: a CVE of the advisories, or the code-evidence-only list (`cve` None)."""
    cve: str | None
    label: str
    banners: tuple[str, ...]
    kev_line: str | None
    counts_line: str
    leadless: bool  # the gate says no leads are produced for it


def kev_text(context: CveContext) -> str:
    return KEV_TEXT[context.kev.state].format(date=context.kev.date_added)


def counts_line(context: CveContext) -> str:
    counts = context.counts
    parts = [f'{n} {word}' for n, word in ((counts.fit, 'fit'), (counts.review, 'review'), (counts.partial, 'partial'))
             if n]
    return ', '.join(parts) or 'no leads'


def _context(context: CveContext) -> Context:
    banners = []
    if context.gate in GATE_TEXT:
        banners.append(GATE_TEXT[context.gate].format(cve=clip(context.cve, 24)))
    if context.confounding.state == 'yes':
        banners.append(WINDOW.format(n=len(context.confounding.cves)))
    kev = KEV_SHORT[context.kev.state]
    label = f'{clip(context.cve, 24)}  {(kev + ", ") if kev else ""}{counts_line(context)}'
    return Context(context.cve, label, tuple(banners), kev_text(context), counts_line(context),
                   context.gate == 'not-applicable')


def contexts_of(assessment: PilotAssessment) -> tuple[Context, ...]:
    """KEV-listed CVEs first, then by identifier; the code-evidence-only list closes the combo, or is the only entry."""
    ordered = sorted(assessment.cves, key=lambda c: (c.kev.state != 'listed', c.cve))
    found = tuple(_context(c) for c in ordered)
    code_only = Context(None, NO_ADVISORY, (L7,) if not found else (), None, '', False)
    return (*found, code_only) if found else (code_only,)


# ---- rows --------------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class LeadRow:
    """One table row. Everything shown is precomputed text; `lead` and `review` are for the actions and the detail."""
    key: str
    lead: Lead
    review: LeadReview
    rank: str
    name: str
    badge: str
    expected: str
    channels: str
    pairing: str
    flags: str
    search: str
    pinned: bool
    accessible: str

    @property
    def dismissed(self) -> bool:
        return self.review.dismissed


def row_key(lead: Lead) -> str:
    return f'{lead.cve or "-"}|{lead.candidate_key}'


def _functions(lead: Lead) -> str:
    def one(side: Sequence) -> str:
        return ' / '.join(f'{clip(ref.name or "unnamed", 80)} @0x{ref.rva:x}' for ref in side[:3]) + (
            ' ...' if len(side) > 3 else '')
    older, newer = one(lead.older), one(lead.newer)
    if older and newer and older != newer:
        return f'{newer} (was {older})'
    return newer or older or 'unnamed function'


def rank_text(lead: Lead) -> str:
    tie = lead.tie
    return f'{tie.first}-{tie.last} (tie)' if tie.size > 1 else str(lead.rank)


def expected_text(lead: Lead) -> str:
    """The best-matching hypothesis' count, e.g. '2 of 3'; a count of what was seen, never a score."""
    if not lead.fits:
        return NO_FITS
    best = max(lead.fits, key=lambda fit: (fit.met, -fit.total))
    return f'{best.met} of {best.total}'


def _channel_words(channels: Iterable[str]) -> list[str]:
    seen = set(channels)
    return [CHANNEL_LABELS[c] for c in CHANNELS if c in seen]


def channels_text(lead: Lead, pool: Mapping[str, Observation], statuses: Mapping[str, ChannelStatus]) -> str:
    """'Advisory + Code; unknown: Capa': the channels that support the lead, then those whose silence is unknown."""
    seen = _channel_words(pool[i].channel for i in lead.support_ids if i in pool)
    silent = {pool[i].channel for i in lead.unknown_ids if i in pool}
    silent |= {c for c, s in statuses.items() if s.state not in NOT_UNKNOWN}
    unknown = _channel_words(silent - {pool[i].channel for i in lead.support_ids if i in pool})
    text = ' + '.join(seen) or 'no supporting channel'
    return f'{text}; unknown: {", ".join(unknown)}' if unknown else text


def flags_text(lead: Lead, review: LeadReview) -> str:
    flags = []
    if lead.depth == 'lexical' and lead.lead_class != 'queue':
        flags.append('text evidence only')
    if lead.identity == 'contested' or lead.lead_class == 'review':
        flags.append('contested')
    if 'toolchain-changed-lexical-only' in lead.caps:
        flags.append('toolchain changed')
    if 'confounded-window-needs-locality' in lead.caps:
        flags.append('several CVEs in this build')
    if review.pinned:
        flags.append('pinned')
    if review.dismissed:
        flags.append('dismissed')
    if review.statements:
        flags.append('analyst note')
    return ', '.join(flags)


def make_row(lead: Lead, review: LeadReview, pool: Mapping[str, Observation],
             statuses: Mapping[str, ChannelStatus]) -> LeadRow:
    name = _functions(lead)
    badge, expected = CLASS_BADGE[lead.lead_class], expected_text(lead)
    flags = flags_text(lead, review)
    return LeadRow(
        row_key(lead), lead, review, rank_text(lead), name, badge, expected, channels_text(lead, pool, statuses),
        f'Pairing {PAIRING_WORDS[lead.identity]}', flags, f'{name} {lead.cve or ""}'.casefold(), review.pinned,
        f'Rank {rank_text(lead)}, {name}, {CLASS_NAME[lead.lead_class]}, {expected} expected changes seen')


# ---- the model of one stored result ------------------------------------------------------------------------------

class LeadsModel:
    """A stored assessment plus the analyst's reviews. Built in a worker; read on the GUI thread (immutable)."""

    def __init__(self, assessment: PilotAssessment, reviews: Mapping[ReviewKey, LeadReview] | None = None) -> None:
        self.assessment = assessment
        self.reviews = reviews or {}
        self.pool = {o.obs_id: o for o in assessment.observations}
        self.statuses = {c.channel: c for c in assessment.channels}
        self.contexts = contexts_of(assessment)
        self._explainer = Explainer(assessment)

    @property
    def leads_total(self) -> int:
        return len(self.assessment.leads)

    def context(self, cve: str | None) -> Context:
        return next((c for c in self.contexts if c.cve == cve), self.contexts[0])

    def rows(self, cve: str | None) -> tuple[LeadRow, ...]:
        """The rows of one context, the Pinned band first, then the stored order (rank, tie, candidate key)."""
        if self.context(cve).leadless:
            return ()
        leads = [lead for lead in self.assessment.leads if lead.cve == cve]
        ordered = pinned_first(leads, self.reviews)
        empty = LeadReview()
        return tuple(make_row(lead, self.reviews.get((lead.candidate_key, lead.cve), empty), self.pool, self.statuses)
                     for lead in ordered)

    def detail(self, row: LeadRow) -> str:
        """'Why this function' as plain text under fixed headers, then the analyst's own statements."""
        lines = list(self._explainer.explain(row.lead))
        for event in row.review.statements:
            text = sanitize_text(event.text, 2_048, multiline=True)
            if text:
                lines += ['', f'Analyst statement ({clip(event.created_utc, 30)}): {text}']
        lines += ['', FOOTER]
        return '\n'.join(lines)

    def observations(self, row: LeadRow) -> tuple[ObservationRow, ...]:
        """The observations the lead cites, grouped for, against, unknown, alternative; at most 256 (P-02)."""
        lead = row.lead
        groups = ((lead.support_ids, 'for'), (lead.counter_ids, 'against'), (lead.unknown_ids, 'unknown'),
                  (lead.alternative_ids, 'alternative'))
        found = (observation_row(self.pool[i], standing) for ids, standing in groups for i in ids if i in self.pool)
        return tuple(islice(found, OBS_LIMIT))


@dataclass(frozen=True, slots=True)
class ObservationRow:
    obs_id: str
    standing: str
    kind: str
    channel: str
    role: str
    verification: str
    origin: str
    detail: str
    nav: object | None  # `Nav` of the contract, or None: nothing is fabricated for a row without a location


def observation_row(obs: Observation, standing: str) -> ObservationRow:
    origins = ', '.join(sorted({ORIGIN_WORDS.get(tag, 'other source') for tag in obs.origins}))
    return ObservationRow(obs.obs_id, standing, clip(kind_label(obs), 80), CHANNEL_LABELS[obs.channel],
                          ROLE_WORDS[obs.role], VERIFICATION_WORDS[obs.verification], origins, clip(obs.detail, 300),
                          obs.nav)


# ---- channel chips -----------------------------------------------------------------------------------------------

def channel_chips(assessment: PilotAssessment) -> tuple[ChipSpec, ...]:
    """One chip per channel in the fixed order; a channel the result does not list reads 'not run'."""
    known = {c.channel: c.state for c in assessment.channels}
    chips = []
    for channel in CHANNELS:
        state = known.get(channel, 'not-run')
        glyph, shape, token = _CHANNEL_CHIP[state]
        chips.append(ChipSpec(channel, glyph, f'{CHANNEL_LABELS[channel]}: {STATE_WORDS[state]}', shape, token))
    return tuple(chips)


# ---- the one state -----------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Presentation:
    """`state` is the plan's id; `headline` replaces the content when `content` is False (L0, L1, L2); banners sit
    above the table in precedence order (L5, L6, L4, then the context's own)."""
    state: str
    headline: str
    banners: tuple[str, ...]
    content: bool
    actions: tuple[str, ...]


def changed_words(changed: Sequence[str]) -> str:
    return ', '.join(_INPUT_WORDS.get(name, 'the project') for name in changed) or 'the project'


def unavailable_channels(assessment: PilotAssessment) -> str:
    return ', '.join(f'{CHANNEL_LABELS[c.channel]} ({STATE_WORDS[c.state]})' for c in assessment.channels
                     if c.state not in NOT_UNKNOWN)


def stage_text(stage: str, done: int, total: int | None) -> str:
    stage = clip(stage, 80) or 'working'
    if total is None:
        return L2_NO_COUNTS.format(stage=stage)
    return L2.format(stage=stage, done=done, total=total)


def present(*, project: bool, has_run: bool, model: LeadsModel | None, stale_changed: tuple[str, ...] | None = None,
            error: tuple[str, str] | None = None, progress: tuple[str, int, int | None] | None = None,
            context: Context | None = None, too_many: int = 0) -> Presentation:
    """Resolve the state. Precedence L5 > L6 > L4 > L3; L2 only before the first table; L0/L1 replace the content."""
    if not project:
        return Presentation('L0', L0, (), False, ())
    if model is None:
        if error is not None:
            return Presentation('L5', L5.format(code=clip(error[0], 40), message=clip(error[1], 200)), (), False,
                                ('retry', 'copy_details'))
        if progress is not None:
            return Presentation('L2', stage_text(*progress), (), False, ('cancel',))
        return Presentation('L1' if not has_run else 'L1b', L1 if not has_run else L1B, (), False,
                            ('prepare',) if has_run else ())
    banners, state, actions = [], 'L3', ['prepare']
    if error is not None:
        banners.append(L5.format(code=clip(error[0], 40), message=clip(error[1], 200)))
        state, actions = 'L5', ['retry', 'copy_details', 'prepare']
    if stale_changed is not None:
        banners.append(L6.format(changed=changed_words(stale_changed)))
        state = state if state == 'L5' else 'L6'
        actions = ['refresh', *actions]
    missing = unavailable_channels(model.assessment)
    if missing:
        banners.append(L4.format(channels=missing))
        state = state if state != 'L3' else 'L4'
    if progress is not None:
        banners.append(stage_text(*progress))
        actions = ['cancel']
    if context is not None:
        banners.extend(context.banners)
    if too_many:
        banners.append(L8.format(n=too_many))
    return Presentation(state, '', tuple(banners), True, tuple(dict.fromkeys(actions)))
