"""Qt-free read model of the Leads dock (PIL-integration-plan.md s8 GUI): which state shows, the context choices, the lead
rows as precomputed plain strings, the banners and the filter. Text is final here so the widget code only places it; it
adds no claim beyond `report.py`/`why.py` (function names are untrusted and shown as plain text with controls escaped)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from ..intelligence.reports import plain_text
from .contracts import CveContext, Lead, PilotAssessment
from .report import (
    GATE_BANNERS,
    MISSING_EVIDENCE,
    NO_ADVISORY,
    PAIRING_WORDS,
    STATE_WORDS,
    addresses,
    badge,
    expected_seen,
    flags,
    function_names,
    rank_text,
    window_text,
)
from .review import LeadReview, ReviewKey
from .store import Loaded
from .why import CHANNEL_LABELS, FOOTER

DEFAULT_ROW_LIMIT = 100_000
CODE_ONLY_LABEL = 'No advisory (code evidence only)'
STATE_TEXT = MappingProxyType({
    'L0': 'Open a project to see leads.',
    'L1': 'No comparison result yet. Run the analysis first; leads are computed from stored results only.',
    'L7': NO_ADVISORY})


@dataclass(frozen=True, slots=True)
class LeadsInput:
    """What the owner thread knows: the project, the stored result (`Loaded`), a running stage and the last failure."""
    project_open: bool = True
    loaded: Loaded | None = None
    preparing: tuple[str, int, int] | None = None  # (stage, done, total)
    error: tuple[str, str] | None = None  # (code, message)
    cve: str | None = None
    reviews: Mapping[ReviewKey, LeadReview] | None = None


@dataclass(frozen=True, slots=True)
class ContextChoice:
    cve: str | None
    label: str
    kev_listed: bool = False


@dataclass(frozen=True, slots=True)
class LeadRow:
    key: str
    cve: str | None
    lead_class: str
    rank: str
    title: str
    badge: str
    expected: str
    pairing: str
    flags: str
    dismissed: bool = False
    pinned: bool = False


@dataclass(frozen=True, slots=True)
class Chip:
    channel: str
    label: str
    state: str


@dataclass(frozen=True, slots=True)
class LeadsView:
    state: str
    message: str
    rows: tuple[LeadRow, ...] = ()
    banners: tuple[str, ...] = ()
    chips: tuple[Chip, ...] = ()
    choices: tuple[ContextChoice, ...] = ()
    footer: str = FOOTER


def _missing(assessment: PilotAssessment) -> tuple[str, ...]:
    return tuple(CHANNEL_LABELS[s.channel] for s in assessment.channels if s.state != 'available')


def resolve_state(given: LeadsInput) -> str:
    """Precedence L5 > L6 > L4 > L3; L2 only before the first table; L8 is decided by `build_view`."""
    if not given.project_open:
        return 'L0'
    if given.error is not None:
        return 'L5'
    loaded = given.loaded
    if loaded is None or loaded.assessment is None:
        return 'L2' if given.preparing else 'L1'
    if loaded.state == 'stale':
        return 'L6'
    return 'L4' if _missing(loaded.assessment) else 'L3'


def _context_choice(context: CveContext) -> ContextChoice:
    fits = context.counts.fit
    kev = 'KEV, ' if context.kev.state == 'listed' else ''
    return ContextChoice(context.cve, f'{context.cve} {kev}{fits} fit', context.kev.state == 'listed')


def context_choices(assessment: PilotAssessment) -> tuple[ContextChoice, ...]:
    ordered = sorted(assessment.cves, key=lambda x: (x.kev.state != 'listed', x.cve))
    return (ContextChoice(None, CODE_ONLY_LABEL), *(_context_choice(x) for x in ordered))


def _row(lead: Lead, reviews: Mapping[ReviewKey, LeadReview]) -> LeadRow:
    state = reviews.get((lead.candidate_key, lead.cve))
    title = f'{plain_text(function_names(lead), 100)} ({addresses(lead)})'
    return LeadRow(key=lead.candidate_key, cve=lead.cve, lead_class=lead.lead_class, rank=rank_text(lead), title=title,
                   badge=badge(lead), expected=expected_seen(lead), pairing=PAIRING_WORDS[lead.identity],
                   flags=', '.join(flags(lead, state)), dismissed=bool(state and state.dismissed),
                   pinned=bool(state and state.pinned))


def _banners(assessment: PilotAssessment, cve: str | None, missing: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    if missing:
        out.append(f"Some evidence was not available: {', '.join(missing)}. {MISSING_EVIDENCE}")
    context = next((x for x in assessment.cves if x.cve == cve), None)
    if cve is None:
        out.append(NO_ADVISORY if not assessment.cves else '')
    elif context is not None:
        out.append(GATE_BANNERS.get(context.gate, ''))
        if context.confounding.state == 'yes':
            out.append(window_text(len(context.confounding.cves)))
    return tuple(text for text in out if text)


def _message(state: str, given: LeadsInput, missing: Sequence[str]) -> str:
    if state == 'L2':
        stage, done, total = given.preparing or ('', 0, 0)
        return f'Preparing leads: {stage} {done}/{total}' if total else 'Preparing leads: (no counts available)'
    if state == 'L5':
        code, message = given.error or ('', '')
        return (f'Leads could not be prepared: {plain_text(code, 64)}: {plain_text(message, 200)}. '
                'The stored comparison and earlier leads are unchanged.')
    if state == 'L6':
        changed = ', '.join(given.loaded.changed) if given.loaded else ''
        return f'These leads are out of date: {plain_text(changed, 200)}. They are shown for reference only.'
    if state == 'L4':
        return f"Some evidence was not available: {', '.join(missing)}. {MISSING_EVIDENCE}"
    return STATE_TEXT.get(state, '')


def build_view(given: LeadsInput, *, row_limit: int = DEFAULT_ROW_LIMIT) -> LeadsView:
    state = resolve_state(given)
    assessment = given.loaded.assessment if given.loaded else None
    if assessment is None:
        return LeadsView(state, _message(state, given, ()))
    missing = _missing(assessment)
    reviews = given.reviews or {}
    rows = tuple(_row(lead, reviews) for lead in assessment.leads if lead.cve == given.cve)
    if state in {'L3', 'L4'} and len(rows) > row_limit:
        return LeadsView('L8', f'Too many rows to display ({len(rows)}). Narrow the filter.')
    if state in {'L3', 'L4'} and given.cve is None and not assessment.cves:
        state = 'L7' if state == 'L3' else state
    chips = tuple(Chip(s.channel, CHANNEL_LABELS[s.channel], STATE_WORDS[s.state]) for s in assessment.channels)
    return LeadsView(state, _message(state, given, missing), rows, _banners(assessment, given.cve, missing), chips,
                     context_choices(assessment))


def filter_rows(rows: Sequence[LeadRow], *, lead_class: str | None, search: str, show_dismissed: bool
                ) -> tuple[LeadRow, ...]:
    needle = search.casefold()
    return tuple(r for r in rows if (lead_class is None or r.lead_class == lead_class)
                 and (show_dismissed or not r.dismissed) and (not needle or needle in r.title.casefold()))
