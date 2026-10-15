"""Exports of a stored assessment: canonical JSON and escaped Markdown (PIL-integration-plan.md s6, s8, s9 PIL-C1).

The assessment is the record and the report only restates it. JSON is the assessment itself (sorted keys, two-space
indentation, pure ASCII, so a bidi or control character can only be an escape) and reads back through
`PilotAssessment.model_validate_json`. Markdown follows the rules of `intelligence.reports`: every string that is not a
fixed template goes through `escape_md` (HTML entities, backslash-escaped Markdown, controls and bidi marks as `\\uXXXX`,
one line per cell, URLs as text), identifiers sit in code spans, and the document has no HTML, link or image.

Words, not slugs: every enum value is mapped to plain words here, and the wording makes no claim about probability or
about what a function contains or fixes (the standing caption of `why.FOOTER` is on every report). The same row words
(`badge`, `expected_seen`, `flags`, `rank_text`) serve the terminal listing of `cli.py`.

Limits (P-10): Markdown lists at most 200 leads per context and stops at 2 MiB with a visible note; JSON over 32 MiB is
refused rather than cut. Files are UTF-8 with LF only and are written atomically (`intelligence.reports.write_export`).
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

from ..intelligence.contracts import IntelError
from ..intelligence.reports import MAX_CELL, MAX_PROSE, escape_md, plain_text
from ..intelligence.reports import write_export as write_atomic
from .contracts import ChannelStatus, CveContext, Kev, Lead, PilotAssessment
from .limits import DEFAULT_LIMITS, PilotError, PilotLimits
from .review import LeadReview, ReviewKey, pinned_first
from .why import CHANNEL_LABELS, CLASS_WORDS, FOOTER, GATE_WORDS, QUEUE_WORDS, Explainer
from .why import STATE_WORDS as _STATE_WORDS

FORMATS = ('json', 'md')
_SUFFIXES = {'.json': 'json', '.md': 'md'}
_SAFE_CODE = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:@+=,~-')
_EXPLAINED = ('fit', 'review', 'partial', 'code')  # classes whose leads get a "Why" block (not the queue)
EXPLAINED_PER_CONTEXT = 20
_RESERVE = 400  # bytes kept free for the closing note

CLASS_BADGES = MappingProxyType({'fit': 'FITS ADVISORY', 'review': 'NEEDS REVIEW', 'partial': 'PARTIAL FIT',
                                 'code': 'CODE CHANGE', 'queue': 'CHANGED, NO FIT'})
NOT_ASSESSED = 'NOT ASSESSED'
PAIRING_WORDS = MappingProxyType({'corroborated': 'corroborated', 'contested': 'contested',
                                  'unassessed': 'not assessed'})
DEPTH_WORDS = MappingProxyType({'typed': 'typed', 'lexical': 'text evidence only', 'none': 'none'})
CAP_FLAGS = MappingProxyType({'confounded-window-needs-locality': 'several CVEs fixed here',
                              'toolchain-changed-lexical-only': 'toolchain changed',
                              'cve-unverified': 'advisory not tied to the builds',
                              'cve-conflict': 'advisory conflicts'})
CWE_WORDS = MappingProxyType({'explicit': 'stated by the advisory', 'derived': 'inferred from the advisory wording',
                              'weak': 'weak match only', 'vague': 'the advisory wording is too vague',
                              'none': 'none found'})
STATE_WORDS = MappingProxyType({'available': 'available', **_STATE_WORDS})
STATUS_WORDS = MappingProxyType({'complete': 'complete', 'partial': 'partial: some evidence was not available',
                                 'abstained': 'abstained: there is no candidate function pair'})
GATE_BANNERS = MappingProxyType({
    'asserted': GATE_WORDS['asserted'], 'unverified': GATE_WORDS['unverified'], 'conflict': GATE_WORDS['conflict'],
    'not-applicable': 'The advisory says these builds are not affected by this CVE, or the newer build is still '
                      'affected. No leads are produced for it.'})
INTRO = ('This report lists changed functions in the order that explainable rules give them. A lead is a place for a '
         'person to look; PatchTrace does not claim that a function contains or fixes a CVE.')
NO_ADVISORY = ('No advisory is loaded. Leads use code evidence only and are not matched to a CVE. Import an advisory to '
               'rank by fit.')
MISSING_EVIDENCE = 'Missing evidence is unknown, not a negative result.'
WINDOW_UNKNOWN = 'Whether other CVEs are fixed in this build is unknown.'
CODE_ONLY_TITLE = 'Code evidence only'


def window_text(count: int) -> str:
    return (f'The advisory lists {count} CVEs fixed in this build. A change that fits the expected shape may belong to '
            'another CVE; only advisory-specific evidence can separate them.')


def kev_text(kev: Kev) -> str:
    if kev.state == 'listed':
        return f'CISA KEV: listed (added {kev.date_added})'
    if kev.state == 'not-in-snapshot':
        return f'CISA KEV: not in the snapshot {kev.snapshot_id[:12]}; absence says nothing about exploitation'
    return 'CISA KEV: unknown'


# --- the words of one lead (shared with the terminal listing) ----------------------------------------------------------

def badge(lead: Lead) -> str:
    if lead.lead_class == 'queue':
        return QUEUE_WORDS[lead.mechanism].upper() if lead.mechanism == 'unexplained' else NOT_ASSESSED
    return CLASS_BADGES[lead.lead_class]


def expected_seen(lead: Lead) -> str:
    """"2 of 3" for the best hypothesis, "-" for a lead that no weakness rule was applied to."""
    return f'{lead.fits[0].met} of {lead.fits[0].total}' if lead.fits else '-'


def rank_text(lead: Lead) -> str:
    return f'{lead.tie.first}-{lead.tie.last} (tie)' if lead.tie.size > 1 else str(lead.rank)


def flags(lead: Lead, state: LeadReview | None = None) -> tuple[str, ...]:
    found = []
    if lead.depth == 'lexical':
        found.append(DEPTH_WORDS['lexical'])
    if lead.identity == 'contested':
        found.append('pairing contested')
    found += [CAP_FLAGS[cap] for cap in lead.caps]
    if state is not None:
        found += [word for word, on in (('pinned', state.pinned), ('dismissed', state.dismissed)) if on]
    return tuple(found)


def function_names(lead: Lead) -> str:
    """UNTRUSTED text: the function names of the newer side (else the older), at most two."""
    refs = lead.newer or lead.older
    names = ', '.join(ref.name or f'0x{ref.rva:x}' for ref in refs[:2])
    return names + (f' and {len(refs) - 2} more' if len(refs) > 2 else '')


def addresses(lead: Lead) -> str:
    """Module-relative addresses per side: numbers and words only, so nothing in it needs escaping."""
    parts = []
    for side in ('older', 'newer'):
        refs = getattr(lead, side)
        if refs:
            parts.append(f'{side} 0x{refs[0].rva:x}' + (f' and {len(refs) - 1} more' if len(refs) > 1 else ''))
    return ', '.join(parts)


def plain_label(lead: Lead, limit: int = 100) -> str:
    """Names and addresses for a terminal: controls and bidi marks as `\\uXXXX`, one line."""
    return f'{plain_text(function_names(lead), limit)} ({addresses(lead)})'


# --- JSON ---------------------------------------------------------------------------------------------------------------

def to_json(assessment: PilotAssessment) -> str:
    return json.dumps(assessment.model_dump(mode='json'), indent=2, sort_keys=True) + '\n'


# --- Markdown -----------------------------------------------------------------------------------------------------------

def _t(value: object, limit: int | None = MAX_CELL) -> str:
    return escape_md(value, limit)


def _c(value: object) -> str:
    """A code span for a safe identifier, otherwise the escaped text."""
    text = str(value)
    return f'`{text}`' if len(text) <= MAX_CELL and text and set(text) <= _SAFE_CODE else escape_md(text)


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    body = ['| ' + ' | '.join(cell or '-' for cell in row) + ' |' for row in rows]
    return ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |', *body, '']


def _head(a: PilotAssessment) -> list[str]:
    return ['# Patch-intent leads', '', INTRO, '', f'> {FOOTER}', '',
            f'- Result: {_c(a.result_id)} (contract {_c(a.contract)})', f'- Status: {STATUS_WORDS[a.status]}',
            f'- Older build: {_c(a.older_sha256)}', f'- Newer build: {_c(a.newer_sha256)}',
            '- Orientation: older to newer', f'- Computed: {_c(a.created_utc)}', '']


def _channels(channels: Sequence[ChannelStatus]) -> list[str]:
    rows = [[CHANNEL_LABELS[s.channel], STATE_WORDS[s.state], _t(s.reason or '')] for s in channels]
    gaps = [CHANNEL_LABELS[s.channel] for s in channels if s.state != 'available']
    note = [f'Some evidence was not available: {", ".join(gaps)}. {MISSING_EVIDENCE}', ''] if gaps else []
    return ['## Evidence channels', '', *_table(['Channel', 'State', 'Note'], rows), *note]


def _limitations(a: PilotAssessment) -> list[str]:
    if not a.limitations:
        return []
    return ['## Limitations', '', *(f'- {_t(line, MAX_PROSE)}' for line in a.limitations), '']


def _why(lines: Sequence[str]) -> list[str]:
    """The explanation of `why.py` as Markdown: its fixed headers in bold, its bullets and next steps as nested bullets.
    The standing caption is on top of the report, so it is not repeated under every lead."""
    body = [line for line in lines if line != f'- {FOOTER}']
    if body and body[-1] == 'Limitations':
        body.pop()
    out: list[str] = []
    for line in body:
        if line.startswith('- '):
            out.append('- ' + _t(line[2:], MAX_PROSE))
        elif line.startswith('  '):
            out.append('  - ' + _t(line.strip(), MAX_PROSE))
        else:
            out += ['', f'**{_t(line)}**', '']
    return out


def _statements(state: LeadReview | None) -> list[str]:
    if state is None or not state.statements:
        return []
    return ['', '**Analyst statement**', '',
            *(f'- {event.created_utc[:10]}: {_t(event.text.strip(), MAX_PROSE)}' for event in state.statements)]


def _context_head(context: CveContext) -> list[str]:
    lines = [f'## {_c(context.cve)}', '']
    banner = GATE_BANNERS.get(context.gate)
    if banner:
        lines += [f'> {banner}', '']
    cwe = context.cwe
    window = context.confounding
    lines += [f'- Weakness class: {CWE_WORDS[cwe.status]}{" (" + ", ".join(cwe.ids) + ")" if cwe.ids else ""}',
              f'- {kev_text(context.kev)}']
    if window.state == 'yes':
        lines.append(f'- {window_text(len(window.cves))}')
    elif window.state == 'unknown':
        lines.append(f'- {WINDOW_UNKNOWN}')
    n = context.counts
    lines += [f'- Leads: {CLASS_WORDS["fit"]} {n.fit}; {CLASS_WORDS["review"]} {n.review}; {CLASS_WORDS["partial"]} '
              f'{n.partial}; {CLASS_WORDS["code"]} {n.code}; {QUEUE_WORDS["unexplained"]} {n.queue}', '']
    return lines


def _lead_row(lead: Lead, state: LeadReview | None) -> list[str]:
    return [rank_text(lead), _t(function_names(lead)), addresses(lead), badge(lead), expected_seen(lead),
            str(lead.components.count), PAIRING_WORDS[lead.identity], ', '.join(flags(lead, state))]


_HEADERS = ('#', 'Function', 'Addresses', 'Class', 'Changes seen', 'Groups', 'Pairing', 'Flags')


class _Budget:
    """Lines that fit the size cap. A block is added whole or not at all, so the document never ends mid-table."""

    def __init__(self, cap: int):
        self.cap, self.size, self.lines, self.full = cap - _RESERVE, 0, [], False

    def add(self, block: Sequence[str]) -> bool:
        need = sum(len(line.encode('utf-8')) + 1 for line in block)
        if self.full or self.size + need > self.cap:
            self.full = True
            return False
        self.lines += block
        self.size += need
        return True


def _context(out: _Budget, a: PilotAssessment, explainer: Explainer, context: CveContext | None,
             reviews: Mapping[ReviewKey, LeadReview], limits: PilotLimits) -> None:
    leads = pinned_first([x for x in a.leads if x.cve == (context.cve if context else None)], reviews)
    if context is None:
        head = [f'## {CODE_ONLY_TITLE}', '', *([NO_ADVISORY, ''] if not a.cves else [])]
    else:
        head = _context_head(context)
    shown = leads[:limits.p10_markdown_leads_per_cve]
    table = _table(_HEADERS, (_lead_row(x, reviews.get((x.candidate_key, x.cve))) for x in shown))
    cut = [f'{len(leads) - len(shown)} further leads are not listed here; the JSON export has them all.', ''] \
        if len(leads) > len(shown) else []
    explained = [x for x in shown if x.lead_class in _EXPLAINED][:EXPLAINED_PER_CONTEXT]
    more = [f'Explanations are written for the first {EXPLAINED_PER_CONTEXT} leads of this list; the stored result '
            'explains any other lead.', ''] if len([x for x in shown if x.lead_class in _EXPLAINED]) > len(explained) else []
    if not out.add([*head, *(table if shown else []), *cut, *more]):
        return
    for lead in explained:
        state = reviews.get((lead.candidate_key, lead.cve))
        title = f'### Why: {_t(function_names(lead))} ({addresses(lead)})'
        if not out.add([title, *_why(explainer.explain(lead)), *_statements(state), '']):
            return


def to_markdown(a: PilotAssessment, reviews: Mapping[ReviewKey, LeadReview] | None = None, *,
                limits: PilotLimits = DEFAULT_LIMITS) -> str:
    reviews, explainer = reviews or {}, Explainer(a)
    out = _Budget(limits.p10_markdown_bytes)
    out.add(_head(a))
    out.add(_channels(a.channels))
    out.add(_limitations(a))
    for context in a.cves:  # the advisory's contexts first: the code-only list is the less specific one
        _context(out, a, explainer, context, reviews, limits)
    if any(lead.cve is None for lead in a.leads):
        _context(out, a, explainer, None, reviews, limits)
    if out.full:
        out.lines += ['', '(The report reached its size limit here; the JSON export has the rest.)']
    return '\n'.join(out.lines).rstrip('\n') + '\n'


# --- files --------------------------------------------------------------------------------------------------------------

def format_for(path: Path) -> str:
    fmt = _SUFFIXES.get(Path(path).suffix.lower())
    if fmt is None:
        raise PilotError('PT-PILOT-INPUT', 'The export file name must end in .json or .md', reason='export-suffix')
    return fmt


def render(assessment: PilotAssessment, fmt: str, reviews: Mapping[ReviewKey, LeadReview] | None = None, *,
           limits: PilotLimits = DEFAULT_LIMITS) -> bytes:
    """UTF-8 bytes with LF line endings only. Raises `PT-PILOT-LIMIT` for a JSON document over P-10."""
    if fmt == 'json':
        data = to_json(assessment).encode('utf-8')
        if len(data) > limits.p10_json_bytes:
            raise PilotError('PT-PILOT-LIMIT', 'The JSON export exceeds its limit; narrow the run to fewer CVEs',
                             reason='export-json-size')
        return data
    if fmt == 'md':
        return to_markdown(assessment, reviews, limits=limits).encode('utf-8')
    raise PilotError('PT-PILOT-INPUT', 'The export format must be json or md', reason='export-format')


def write_export(path: Path, data: bytes) -> None:
    """Write next to `path` and replace it atomically; an earlier file survives any failure."""
    try:
        write_atomic(path, data)
    except IntelError:
        raise PilotError('PT-PILOT-STORAGE', 'The export file could not be written', reason='export-write') from None
