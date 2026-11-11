"""The KB context of a project as `kb` and `cve` advisory records (SPEC-50 amendment A-2). Pure, Qt-free.

`adapters._kb_context` reads the `kb-context` rows; this module picks the bundle that `kb explain` and `kb export` use
and restates it. A record says what the stored context holds and nothing more: the documents are named by digest
(the bundle stores no vendor, address or retrieval time), the KEV state is the one stored with the card, and every
record text ends with the context's own limitation. A stored field is neutralized to one line and capped before it
enters a record text, so persisted text cannot forge a line of a record; the caps keep the whole text under
`text.CAP_ADVISORY`, so the limitation is never cut off.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence

from ..kbcorrelation.context import LIMITATION, ContextBundle, SourceDigest
from ..kbcorrelation.contracts import CveCard
from ..kbcorrelation.ids import is_canonical_kb
from . import text
from .sections.advisories import AdvisoryRecord

FIELD_CAP, LABEL_CAP = 1000, 64  # one stored field / one source label inside a record text, after neutralization
MAX_SOURCES_LISTED, MAX_CVES_LISTED, MAX_CONTEXT_UNKNOWNS = 4, 20, 5
KEV_LISTED = {'listed': True, 'not-in-snapshot': False, 'not-loaded': None}
NOTE_SOURCE_FIELDS = ('advisories: KB context records name their source documents by SHA-256 only; vendor, address '
                      'and retrieval time are not stored in the project (unknown, not absent)')
NOTE_OTHER_PAIR = ('advisories: the stored KB context was prepared for another file pair than this project holds; '
                   'its kb and cve records are omitted')


def latest(bodies: Iterable[str]) -> ContextBundle | None:
    """The bundle `kb explain` and `kb export` use: the last by `(base_revision, context_key)`. Raises on a row that
    is not a valid `kbcorrelation/1` bundle or whose KB lead is not a canonical id."""
    bundles = [ContextBundle.model_validate_json(body) for body in bodies]
    chosen = max(bundles, key=lambda b: (b.base_revision, b.context_key), default=None)
    if chosen is not None and chosen.lead.kind == 'kb' and not is_canonical_kb(chosen.lead.value):
        raise ValueError('the KB lead of the stored context is not a canonical id')
    return chosen


def _field(value: str, cap: int = FIELD_CAP) -> str:
    return text.normalize_text(value, max_chars=cap)


def _source_lines(sources: Sequence[SourceDigest]) -> list[str]:
    lines = [' '.join(filter(None, ('Source:', _field(s.kind, LABEL_CAP), _field(s.release_id or '', LABEL_CAP),
                                    'SHA-256', s.sha256))) for s in sources[:MAX_SOURCES_LISTED]]
    if len(sources) > MAX_SOURCES_LISTED:
        lines.append(f'Source: {len(sources) - MAX_SOURCES_LISTED} more source document(s) are not listed here')
    return lines or ['Source: not recorded in the stored context']


def _digest(sources: Sequence[SourceDigest]) -> str | None:
    digests = {s.sha256 for s in sources}
    return next(iter(digests)) if len(digests) == 1 else None


def _card_sources(bundle: ContextBundle, card: CveCard) -> tuple[SourceDigest, ...]:
    """The documents the card's `cve` field reference names; a bundle without field references: every source."""
    named = {r.doc_id for r in bundle.card_facts if r.cve == card.cve and r.field == 'cve'}
    if not bundle.card_facts:
        return bundle.sources
    return tuple(s for s in bundle.sources if s.doc_id in named)


def _body(lines: list[str], sources: Sequence[SourceDigest]) -> str:
    return '\n'.join([*lines, *_source_lines(sources), f'Limitation: {LIMITATION}'])


def _cve_record(bundle: ContextBundle, card: CveCard) -> AdvisoryRecord:
    sources = _card_sources(bundle, card)
    cwe = (f'CWE: {card.stated_cwe} (stated by vendor, {card.source_kind.upper()})' if card.stated_cwe
           else 'CWE: not stated by the vendor')
    lines = [f'Title: {_field(card.title) if card.title else "not stated"}', cwe,
             f'Applicability: {_field(card.applicability) if card.applicability else "unknown"}']
    return AdvisoryRecord('cve', card.cve, _body(lines, sources), snapshot_digest=_digest(sources),
                          kev_listed=KEV_LISTED[card.kev])


def _kb_record(bundle: ContextBundle) -> AdvisoryRecord:
    cves = [card.cve for card in bundle.context.cards]
    shown = ', '.join(cves[:MAX_CVES_LISTED]) + (f' and {len(cves) - MAX_CVES_LISTED} more'
                                                 if len(cves) > MAX_CVES_LISTED else '')
    lines = [f'Lead of the KB investigation attached to this project (investigation {bundle.investigation_id}, '
             f'context key {bundle.context_key}).',
             f'CVE cards in the stored advisory context ({len(cves)}): {shown}' if cves
             else 'CVE cards in the stored advisory context: none']
    return AdvisoryRecord('kb', bundle.lead.value, _body(lines, bundle.sources),
                          snapshot_digest=_digest(bundle.sources))


def records(bundle: ContextBundle) -> tuple[tuple[AdvisoryRecord, ...], tuple[str, ...]]:
    """(one `kb` record for a KB lead, then one `cve` record per card; the lines `unknowns` gains)."""
    lead = bundle.lead
    out = [_kb_record(bundle)] if lead.kind == 'kb' else []
    out += [_cve_record(bundle, card) for card in bundle.context.cards]
    notes = [] if lead.kind == 'kb' else [
        f'advisories: the KB context has a {lead.kind} lead and the project stores no KB id for it; no kb record is '
        'exported (unknown, not absent)']
    if out:
        notes.append(NOTE_SOURCE_FIELDS)
    undated = sum(r.snapshot_digest is None for r in out)
    if undated:
        notes.append(f'advisories: {undated} KB context record(s) rest on more than one source document or on none, '
                     'so snapshot_digest is not set; the record text lists the documents')
    stated = bundle.context.unknowns
    notes += [f'advisories (KB context): {u}' for u in stated[:MAX_CONTEXT_UNKNOWNS]]
    if len(stated) > MAX_CONTEXT_UNKNOWNS:
        notes.append(f'advisories (KB context): {len(stated) - MAX_CONTEXT_UNKNOWNS} more stored unknown(s) are not '
                     'listed here')
    return tuple(out), tuple(notes)
