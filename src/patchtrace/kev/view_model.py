"""Qt-free view models and exact wording for the KEV context (KEV-integration-plan section 8). Pure.

``KevColumnProvider.cell`` is one dict lookup, so a 100,000-row KB table can call it per visible row. Every string
that came from the catalog passes through ``sanitize_text`` before it reaches a label, cell or export; nothing here
produces markup. Neither a number nor a colour is derived from KEV: the only ordering is the opt-in reading order.
"""
from __future__ import annotations

import datetime
from collections.abc import Sequence
from dataclasses import dataclass

from ..search.normalize import sanitize_text
from . import limits, teach
from .contracts import KevCatalog, KevChange, KevDelta, KevEntry, KevLookup
from .join import KevIndex, freshness, lookup_one

_STATES = ('listed', 'listed-ransomware', 'not-listed', 'no-catalog', 'invalid')
_TEXT = {'listed': teach.CELL_LISTED, 'listed-ransomware': teach.CELL_LISTED_RANSOMWARE,
         'not-listed': teach.CELL_NOT_LISTED, 'no-catalog': teach.CELL_NO_CATALOG, 'invalid': teach.CELL_INVALID}
_USE = {'known': 'Known', 'unknown': 'Unknown', 'absent': teach.SUMMARY_NOT_STATED,
        'unrecognized': teach.SUMMARY_UNRECOGNIZED}
_TRIAGE = {'yes': 'Yes', 'no': 'No', 'absent': teach.SUMMARY_NOT_STATED, 'unrecognized': teach.SUMMARY_UNRECOGNIZED}


def _clean(text: str, limit: int = 300) -> str:
    return sanitize_text(text, limit)


@dataclass(frozen=True)
class KevCell:
    """One table cell. ``order_key`` is 0 for listed CVEs and 1 otherwise (reading order, not a score)."""

    cve_id: str
    state: str
    text: str
    accessible: str
    order_key: int
    ransomware_known: bool
    italic: bool
    version: str
    meaning: str

    def tooltip_values(self) -> dict[str, str]:
        return {'cve': self.cve_id, 'state': self.text, 'version': self.version, 'meaning': self.meaning}


def age_phrase(days: int | None) -> str:
    if days is None:
        return 'age unknown'
    return 'today' if days == 0 else f'{days} day{"" if days == 1 else "s"} old'


def _state(lookup: KevLookup) -> str:
    if lookup.status == 'invalid-id':
        return 'invalid'
    if lookup.status == 'unavailable':
        return 'no-catalog'
    if lookup.status == 'not-listed':
        return 'not-listed'
    return 'listed-ransomware' if lookup.entry and lookup.entry.ransomware_use == 'known' else 'listed'


def _accessible(lookup: KevLookup, state: str, version: str) -> str:
    cve = lookup.cve_id
    if state == 'invalid':
        return f'{cve}: not a valid CVE ID. {teach.INVALID_ID_DETAIL}'
    if state == 'no-catalog':
        return f'{cve}: no KEV catalog is loaded.'
    stale = ' This catalog is out of date or its time is unverified.' if lookup.freshness in ('stale', 'future') else ''
    if state == 'not-listed':
        return (f'{cve}: not listed in CISA KEV catalog {version}, {age_phrase(lookup.age_days)}. '
                f'Not listed {teach.NOT_EXPLOITED_NEGATION}.{stale}')
    entry = lookup.entry
    ransomware = ', ransomware campaign use known to CISA' if state == 'listed-ransomware' else ''
    return f'{cve}: listed in CISA KEV, added {entry.date_added}{ransomware}. Catalog {version}.{stale}'


def cell_for(lookup: KevLookup, version: str) -> KevCell:
    state = _state(lookup)
    return KevCell(cve_id=lookup.cve_id, state=state, text=_TEXT[state], accessible=_accessible(lookup, state, version),
                   order_key=0 if state in ('listed', 'listed-ransomware') else 1,
                   ransomware_known=state == 'listed-ransomware', italic=state != 'invalid' and lookup.freshness in ('stale', 'future'),
                   version=version, meaning=teach.MEANING_KEV)


class KevColumnProvider:
    """Cells for any CVE over one snapshot (or none). Implements ``ports.KevLookupPort``."""

    def __init__(self, catalog: KevCatalog | None, now: datetime.datetime) -> None:
        self._index, self._now = KevIndex(catalog), now
        self.version = catalog.meta.catalog_version if catalog else ''

    def cell(self, cve: str) -> KevCell:
        return cell_for(lookup_one(self._index, cve, self._now), self.version)


def filter_indices(cells: Sequence[KevCell], key: str) -> list[int]:
    """Indices of the cells that pass filter ``key`` (one of ``teach.FILTERS``), in input order."""
    wanted = {'all': set(_STATES), 'listed': {'listed', 'listed-ransomware'}, 'listed-ransomware': {'listed-ransomware'},
              'not-listed': {'not-listed'}, 'no-catalog-or-invalid': {'no-catalog', 'invalid'}}[key]
    return [i for i, cell in enumerate(cells) if cell.state in wanted]


def order_indices(cells: Sequence[KevCell], indices: Sequence[int], key: str) -> list[int]:
    """``input`` keeps the order; ``kev-first`` moves listed CVEs ahead and keeps input order inside each group."""
    if key == 'input':
        return list(indices)
    return sorted(indices, key=lambda i: (cells[i].order_key, i))


def status_line(catalog: KevCatalog, now: datetime.datetime) -> str:
    meta = catalog.meta
    _, days = freshness(meta, now)
    released = f'{meta.date_released[:10]} {meta.date_released[11:16]}'
    return (f'KEV catalog {_clean(meta.catalog_version, 32)} - released {released} UTC - {meta.entry_count} entries - '
            f'retrieved {meta.retrieved_at[:10]} from {teach.SOURCE_LABELS[meta.source]} - {age_phrase(days)}')


def banner(catalog: KevCatalog | None, now: datetime.datetime) -> str:
    """The freshness banner, or an empty string for a fresh catalog (and for no catalog: page K0 speaks)."""
    state, days = freshness(catalog.meta if catalog else None, now)
    if state == 'future':
        return teach.K6_FUTURE
    if state == 'aging':
        return teach.K5_AGING.format(n=days)
    return teach.K6_STALE.format(n=days) if state == 'stale' else ''


def _lines(text: str, limit: int) -> list[str]:
    return [_clean(part.strip(), limit) for part in text.split(';') if part.strip()]


def _source_line(catalog: KevCatalog) -> str:
    meta = catalog.meta
    where = 'a local file' if meta.source == 'local-import' else (meta.final_url or meta.source_url or '').split('/')[2]
    return (f'Source: CISA KEV catalog (CC0 1.0), retrieved {meta.retrieved_at[:10]} from {_clean(where, 80)}, '
            f'SHA-256 {meta.raw_sha256}, parser {limits.PARSER_NAME}.')


def _listed_lines(entry: KevEntry, meta_version: str, released: str) -> list[str]:
    use = _USE[entry.ransomware_use]
    lines = [
        'KEV: listed',
        f"{entry.cve_id} is in CISA's Known Exploited Vulnerabilities catalog (catalog {meta_version}, "
        f'released {released}).',
        f'Added to KEV: {entry.date_added}', f'CISA due date: {entry.due_date}',
        f'Known ransomware campaign use: {use}']
    if entry.ransomware_use in ('known', 'unknown'):
        lines.append(f'  {use}: ' + (teach.RANSOMWARE_KNOWN if entry.ransomware_use == 'known'
                                     else teach.RANSOMWARE_UNKNOWN))
    cwes = ', '.join(entry.cwes) or 'none listed'
    lines += [
        f'Forensic triage required by CISA: {_TRIAGE[entry.forensic_triage]}',
        f'CISA lists this as: {_clean(entry.vendor_project, 128)} {_clean(entry.product, 256)} - {_clean(entry.name)}',
        f'CISA weakness list (CWE): {cwes} (listed by CISA; not used by PatchTrace for ranking)',
        f'CISA required action: {_clean(entry.required_action, 2048)}']
    notes = _lines(entry.notes, 300)
    lines.append('CISA notes: ' + (notes[0] if notes else '-'))
    lines += [f'  {note}' for note in notes[1:]]
    return lines + [f'What this means: {teach.WHAT_THIS_MEANS_LISTED}']


def detail_text(lookup: KevLookup, catalog: KevCatalog | None, now: datetime.datetime) -> str:
    """Plain text (LF) for the detail pane and the clipboard. Hostile catalog text is escaped, never interpreted."""
    if lookup.status == 'invalid-id':
        return f'Invalid CVE ID\n{teach.INVALID_ID_DETAIL}'
    if lookup.status == 'unavailable' or catalog is None:
        return f'KEV: no catalog loaded\n{teach.NO_CATALOG_DETAIL}'
    meta = catalog.meta
    released = meta.date_released[:10]
    if lookup.status == 'listed':
        lines = _listed_lines(lookup.entry, _clean(meta.catalog_version, 32), released)
    else:
        _, days = freshness(meta, now)
        lines = ['KEV: not listed',
                 f"{lookup.cve_id} is not in CISA's Known Exploited Vulnerabilities catalog "
                 f'{_clean(meta.catalog_version, 32)} (released {released}, {age_phrase(days)}).',
                 f'What this means: {teach.WHAT_THIS_MEANS_NOT_LISTED}']
    return '\n'.join(lines + [_source_line(catalog)])


def _change_phrases(change: KevChange) -> list[str]:
    old, new = change.before, change.after
    parts = []
    if old.ransomware_use != new.ransomware_use:
        parts.append(f'Known ransomware campaign use was {_USE[old.ransomware_use]}, now {_USE[new.ransomware_use]}')
    if old.due_date != new.due_date:
        parts.append(f'CISA due date was {old.due_date}, now {new.due_date}')
    if old.forensic_triage != new.forensic_triage:
        parts.append(f'Forensic triage required by CISA was {_TRIAGE[old.forensic_triage]}, '
                     f'now {_TRIAGE[new.forensic_triage]}')
    if old.cwes != new.cwes:
        parts.append(f'CISA weakness list was {", ".join(old.cwes) or "none"}, now {", ".join(new.cwes) or "none"}')
    return [f'{change.cve_id} changed: {part}' for part in parts]


def delta_lines(delta: KevDelta, new_catalog: KevCatalog) -> list[str]:
    """The "Show changes" list: a headline then at most 200 lines in all (the list is capped, never silently)."""
    by_id = {entry.cve_id: entry for entry in new_catalog.entries}
    lines = [teach.CHANGES_HEADLINE.format(a=delta.added_count, c=delta.changed_count, r=delta.removed_count,
                                           previous=_clean(delta.from_catalog_version, 32))]
    for cve in delta.added:
        entry = by_id.get(cve)
        lines.append(f'{cve} added {entry.date_added} ({_clean(entry.vendor_project, 128)} '
                     f'{_clean(entry.product, 256)})' if entry else f'{cve} added')
    for change in delta.changed:
        lines.extend(_change_phrases(change))
    lines.extend(f'{cve} removed' for cve in delta.removed)
    if len(lines) > limits.MAX_DELTA_LINES:
        shown = limits.MAX_DELTA_LINES - 1
        return lines[:shown] + [f'{len(lines) - shown} more lines are not shown.']
    return lines
