"""Pure view model of the KEV dock and of the KEV column other tables embed (KEV-integration-plan section 8).

No Qt and no I/O. Every string here is plain text: CISA's own words are cleaned to one line each at parse time, so a
value can never open a line of its own, and the fixed sentences never claim more than the catalog says: "Listed" means
CISA lists the CVE, "Not listed" means this snapshot does not and is never evidence of safety, and "no catalog" and
"invalid ID" say nothing about the CVE. The only ordering offered is the opt-in "listed first" reading order, a stable
partition that is not a score; nothing here touches a ranking.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from . import limits
from .contracts import (
    Freshness,
    KevCatalog,
    KevCatalogMeta,
    KevChange,
    KevDelta,
    KevEntry,
    KevLookup,
    KevPlan,
    clean_text,
    https_host,
    is_cve_id,
)
from .join import classify, freshness_of, lookup

CellState = Literal['listed', 'not-listed', 'no-catalog', 'invalid-id']

FOOTER = ('KEV is context about a CVE. It does not locate the fix in code. Data: CISA Known Exploited Vulnerabilities '
          'catalog (CC0 1.0); not endorsed by CISA or DHS.')
NOT_PROVIDED = 'not provided in this catalog'
NOT_RECOGNIZED = 'value not recognized by PatchTrace'
LISTED_MEANING = 'CISA lists this CVE as a known exploited vulnerability.'
NOT_LISTED_NEGATION = 'Not listed does not mean not exploited.'

STATE_MEANING: dict[str, str] = {
    'listed': LISTED_MEANING,
    'not-listed': 'Absent from this catalog snapshot, which does not mean unexploited.',
    'no-catalog': 'No catalog is loaded, so nothing is known about this CVE.',
    'invalid-id': 'Expected CVE-YYYY-NNNN with ASCII digits.',
}
RANSOMWARE_KNOWN = 'CISA reports this vulnerability has been leveraged as part of a ransomware campaign.'
RANSOMWARE_UNKNOWN = ('CISA lacks confirmation that this vulnerability has been utilized for ransomware. This is not a '
                      'statement that it has not been.')
COLUMN_MEANING: dict[str, str] = {
    'kev': ('Listed: CISA lists this CVE as a known exploited vulnerability. Not listed: absent from this catalog '
            'snapshot, which does not mean unexploited. No catalog: nothing is loaded.'),
    'added': ('The date CISA added this CVE to the catalog. It is not the date exploitation began or the date a fix '
              'shipped.'),
    'due': ('The date CISA lists for completing the required action. It is a CISA date for the organizations its '
            'directive covers, not a Microsoft date and not a severity rating.'),
    'ransomware': f'Known: {RANSOMWARE_KNOWN} Unknown: {RANSOMWARE_UNKNOWN}',
}
_RANSOMWARE_LABEL = {'known': 'Known', 'unknown': 'Unknown', 'absent': NOT_PROVIDED, 'unrecognized': NOT_RECOGNIZED}
_TRIAGE_LABEL = {'yes': 'Yes', 'no': 'No', 'absent': NOT_PROVIDED, 'unrecognized': NOT_RECOGNIZED}
_SOURCE_LABEL = {'cisa-site': 'CISA website', 'cisa-github': 'CISA GitHub mirror', 'local-import': 'a local file'}

FILTER_ITEMS = (('all', 'All CVEs'), ('listed', 'Listed in KEV'), ('listed-ransomware', 'Listed, ransomware use known'),
                ('not-listed', 'Not listed'), ('no-catalog-or-invalid', 'No catalog or invalid ID'))
SORT_ITEMS = (('input', 'Input order'), ('kev-first', 'KEV-listed first (reading order, not a score)'))

# States of the dock that need no data from a catalog (K0, K8 and K9 of the plan).
STATE_TEXT: dict[str, str] = {
    'no-catalog': ('No KEV catalog is loaded. PatchTrace works without it. Update from CISA... downloads about 1.8 MB '
                   'after you confirm the exact request. Import file... reads a KEV JSON file you saved yourself '
                   '(known_exploited_vulnerabilities.json).'),
    'checking': 'Checking the downloaded file...',
    'blocked': 'Network updates are switched off here. Import file... still works.',
    'loading': 'Loading the KEV catalog from this computer...',
    'empty-list': 'Type or paste CVE IDs above, or open a KB or CVE view that passes its CVEs here.',
}
SOURCE_CHOICES: dict[str, str] = {
    'cisa-site': 'CISA website (www.cisa.gov)',
    'cisa-github': "CISA GitHub mirror (raw.githubusercontent.com): CISA's own copy, synchronized within minutes."}
ERROR_REASONS: dict[str, str] = {
    'network': 'the connection failed or timed out',
    'http': 'the server answered HTTP {status}',
    'size': f'the file is larger than {limits.MAX_CATALOG_BYTES // limits.MIB} MiB',
    'format': 'the file is not a KEV JSON catalog',
    'checks': 'the file failed checks ({check})',
    'shrink': 'the new catalog has {n} fewer entries than the one in use',
    'storage': 'the catalog folder cannot be written',
}
_WHAT_THIS_MEANS_LISTED = (
    f'What this means: {LISTED_MEANING} It does not say which builds, KBs, files or functions were involved, and it '
    'does not show that any function changed in your comparison relates to this CVE.')
_WHAT_THIS_MEANS_NOT_LISTED = (
    'What this means: this snapshot does not list the CVE. That is not evidence that the CVE is unexploited: CISA lists '
    'only entries that meet its own requirements, and the catalog may have changed since this snapshot.')
_FUTURE_LINE = ("The catalog's release time is in the future. Check this computer's clock and treat results as "
                'unverified.')
_NO_CATALOG_DETAIL = ('KEV: no catalog loaded\nNothing can be said about this CVE until a catalog is loaded. Use '
                      'Update from CISA... or Import file...')
_INVALID_DETAIL = 'Invalid CVE ID\nExpected CVE-YYYY-NNNN with ASCII digits (for example CVE-2024-38063).'


# --- age and catalog lines ----------------------------------------------------------------------------------

def age_phrase(freshness: Freshness, age_days: int | None) -> str:
    if freshness == 'future':
        return 'release time in the future'
    if age_days is None:
        return 'age not known'
    if age_days == 0:
        return 'today'
    return '1 day old' if age_days == 1 else f'{age_days} days old'


def _age_clause(freshness: Freshness, age_days: int | None) -> str:
    if freshness == 'aging':
        return f' The catalog is {age_days} days old.'
    if freshness == 'stale':
        return f' The catalog is {age_days} days old and may lack newer entries.'
    if freshness == 'future':
        return " The catalog's release time is in the future; treat as unverified."
    return ''


def status_line(meta: KevCatalogMeta, freshness: Freshness, age_days: int | None) -> str:
    entries = '1 entry' if meta.entry_count == 1 else f'{meta.entry_count} entries'
    released = meta.date_released.replace('T', ' ').removesuffix('Z')
    return (f'KEV catalog {meta.catalog_version} - released {released} UTC - {entries} - retrieved '
            f'{meta.retrieved_at[:10]} from {_SOURCE_LABEL[meta.source]} - {age_phrase(freshness, age_days)}')


def banner_text(freshness: Freshness, age_days: int | None) -> str | None:
    if freshness == 'aging':
        return f'This catalog is {age_days} days old. CVEs CISA added since then are not shown as listed.'
    if freshness == 'stale':
        return (f'This catalog is {age_days} days old. A CVE shown as Not listed may have been added since. Update '
                'from CISA... or import a newer file.')
    if freshness == 'future':
        return _FUTURE_LINE
    return None


# --- cells --------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class KevCell:
    """One KEV cell of any table. ``order_key`` is 0 for a listed CVE and 1 for every other state; it feeds the opt-in
    reading order only. ``italic`` is the non-colour cue for a stale or future-dated catalog."""
    cve: str
    state: CellState
    text: str
    accessible: str
    order_key: int
    ransomware_known: bool
    italic: bool
    version: str
    meaning: str

    def tooltip_values(self) -> dict[str, str]:
        return {'cve': self.cve, 'state': self.text, 'version': self.version, 'meaning': self.meaning}


def _cell(cve: str, catalog: KevCatalog | None, freshness: Freshness, age_days: int | None) -> KevCell:
    status, entry = classify(catalog, cve)
    if status == 'invalid-id':
        echo = clean_text(cve, limits.MAX_ECHO_CHARS)
        sentence = f'Invalid CVE ID {echo}. ' if echo else 'Invalid CVE ID. '
        return KevCell(echo, 'invalid-id', 'Invalid CVE ID', sentence + 'Expected CVE-YYYY-NNNN with ASCII digits.',
                       1, False, False, 'none', STATE_MEANING['invalid-id'])
    if catalog is None:
        return KevCell(cve, 'no-catalog', 'No catalog', f'{cve}: no KEV catalog is loaded.', 1, False, False,
                       'none', STATE_MEANING['no-catalog'])
    version, clause = catalog.meta.catalog_version, _age_clause(freshness, age_days)
    italic = freshness in ('stale', 'future')
    if entry is None:
        sentence = f'{cve}: not listed in CISA KEV catalog {version}. {NOT_LISTED_NEGATION}{clause}'
        return KevCell(cve, 'not-listed', 'Not listed', sentence, 1, False, italic, version,
                       STATE_MEANING['not-listed'])
    known = entry.ransomware_use == 'known'
    sentence = (f'{cve}: listed in CISA KEV, added {entry.date_added}'
                f'{", ransomware campaign use known to CISA" if known else ""}. Catalog {version}.{clause}')
    text = 'Listed - ransomware known' if known else 'Listed'
    return KevCell(cve, 'listed', text, sentence, 0, known, italic, version, STATE_MEANING['listed'])


class KevColumnProvider:
    """Cells for one catalog snapshot at one injected moment (``ports.KevLookupPort``). A cell is built once per ID,
    so a table of 100,000 rows only pays for its distinct CVEs."""
    __slots__ = ('_catalog', '_now', '_cells', 'meta', 'freshness', 'age_days')

    def __init__(self, catalog: KevCatalog | None, now: datetime):
        self._catalog, self._now = catalog, now
        self._cells: dict[str, KevCell] = {}
        self.meta = None if catalog is None else catalog.meta
        self.freshness, self.age_days = (('unknown', None) if catalog is None
                                         else freshness_of(catalog.meta.date_released, now))

    def cell(self, cve: str) -> KevCell:
        found = self._cells.get(cve)
        if found is None:
            found = self._cells[cve] = _cell(cve, self._catalog, self.freshness, self.age_days)
        return found

    def lookup(self, cve: str) -> KevLookup:
        return lookup(self._catalog, [cve], self._now)[0]

    def summary_line(self, cves: Iterable[str]) -> str | None:
        """One sentence such as "2 of 6 CVEs in this KB are listed ...": counts only, no percentage, no score word."""
        if self._catalog is None:
            return None
        valid = [cve for cve in dict.fromkeys(cves) if is_cve_id(cve)]
        if not valid:
            return None
        listed = sum(1 for cve in valid if cve in self._catalog.by_cve)
        return (f'{listed} of {len(valid)} CVEs in this KB are listed in CISA KEV (catalog '
                f'{self._catalog.meta.catalog_version}, {age_phrase(self.freshness, self.age_days)}). '
                f'{NOT_LISTED_NEGATION}')


# --- filter and reading order: one pass each, never a score -------------------------------------------------

_FILTERS = {
    'all': lambda cell: True,
    'listed': lambda cell: cell.state == 'listed',
    'listed-ransomware': lambda cell: cell.state == 'listed' and cell.ransomware_known,
    'not-listed': lambda cell: cell.state == 'not-listed',
    'no-catalog-or-invalid': lambda cell: cell.state in ('no-catalog', 'invalid-id'),
}


def filter_indices(cells: Sequence[KevCell], mode: str) -> list[int]:
    try:
        keep = _FILTERS[mode]
    except KeyError:
        raise ValueError(f'unknown filter {mode!r}') from None
    return [index for index, cell in enumerate(cells) if keep(cell)]


def order_indices(cells: Sequence[KevCell], mode: str, indices: Iterable[int] | None = None) -> list[int]:
    """``input`` keeps the order given; ``kev-first`` is a stable partition: listed CVEs first, each group in the input
    order. It is a reading order for a person with little time, not a ranking and not a score."""
    chosen = range(len(cells)) if indices is None else indices
    if mode == 'input':
        return list(chosen)
    if mode != 'kev-first':
        raise ValueError(f'unknown order {mode!r}')
    listed, other = [], []
    for index in chosen:
        (listed if cells[index].order_key == 0 else other).append(index)
    return listed + other


# --- detail text --------------------------------------------------------------------------------------------

def _source_line(meta: KevCatalogMeta) -> str:
    if meta.final_url is not None:
        where = https_host(meta.final_url)
    else:
        where = f'a local file ({clean_text(meta.file_name, 64)})' if meta.file_name else 'a local file'
    return (f'Source: CISA KEV catalog (CC0 1.0), retrieved {meta.retrieved_at[:10]} from {where}, SHA-256 '
            f'{meta.raw_sha256}, parser kev-parse/{meta.parser_version}.')


def _listed_as(entry) -> str:
    who = ' '.join(part for part in (entry.vendor_project, entry.product) if part)
    return ' - '.join(part for part in (who, entry.name) if part) or NOT_PROVIDED


def _entry_lines(row: KevLookup, meta: KevCatalogMeta) -> list[str]:
    entry = row.entry
    lines = ['KEV: listed',
             f"{row.cve_id} is in CISA's Known Exploited Vulnerabilities catalog (catalog {meta.catalog_version}, "
             f'released {meta.date_released[:10]}).',
             f'Added to KEV: {entry.date_added}', f'CISA due date: {entry.due_date}',
             f'Known ransomware campaign use: {_RANSOMWARE_LABEL[entry.ransomware_use]}']
    if entry.ransomware_use in ('known', 'unknown'):
        lines.append(f'  {_RANSOMWARE_LABEL[entry.ransomware_use]}: '
                     f'{RANSOMWARE_KNOWN if entry.ransomware_use == "known" else RANSOMWARE_UNKNOWN}')
    lines += [f'Forensic triage required by CISA: {_TRIAGE_LABEL[entry.forensic_triage]}',
              f'CISA lists this as: {_listed_as(entry)}']
    if entry.cwes:
        lines.append(f'CISA weakness list (CWE): {", ".join(entry.cwes)} '
                     '(listed by CISA; not used by PatchTrace for ranking)')
    else:
        lines.append('CISA weakness list (CWE): none listed')
    if isinstance(entry, KevEntry):
        if entry.required_action:
            lines.append(f'CISA required action: {entry.required_action}')
        segments = [part.strip() for part in entry.notes.split(';') if part.strip()]
        if segments:
            lines.append('CISA notes:')
            lines += [f'  {part}' for part in segments[:limits.MAX_NOTE_LINES]]
            if len(segments) > limits.MAX_NOTE_LINES:
                lines.append(f'  ... and {len(segments) - limits.MAX_NOTE_LINES} more segments not shown.')
    return lines


def detail_text(row: KevLookup, meta: KevCatalogMeta | None) -> str:
    """The read-only detail of one lookup: exact CISA wording for a listed CVE, and for every other state a plain
    statement of what the answer does not mean. Lines are LF-separated; no value can start a line of its own."""
    if row.status == 'invalid-id':
        return _INVALID_DETAIL
    if row.status == 'unavailable':
        return _NO_CATALOG_DETAIL
    if meta is None:
        raise ValueError('an answered lookup needs the meta of its catalog')
    if row.status == 'listed':
        lines = _entry_lines(row, meta)
        if row.freshness == 'future':
            lines.insert(2, _FUTURE_LINE)
        return '\n'.join([*lines, _WHAT_THIS_MEANS_LISTED, _source_line(meta)])
    lines = ['KEV: not listed',
             f"{row.cve_id} is not in CISA's Known Exploited Vulnerabilities catalog {meta.catalog_version} (released "
             f'{meta.date_released[:10]}, {age_phrase(row.freshness, row.age_days)}).']
    if row.freshness == 'future':
        lines.append(_FUTURE_LINE)
    return '\n'.join([*lines, _WHAT_THIS_MEANS_NOT_LISTED, _source_line(meta)])


# --- snapshot changes ---------------------------------------------------------------------------------------

def _change_text(change: KevChange) -> str:
    before, after = change.before, change.after
    parts = []
    if before.ransomware_use != after.ransomware_use:
        parts.append(f'Known ransomware campaign use was {_RANSOMWARE_LABEL[before.ransomware_use]}, now '
                     f'{_RANSOMWARE_LABEL[after.ransomware_use]}')
    if before.due_date != after.due_date:
        parts.append(f'CISA due date was {before.due_date}, now {after.due_date}')
    if before.forensic_triage != after.forensic_triage:
        parts.append(f'Forensic triage required by CISA was {_TRIAGE_LABEL[before.forensic_triage]}, now '
                     f'{_TRIAGE_LABEL[after.forensic_triage]}')
    if before.cwes != after.cwes:
        parts.append(f'CISA weakness list was {", ".join(before.cwes) or "empty"}, now '
                     f'{", ".join(after.cwes) or "empty"}')
    return f'{change.cve_id} changed: ' + '; '.join(parts)


def changes_lines(delta: KevDelta, new: KevCatalog, previous_version: str) -> tuple[str, ...]:
    """The read-only "Show changes" list: a header with the true counts, then added, changed and removed CVEs, at most
    ``MAX_CHANGE_LINES`` lines with an honest remainder."""
    header = (f'{delta.added_count} new, {delta.changed_count} changed, {delta.removed_count} removed since catalog '
              f'{previous_version}.')
    items = []
    for cve in delta.added:
        entry = new.by_cve[cve]
        who = ' '.join(part for part in (entry.vendor_project, entry.product) if part)
        items.append(f'{cve} added {entry.date_added}' + (f' ({who})' if who else ''))
    items += [_change_text(change) for change in delta.changed]
    items += [f'{cve} is no longer listed' for cve in delta.removed]
    total = delta.added_count + delta.changed_count + delta.removed_count
    room = limits.MAX_CHANGE_LINES - 1
    if total <= room and len(items) == total:
        return (header, *items)
    shown = items[:room - 1]
    return (header, *shown, f'... and {total - len(shown)} more not shown.')


# --- copy of the other dock states --------------------------------------------------------------------------

def consent_lines(plan: KevPlan) -> tuple[str, ...]:
    """The inline confirmation: the exact request, what is sent and what comes back."""
    size = f'about {plan.expected_bytes_hint / 1_000_000:.1f} MB' if plan.expected_bytes_hint else 'size not known'
    return ('Download the KEV catalog from CISA?', f'Request: GET {plan.url}',
            'Sent: only this address and the headers Accept: application/json and User-Agent: PatchTrace. No project '
            'data and no CVE IDs. Environment proxies are ignored.',
            f'Received: one JSON file, {size} (limit {plan.max_bytes // limits.MIB} MiB). It is saved on this computer '
            'and checked before it replaces the catalog in use.')


def downloading_text(host: str, received_mb: float, expected_mb: float) -> str:
    return f'Downloading from {host}... {received_mb:.1f} of about {expected_mb:.1f} MB'


def mirror_older_text(downloaded_version: str, in_use_version: str) -> str:
    return (f'The downloaded catalog ({downloaded_version}) is older than the one in use ({in_use_version}); the newer '
            'one was kept.')


def kept_text(version: str | None, date_text: str | None) -> str:
    return 'No catalog is loaded.' if version is None else f'The catalog {version} from {date_text} is still in use.'


def error_text(reason: str, kept: str, **values) -> str:
    """The K7 sentence "Could not update the KEV catalog: {reason}. {kept}". An unknown ``reason`` raises KeyError;
    every value is cleaned to one short plain line first."""
    cleaned = {name: clean_text(value, 80) for name, value in values.items()}
    return f'Could not update the KEV catalog: {ERROR_REASONS[reason].format(**cleaned)}. {kept}'
