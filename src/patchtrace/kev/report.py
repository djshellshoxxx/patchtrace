"""The KEV block of an exported report (KEV-integration-plan section 8): Markdown in which nothing from the catalog, a
file name or a caller is ever markup. Pure: no Qt, network, sqlite3 or clock.

Fixed sentences are written here; every other string is either a value the contract already restricted to a fixed ASCII
shape (CVE and KB ids, dates, hashes, hosts), shown as a code span, or free text that passes ``escape_md``: HTML
characters become entities, Markdown punctuation is backslash-escaped (so a URL is text, never a link), control and
bidirectional characters are removed and line breaks become spaces, so a table row is always one line. Notes from CISA
are not part of the block. A person reads the block as of the day it was recorded, so the provenance line names the
catalog, its hash and its dates.
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from .contracts import SOURCE_HOSTS, KevCatalogMeta, KevContext, KevLookup, clean_text
from .kb_adapter import TIMELINE_UNKNOWN, TIMELINE_UNVERIFIED, timeline_phrase
from .view_model import NOT_RECOGNIZED, RANSOMWARE_UNKNOWN

HEADING = '### Exploitation context (CISA KEV)'
CLOSING = ('KEV lists a CVE as a known exploited vulnerability. It does not identify builds, KBs, files or functions. '
           'Not listed does not mean not exploited.')
ATTRIBUTION = 'Data: CISA Known Exploited Vulnerabilities catalog, CC0 1.0; not endorsed by CISA or DHS.'
MAX_CELL = 300
MAX_PROSE = 1000
_HEADERS = ('CVE', 'KEV', 'Added to KEV', 'CISA due date', 'Known ransomware campaign use',
            'Forensic triage required by CISA')
_MARKDOWN = frozenset('\\`*_{}[]()#+-.!|~=^$@:')
_ENTITIES = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'}
_ESCAPES = {ord(char): '\\' + char for char in _MARKDOWN} | {ord(char): text for char, text in _ENTITIES.items()}
_SAFE_CODE = re.compile(r'[A-Za-z0-9_./:@+=,~-]+')       # no space, backtick, pipe or backslash: inert in a code span
_RANSOMWARE = {'known': 'Known', 'unknown': 'Unknown', 'absent': '-', 'unrecognized': NOT_RECOGNIZED}
_TRIAGE = {'yes': 'Yes', 'no': 'No', 'absent': '-', 'unrecognized': NOT_RECOGNIZED}


def escape_md(value: object, limit: int = MAX_CELL) -> str:
    """Inert single-line Markdown text for untrusted ``value``, cut to ``limit`` characters with an ellipsis."""
    return clean_text(value, limit).translate(_ESCAPES)


def _code(text: str) -> str:
    """A code span for a safe token, the escaped text for anything else."""
    return f'`{text}`' if _SAFE_CODE.fullmatch(text) else escape_md(text)


def _row(cells: Sequence[str]) -> str:
    return '| ' + ' | '.join(cells) + ' |'


def _cells(row: KevLookup) -> list[str]:
    if row.status != 'listed':
        return [_code(row.cve_id), 'Not listed', '-', '-', '-', '-']
    entry = row.entry
    return [_code(row.cve_id), 'Listed', _code(entry.date_added), _code(entry.due_date),
            _RANSOMWARE[entry.ransomware_use], _TRIAGE[entry.forensic_triage]]


def _provenance(context: KevContext, meta: KevCatalogMeta | None) -> str:
    released = context.date_released.replace('T', ' ').removesuffix('Z')
    recorded = f'recorded {context.created_at[:10]}'
    head = f'Catalog {_code(context.catalog_version)}, released {released} UTC'
    if meta is None:
        where = _code(SOURCE_HOSTS[context.source]) if context.source in SOURCE_HOSTS else 'a local file'
        return (f'{head}; source {where}; snapshot {_code(context.snapshot_id)}; content '
                f'{_code(context.content_digest)}; {recorded}. The catalog file is no longer stored on this computer, '
                f'so its SHA-256 and retrieval details are not shown. {ATTRIBUTION}')
    if meta.source in SOURCE_HOSTS:
        where = _code(SOURCE_HOSTS[meta.source])
    else:
        where = f'a local file ({_code(meta.file_name)})' if meta.file_name else 'a local file'
    entries = '1 entry' if meta.entry_count == 1 else f'{meta.entry_count} entries'
    return (f'{head}, {entries}; retrieved {meta.retrieved_at[:10]} from {where}; SHA-256 {_code(meta.raw_sha256)}; '
            f'snapshot {_code(context.snapshot_id)}; {recorded}. {ATTRIBUTION}')


def _timeline(context: KevContext) -> list[str]:
    """One bullet per listed CVE; when orientation or release date leave nothing to relate, that one sentence, once."""
    if context.kb is None:
        return []
    phrases = [(row.cve_id, timeline_phrase(row, context.kb, context.release_date,
                                            orientation_verified=context.orientation_verified))
               for row in context.lookups]
    phrases = [(cve, text) for cve, text in phrases if text]
    texts = {text for _, text in phrases}
    if texts <= {TIMELINE_UNVERIFIED, TIMELINE_UNKNOWN}:
        return sorted(texts)
    return [f'- {_code(cve)}: {text}' for cve, text in phrases]


def report_block(context: KevContext, meta: KevCatalogMeta | None = None, *, drift: Sequence[str] = ()) -> str:
    """The Markdown block for one recorded context: heading, provenance line, a table with one row per CVE (an empty
    cell is ``-``), the relation to the update's release when the context names a KB, any ``drift`` sentences (see
    ``project_context.drift_lines``) and the closing sentence. ``meta`` is the stored catalog of the context, when it is
    still on this computer; ``ValueError`` if it is another one. Ends with one newline, LF only."""
    if meta is not None and meta.snapshot_id != context.snapshot_id:
        raise ValueError('meta describes another snapshot than the context')
    table = [_row(_HEADERS), _row(['---'] * len(_HEADERS)), *(_row(_cells(row)) for row in context.lookups)]
    parts = [[HEADING], [_provenance(context, meta)], table]
    if any(row.entry is not None and row.entry.ransomware_use == 'unknown' for row in context.lookups):
        parts.append([f'In the ransomware column, Unknown means: {RANSOMWARE_UNKNOWN}'])
    parts += [part for part in (_timeline(context), [f'- {escape_md(line, MAX_PROSE)}' for line in drift]) if part]
    parts.append([CLOSING])
    return '\n\n'.join('\n'.join(part) for part in parts) + '\n'
