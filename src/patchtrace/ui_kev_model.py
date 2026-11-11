"""What the KEV dock shows, decided without Qt (KEV panel spec s3-s5; it lives beside ``ui_kev`` because the ``kev`` package is held to stdlib-only imports): input parsing, table rows and columns, the
filtered and ordered view, and the closed wording of a failed update. Workers call ``load_snapshot`` and
``prepare_view`` with immutable inputs and return immutable results; nothing here touches a widget."""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from .kev import limits
from .kev.contracts import KevCatalogMeta, KevError, KevLookup, clean_text
from .kev.service import KevService
from .kev.view_model import (
    _RANSOMWARE_LABEL,
    COLUMN_MEANING,
    FILTER_ITEMS,
    SORT_ITEMS,
    KevCell,
    KevColumnProvider,
    filter_indices,
    order_indices,
)

MAX_INPUT_IDS = 5_000
NOT_SUPPLIED = 'Not supplied'
FILTER_MODES = tuple(value for value, _ in FILTER_ITEMS)
SORT_MODES = tuple(value for value, _ in SORT_ITEMS)
_SEPARATORS = re.compile(r'[\s,;]+')
_SHRINK = re.compile(r'has (\d{1,7}) fewer')
_HTTP = re.compile(r'HTTP (\d{3})')
_REASONS = {'PT-KEV-NETWORK': 'network', 'PT-KEV-PROVIDER': 'network', 'PT-KEV-LIMIT': 'size', 'PT-KEV-FORMAT': 'format',
            'PT-KEV-VALIDATE': 'checks', 'PT-KEV-SHRINK': 'shrink', 'PT-KEV-STORAGE': 'storage'}


def parse_ids(text: str) -> tuple[tuple[str, ...], bool]:
    """The distinct CVE IDs typed or pasted, in input order and cleaned (an invalid one stays, as an invalid row),
    and whether more than ``MAX_INPUT_IDS`` were given."""
    found = dict.fromkeys(clean_text(part, limits.MAX_ECHO_CHARS) for part in _SEPARATORS.split(text or '') if part)
    found.pop('', None)
    ids = tuple(found)
    return ids[:MAX_INPUT_IDS], len(ids) > MAX_INPUT_IDS


@dataclass(frozen=True, slots=True)
class KevRow:
    key: str
    cell: KevCell
    lookup: KevLookup

    @property
    def cve(self) -> str:
        return self.cell.cve or 'Invalid CVE ID'

    def _date(self, field: str) -> str:
        entry = self.lookup.entry
        return NOT_SUPPLIED if entry is None else getattr(entry, field)

    @property
    def added(self) -> str:
        return self._date('date_added')

    @property
    def due(self) -> str:
        return self._date('due_date')

    @property
    def ransomware(self) -> str:
        entry = self.lookup.entry
        return NOT_SUPPLIED if entry is None else _RANSOMWARE_LABEL[entry.ransomware_use]


def _column(key: str, title: str, text, width_em: float, meaning: str, **extra) -> ColumnSpec:
    return ColumnSpec(key, title, text, width_em=width_em, tooltip=lambda _row: meaning, **extra)


COLUMNS = (
    ColumnSpec('cve', 'CVE', lambda r: r.cve, width_em=20, accessible=lambda r: r.cell.accessible),
    _column('kev', 'KEV', lambda r: r.cell.text, 24, COLUMN_MEANING['kev'], accessible=lambda r: r.cell.accessible),
    _column('added', 'Added to KEV', lambda r: r.added, 16, COLUMN_MEANING['added']),
    _column('due', 'CISA due date', lambda r: r.due, 16, COLUMN_MEANING['due']),
    _column('ransomware', 'Known ransomware campaign use', lambda r: r.ransomware, 30, COLUMN_MEANING['ransomware']))
SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: f'{r.cve} {r.cell.text}')


@dataclass(frozen=True, slots=True)
class Snapshot:
    """The catalog in use, read on a worker: ``provider`` answers for it (also when none is loaded)."""
    provider: KevColumnProvider
    notes: tuple[str, ...]
    snapshots: int


def load_snapshot(service: KevService, cancel) -> Snapshot:
    loaded = service.store.load_current()
    if cancel.checkpoint():
        raise KevError('PT-KEV-CANCEL', 'cancelled')
    provider = KevColumnProvider(None if loaded is None else loaded.catalog, service.now())
    return Snapshot(provider, () if loaded is None else loaded.notes, len(service.store.list_snapshots()))


@dataclass(frozen=True, slots=True)
class KevView:
    prepared: PreparedTable
    total: int      # distinct IDs asked for
    shown: int      # rows left after the filter


def prepare_view(provider: KevColumnProvider, ids: Sequence[str], filter_mode: str, sort_mode: str, cancel) -> KevView:
    """Cells, lookups, the status filter and the opt-in reading order. Filtering never removes an ID from the input."""
    cells = [provider.cell(cve) for cve in ids]
    if cancel.checkpoint():
        raise KevError('PT-KEV-CANCEL', 'cancelled')
    chosen = order_indices(cells, sort_mode, filter_indices(cells, filter_mode))
    rows = tuple(KevRow(f'{index}:{cells[index].cve}', cells[index], provider.lookup(ids[index])) for index in chosen)
    return KevView(prepare_table(SPEC, COLUMNS, rows, cancel), len(ids), len(rows))


def failure_reason(error: KevError) -> tuple[str, dict[str, object]]:
    """The closed reason template and its values for ``view_model.error_text``; the message is never shown."""
    key = _REASONS.get(error.code, 'format')
    if key == 'network':
        status = _HTTP.search(error.message)
        return ('http', {'status': status.group(1)}) if status else ('network', {})
    if key == 'shrink':
        found = _SHRINK.search(error.message)
        return 'shrink', {'n': found.group(1) if found else '0'}
    if key == 'checks':
        return 'checks', {'check': error.code}
    return key, {}


def kept_line(meta: KevCatalogMeta | None) -> tuple[str | None, str | None]:
    return (None, None) if meta is None else (meta.catalog_version, meta.date_released[:10])
