"""Qt-free view model of the leads page (KB-integration-plan 8.2, `leads_table`; slice K4a). Pure.

The dock (slice K4b) wraps this in a ``QAbstractTableModel`` and adds nothing of its own: row order, text, accessible
text, navigation and the copy block all come from here. Rows are built once into a tuple, so ``cell`` and
``accessible`` are O(1) at any row count (the virtualization gate). Every string is plain text that went through
:func:`~.products.clean_text`; nothing here is markup. State is never colour alone: each chip line starts with a glyph
and the state word.

Rows alternate group header rows and lead rows in the report's order. Navigation (``goto``) is off for header rows, for
stale reports and for leads without a match id.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from .contracts import LeadRow
from .leads import LeadsReport, lead_summary, plain_text

COLUMNS = ('Order', 'Function', 'CVE group', 'Evidence', 'Attention order')
COLUMN_NAMES = ('Order', 'Function', 'CVE group', 'Evidence by channel', 'Attention order, the engine\'s own order')
COPY_LIMIT = 16 * 1024
TEXT_EMPTY = 'The stored ranking lists no changed functions for this project.'
GLYPHS = {'supports': '+', 'contradicts': '!', 'neutral': '=', 'unknown': '?', 'not-run': '-'}
_ORDER = re.compile(r'attention order ([0-9]+) of ([0-9]+)')
ALL_GROUPS = 'all'
UNATTRIBUTED_HEADER = 'unattributed (always visible)'


@dataclass(frozen=True)
class TableRow:
    kind: Literal['group', 'lead']
    group: str
    cells: tuple[str, ...]
    accessible: tuple[str, ...]
    ordinal: int | None = None
    lead_id: str | None = None
    match_id: str | None = None
    copy_text: str = ''


def _text(value: object, limit: int = 1000) -> str:
    return plain_text(value, limit)


def chip_lines(lead: LeadRow) -> tuple[str, ...]:
    """One line per channel, glyph first: ``[+] supports  hypothesis: ...``."""
    return tuple(_text(f'[{GLYPHS[c.state]}] {c.state}  {c.channel}: {c.text}', 600) for c in lead.chips)


def _attention(lead: LeadRow) -> tuple[str, str]:
    found = _ORDER.search(lead.rank_basis)
    if found is None:
        return 'none', 'no attention order'
    return (f'{found.group(1)} of {found.group(2)}',
            f'attention order {found.group(1)} of {found.group(2)}, the engine\'s own order')


def _copy_block(lead: LeadRow, report: LeadsReport) -> str:
    lines = [f'Function: {_text(lead.subject, 200)}', f'CVE group: {lead.group}', f'Lead: {lead.lead_id}',
             f'Basis: {_text(lead.rank_basis)}', f'Run: {lead.nav.run_id or "none"}',
             f'Project revision: {lead.nav.project_revision}', f'Context: {report.context_key or "none"}',
             *chip_lines(lead), *(_text(f'Limit: {x}') for x in report.limitations)]
    return '\n'.join(lines)[:COPY_LIMIT]


def _lead_row(lead: LeadRow, ordinal: int, report: LeadsReport) -> TableRow:
    order_cell, order_spoken = _attention(lead)
    evidence = _text(lead_summary(lead), 1000)
    group = lead.group
    go = None if lead.stale or report.stale else lead.nav.match_id
    cells = (str(ordinal), _text(lead.subject, 200), group, evidence, order_cell)
    spoken = (f'Order {ordinal}', f'Function {cells[1]}', f'CVE group {group}', f'Evidence: {evidence}', order_spoken)
    return TableRow('lead', group, cells, tuple(_text(s, 1200) for s in spoken), ordinal, lead.lead_id, go,
                    _copy_block(lead, report))


def _header_row(group: str, text: str) -> TableRow:
    text = _text(text, 1000)
    return TableRow('group', group, ('', text, group, '', ''), ('', f'Group {text}', f'CVE group {group}', '', ''))


class LeadsViewModel:
    """Immutable; ``filtered`` returns a new model for the group filter."""

    def __init__(self, report: LeadsReport, rows: tuple[TableRow, ...], selected: str = ALL_GROUPS):
        self.report = report
        self._rows = rows
        self.selected_group = selected

    @classmethod
    def from_report(cls, report: LeadsReport, group: str = ALL_GROUPS) -> LeadsViewModel:
        rows: list[TableRow] = []
        ordinal = 0
        sections = [(g.group, _group_header(g), g.leads) for g in report.groups]
        sections.append(('unattributed', UNATTRIBUTED_HEADER, report.unattributed))
        for key, header, leads in sections:
            if group not in (ALL_GROUPS, key):
                continue
            rows.append(_header_row(key, header))
            for lead in leads:
                ordinal += 1
                rows.append(_lead_row(lead, ordinal, report))
        return cls(report, tuple(rows), group)

    def filtered(self, group: str) -> LeadsViewModel:
        return LeadsViewModel.from_report(self.report, group)

    @property
    def columns(self) -> tuple[str, ...]:
        return COLUMNS

    @property
    def column_names(self) -> tuple[str, ...]:
        return COLUMN_NAMES

    @property
    def row_count(self) -> int:
        return len(self._rows)

    @property
    def lead_count(self) -> int:
        return sum(1 for r in self._rows if r.kind == 'lead')

    def row(self, index: int) -> TableRow:
        return self._rows[index]

    def cell(self, row: int, column: int) -> str:
        return self._rows[row].cells[column]

    def accessible(self, row: int, column: int) -> str:
        return self._rows[row].accessible[column]

    def goto(self, row: int) -> str | None:
        """The match id to open, or None when navigation is off (header row, stale report, no match)."""
        return self._rows[row].match_id

    def copy_block(self, row: int) -> str:
        return self._rows[row].copy_text

    def group_options(self) -> tuple[str, ...]:
        return (ALL_GROUPS, *(g.group for g in self.report.groups), 'unattributed')

    @property
    def status_text(self) -> str:
        """The state sentence (KB13/KB14-style); an empty list is always explained, never silent."""
        if self.report.state == 'ready' and not self.lead_count:
            return _text(TEXT_EMPTY)
        return _text(self.report.text)

    @property
    def coverage_line(self) -> str:
        return _text(' '.join(self.report.coverage_text) or 'No advisory coverage is recorded for this project.')

    @property
    def navigation_enabled(self) -> bool:
        return self.report.state == 'ready'

    @property
    def footer_lines(self) -> tuple[str, ...]:
        """Not-applicable and mention-only CVEs, unknowns and limits: always visible, never hidden in a tooltip."""
        lines = [f'Not applicable: {n.text}' for n in self.report.not_applicable]
        lines += [f'Mention only: {cve}' for cve in self.report.mention_only]
        lines += [f'Unknown: {u}' for u in self.report.unknowns] + [f'Limit: {x}' for x in self.report.limitations]
        return tuple(_text(line, 1000) for line in lines)

    @property
    def hooks(self) -> tuple[str, ...]:
        return tuple(self.report.hooks)


def _group_header(group) -> str:
    cwe = f' | {group.cwe_text}' if group.cwe_text else ''
    rules = f' | hypothesis {", ".join(group.hypotheses)}' if group.hypotheses else ''
    return f'{group.group}  {group.kev_text}{cwe}{rules}'
