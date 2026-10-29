"""Pure view-model of the Related evidence panel (FAB-integration-plan.md s8, slice FAB-6). No Qt, no I/O.

Rows are the anchors the fabric holds for the selected pair. One row per anchor: its witnesses are counted as
independent origins, never summed, and there is no score. Every text that came from a producer is plain already
(`contracts.clean_line`) and still passes `sanitize_text` here, because the table is a display boundary.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..gui.anchors import AnchorRef
from ..gui.state import StateModel, state_model
from ..gui.table_spec import ColumnSpec, TableSpec
from ..gui.text import LABEL_LIMIT, sanitize_text
from .contracts import Anchor
from .origins import DefaultOriginRegistry

TITLE = 'Related evidence'
NOUN = 'related evidence'
PAGE_ROWS = 500
EMPTY = ('Nothing else is known about this function yet. Run capabilities, strings or build tools to add evidence. '
         'Missing evidence is unknown, not a negative result.')
NO_SELECTION = 'Select a function pair to see what else is known about it.'
DETAIL_NONE = 'Select a row to see where it comes from.'
ROLE_NOTES = {
    'hint': 'A hint is something to look for; it was not found here.',
    'stated': 'A statement comes from an advisory or catalog; by itself it says nothing about this code.',
    'observed': ''}
KIND_TITLES = {
    'function': 'Function', 'string': 'String', 'import': 'Import', 'capability': 'Capability', 'rule': 'Rule',
    'build_fact': 'Build fact', 'advisory_phrase': 'Advisory phrase', 'cve': 'CVE', 'kb': 'KB article', 'cwe': 'CWE'}
GLYPHS = {'observed': '+', 'stated': 'i', 'hint': '?'}  # ASCII glyph plus the word: colour is never the only cue
_REGISTRY = DefaultOriginRegistry()


def _count(count: int, one: str, many: str) -> str:
    return f'{count} {one if count == 1 else many}'


@dataclass(frozen=True, slots=True)
class RelatedRow:
    anchor: Anchor
    kind: str
    label: str
    side: str
    role: str
    independent: int
    witnesses: int
    producers: str

    @property
    def key(self) -> str:
        return self.anchor.anchor_id

    @property
    def role_text(self) -> str:
        return f'{GLYPHS[self.role]} {self.role}'

    @property
    def witness_text(self) -> str:
        return f'{self.independent} independent of {self.witnesses}'

    @property
    def accessible(self) -> str:
        origins = _count(self.independent, 'independent origin', 'independent origins')
        return (f'{KIND_TITLES[self.kind]} {self.label}, {self.side}, {self.role}, '
                f'{origins} of {_count(self.witnesses, "witness", "witnesses")}')

    @property
    def search(self) -> str:
        return f'{self.label} {self.kind} {self.producers}'

    @property
    def detail(self) -> str:
        text = (f'Seen by {self.witnesses} witnesses from {self.independent} independent origins: {self.producers}. '
                'Witnesses that share an origin count once.')
        return f'{text} {ROLE_NOTES[self.role]}'.strip()


def row_of(anchor: Anchor) -> RelatedRow:
    sets = [witness.origins for witness in anchor.witnesses]
    producers = sorted({w.producer for w in anchor.witnesses})
    return RelatedRow(anchor, anchor.kind, sanitize_text(anchor.label, LABEL_LIMIT), anchor.side, anchor.role,
                      len(_REGISTRY.components(sets)), len(sets), ', '.join(producers))


def rows_of(anchors: tuple[Anchor, ...] | list[Anchor]) -> tuple[RelatedRow, ...]:
    return tuple(row_of(anchor) for anchor in anchors)


COLUMNS = (
    ColumnSpec('kind', 'Kind', lambda r: KIND_TITLES[r.kind], width_em=14, accessible=lambda r: r.accessible),
    ColumnSpec('label', 'Label', lambda r: r.label, width_em=36),
    ColumnSpec('side', 'Side', lambda r: r.side, width_em=8),
    ColumnSpec('role', 'Role', lambda r: r.role_text, width_em=12),
    ColumnSpec('witnesses', 'Witnesses', lambda r: r.witness_text, width_em=18,
               sort_key=lambda r: (r.independent, r.witnesses)),
    ColumnSpec('producers', 'Producers', lambda r: r.producers, width_em=20))
# No default order: the rows arrive in the fabric's canonical order and keep it.
SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: r.search)


def anchor_ref(anchor: Anchor, run_id: str | None, origin: str | None = 'related') -> AnchorRef:
    """`AnchorRef.from_fabric` of the plan (s10), kept here until the GUI core adopts it: a pure function. The ten
    fabric kinds are the GUI's names verbatim; side `none` is no particular side."""
    side = None if anchor.side == 'none' else anchor.side
    return AnchorRef(anchor.kind, anchor.key, side, run_id, anchor.label, origin)


def related_state(*, has_project: bool, subject: str | None, loading: bool, error: tuple[str, str] | None,
                  total: int, too_large: bool, stale: bool = False, partial: str = '') -> StateModel:
    """The strip above the table. Precedence is the framework's; an empty result says it is unknown, not negative."""
    if not has_project:
        return state_model('no-project', TITLE)
    if subject is None:
        return state_model('idle', TITLE, hint=NO_SELECTION)
    if error is not None:
        return state_model('error', TITLE, code=error[0], message=error[1])
    if too_large:
        return state_model('too-large', TITLE, n=total)
    if stale:
        return state_model('stale', TITLE, reason='the project changed while this was loading')
    if partial:
        return state_model('partial', TITLE, reasons=partial)
    if loading:
        return state_model('loading', TITLE, noun=NOUN)
    if total == 0:
        return StateModel('ready', EMPTY)
    return StateModel('ready', '')
