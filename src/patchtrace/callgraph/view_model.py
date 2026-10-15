"""Qt-free view models of the Calls panel (WB2 G5): Changes, Neighbours and Tree rows, status copy,
detail and clipboard text, and the local `graph.*` tooltip table. All text from binaries is sanitized."""
from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .contracts import GraphNode, GraphView, Pairing
from .contracts_delta import CallDelta, CalleeChange, ChangeClass, EntryDistance, GraphLead
from .query import MAX_DEPTH, NEIGHBOURS_PER_NODE
from .text import one_line, sanitize

ROW_CAP = 100_000  # E7
CLIPBOARD_CAP = 16 * 1024
MAX_LINES_SCANNED = 100_000

# ---- copy (exact text from the WB2 card, s8.2) ---------------------------------------------------

STATE_TEXT: dict[str, str] = {
    'E0': 'Open a project to explore calls.',
    'E1': 'No completed comparison yet. Run a comparison to see call relationships.',
    'E2': 'Reading call lists...',
    'E4': ('This function is not in the stored change set, so no call lists are stored for it. '
           'Unchanged functions have no stored call lists.'),
    'E5': 'No caller or callee names are stored for this function.',
    'E6': ('The preserved Ghidriff output is missing or does not match its recorded hash, so names of '
           'unchanged functions cannot be paired. Call changes are shown only where both names appear in '
           'stored lists.'),
    'E7': 'Showing {n} of {m} neighbours. Narrow the depth or the filters to see the rest.',
    'E8': 'Cancelled. Earlier results are unchanged.',
    'E9': 'Calls could not be read: {code}: {message}',
    'E10': 'The call view is stale: {reason}. Reload to refresh.',
    'E11': 'Too large to draw ({n} nodes). Use the Neighbours table or narrow the depth.',
    'E12': ('Whole-program paths need extracted instruction data (unified analysis), which this project '
            'does not have. Paths shown use stored call lists only.'),
}
FOOTER = ("Call lists are the distinct direct calls recorded by Ghidra's analysis. Jumps, calls through "
          'registers or tables, and the lists of unchanged functions are not included. Missing is unknown, '
          'not removed.')
CALLSITE_FOUND = 'text match in decompiled code'
CALLSITE_MISSING = 'Call site not found in the decompiled text (it may be inlined or renamed).'
NO_ENTRY_PATH = 'No observed path from an export or the entry point; stored call lists are partial'

CHANGE_TEXT: dict[ChangeClass, str] = {
    'same-link': '= Same', 'added-call': '+ Added', 'call-to-new-function': '+ Added',
    'removed-call': '- Removed', 'callee-deleted': '- Removed', 'cannot-determine': '? Not comparable'}
HUB_TEXT = '~ Hub, not compared'
NOT_COMPARABLE = '? Not comparable'
DELTA_STATE_TEXT = {'compared': 'Compared', 'one-sided': 'Listed on one side only',
                    'not-comparable': 'Not comparable', 'unavailable': 'Call lists unavailable'}
ADDED, REMOVED = frozenset({'added-call', 'call-to-new-function'}), frozenset({'removed-call', 'callee-deleted'})

PanelFlag = Literal['no-project', 'no-comparison', 'loading', 'cancelled', 'failed', 'stale', 'not-in-set',
                    'no-lists', 'too-large', 'capped', 'raw-missing', 'no-instruction-data']


@dataclass(frozen=True)
class PanelState:
    """Everything the status line depends on; the controller fills it, this module only words it."""
    flags: frozenset[PanelFlag] = frozenset()
    shown: int = 0
    total: int = 0
    code: str = ''
    message: str = ''
    reason: str = ''
    nodes: int = 0


# First flag present wins as the headline; the rest are appended as notes in this order.
_HEADLINES: tuple[tuple[PanelFlag, str], ...] = (
    ('no-project', 'E0'), ('no-comparison', 'E1'), ('loading', 'E2'), ('cancelled', 'E8'), ('failed', 'E9'),
    ('stale', 'E10'), ('not-in-set', 'E4'), ('no-lists', 'E5'), ('too-large', 'E11'), ('capped', 'E7'))
_NOTES: tuple[tuple[PanelFlag, str], ...] = (('raw-missing', 'E6'), ('no-instruction-data', 'E12'))


def _word(key: str, state: PanelState) -> str:
    return STATE_TEXT[key].format(
        n=f'{state.nodes:,}' if key == 'E11' else f'{state.shown:,}', m=f'{state.total:,}',
        code=sanitize(state.code, 40), message=one_line(state.message, 300), reason=one_line(state.reason, 200))


def status_lines(state: PanelState) -> tuple[str, ...]:
    """Headline first, then notes; an empty tuple means nothing to say beyond the footer."""
    out = [_word(key, state) for flag, key in _HEADLINES if flag in state.flags][:1]
    out += [_word(key, state) for flag, key in _NOTES if flag in state.flags]
    return tuple(out)


# ---- cells --------------------------------------------------------------------------------------


def pairing_text(pairing: Pairing | None) -> str:
    if pairing is None or pairing.kind == 'unknown':
        return 'No pairing data'
    if pairing.kind == 'one':
        return 'Paired'
    if pairing.kind == 'added':
        return 'New in newer build'
    if pairing.kind == 'removed':
        return 'Deleted from older build'
    return f'Ambiguous ({max(len(pairing.partners), len(pairing.engines), 2)})'


def change_text(change: CalleeChange) -> str:
    if 'hub' in change.flags and change.cls != 'same-link':
        return HUB_TEXT
    return CHANGE_TEXT[change.cls]


def entry_text(entry: EntryDistance | None) -> str:
    if entry is None or entry.state == 'unknown':
        return ''
    if entry.state == 'reached':
        via, hops = one_line(entry.via, 80), entry.hops
        return f'Reachable from export {via} in at most {hops} calls (observed path)'
    return NO_ENTRY_PATH


def _token_pattern(callee: str) -> re.Pattern[str] | None:
    token = callee.rsplit('::', 1)[-1]
    return re.compile(r'(?<![\w$@?])' + re.escape(token) + r'(?![\w$@?])') if token else None


def find_call_site(text: str, callee: str) -> int | None:
    """1-based number of the first line whose identifier token equals the callee, else None."""
    pattern = _token_pattern(callee)
    if pattern is None:
        return None
    for number, line in enumerate(text.splitlines()[:MAX_LINES_SCANNED], 1):
        if pattern.search(line):
            return number
    return None


def find_call_sites(text: str, callee: str) -> list[tuple[int, str]]:
    """Every (1-based line number, line) whose identifier token equals the callee, in line order."""
    pattern = _token_pattern(callee)
    if pattern is None:
        return []
    return [(number, line) for number, line in enumerate(text.splitlines()[:MAX_LINES_SCANNED], 1)
            if pattern.search(line)]


def callsite_text(found: int | None) -> str:
    return CALLSITE_MISSING if found is None else f'{CALLSITE_FOUND}, line {found}'


# ---- Changes ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ChangesRow:
    match_id: str
    name: str
    meaning: str
    added: int
    removed: int
    api_hints: tuple[str, ...]
    direct_callers: int | None
    ghidriff_says: tuple[str, ...]
    state: str
    noise: bool  # an all-renumbering or hub-only change
    accessible: str


CHANGES_COLUMNS = ('Function', 'Meaning', 'Added', 'Removed', 'API hints', 'Direct callers', 'Ghidriff says',
                   'State')
_SORT_KEYS: dict[str, Callable[[ChangesRow], object]] = {
    'Function': lambda r: (r.name, r.match_id), 'Meaning': lambda r: (r.meaning, r.name, r.match_id),
    'Added': lambda r: (r.added, r.name, r.match_id), 'Removed': lambda r: (r.removed, r.name, r.match_id),
    'API hints': lambda r: (len(r.api_hints), r.name, r.match_id),
    'Direct callers': lambda r: (-1 if r.direct_callers is None else r.direct_callers, r.name, r.match_id),
    'Ghidriff says': lambda r: (r.ghidriff_says, r.name, r.match_id), 'State': lambda r: (r.state, r.name, r.match_id)}


def _changes_row(delta: CallDelta, lead: GraphLead | None) -> ChangesRow:
    name = one_line(delta.newer_label or delta.older_label or delta.match_id)
    added = sum(c.cls in ADDED for c in delta.changes)
    removed = sum(c.cls in REMOVED for c in delta.changes)
    apis = tuple(sorted({one_line(hit.api, 80) for c in delta.changes for hit in c.api}))
    meaning = one_line(lead.signals[0].meaning, 200) if lead and lead.signals else ''
    callers = lead.blast.direct_callers if lead and lead.blast else None
    says = tuple(one_line(t, 60) for t in delta.ghidriff_diff_types)
    state = DELTA_STATE_TEXT[delta.state]
    parts = [name, meaning or 'no lead', f'added {added}', f'removed {removed}', state]
    if apis:
        parts.append('API hints ' + ', '.join(apis))
    return ChangesRow(delta.match_id, name, meaning, added, removed, apis, callers, says, state,
                      delta.downgrade != 'none', ', '.join(parts))


def changes_cell(row: ChangesRow, column: int) -> str:
    """O(1) display text of one cell."""
    values = (row.name, row.meaning, str(row.added), str(row.removed), ', '.join(row.api_hints),
              '' if row.direct_callers is None else str(row.direct_callers), ', '.join(row.ghidriff_says),
              row.state)
    return values[column]


@dataclass(frozen=True)
class ChangesView:
    rows: tuple[ChangesRow, ...]
    total: int  # rows that matched the filters, before the cap

    @property
    def capped(self) -> bool:
        return self.total > len(self.rows)


def changes_view(deltas: Iterable[CallDelta], leads: Iterable[GraphLead] = (), *, changed_only: bool = False,
                 hide_noise: bool = False, text: str = '', sort: str = 'Function',
                 descending: bool = False, cap: int = ROW_CAP) -> ChangesView:
    """Rows for the Changes tab, filtered and sorted by the model (no proxy), capped for display."""
    by_match = {lead.match_id: lead for lead in leads}
    needle = text.casefold().strip()
    rows = [_changes_row(d, by_match.get(d.match_id)) for d in deltas]
    rows = [r for r in rows if not (changed_only and not (r.added or r.removed))
            and not (hide_noise and r.noise) and (not needle or needle in r.name.casefold())]
    rows.sort(key=_SORT_KEYS[sort], reverse=descending)
    return ChangesView(tuple(rows[:cap]), len(rows))


# ---- Neighbours ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class NeighbourRow:
    node_id: str
    name: str
    relation: str  # Caller, Callee, Caller and callee, Related
    hops: int
    kind: str
    change: str
    pairing: str
    accessible: str


NEIGHBOUR_COLUMNS = ('Function', 'Relation', 'Calls away', 'Call change', 'Pairing')


def neighbour_cell(row: NeighbourRow, column: int) -> str:
    return (row.name, row.relation, str(row.hops), row.change, row.pairing)[column]


def _distances(start: str, adjacency: Mapping[str, Sequence[str]]) -> dict[str, int]:
    seen, queue = {start: 0}, deque([start])
    while queue:
        node = queue.popleft()
        for other in adjacency.get(node, ()):
            if other not in seen:
                seen[other] = seen[node] + 1
                queue.append(other)
    return seen


def _adjacency(view: GraphView) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    out: dict[str, list[str]] = {}
    back: dict[str, list[str]] = {}
    for edge in view.edges:
        out.setdefault(edge.src, []).append(edge.dst)
        back.setdefault(edge.dst, []).append(edge.src)
    return out, back


def _relation(down: int | None, up: int | None) -> str:
    if down is not None and up is not None:
        return 'Caller and callee'
    if down is None and up is None:
        return 'Related'  # reached through a shared caller or callee, not along a call chain
    return 'Callee' if down is not None else 'Caller'


def neighbour_rows(view: GraphView, focus_id: str, *, delta: CallDelta | None = None,
                   pairings: Mapping[str, Pairing] | None = None, cap: int = ROW_CAP
                   ) -> tuple[tuple[NeighbourRow, ...], int]:
    """(rows, total). Relation is by observed edges from the focus; `delta` names the call change of a
    direct callee, `pairings` (node id -> Pairing) fills the pairing cell."""
    out, back = _adjacency(view)
    down, up = _distances(focus_id, out), _distances(focus_id, back)
    around = _distances(focus_id, {k: [*out.get(k, ()), *back.get(k, ())] for k in out.keys() | back.keys()})
    changes: dict[str, str] = {}
    for c in (delta.changes if delta else ()):
        for label in (c.newer_label, c.older_label):
            if label is not None:
                changes.setdefault(sanitize(label), change_text(c))
    rows: list[NeighbourRow] = []
    for node in view.nodes:
        if node.id == focus_id:
            continue
        if node.id not in around:
            continue
        rows.append(_neighbour(node, down.get(node.id), up.get(node.id), around[node.id], changes.get(node.label, ''), (pairings or {}).get(node.id)))
    rows.sort(key=lambda r: (r.hops, r.name, r.node_id))
    return tuple(rows[:cap]), len(rows)


def _neighbour(node: GraphNode, down: int | None, up: int | None, hops: int, change: str,
               pairing: Pairing | None) -> NeighbourRow:
    relation = _relation(down, up)
    name, pair = one_line(node.label), pairing_text(pairing)
    spoken = [name, f'{relation.lower()}, {hops} calls away']
    if change:
        spoken.append('call change ' + change.lstrip('+-=?~ '))
    spoken.append(f'pairing {pair}')
    return NeighbourRow(node.id, name, relation, hops, node.kind, change, pair, ', '.join(spoken))


# ---- Tree ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TreeChild:
    node_id: str
    name: str
    repeat: bool  # already on the path from the root; not expanded again
    expandable: bool


@dataclass(frozen=True)
class TreeChildren:
    children: tuple[TreeChild, ...]
    more: int  # shown as "+N more"

    @property
    def more_text(self) -> str:
        return f'+{self.more} more' if self.more else ''


class TreeIndex:
    """Lazy call tree over a `GraphView`: children are computed when a row is expanded."""

    def __init__(self, view: GraphView, direction: Literal['callees', 'callers'] = 'callees') -> None:
        out, back = _adjacency(view)
        self._names = {n.id: one_line(n.label) for n in view.nodes}
        adjacency = out if direction == 'callees' else back
        self._next = {k: sorted(set(v), key=lambda i: (self._names.get(i, ''), i)) for k, v in adjacency.items()}

    def name(self, node_id: str) -> str:
        return self._names.get(node_id, '')

    def children(self, node_id: str, path: Sequence[str] = ()) -> TreeChildren:
        """`path` is the ancestor ids from the root down to and including `node_id`."""
        if len(path) > MAX_DEPTH:
            return TreeChildren((), 0)
        found = [i for i in self._next.get(node_id, ()) if i in self._names]
        on_path = set(path) | {node_id}
        shown = tuple(TreeChild(i, self._names[i], i in on_path, i not in on_path and len(path) < MAX_DEPTH
                                and bool(self._next.get(i))) for i in found[:NEIGHBOURS_PER_NODE])
        return TreeChildren(shown, max(0, len(found) - NEIGHBOURS_PER_NODE))


# ---- detail and clipboard -----------------------------------------------------------------------

SECTIONS = ('Identity', 'Pairing', 'Call evidence', 'Limits', 'Provenance')
Detail = dict[str, list[str]]


def _detail() -> Detail:
    return {name: [] for name in SECTIONS}


def change_detail(delta: CallDelta, lead: GraphLead | None = None, view: GraphView | None = None) -> Detail:
    """Fixed-section detail of one modified pair."""
    detail = _detail()
    detail['Identity'] += [f'Newer: {one_line(delta.newer_label or "none")}',
                           f'Older: {one_line(delta.older_label or "none")}', f'Match: {sanitize(delta.match_id, 80)}']
    for c in delta.changes:
        if c.cls != 'same-link':
            side = one_line(c.newer_label or c.older_label or '')
            detail['Call evidence'].append(f'{change_text(c)}: {side} ({pairing_text(c.pairing)})')
    if lead:
        detail['Call evidence'] += [f'{s.meaning}. Next: {one_line(s.next_step, 200)}' for s in lead.signals]
        detail['Call evidence'] += [t for t in (entry_text(lead.entry),) if t]
        detail['Provenance'].append(f'Engine {sanitize(lead.origin.engine, 60)}, run {sanitize(lead.origin.run_id, 60)}')
    detail['Limits'] += [one_line(t, 300) for t in delta.limitations] + [FOOTER]
    if view and view.limitations:
        detail['Limits'] += [one_line(t, 300) for t in view.limitations]
    return detail


def node_detail(node: GraphNode, pairing: Pairing | None, view: GraphView) -> Detail:
    detail = _detail()
    detail['Identity'] += [f'Name: {one_line(node.label)}', f'Kind: {node.kind}', f'Side: {node.side}']
    detail['Pairing'].append(pairing_text(pairing))
    if pairing and pairing.partners:
        detail['Pairing'].append('Partners: ' + ', '.join(one_line(p, 80) for p in pairing.partners[:5]))
    detail['Call evidence'].append(f'Resolved by {node.via} ({node.tier} tier)')
    detail['Limits'] += [one_line(t, 300) for t in view.limitations] + [FOOTER]
    detail['Provenance'].append(f'Source {sanitize(view.source.source_id, 60)} {sanitize(view.source.version, 40)}, '
                                f'run {sanitize(view.run_id, 60)}')
    return detail


def copy_text(detail: Detail) -> str:
    """Plain clipboard text: section heading then lines, empty sections omitted, capped."""
    blocks = [f'{name}\n' + '\n'.join(lines) for name, lines in detail.items() if lines]
    text = '\n\n'.join(blocks)
    return text if len(text) <= CLIPBOARD_CAP else text[:CLIPBOARD_CAP - 3] + '...'


# ---- tooltips (local table; WHAT, WHY, EFFECT; no angle brackets) -----------------------------------

TipEntry = tuple[str, str, str]
_VIEW_ONLY = 'Changes only what is shown; nothing in the project is modified.'
GRAPH_TIPS: dict[str, TipEntry] = {
    'graph.dock': ('Panel that shows who calls whom around the selected function.',
                   'Call changes between builds point at code worth reading first.', _VIEW_ONLY),
    'graph.action': ('Show or hide the Calls panel.', 'Keeps the main window uncluttered.',
                     'Toggles the panel; Ctrl+Shift+G does the same.'),
    'graph.tabs': ('Switch between Changes, Neighbours, Tree and Diagram views.',
                   'Each view answers a different question about the same call data.', _VIEW_ONLY),
    'graph.side': ('Choose the older build, the newer build or both.',
                   'Calls differ between builds, so the side must be explicit.', 'Reloads the neighbours.'),
    'graph.direction': ('Choose callers, callees or both.', 'Callers show who reaches the function; callees show what it uses.',
                        'Reloads the neighbours.'),
    'graph.depth': ('How many calls away from the selected function to follow, 1 to 4.',
                    'Deeper views show more context but get large quickly.', 'Reloads the neighbours.'),
    'graph.show_unresolved': ('Include names that could not be tied to a function record.',
                              'Imports and unnamed targets are real calls even without a record.', _VIEW_ONLY),
    'graph.changed_only': ('Hide pairs whose stored calls did not change.',
                           'Focuses the table on pairs with added or removed calls.', _VIEW_ONLY),
    'graph.hide_noise': ('Hide pairs where only renumbered names or common helper calls changed.',
                         'Those changes rarely explain a behaviour change.', _VIEW_ONLY),
    'graph.follow': ('Follow the function selected in the main window.', 'Keeps this panel in step with your reading.',
                     'Turn off to keep the current function.'),
    'graph.changes_table': ('One row per modified pair with its call changes.',
                            'A starting point for deciding what to read.', 'Select a row to see details.'),
    'graph.table': ('Functions near the selected one, with how they relate.',
                    'The same information as the diagram, readable by keyboard and screen reader.',
                    'Select a row to see details; Enter opens the function.'),
    'graph.tree': ('Call tree of the selected function, expanded one level at a time.',
                   'Shows chains of calls without drawing a graph.', 'Expand a row to load its children.'),
    'graph.diagram': ('Visual drawing of the nearby calls.', 'Gives a quick overview of the shape of the calls.',
                      'Visual only; the Neighbours table has the same information.'),
    'graph.minimap': ('Small overview of the whole diagram.', 'Helps you find your place in a large drawing.',
                      'Click to centre the diagram there.'),
    'graph.detail': ('Details of the selected row: identity, pairing, call evidence, limits and provenance.',
                     'Shows where each statement comes from.', _VIEW_ONLY),
    'graph.open': ('Open the selected function in the main window.', 'Lets you read its decompiled text.',
                   'Selects the matching pair in the main window.'),
    'graph.callsite': ('Find the line in the decompiled text where the call appears.',
                       'Takes you straight to the evidence for a call.',
                       'Searches the text; the call may be inlined or renamed and then is not found.'),
    'graph.focus': ('Make the selected function the new centre of the view.', 'Lets you follow a chain of calls.',
                    'Ctrl+Enter does the same.'),
    'graph.back': ('Return to the previous centre.', 'Undoes a focus change.', 'Backspace does the same.'),
    'graph.copy': ('Copy the details as plain text.', 'Lets you paste the evidence into notes.',
                   'Puts text on the clipboard; nothing is sent anywhere.'),
    'graph.export_dot': ('Save the current neighbourhood as a DOT file.', 'Lets other graph tools draw it.',
                         'Writes one file where you choose; existing files are not replaced without asking.'),
    'graph.status': ('Current state of the Calls panel.', 'Explains why a view is empty or limited.', _VIEW_ONLY),
}
GRAPH_TIP_TEMPLATES: dict[str, TipEntry] = {
    'graph.row': ('Select the call change of {name}.', 'Review how its calls differ between builds.', _VIEW_ONLY),
    'graph.cell': ('Value of {column} for {name}.', 'Shows one fact about this pair.', _VIEW_ONLY),
    'graph.node': ('Function {name} in the call view.', 'Select it to see how it relates to the centre.', _VIEW_ONLY),
}
ACCESSIBLE_NAMES = {
    'dock': 'Calls panel', 'tabs': 'Calls views', 'changes_table': 'Changed calls table',
    'table': 'Neighbours of the selected function', 'tree': 'Call tree of the selected function',
    'diagram': 'Call diagram (visual only; the Neighbours table has the same information)',
    'detail': 'Selected call details', 'open': 'Open selected function', 'callsite': 'Show call site',
    'export_dot': 'Export DOT file'}


def all_copy() -> Iterable[str]:
    """Every fixed user-facing string, for the banned-word sweep."""
    yield from STATE_TEXT.values()
    yield from (FOOTER, CALLSITE_FOUND, CALLSITE_MISSING, NO_ENTRY_PATH, HUB_TEXT, NOT_COMPARABLE)
    yield from CHANGE_TEXT.values()
    yield from DELTA_STATE_TEXT.values()
    yield from ACCESSIBLE_NAMES.values()
    for entry in (*GRAPH_TIPS.values(), *GRAPH_TIP_TEMPLATES.values()):
        yield from entry

