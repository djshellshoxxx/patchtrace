"""Qt presentation of the Calls panel (WB2 G5/G6; GUI plan 8.10). Everything that decides what is said lives in the
Qt-free `view_model` and `panel_data`; this module moves it to widgets. The project is copied on the GUI thread and
workers only get that immutable copy; every result carries the controller epoch and is dropped when the project
changed meanwhile. The dock never opens a window of its own and no timer runs here."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..gui.anchors import AnchorRef, NavResult
from ..gui.graph_view import GraphEdgeView, GraphNodeView, GraphTooLargeError
from ..gui.qt.canvas import GraphCanvas
from ..gui.qt.docks import ControllerBase
from ..gui.qt.labels import PlainLabel, SafeTextView
from ..gui.qt.state_view import StateView
from ..gui.qt.table import ROW_ROLE, VirtualTable
from ..gui.registry import PanelContext
from ..gui.state import StateModel
from ..gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from ..gui.text import sanitize_text
from ..gui.tips import apply_tip, register_gui_tips, register_tips
from . import panel_data as pd
from .call_sites import (
    CALLSITE_COLUMNS,
    EDGE_COLUMNS,
    CallSiteRow,
    CallSiteView,
    EdgeRow,
    call_site_view,
    callsite_cell,
    edge_cell,
    edge_rows,
    function_code,
)
from .export_json import write_export
from .limits import GraphError
from .minimap_qt import MinimapWidget
from .tooltip_entries import TEMPLATES, TIPS
from .view_model import (
    ACCESSIBLE_NAMES,
    CHANGES_COLUMNS,
    FOOTER,
    NEIGHBOUR_COLUMNS,
    NO_EDGE_TEXT,
    ChangesRow,
    ChangesView,
    NeighbourRow,
    PanelFlag,
    PanelState,
    TreeIndex,
    change_detail,
    changes_cell,
    changes_view,
    copy_text,
    neighbour_cell,
    node_detail,
    status_lines,
)

DETAIL_LIMIT = 16_384
HISTORY_LIMIT = 50
TREE_ROLE = Qt.ItemDataRole.UserRole + 1
DIRECTIONS = (('Both', 'both'), ('Callers', 'in'), ('Callees', 'out'))
SIDES = (('Newer', 'newer'), ('Older', 'older'))
Loader = Callable[[object, Path | None, Callable[[], bool]], object]
CHANNELS = ('graph-load', 'graph-rows', 'graph-query', 'graph-callsite', 'graph-export')

CHANGE_WIDTHS = (26, 36, 10, 10, 24, 12, 24, 18)
CHANGE_COLUMNS = tuple(
    ColumnSpec(title.lower().replace(' ', '_'), title, (lambda r, i=i: changes_cell(r, i)), width_em=CHANGE_WIDTHS[i],
               accessible=lambda r: r.accessible)
    for i, title in enumerate(CHANGES_COLUMNS))
CHANGE_SPEC = TableSpec(row_key=lambda r: r.match_id, search_text=lambda r: r.name)
NEIGHBOUR_WIDTHS = (30, 18, 12, 20, 24)
NEIGHBOUR_COLS = tuple(
    ColumnSpec(title.lower().replace(' ', '_'), title, (lambda r, i=i: neighbour_cell(r, i)), width_em=NEIGHBOUR_WIDTHS[i],
               accessible=lambda r: r.accessible)
    for i, title in enumerate(NEIGHBOUR_COLUMNS))
NEIGHBOUR_SPEC = TableSpec(row_key=lambda r: r.node_id, search_text=lambda r: r.name)
EDGE_WIDTHS = (24, 24, 14, 14, 18)
EDGE_COLS = tuple(
    ColumnSpec(title.lower().replace(' ', '_'), title, (lambda r, i=i: edge_cell(r, i)), width_em=EDGE_WIDTHS[i],
               accessible=lambda r: r.accessible)
    for i, title in enumerate(EDGE_COLUMNS))
EDGE_SPEC = TableSpec(row_key=lambda r: r.edge_id, search_text=lambda r: f'{r.caller} {r.callee}')
SITE_WIDTHS = (8, 70)
SITE_COLS = tuple(
    ColumnSpec(title.lower(), title, (lambda r, i=i: callsite_cell(r, i)), width_em=SITE_WIDTHS[i],
               accessible=lambda r: r.accessible)
    for i, title in enumerate(CALLSITE_COLUMNS))
SITE_SPEC = TableSpec(row_key=lambda r: str(r.line), search_text=lambda r: r.text)


def default_save_dialog(parent: QWidget, name: str) -> str:
    """The only way a DOT file gets a path: the analyst picks it here. Cancel returns an empty string."""
    value, _ = QFileDialog.getSaveFileName(parent, 'Export call graph as DOT', name,
                                           'Graphviz DOT (*.dot);;All files (*)')
    return value


def _build_dot(data: pd.GraphData, found: pd.Neighbourhood) -> str | pd.Failure:
    try:
        return pd.dot_text(data, found)
    except GraphError as exc:
        return pd.Failure(exc.code, exc.message)


def _write_dot(path: str, text: str) -> int | pd.Failure:
    try:
        write_export(Path(path), text, 'dot', overwrite=True)  # the save dialog already asked about replacing
    except GraphError as exc:
        return pd.Failure(exc.code, exc.message)
    return len(text.encode('utf-8'))


@dataclass(frozen=True)
class Rows:
    """Worker output of the Changes tab: the capped view and its prepared table."""
    view: ChangesView
    table: PreparedTable


def _button(text: str, name: str, tip: str, signal: Signal) -> QPushButton:
    button = QPushButton(text)
    button.setAccessibleName(name)
    apply_tip(button, tip)
    button.clicked.connect(lambda _checked=False: signal.emit())
    return button


class NeighbourTable(VirtualTable):
    """Adds Ctrl+Enter (focus here) and Backspace (back) to the shared table."""

    focus_key = Signal()
    back_key = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802
        enter = event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
        if enter and event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.focus_key.emit()
        elif event.key() == Qt.Key.Key_Backspace:
            self.back_key.emit()
        else:
            super().keyPressEvent(event)


class CallsPanel(QWidget):
    """The widgets. It holds no result state: the controller feeds it."""

    option_changed = Signal()
    action_requested = Signal(str)  # open, focus, back, copy, callsite, export_dot

    def __init__(self, announcer=None) -> None:
        super().__init__()
        self.setObjectName('graph.panel')
        self.side = self._combo('Side of the call view', 'graph.side', SIDES)
        self.direction = self._combo('Direction of calls', 'graph.direction', DIRECTIONS)
        self.depth = QSpinBox()
        self.depth.setRange(1, 4)
        self.depth.setAccessibleName('Depth of the call view')
        apply_tip(self.depth, 'graph.depth')
        self.flags = {key: self._check(text, tip, default) for key, text, tip, default in (
            ('show_unresolved', 'Unresolved', 'graph.show_unresolved', True),
            ('changed_only', 'Changed only', 'graph.changed_only', False),
            ('hide_noise', 'Hide noise', 'graph.hide_noise', False),
            ('follow', 'Follow selection', 'graph.follow', True))}
        controls = QHBoxLayout()
        for widget in (self.side, self.direction, self.depth, *self.flags.values()):
            controls.addWidget(widget)
        controls.addStretch(1)
        self.depth.valueChanged.connect(lambda _v: self.option_changed.emit())
        self.changes = VirtualTable(ACCESSIBLE_NAMES['changes_table'])
        self.changes.setObjectName('graph.changes_table')
        self.neighbours = NeighbourTable(ACCESSIBLE_NAMES['table'])
        self.neighbours.setObjectName('graph.table')
        self.tree = QTreeWidget()
        self.tree.setObjectName('graph.tree')
        self.tree.setAccessibleName(ACCESSIBLE_NAMES['tree'])
        self.tree.setHeaderLabels(['Function'])
        self.tree.header().setAccessibleName('Call tree column headers')
        self.edges = VirtualTable(ACCESSIBLE_NAMES['edges'])
        self.edges.setObjectName('graph.edges_table')
        self.sites = VirtualTable(ACCESSIBLE_NAMES['sites'])
        self.sites.setObjectName('graph.callsite_table')
        self.site_note = PlainLabel(NO_EDGE_TEXT, wrap=True, limit=400)
        self.site_note.setObjectName('graph.callsite_note')
        site_page = QWidget()
        site_column = QVBoxLayout(site_page)
        site_column.setContentsMargins(0, 0, 0, 0)
        site_column.addWidget(self.edges, 2)
        site_column.addWidget(self.site_note)
        site_column.addWidget(self.sites, 1)
        self.canvas = GraphCanvas(announcer)
        self.canvas.setAccessibleName(ACCESSIBLE_NAMES['diagram'])
        self.canvas.setObjectName('graph.diagram')
        self.diagram_note = PlainLabel(wrap=True, limit=400)
        self.diagram_note.setObjectName('graph.diagram_note')
        self.minimap = MinimapWidget(self.canvas)
        self.minimap_toggle = QPushButton('Minimap')
        self.minimap_toggle.setObjectName('graph.minimap')
        self.minimap_toggle.setAccessibleName(ACCESSIBLE_NAMES['minimap'])
        self.minimap_toggle.setCheckable(True)
        self.minimap_toggle.setChecked(True)
        self.minimap.setVisible(False)
        self.diagram = QWidget()
        diagram = self.diagram
        column = QVBoxLayout(diagram)
        column.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        top.addWidget(self.diagram_note, 1)
        top.addWidget(self.minimap_toggle)
        body = QHBoxLayout()
        body.addWidget(self.canvas, 1)
        body.addWidget(self.minimap, 0, Qt.AlignmentFlag.AlignTop)
        column.addLayout(top)
        column.addLayout(body, 1)
        self.tabs = QTabWidget()
        self.tabs.setAccessibleName(ACCESSIBLE_NAMES['tabs'])
        self.tabs.setObjectName('graph.tabs')
        for widget, title in ((self.changes, 'Changes'), (self.neighbours, 'Neighbours'), (self.tree, 'Tree'),
                              (diagram, 'Diagram'), (site_page, 'Call sites')):
            self.tabs.addTab(widget, title)
        for widget, tip in ((self.tabs, 'graph.tabs'), (self.changes, 'graph.changes_table'),
                            (self.neighbours, 'graph.table'), (self.tree, 'graph.tree'),
                            (self.canvas, 'graph.diagram'), (self.edges, 'graph.edges'),
                            (self.sites, 'graph.callsites'), (self.minimap_toggle, 'graph.minimap'),
                            (self.minimap, 'graph.minimap')):
            apply_tip(widget, tip)
        self.detail = SafeTextView(ACCESSIBLE_NAMES['detail'], limit=DETAIL_LIMIT, wrap=True)
        self.detail.setObjectName('graph.detail')
        apply_tip(self.detail, 'graph.detail')
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.tabs)
        split.addWidget(self.detail)
        split.setChildrenCollapsible(False)
        self.buttons: dict[str, QPushButton] = {}
        actions = QHBoxLayout()
        for action, text, name, tip in (('open', 'Open', ACCESSIBLE_NAMES['open'], 'graph.open'),
                                        ('focus', 'Focus here', 'Focus on selected function', 'graph.focus'),
                                        ('back', 'Back', 'Back to previous function', 'graph.back'),
                                        ('copy', 'Copy details', 'Copy details of selection', 'graph.copy'),
                                        ('callsite', 'Show call site', ACCESSIBLE_NAMES['callsite'], 'graph.callsite'),
                                        ('export_dot', 'Export DOT', ACCESSIBLE_NAMES['export_dot'],
                                         'graph.export_dot')):
            button = QPushButton(text)
            button.setAccessibleName(name)
            apply_tip(button, tip)
            button.clicked.connect(lambda _c=False, a=action: self.action_requested.emit(a))
            self.buttons[action] = button
            actions.addWidget(button)
        actions.addStretch(1)
        self.footer = PlainLabel(FOOTER, wrap=True, limit=400)
        self.footer.setObjectName('graph.footer')
        self.content = QWidget()
        inner = QVBoxLayout(self.content)
        inner.setContentsMargins(0, 0, 0, 0)
        inner.addLayout(controls)
        inner.addWidget(split, 1)
        inner.addLayout(actions)
        inner.addWidget(self.footer)
        self.state = StateView('graph', 'Calls', announcer, text_limit=1_200)
        self.state.set_content(self.content)
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.addWidget(self.state, 1)
        self.setFocusProxy(self.changes)

    def _combo(self, name: str, tip: str, items) -> QComboBox:
        combo = QComboBox()
        combo.setAccessibleName(name)
        for text, value in items:
            combo.addItem(text, value)
        apply_tip(combo, tip)
        combo.view().setAccessibleName(f'{name} options')
        combo.currentIndexChanged.connect(lambda _i: self.option_changed.emit())
        return combo

    def _check(self, text: str, tip: str, default: bool) -> QCheckBox:
        box = QCheckBox(text)
        box.setAccessibleName(text)
        box.setChecked(default)
        apply_tip(box, tip)
        box.toggled.connect(lambda _c: self.option_changed.emit())
        return box


class CallsController(ControllerBase):
    """Owns the loaded data and the requests in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, loader: Loader = pd.load_graph_data,
                 save_dialog: Callable[[QWidget, str], str] = default_save_dialog) -> None:
        register_gui_tips()
        register_tips(TIPS, TEMPLATES)
        panel = CallsPanel(getattr(ctx.shell, 'announcer', None))
        super().__init__(panel)
        self.panel, self.ctx, self.port, self.tasks, self.loader = panel, ctx, ctx.project, ctx.tasks, loader
        self.epoch = 0
        self.save_dialog = save_dialog
        self.project_copy = None
        self.key = None
        self.data: pd.GraphData | None = None
        self.found: pd.Neighbourhood | None = None
        self.rows: ChangesView | None = None
        self.seed: str | None = None
        self.history: list[str] = []
        self.flags: set[PanelFlag] = set()
        self.error = ('', '')
        self.stale_reason = ''
        self.tree_index: TreeIndex | None = None
        self.loading = False
        self._wire()
        self._render()

    # ---- wiring ------------------------------------------------------------------------------------

    def _wire(self) -> None:
        panel = self.panel
        panel.option_changed.connect(self._options_changed)
        QShortcut(QKeySequence('Escape'), panel, activated=self.cancel).setContext(
            Qt.ShortcutContext.WidgetWithChildrenShortcut)
        panel.action_requested.connect(self._action)
        panel.state.retry_requested.connect(self.reload)
        panel.state.refresh_requested.connect(self.reload)
        panel.state.copy_requested.connect(self.ctx.shell.copy_text)
        panel.changes.selectionModel().currentRowChanged.connect(lambda *_: self._changes_selected())
        panel.changes.activated_key.connect(lambda _k: self._action('open'))
        panel.neighbours.selectionModel().currentRowChanged.connect(lambda *_: self._neighbour_selected())
        panel.neighbours.activated_key.connect(lambda _k: self._action('open'))
        panel.neighbours.focus_key.connect(lambda: self._action('focus'))
        panel.neighbours.back_key.connect(lambda: self._action('back'))
        panel.edges.selectionModel().currentRowChanged.connect(lambda *_: self._edge_selected())
        panel.edges.activated_key.connect(lambda _k: self._action('callsite'))
        panel.minimap_toggle.toggled.connect(lambda _c: self._sync_minimap())
        QShortcut(QKeySequence('M'), panel.diagram, activated=panel.minimap_toggle.toggle).setContext(
            Qt.ShortcutContext.WidgetWithChildrenShortcut)
        panel.tree.itemExpanded.connect(self._expand)
        panel.tree.currentItemChanged.connect(lambda *_: self._tree_selected())
        panel.canvas.node_focused.connect(self._canvas_focused)
        panel.canvas.node_activated.connect(lambda _k: self._action('open'))

    # ---- host hooks --------------------------------------------------------------------------------

    def project_changed(self, key) -> None:
        self.epoch += 1
        for channel in CHANNELS:
            self.tasks.cancel(channel)
        self.key, self.data, self.found, self.rows, self.seed = key, None, None, None, None
        self.project_copy = None
        self.history.clear()
        self.flags, self.error, self.stale_reason, self.loading, self.tree_index = set(), ('', ''), '', False, None
        self._clear_views()
        if key is not None and key.run_id is not None:
            self.reload()
        else:
            self._render()

    def selection_changed(self, match_id: str | None) -> None:
        if match_id and self.panel.flags['follow'].isChecked() and self.data is not None:
            self._set_seed(match_id, remember=False)

    def busy_changed(self, busy: bool) -> None:
        self._render()

    def cancel(self) -> None:
        """Escape: stop the reads in flight; what is shown stays."""
        if not self.loading:
            return
        for channel in ('graph-load', 'graph-rows', 'graph-query'):
            self.tasks.cancel(channel)
        self.loading = False
        self.flags.add('cancelled')
        self._render()

    def shutdown(self) -> None:
        self.epoch += 1
        for channel in CHANNELS:
            self.tasks.cancel(channel)

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        if anchor.kind != 'match' or self.data is None:
            return NavResult.blocked('Calls', f'it does not open {anchor.kind} links')
        if all(d.match_id != anchor.key for d in self.data.deltas):
            return NavResult.not_found(anchor.label or anchor.key, anchor.run_id)
        self._set_seed(anchor.key, remember=True)
        return NavResult.shown()

    # ---- loading -----------------------------------------------------------------------------------

    def reload(self) -> None:
        """Re-read the stored data on a worker (never re-runs an analysis)."""
        project = self.port.project()
        if project is None:
            return self._render()
        service = getattr(self.port, 'service', None)
        root = Path(service.root) if service is not None and getattr(service, 'root', None) is not None else None
        copy, epoch, loader, key = project.model_copy(deep=True), self.epoch, self.loader, self.key
        self.project_copy = copy
        self.loading, self.error, self.stale_reason = True, ('', ''), ''
        self.flags.discard('cancelled')
        self._render()
        self.tasks.submit('graph-load', lambda token, _report: loader(copy, root, token),
                          lambda result, e=epoch, k=key: self._loaded(result, e, k), lambda f, e=epoch: self._failed(f, e))

    def _current(self, epoch: int) -> bool:
        return epoch == self.epoch

    def _loaded(self, result, epoch: int, key) -> None:
        if not self._current(epoch):
            return
        self.loading = False
        if self.port.key() != key:
            self.stale_reason = 'the project changed while the call lists were read'
            return self._render()
        if isinstance(result, pd.Failure):
            self.error = (result.code, result.message)
            return self._render()
        self.data = result
        self.flags = {'raw-missing'} if result.raw_missing else set()
        if result.snapshot.completeness != 'whole-program':
            self.flags.add('no-instruction-data')
        self._refresh_rows()
        if self.seed is not None:
            self._query()
        self._render()

    def _failed(self, failure, epoch: int) -> None:
        if not self._current(epoch):
            return
        self.loading = False
        self.error = (failure.code, f'{failure.exception_class} stopped the work')
        self._render()

    def _refresh_rows(self) -> None:
        data, epoch = self.data, self.epoch
        if data is None:
            return
        changed, noise = self.panel.flags['changed_only'].isChecked(), self.panel.flags['hide_noise'].isChecked()

        def work(token, _report):
            view = changes_view(data.deltas, data.leads, changed_only=changed, hide_noise=noise)
            return Rows(view, prepare_table(CHANGE_SPEC, CHANGE_COLUMNS, view.rows, token))
        self.tasks.submit('graph-rows', work, lambda r, e=epoch: self._rows_ready(r, e),
                          lambda f, e=epoch: self._failed(f, e))

    def _rows_ready(self, rows: Rows, epoch: int) -> None:
        if not self._current(epoch):
            return
        self.rows = rows.view
        (self.flags.add if rows.view.capped else self.flags.discard)('capped')
        self.panel.changes.set_prepared(rows.table)
        self._render()

    # ---- seed and neighbourhood --------------------------------------------------------------------

    def _spec(self, match_id: str) -> pd.QuerySpec:
        panel = self.panel
        return pd.QuerySpec(match_id, panel.side.currentData(), panel.direction.currentData(), panel.depth.value(),
                            panel.flags['show_unresolved'].isChecked())

    def _set_seed(self, match_id: str, *, remember: bool) -> None:
        if match_id == self.seed:
            return
        if remember and self.seed is not None:
            self.history = [*self.history, self.seed][-HISTORY_LIMIT:]
        self.seed = match_id
        self.panel.changes.selectionModel().blockSignals(True)
        row = self.panel.changes.table_model.view_row_of(match_id)
        if row >= 0:
            self.panel.changes.selectRow(row)
        self.panel.changes.selectionModel().blockSignals(False)
        self._show_change_detail()
        self._query()

    def _query(self) -> None:
        data, seed, epoch = self.data, self.seed, self.epoch
        if data is None or seed is None:
            return
        spec = self._spec(seed)
        self.flags -= {'not-in-set', 'no-lists', 'too-large'}
        self.loading = True
        self._render()
        self.tasks.submit('graph-query', lambda token, _report: pd.query(data, spec, token),
                          lambda r, e=epoch: self._queried(r, e), lambda f, e=epoch: self._failed(f, e))

    def _queried(self, result, epoch: int) -> None:
        if not self._current(epoch):
            return
        self.loading = False
        self.found = None
        if isinstance(result, pd.Failure):
            self.error = (result.code, result.message)
        elif result is None:
            self.flags.add('not-in-set')
        else:
            self.error = ('', '')
            self.found = result
            self._apply_found(result)
            if not result.rows:
                self.flags.add('no-lists')
            if result.total > len(result.rows) or result.view.truncated:
                self.flags.add('capped')
        if self.found is None:
            self._clear_views(keep_changes=True)
        self._render()

    def _apply_found(self, found: pd.Neighbourhood) -> None:
        panel = self.panel
        panel.neighbours.set_prepared(prepare_table(NEIGHBOUR_SPEC, NEIGHBOUR_COLS, found.rows))
        self._refresh_edges(found.focus_id)
        self._fill_tree(found)
        self._fill_diagram(found)

    def _fill_tree(self, found: pd.Neighbourhood) -> None:
        tree = self.panel.tree
        tree.clear()
        direction = 'callers' if found.spec.direction == 'in' else 'callees'
        self.tree_index = TreeIndex(found.view, direction)
        root = QTreeWidgetItem([self.tree_index.name(found.focus_id)])
        root.setData(0, TREE_ROLE, (found.focus_id, (found.focus_id,), False))
        root.addChild(QTreeWidgetItem(['']))  # replaced on expand
        tree.addTopLevelItem(root)
        tree.expandItem(root)

    def _expand(self, item: QTreeWidgetItem) -> None:
        index, data = self.tree_index, item.data(0, TREE_ROLE)
        if index is None or data is None or data[2]:
            return
        node_id, path, _ = data
        item.takeChildren()
        children = index.children(node_id, path)
        for child in children.children:
            row = QTreeWidgetItem([sanitize_text(child.name + (' (repeat)' if child.repeat else ''), 200)])
            row.setData(0, TREE_ROLE, (child.node_id, (*path, child.node_id), False))
            if child.expandable:
                row.addChild(QTreeWidgetItem(['']))
            item.addChild(row)
        if children.more:
            item.addChild(QTreeWidgetItem([children.more_text]))
        item.setData(0, TREE_ROLE, (node_id, path, True))

    def _fill_diagram(self, found: pd.Neighbourhood) -> None:
        panel = self.panel
        from .view_model import STATE_TEXT
        place = pd.positions(found)
        layer = pd.layers(found)
        nodes = [GraphNodeView(n.id, n.label, *place.get(n.id, (0.0, 0.0)),
                               chip='info' if n.id == found.focus_id else 'plain',
                               description=f'{n.kind}, layer {layer.get(n.id, 0)}') for n in found.view.nodes]
        edges = [GraphEdgeView(e.src, e.dst, 'call') for e in found.view.edges]
        try:
            panel.canvas.set_graph(nodes, edges)
            panel.minimap.set_points({n.key: (n.x, n.y) for n in nodes}, found.focus_id)
            panel.diagram_note.setText('')
        except GraphTooLargeError:
            panel.diagram_note.setText(STATE_TEXT['E11'].format(n=f'{len(nodes):,}'))
            self.flags.add('too-large')
        panel.diagram_note.setVisible(bool(panel.diagram_note.full_text()))
        self._sync_minimap()

    def _clear_views(self, keep_changes: bool = False) -> None:
        panel = self.panel
        if not keep_changes:
            panel.changes.set_prepared(prepare_table(CHANGE_SPEC, CHANGE_COLUMNS, ()))
        panel.neighbours.set_prepared(prepare_table(NEIGHBOUR_SPEC, NEIGHBOUR_COLS, ()))
        panel.tree.clear()
        panel.canvas.set_graph([], [])
        panel.minimap.clear()
        self._sync_minimap()
        panel.edges.set_prepared(prepare_table(EDGE_SPEC, EDGE_COLS, ()))
        self._clear_sites(NO_EDGE_TEXT)
        panel.diagram_note.setVisible(False)
        panel.detail.setPlainText('')

    # ---- selection and the detail ------------------------------------------------------------------

    def current_change(self) -> ChangesRow | None:
        index = self.panel.changes.currentIndex()
        return index.data(ROW_ROLE) if index.isValid() else None

    def current_neighbour(self) -> NeighbourRow | None:
        index = self.panel.neighbours.currentIndex()
        return index.data(ROW_ROLE) if index.isValid() else None

    def _changes_selected(self) -> None:
        row = self.current_change()
        if row is not None:
            self._set_seed(row.match_id, remember=True)
        self._enable()

    def _show_change_detail(self) -> None:
        if self.data is None or self.seed is None:
            return
        delta = next((d for d in self.data.deltas if d.match_id == self.seed), None)
        lead = next((x for x in self.data.leads if x.match_id == self.seed), None)
        if delta is not None:
            self.panel.detail.setPlainText(copy_text(change_detail(delta, lead, self.found.view if self.found else None)))

    def _neighbour_selected(self) -> None:
        row, found = self.current_neighbour(), self.found
        if row is not None and found is not None:
            node = next((n for n in found.view.nodes if n.id == row.node_id), None)
            if node is not None:
                partner_ = pd.partner(self.data.snapshot, found.spec.side, node.id)
                self.panel.detail.setPlainText(copy_text(node_detail(node, partner_, found.view)))
            self._refresh_edges(row.node_id)
        self._enable()

    def _tree_selected(self) -> None:
        self._enable()

    def _canvas_focused(self, node_id: str) -> None:
        row = self.panel.neighbours.table_model.view_row_of(node_id)
        if row >= 0:
            self.panel.neighbours.selectRow(row)

    def _selected_node_id(self) -> str | None:
        tabs = self.panel.tabs.currentIndex()
        if tabs == 4:
            edge = self.current_edge()
            return edge.caller_id if edge else None
        if tabs == 3:
            return self.panel.canvas.focused_key
        if tabs == 2:
            item = self.panel.tree.currentItem()
            data = item.data(0, TREE_ROLE) if item is not None else None
            return data[0] if data else None
        row = self.current_neighbour()
        return row.node_id if row else None

    # ---- actions -----------------------------------------------------------------------------------

    def _options_changed(self) -> None:
        if self.data is None:
            return
        self._refresh_rows()
        if self.seed is not None:
            self._query()

    def _action(self, action: str) -> None:
        {'open': self.open, 'focus': self.focus_here, 'back': self.back, 'copy': self.copy,
         'callsite': self.show_call_site, 'export_dot': self.export_dot}[action]()

    def open(self) -> None:
        """Open the selected function in the code panes through the anchor router; a miss changes nothing."""
        target = self._selected_target()
        if target is None or self.key is None:
            return
        key, side, label = target
        result = self.ctx.nav.navigate(AnchorRef('function', key, side, label=label, origin='graph').pinned(self.key))
        if getattr(result, 'status', 'shown') != 'shown':
            self.ctx.shell.status(getattr(result, 'message', ''))

    def _selected_target(self) -> tuple[str, str, str] | None:
        found = self.found
        node_id = self._selected_node_id()
        if found is not None and node_id is not None:
            node = next((n for n in found.view.nodes if n.id == node_id), None)
            if node is not None and node.function_id:
                return node.function_id, node.side, node.label
            if node is not None:
                self.ctx.shell.status(sanitize_text(node.reason or 'This name has no function record.', 200))
                return None
        row = self.current_change()
        delta = next((d for d in self.data.deltas if row and d.match_id == row.match_id), None) if self.data else None
        if delta is not None and delta.newer_function_id:
            return delta.newer_function_id, 'newer', delta.newer_label or ''
        return None

    def focus_here(self) -> None:
        """Re-seed on the selected neighbour when it is a changed function; otherwise say why not."""
        found, node_id = self.found, self._selected_node_id()
        node = next((n for n in found.view.nodes if n.id == node_id), None) if found else None
        if node is None or node.match_id is None or self.data is None \
                or all(d.match_id != node.match_id for d in self.data.deltas):
            self.flags.add('not-in-set')
            return self._render()
        self._set_seed(node.match_id, remember=True)

    def back(self) -> None:
        if self.history:
            seed = self.history.pop()
            self.seed = None
            self._set_seed(seed, remember=False)

    def copy(self) -> None:
        self.ctx.shell.copy_text(self.panel.detail.toPlainText()[:16 * 1024])

    # ---- edges, call sites and the minimap ------------------------------------------------------------------------

    def current_edge(self) -> EdgeRow | None:
        index = self.panel.edges.currentIndex()
        return index.data(ROW_ROLE) if index.isValid() else None

    def _refresh_edges(self, node_id: str) -> None:
        found = self.found
        if found is None:
            return
        rows, _total = edge_rows(found.view, node_id)
        self.panel.edges.set_prepared(prepare_table(EDGE_SPEC, EDGE_COLS, rows))
        self._clear_sites(NO_EDGE_TEXT)

    def _clear_sites(self, note: str) -> None:
        self.panel.sites.set_prepared(prepare_table(SITE_SPEC, SITE_COLS, ()))
        self.panel.site_note.setText(note)

    def _edge_selected(self) -> None:
        self._clear_sites(NO_EDGE_TEXT)
        self._enable()

    def show_call_site(self) -> None:
        """Reveal the lines of the caller's stored decompiled text that name the callee (a text match)."""
        edge, found, project = self.current_edge(), self.found, self.project_copy
        if edge is None or found is None or project is None:
            return
        nodes = {n.id: n for n in found.view.nodes}
        caller, callee = nodes.get(edge.caller_id), nodes.get(edge.callee_id)
        if caller is None or callee is None:
            return
        if not caller.function_id:
            return self._show_sites(call_site_view(None, callee.label))
        function_id, label, epoch, edge_id = caller.function_id, callee.label, self.epoch, edge.edge_id
        self.tasks.submit('graph-callsite',
                          lambda _token, _report: call_site_view(function_code(project, function_id), label),
                          lambda view, e=epoch, i=edge_id: self._sites_ready(view, e, i),
                          lambda f, e=epoch: self._export_failed(f, e))

    def _sites_ready(self, view: CallSiteView, epoch: int, edge_id: str) -> None:
        edge = self.current_edge()
        if not self._current(epoch) or edge is None or edge.edge_id != edge_id:
            return
        self._show_sites(view)

    def _show_sites(self, view: CallSiteView) -> None:
        rows: tuple[CallSiteRow, ...] = view.rows
        self.panel.sites.set_prepared(prepare_table(SITE_SPEC, SITE_COLS, rows))
        if view.message:
            note = view.message
        else:
            shown = f'{len(rows)} of {view.total}' if view.total > len(rows) else str(view.total)
            note = f'{shown} text match{"" if view.total == 1 else "es"} in decompiled code'
        self.panel.site_note.setText(note)
        self.ctx.shell.announce(note)

    def _sync_minimap(self) -> None:
        panel = self.panel
        panel.minimap.setVisible(panel.minimap_toggle.isChecked() and panel.canvas.node_count > 0)
        panel.minimap.refresh()

    def export_dot(self) -> None:
        """Build the DOT text on a worker; only then ask for a path. No path means no file."""
        data, found, epoch = self.data, self.found, self.epoch
        if data is None or found is None:
            return
        self.tasks.submit('graph-export', lambda _token, _report: _build_dot(data, found),
                          lambda result, e=epoch: self._dot_ready(result, e), lambda f, e=epoch: self._export_failed(f, e))

    def _dot_ready(self, result: str | pd.Failure, epoch: int) -> None:
        if not self._current(epoch):
            return
        if isinstance(result, pd.Failure):
            return self._say(f'DOT export failed: {result.code}: {result.message}')
        path = self.save_dialog(self.panel, pd.dot_name(result))
        if not path:
            return self._say('Export cancelled. Nothing was written.')
        self.tasks.submit('graph-export', lambda _token, _report: _write_dot(path, result),
                          lambda size, e=epoch, p=path: self._written(size, e, p),
                          lambda f, e=epoch: self._export_failed(f, e))

    def _written(self, result: int | pd.Failure, epoch: int, path: str) -> None:
        if not self._current(epoch):
            return
        if isinstance(result, pd.Failure):
            return self._say(f'DOT export failed: {result.code}: {result.message}')
        self._say(f'Wrote {sanitize_text(Path(path).name, 120)} ({result:,} bytes).')

    def _export_failed(self, failure, epoch: int) -> None:
        if self._current(epoch):
            self._say(f'DOT export failed: {failure.code}: {failure.exception_class} stopped the work')

    def _say(self, text: str) -> None:
        """Status bar and screen reader; the committed call view is not replaced."""
        self.ctx.shell.status(text)
        self.ctx.shell.announce(text)

    def _enable(self) -> None:
        buttons = self.panel.buttons
        buttons['back'].setEnabled(bool(self.history))
        buttons['open'].setEnabled(self.data is not None and self._selected_target_exists())
        buttons['focus'].setEnabled(self.found is not None and self._selected_node_id() is not None)
        buttons['copy'].setEnabled(bool(self.panel.detail.toPlainText()))
        buttons['callsite'].setEnabled(self.found is not None and self.current_edge() is not None)
        buttons['export_dot'].setEnabled(self.data is not None and self.found is not None and not self.loading)

    def _selected_target_exists(self) -> bool:
        return self.current_change() is not None or self._selected_node_id() is not None

    # ---- state -------------------------------------------------------------------------------------

    def _render(self) -> None:
        self.panel.state.set_state(self._state(), has_content=self.data is not None)
        self._enable()

    def _state(self) -> StateModel:
        from .view_model import STATE_TEXT
        if self.key is None:
            return StateModel('no-project', STATE_TEXT['E0'])
        if self.key.run_id is None:
            return StateModel('idle', STATE_TEXT['E1'])
        if self.error[0]:
            lines = status_lines(PanelState(frozenset({'failed'}), code=self.error[0], message=self.error[1]))
            return StateModel('error', lines[0], lines[0], ('retry', 'copy'))
        if self.stale_reason:
            lines = status_lines(PanelState(frozenset({'stale'}), reason=self.stale_reason))
            return StateModel('stale', lines[0], '', ('refresh',))
        if 'cancelled' in self.flags:
            return StateModel('cancelled', STATE_TEXT['E8'])
        if self.loading:
            return StateModel('refreshing' if self.data else 'loading', STATE_TEXT['E2'])
        found, total = self.found, self.found.total if self.found else 0
        shown = len(found.rows) if found else 0
        lines = status_lines(PanelState(frozenset(self.flags), shown=shown, total=total,
                                        nodes=len(found.view.nodes) if found else 0))
        if lines:
            return StateModel('partial', ' '.join(lines))
        if self.data is None:
            return StateModel('idle', STATE_TEXT['E1'])
        nodes, edges = (len(found.view.nodes), len(found.view.edges)) if found else (0, 0)
        return StateModel('ready', f'Showing {nodes} nodes and {edges} observed call relationships; coverage '
                                   f'{self.data.snapshot.completeness}.')
