"""Qt presentation of the Detection rules dock (panel spec R6b; GUI plan 8.10). Loaded only by the panel factory.

It shows the stored rule rows of the open project in three tabs (proposed rules, the newest test grid, saved versions).
What is said lives in the Qt-free `view_model` and `tables`; this module moves it to widgets. The project database
belongs to the GUI thread, so the GUI thread reads the rows and a worker only prepares the tables from the immutable
snapshot. A request carries the project key; a result whose key is no longer the current one is dropped, so a late
build never paints over another project. The dock never opens a window of its own and proposes, tests and exports
nothing (those need the R6a service).
"""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..gui.anchors import AnchorRef, NavResult
from ..gui.qt.docks import ControllerBase
from ..gui.qt.labels import PlainLabel, SafeTextView
from ..gui.qt.state_view import StateView
from ..gui.qt.table import ROW_ROLE, VirtualTable
from ..gui.registry import PanelContext
from ..gui.state import NoticeModel
from ..gui.table_spec import prepare_table
from ..gui.text import sanitize_text
from ..gui.tips import apply_tip, register_gui_tips, register_tips
from . import tables as tb
from . import view_model as vm
from .tooltip_entries import TEMPLATES, TIPS

CHANNEL = 'rules.build'
TAB_NAMES = ('Proposed rules', 'Test grid', 'Saved rules')
Loader = Callable[[object, object], vm.Stored]


class _Announcer:
    """Adapts the shell's keyword-only `announce` to the StateView's positional one."""

    def __init__(self, shell: object) -> None:
        self._shell = shell

    def announce(self, text: str, assertive: bool = False) -> None:
        self._shell.announce(text, assertive=assertive)


class RulesPanel(QWidget):
    """The widgets. It holds no state of the result: the controller feeds it."""

    copy_requested = Signal()
    open_requested = Signal()
    grid_filter_changed = Signal()

    def __init__(self, announcer: object | None) -> None:
        super().__init__()
        self.setObjectName('rules.panel')
        self.state = StateView('rules.body', vm.TITLE, announcer)
        self.tabs = QTabWidget()
        self.tabs.setAccessibleName('Detection rules views')
        self.tabs.tabBar().setAccessibleName('Detection rules views')
        self.search = QLineEdit()
        self.search.setAccessibleName('Search proposed rules by name, function or label')
        self.search.setObjectName('rules.search')
        self.search.setPlaceholderText('Rule, function or label')
        self.candidates = VirtualTable('Proposed rules table')
        self.features = VirtualTable('Features of the selected rule')
        self.checks = VirtualTable('Checks of the selected rule')
        self.rule_text = SafeTextView('Rule text of the selected rule', limit=vm.TEXT_LIMIT)
        self.rule_text.setFont(self._monospace())
        self.detail = SafeTextView('Details of the selected rule', limit=4_000, wrap=True)
        self.copy_button = self._button('Copy rule text', 'Copy exact rule text of the selected rule', 'rules.copy_text',
                                        self.copy_requested)
        self.open_button = self._button('Open pair', 'Go to the changed function of the selected rule', 'rules.open_pair',
                                        self.open_requested)
        self.role = self._combo('Show builds of one role in the test grid', 'rules.grid_role', vm.ROLE_FILTER)
        self.result = self._combo('Show grid rows with one kind of result', 'rules.grid_state', vm.STATE_FILTER)
        self.unexpected = QCheckBox('Unexpected results only')
        self.unexpected.setAccessibleName('Show only builds with an unexpected result')
        self.grid = VirtualTable('Test grid')
        self.grid_detail = SafeTextView('Details of the selected grid row', limit=4_000, wrap=True)
        self.saved = VirtualTable('Saved rule versions table')
        self.footer = PlainLabel(vm.FOOTER, wrap=True, limit=400)
        self.footer.setObjectName('rules.footer')
        self._lay_out()
        self._tips()
        for control in (self.role, self.result):
            control.currentIndexChanged.connect(lambda _i: self.grid_filter_changed.emit())
        self.unexpected.toggled.connect(lambda _on: self.grid_filter_changed.emit())
        self.search.textChanged.connect(self.candidates.set_filter)
        self.setFocusProxy(self.candidates)

    @staticmethod
    def _monospace():
        from PySide6.QtGui import QFontDatabase
        return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)

    def _button(self, text: str, name: str, tip: str, signal: Signal) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(name)
        button.setObjectName(tip)
        button.clicked.connect(lambda _checked=False: signal.emit())
        return button

    def _combo(self, name: str, tip: str, items: tuple[tuple[str, str], ...]) -> QComboBox:
        combo = QComboBox()
        combo.setAccessibleName(name)
        combo.setObjectName(tip)
        for value, text in items:
            combo.addItem(text, value)
        combo.view().setAccessibleName(f'{name} options')
        return combo

    def _lay_out(self) -> None:
        text_pane = QWidget()
        column = QVBoxLayout(text_pane)
        column.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self.detail)
        column.addWidget(self.rule_text, 1)
        actions = QHBoxLayout()
        actions.addWidget(self.copy_button)
        actions.addWidget(self.open_button)
        actions.addStretch(1)
        column.addLayout(actions)
        lower = QSplitter(Qt.Orientation.Horizontal)
        for table in (self.features, self.checks):
            lower.addWidget(table)
        body = QSplitter(Qt.Orientation.Vertical)
        for part in (self.candidates, lower, text_pane):
            body.addWidget(part)
        body.setChildrenCollapsible(False)
        first = QWidget()
        layout = QVBoxLayout(first)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.search)
        layout.addWidget(body, 1)
        second = QWidget()
        grid_layout = QVBoxLayout(second)
        grid_layout.setContentsMargins(0, 0, 0, 0)
        filters = QHBoxLayout()
        for widget in (self.role, self.result, self.unexpected):
            filters.addWidget(widget)
        filters.addStretch(1)
        grid_layout.addLayout(filters)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.grid)
        split.addWidget(self.grid_detail)
        split.setChildrenCollapsible(False)
        grid_layout.addWidget(split, 1)
        for page, title in zip((first, second, self.saved), TAB_NAMES, strict=True):
            self.tabs.addTab(page, title)
        self.content = QWidget()
        outer = QVBoxLayout(self.content)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.tabs, 1)
        outer.addWidget(self.footer)
        self.state.set_content(self.content)
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.addWidget(self.state, 1)

    def _tips(self) -> None:
        for widget, tip in ((self.tabs, 'rules.tabs'), (self.candidates, 'rules.candidates'),
                            (self.features, 'rules.features'), (self.checks, 'rules.checks'),
                            (self.rule_text, 'rules.rule_text'), (self.detail, 'rules.detail'),
                            (self.copy_button, 'rules.copy_text'), (self.open_button, 'rules.open_pair'),
                            (self.role, 'rules.grid_role'), (self.result, 'rules.grid_state'),
                            (self.unexpected, 'rules.unexpected_only'), (self.grid, 'rules.grid'),
                            (self.saved, 'rules.saved')):
            apply_tip(widget, tip)
        self.grid_detail.setObjectName('rules.grid_detail')
        apply_tip(self.grid_detail, 'rules.detail', name='rules.grid_detail')
        apply_tip(self.search, 'rules.candidates', name='rules.search')
        apply_tip(self.tabs.tabBar(), 'rules.tabs', name='rules.tab_bar')

    def grid_filter(self) -> Callable[[object], bool]:
        role, result, unexpected = self.role.currentData(), self.result.currentData(), self.unexpected.isChecked()

        def keep(row) -> bool:
            return ((role == 'all' or row.role_key == role) and (result == 'all' or result in row.states)
                    and (not unexpected or row.unexpected))
        return keep


class RulesController(ControllerBase):
    """Owns the loaded rows and the request in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, loader: Loader = vm.load_stored) -> None:
        register_gui_tips()
        register_tips(TIPS, TEMPLATES)
        panel = RulesPanel(_Announcer(ctx.shell))
        super().__init__(panel)
        self.panel, self.ctx, self.port, self.tasks, self.loader = panel, ctx, ctx.project, ctx.tasks, loader
        self.key = None
        self.stored: vm.Stored | None = None
        self.error: tuple[str, str] | None = None
        self.loading = False
        self.candidate_by_id: dict[str, object] = {}
        self.closed = False
        self._wire()
        self._empty_tables()
        self._render()

    # ---- wiring --------------------------------------------------------------------------------------

    def _wire(self) -> None:
        panel = self.panel
        panel.state.retry_requested.connect(self.reload)
        panel.state.refresh_requested.connect(self.reload)
        panel.state.copy_requested.connect(lambda text: self.ctx.shell.copy_text(text))
        panel.copy_requested.connect(self.copy_rule)
        panel.open_requested.connect(self.open_pair)
        panel.grid_filter_changed.connect(self._filter_grid)
        panel.candidates.selectionModel().currentRowChanged.connect(lambda *_: self._candidate_selected())
        panel.candidates.table_model.modelReset.connect(self._candidate_selected)
        panel.candidates.activated_key.connect(lambda _key: self.open_pair())
        panel.grid.selectionModel().currentRowChanged.connect(lambda *_: self._grid_selected())
        panel.grid.table_model.modelReset.connect(self._grid_selected)

    def _empty_tables(self) -> None:
        panel = self.panel
        for table, spec, columns in ((panel.candidates, tb.CANDIDATE_SPEC, tb.CANDIDATE_COLUMNS),
                                     (panel.saved, tb.SAVED_SPEC, tb.SAVED_COLUMNS),
                                     (panel.grid, tb.GRID_SPEC, tb.GRID_FIXED),
                                     (panel.features, tb.FEATURE_SPEC, tb.FEATURE_COLUMNS),
                                     (panel.checks, tb.CHECK_SPEC, tb.CHECK_COLUMNS)):
            table.set_prepared(tb.empty_table(spec, columns))

    # ---- host hooks ----------------------------------------------------------------------------------

    def project_changed(self, key) -> None:
        self.tasks.cancel(CHANNEL)
        self.key, self.stored, self.error, self.loading = key, None, None, False
        self.candidate_by_id = {}
        self._empty_tables()
        self._notices(None)
        if key is not None:
            self.reload()
        else:
            self._render()

    def shutdown(self) -> None:
        self.closed = True
        self.tasks.cancel(CHANNEL)

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        if anchor.kind != 'rule':
            return NavResult.blocked(vm.TITLE, f'it does not open {anchor.kind} links')
        if self.stored is None:
            return NavResult.blocked(vm.TITLE, 'no rules are loaded')
        panel = self.panel
        for table, tab in ((panel.candidates, 0), (panel.saved, 2)):
            row = table.table_model.view_row_of(anchor.key)
            if row >= 0:
                panel.tabs.setCurrentIndex(tab)
                table.selectRow(row)
                table.setCurrentIndex(table.table_model.index(row, 0))
                return NavResult.shown()
        return NavResult.not_found(anchor.label or anchor.key, anchor.run_id)

    # ---- loading -------------------------------------------------------------------------------------

    def reload(self) -> None:
        """Read the stored rows (GUI thread: it owns the project connection), then prepare the tables in a worker."""
        service, project = getattr(self.port, 'service', None), self.port.project()
        if service is None or project is None:
            return self._render()
        try:
            stored = self.loader(service, project)
        except vm.READ_ERRORS as exc:
            self.error = (getattr(exc, 'code', 'PT-RULE-STORAGE'), f'{type(exc).__name__} stopped the read')
            return self._render()
        self.error, self.loading = None, True
        key = self.key
        self._render()
        self.tasks.submit(CHANNEL, lambda token, _report: (key, tb.build(stored, token)),
                          self._built, self._failed)

    def _built(self, result) -> None:
        key, built = result
        if self.closed or key != self.key:
            return
        self.loading, self.stored = False, built.stored
        self.candidate_by_id = {c.candidate_id: c for c in built.stored.candidates}
        panel = self.panel
        panel.candidates.set_prepared(built.candidates)
        panel.saved.set_prepared(built.saved)
        panel.grid.set_prepared(built.grid)
        self._filter_grid()
        self._render()

    def _failed(self, failure) -> None:
        self.loading = False
        self.error = (failure.code, f'{failure.exception_class} stopped the work')
        self._render()

    # ---- selection and actions -----------------------------------------------------------------------

    def current_candidate(self):
        index = self.panel.candidates.currentIndex()
        row = index.data(ROW_ROLE) if index.isValid() else None
        return self.candidate_by_id.get(row.key) if row is not None else None

    def _candidate_selected(self) -> None:
        panel, candidate = self.panel, self.current_candidate()
        if candidate is None or self.stored is None:
            panel.detail.setPlainText('')
            panel.rule_text.setPlainText('')
            panel.features.set_prepared(tb.empty_table(tb.FEATURE_SPEC, tb.FEATURE_COLUMNS))
            panel.checks.set_prepared(tb.empty_table(tb.CHECK_SPEC, tb.CHECK_COLUMNS))
        else:
            panel.detail.setPlainText(vm.candidate_detail(self.stored, candidate))
            panel.rule_text.setPlainText(vm.rule_text(candidate))
            panel.features.set_prepared(prepare_table(tb.FEATURE_SPEC, tb.FEATURE_COLUMNS, vm.feature_rows(candidate)))
            panel.checks.set_prepared(prepare_table(tb.CHECK_SPEC, tb.CHECK_COLUMNS, vm.check_rows(candidate)))
        panel.copy_button.setEnabled(candidate is not None)
        panel.open_button.setEnabled(candidate is not None and self.key is not None)

    def _grid_selected(self) -> None:
        index = self.panel.grid.currentIndex()
        row = index.data(ROW_ROLE) if index.isValid() else None
        text = ''
        if row is not None:
            titles = [c.title for c in self.panel.grid.table_model.prepared.columns[len(tb.GRID_FIXED):]]
            lines = [f'Build {row.build}: {row.label}', f'Role: {row.role}', f'Expectation: {row.expectation}',
                     f'Advisory says: {row.advisory}']
            lines += [f'{title}: {cell}' for title, cell in zip(titles, row.cells, strict=False)]
            text = '\n'.join(lines)
        self.panel.grid_detail.setPlainText(text)

    def _filter_grid(self) -> None:
        self.panel.grid.set_filter('', self.panel.grid_filter())

    def copy_rule(self) -> None:
        candidate = self.current_candidate()
        if candidate is None:
            return
        text = vm.clipboard_text(candidate.rule_text)
        shell = self.ctx.shell
        if text is None:
            shell.status(vm.OVERSIZE)
            shell.announce(vm.OVERSIZE)
        elif shell.copy_text(text):
            shell.status(f'Copied rule text of {sanitize_text(candidate.rule_name, 60)}.')

    def open_pair(self) -> NavResult | None:
        candidate = self.current_candidate()
        if candidate is None:
            return None
        source = candidate.source
        anchor = AnchorRef('match', source.match_id, side=candidate.direction, run_id=source.run_id,
                           label=vm.function_label(candidate), origin='rules', revision=source.revision)
        result = self.ctx.nav.navigate(anchor)
        if getattr(result, 'status', 'shown') != 'shown':
            self.ctx.shell.status(sanitize_text(result.message))
        return result

    # ---- state ---------------------------------------------------------------------------------------

    def _notices(self, found: dict | None) -> None:
        """Caution lines for the states that keep results readable; the host strip is never modal."""
        notify = getattr(self.ctx.shell, 'notice', None)
        if notify is None:
            return
        for kind, field, text in (('partial', 'reasons', 'Detection rules: some stored rows could not be read.'),
                                  ('stale', 'reason', 'Detection rules: stored rules describe an earlier analysis.')):
            fields = (found or {}).get(kind)
            key = f'rules.{kind}'
            detail = sanitize_text(str(fields[field]), 400, multiline=True) if fields is not None else ''
            notify(key, None if fields is None else NoticeModel(key, 'caution', text, detail))

    def _render(self) -> None:
        found = vm.conditions(self.stored, self.key, error=self.error, loading=self.loading)
        has_content = self.stored is not None and not self.stored.empty
        self.panel.state.show_conditions(found, has_content=has_content)
        self._notices(found)
        self.panel.copy_button.setEnabled(self.current_candidate() is not None)
