"""Qt presentation of the KB and CVE dock (KB-integration-plan 8.2, slice K4b; GUI plan 8.10).

Everything that decides what is said lives in the Qt-free `view_model` and `panel_state`; this module moves it to
widgets. Reading the stored leads (the advisory workspace and the project's ranking) and building the table happen on
the `TaskRunner`, never on the GUI thread; a project switch cancels the request and a late result is dropped. The
panel reads stored results only: it opens no network connection, runs no tool and creates no window.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QPushButton, QSplitter, QVBoxLayout, QWidget

from ..gui.anchors import AnchorRef, NavResult
from ..gui.qt.docks import ControllerBase
from ..gui.qt.labels import PlainLabel, SafeTextView
from ..gui.qt.state_view import StateView
from ..gui.qt.table import ROW_ROLE, VirtualTable
from ..gui.registry import PanelContext
from ..gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from ..gui.text import VIEW_LIMIT, sanitize_text
from ..gui.tips import apply_tip, escaped_tip, register_gui_tips, register_tips
from .leads import LeadsReport, build_leads
from .panel_state import coverage_notice, failure_conditions, report_conditions
from .tooltip_entries import TEMPLATES, TIPS
from .view_model import ALL_GROUPS, COLUMN_NAMES, COPY_LIMIT, LeadsViewModel, TableRow

CHANNEL = 'kb.load'
ROWS_CHANNEL = 'kb.rows'
NOUN = 'KB and CVE leads'
Loader = Callable[[Path, str, object], LeadsReport]

COLUMNS = tuple(
    ColumnSpec(key, title, (lambda r, i=i: r.cells[i]), width_em=width, accessible=(lambda r, i=i: r.accessible[i]),
               sort_key=(lambda r, i=i: (int(r.cells[0]) if r.cells[0].isdigit() else 0) if i == 0 else r.cells[i].casefold()))
    for i, (key, title, width) in enumerate((('order', 'Order', 7), ('function', 'Function', 26),
                                              ('group', 'CVE group', 18), ('evidence', 'Evidence by channel', 44),
                                              ('attention', 'Attention order', 16))))
assert len(COLUMNS) == len(COLUMN_NAMES)
SPEC = TableSpec(row_key=lambda r: f'{r.kind}:{r.group}:{r.lead_id or ""}', search_text=lambda r: ' '.join(r.cells))


def load_report(workspace: Path, project_dir: str, token: object) -> LeadsReport:
    """Worker: the stored advisory context and ranking as a leads report. It opens no network connection."""
    from .cli_leads import RealEngine, default_alignment, leads_outcome
    from .wiring import build_service
    outcome = leads_outcome(build_service(workspace), RealEngine(), project_dir)
    if 'text' in outcome.result:
        return LeadsReport.model_validate(outcome.result)
    return build_leads(None, None, alignment=default_alignment())  # no advisory and no ranking: nothing to pair


def _prepare(report: LeadsReport, group: str, token: object) -> tuple[LeadsViewModel, PreparedTable]:
    model = LeadsViewModel.from_report(report, group)
    rows = tuple(model.row(i) for i in range(model.row_count))
    return model, prepare_table(SPEC, COLUMNS, rows, token)


class KbPanel(QWidget):
    """The widgets. It holds no state of the result: the controller feeds it."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName('kb.panel')
        self.state_view = StateView('kb.leads', NOUN, text_limit=VIEW_LIMIT, multiline=True)
        self.group = QComboBox()
        self.group.setObjectName('kb.group')
        self.group.setAccessibleName('CVE group of the leads')
        self.search = QLineEdit()
        self.search.setObjectName('kb.search')
        self.search.setAccessibleName('Search leads by function name')
        self.search.setPlaceholderText('Function name')
        self.buttons = {name: self._button(name, text, accessible) for name, text, accessible in (
            ('refresh', 'Refresh', 'Refresh the stored KB and CVE leads'),
            ('goto', 'Go to function', 'Go to the selected function in the code panes'),
            ('copy', 'Copy evidence', 'Copy the evidence of the selected row'))}
        self.table = VirtualTable('KB and CVE leads table')
        self.table.setObjectName('kb.table')
        self.detail = SafeTextView('Evidence of the selected row', wrap=True)
        self.detail.setObjectName('kb.detail')
        self.footer = PlainLabel(wrap=True, limit=4_000, multiline=True)
        self.footer.setObjectName('kb.footer')
        self.footer.setAccessibleName('Coverage and limits')
        self.content = QWidget()
        top = QHBoxLayout()
        top.addWidget(self.group)
        top.addWidget(self.search, 1)
        for name in ('goto', 'copy', 'refresh'):
            top.addWidget(self.buttons[name])
        body = QSplitter(Qt.Orientation.Vertical)
        body.addWidget(self.table)
        body.addWidget(self.detail)
        body.setChildrenCollapsible(False)
        column = QVBoxLayout(self.content)
        column.setContentsMargins(0, 0, 0, 0)
        column.addLayout(top)
        column.addWidget(body, 1)
        column.addWidget(self.footer)
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.addWidget(self.state_view, 1)
        self.state_view.set_content(self.content)
        self.group.view().setAccessibleName('CVE group of the leads options')
        for widget, tip in ((self.group, 'kb.group'), (self.search, 'kb.search'), (self.table, 'kb.table'),
                            (self.detail, 'kb.detail'), (self.footer, 'kb.footer')):
            apply_tip(widget, tip)
        self.setFocusProxy(self.table)

    def _button(self, name: str, text: str, accessible: str) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(accessible)
        apply_tip(button, f'kb.{name}')
        return button


class KbController(ControllerBase):
    """Owns the loaded view model and the requests in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, loader: Loader = load_report, workspace: Path | None = None) -> None:
        register_gui_tips()  # idempotent; the StateView buttons use these tips
        register_tips(TIPS, TEMPLATES)
        panel = KbPanel()
        super().__init__(panel)
        self.panel, self.ctx, self.loader = panel, ctx, loader
        self.port, self.tasks = ctx.project, ctx.tasks
        self.workspace = workspace
        self.goto_tip = panel.buttons['goto'].toolTip()
        self.key = None
        self.model: LeadsViewModel | None = None
        self.group = ALL_GROUPS
        self.loading = False
        self._wire()
        self._render({'idle': {'hint': 'Open a project to read its KB and CVE leads.'}}, False)

    def _wire(self) -> None:
        panel = self.panel
        panel.group.currentIndexChanged.connect(lambda _i: self._group_changed(panel.group.currentData()))
        panel.search.textChanged.connect(panel.table.set_filter)
        panel.buttons['refresh'].clicked.connect(self.reload)
        panel.buttons['goto'].clicked.connect(self.go)
        panel.buttons['copy'].clicked.connect(self.copy_evidence)
        panel.state_view.retry_requested.connect(self.reload)
        panel.state_view.refresh_requested.connect(self.reload)
        panel.state_view.copy_requested.connect(self.ctx.shell.copy_text)
        panel.table.activated_key.connect(lambda _key: self.go())
        panel.table.selectionModel().currentRowChanged.connect(lambda *_: self._selection_changed())
        panel.table.table_model.modelReset.connect(self._selection_changed)

    # ---- host hooks ----------------------------------------------------------------------------------

    def project_changed(self, key) -> None:
        self.tasks.cancel(CHANNEL)
        self.tasks.cancel(ROWS_CHANNEL)
        self.key, self.model, self.group, self.loading = key, None, ALL_GROUPS, False
        self.ctx.shell.notice('kb.coverage', None)
        self.panel.table.set_prepared(prepare_table(SPEC, COLUMNS, ()))
        self._set_groups(())
        if key is None:
            self._render({'no-project': {}}, False)
        else:
            self.reload()

    def busy_changed(self, busy: bool) -> None:
        self._enable()

    def shutdown(self) -> None:
        self.tasks.cancel(CHANNEL)
        self.tasks.cancel(ROWS_CHANNEL)

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        if anchor.kind != 'cve':
            return NavResult.blocked('KB and CVE', f'it does not open {anchor.kind} links')
        index = self.panel.group.findData(anchor.key)
        if self.model is None or index < 0:
            return NavResult.not_found(anchor.key, anchor.run_id)
        self.panel.group.setCurrentIndex(index)
        return NavResult.shown()

    # ---- loading -------------------------------------------------------------------------------------

    def _project_dir(self) -> str | None:
        root = getattr(getattr(self.port, 'service', None), 'root', None)
        return str(root) if root is not None else None

    def reload(self) -> None:
        directory = self._project_dir()
        if self.key is None or directory is None:
            if self.key is not None:
                self._render({'blocked': {'reason': 'the project folder is not available.',
                                          'remedy': 'Reopen the project.'}}, False)
            return
        key, group, loader = self.key, self.group, self.loader
        workspace = self.workspace or _default_workspace()
        self.loading = True
        self._render({('refreshing' if self.model else 'loading'): {'noun': NOUN}}, self.model is not None)

        def work(token, _report):
            report = loader(workspace, directory, token)
            return (key, report, *_prepare(report, group, token))
        self.tasks.submit(CHANNEL, work, self._loaded, self._failed)

    def _loaded(self, result) -> None:
        key, report, model, prepared = result
        if key != self.key:
            return
        self.loading, self.model = False, model
        self._set_groups(model.group_options())
        self.panel.table.set_prepared(prepared)
        self.panel.footer.setText('\n'.join((model.coverage_line, *model.footer_lines)))
        conditions, has_content = report_conditions(model)
        self._render(conditions, has_content)
        self.ctx.shell.notice('kb.coverage', coverage_notice(model))

    def _failed(self, failure) -> None:
        self.loading = False
        self._render(failure_conditions(failure.code, f'{failure.exception_class} stopped the work'),
                     self.model is not None)

    def _render(self, conditions, has_content: bool) -> None:
        self.panel.state_view.show_conditions(conditions, has_content=has_content)
        self._enable()

    # ---- filters, selection, actions -----------------------------------------------------------------

    def _set_groups(self, options) -> None:
        combo = self.panel.group
        combo.blockSignals(True)
        combo.clear()
        for option in options:
            combo.addItem('All groups' if option == ALL_GROUPS else sanitize_text(option, 120), option)
        combo.setCurrentIndex(max(0, combo.findData(self.group)) if options else -1)
        combo.blockSignals(False)

    def _group_changed(self, group) -> None:
        if self.model is None or group is None:
            return
        self.group, report = group, self.model.report
        self.tasks.submit(ROWS_CHANNEL, lambda token, _r: _prepare(report, group, token), self._rows_ready, self._failed)

    def _rows_ready(self, result) -> None:
        self.model = result[0]
        self.panel.table.set_prepared(result[1])

    def current_row(self) -> TableRow | None:
        index = self.panel.table.currentIndex()
        return index.data(ROW_ROLE) if index.isValid() else None

    def _selection_changed(self) -> None:
        row = self.current_row()
        report = self.model.report if self.model else None
        if row is None or report is None:
            self.panel.detail.setPlainText('')
        elif row.kind == 'group':
            self.panel.detail.setPlainText(row.cells[1])
        else:
            self.panel.detail.setPlainText(row.copy_text)
        self._enable()

    def _go_reason(self, row: TableRow | None) -> str | None:
        if row is None or row.kind != 'lead':
            return 'Select a function row first.'
        if self.model is None or not self.model.navigation_enabled or row.match_id is None:
            return 'This row is not tied to a current comparison row, so there is no function to show.'
        return None

    def _enable(self) -> None:
        buttons, row = self.panel.buttons, self.current_row()
        reason = self._go_reason(row)
        buttons['goto'].setEnabled(reason is None)
        buttons['goto'].setToolTip(escaped_tip(reason) if reason else self.goto_tip)
        buttons['copy'].setEnabled(row is not None and row.kind == 'lead')
        buttons['refresh'].setEnabled(not self.loading and self.key is not None)

    def go(self) -> None:
        row = self.current_row()
        if self._go_reason(row) is None:
            self.ctx.nav.select_match(row.match_id)

    def copy_evidence(self) -> None:
        row = self.current_row()
        if row is not None and row.kind == 'lead':
            self.ctx.shell.copy_text(row.copy_text[:COPY_LIMIT])


def _default_workspace() -> Path:
    from .store import default_workspace
    return default_workspace()

