"""Qt presentation of the Capabilities dock (CAP-6a stored changes, CAP-6b local setup, probe and run).

Everything that decides what is said lives in the Qt-free `capa_view`, `capa_data` and `capa_exec`; this module moves
it to widgets. The project database belongs to the GUI thread, so the GUI thread reads the stored evidence and stores
run results, while workers get immutable values (the stored evidence to assemble, the run spec to execute). Every
request carries the project key and an epoch; a result is applied only when both still match. Nothing runs or
reaches the network without an explicit click, and a run needs a previewed, confirmed operation.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...enrichment.contracts import EnrichmentError
from ...gui.anchors import AnchorRef, NavResult
from ...gui.qt.docks import ControllerBase
from ...gui.qt.labels import PlainLabel, SafeTextView, labelled
from ...gui.qt.state_view import StateView
from ...gui.qt.table import ROW_ROLE, VirtualTable
from ...gui.registry import PanelContext
from ...gui.state import StateModel
from ...gui.table_spec import prepare_table
from ...gui.text import sanitize_text
from ...gui.tips import apply_tip, escaped_tip, gui_tips, register_tips
from . import capa_data, capa_exec
from .capa_view import (
    FILTERS,
    FOOTER,
    GROUPINGS,
    Arrangement,
    StateInputs,
    ViewOptions,
    flags_banner,
    resolve_state,
)
from .common import ToolError, ToolManifest
from .runner import ArtifactRef
from .tooltip_entries import TEMPLATES, TIPS

LOAD, ROWS, PROBE, RUN = 'capabilities-load', 'capabilities-rows', 'capabilities-probe', 'capabilities-run'
CHANNELS = (LOAD, ROWS, PROBE, RUN)
LOG_LIMIT = 4_000
READ_ERRORS = (ToolError, EnrichmentError, sqlite3.Error, OSError)
KINDS = {'C0': 'no-project', 'C1': 'blocked', 'C2': 'idle', 'C3': 'loading', 'C4': 'ready', 'C5': 'partial',
         'C6': 'error', 'C7': 'stale', 'C8': 'partial', 'C9': 'ready', 'C10': 'blocked', 'C11': 'too-large',
         'C12': 'partial', 'C13': 'stale'}
ACTIONS = {'C1': ('setup',), 'C2': ('setup',), 'C4': ('refresh',), 'C5': ('setup',), 'C6': ('retry', 'copy'),
           'C7': ('refresh', 'setup'), 'C10': ('setup',), 'C13': ('refresh',)}
TAB_CHANGES, TAB_SETUP = 0, 1
REFRESHING = 'Refreshing capability observations...'
CANCELLED = 'Cancelled. Earlier results are unchanged.'
TRUNCATED = 'The capa output was cut by a size limit. The list is incomplete.'
SETTING_ENUMS = {'filter': tuple(v for v, _t in FILTERS), 'group_by': tuple(v for v, _t in GROUPINGS)}
Loader = Callable[[object, object], capa_data.Stored]
Assembler = Callable[..., capa_data.Assembled]
Preparer = Callable[..., tuple[Arrangement, object]]
Prober = Callable[[str, str, int, object], ToolManifest]
Runner = Callable[[capa_exec.RunSpec, ToolManifest, object, Callable], list]
Publisher = Callable[[object, object, list], list]


@dataclass(frozen=True, slots=True)
class Request:
    """What a result must still match to be applied."""
    epoch: int
    key: object


@dataclass(frozen=True, slots=True)
class Built:
    request: Request
    assembled: capa_data.Assembled | None
    arrangement: Arrangement | None
    prepared: object | None


class ChangesTable(VirtualTable):
    """The shared table plus Ctrl+C for the provenance of the row (not the row text)."""

    provenance_copy = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802 (Qt name)
        if event.matches(QKeySequence.StandardKey.Copy):
            self.provenance_copy.emit()
        else:
            super().keyPressEvent(event)


def _button(text: str, name: str, tip: str) -> QPushButton:
    button = QPushButton(text)
    button.setAccessibleName(name)
    button.setObjectName(tip)
    apply_tip(button, tip)
    return button


def _tipped(widget: QWidget, tip: str, name: str) -> QWidget:
    widget.setObjectName(tip)
    widget.setAccessibleName(name)
    apply_tip(widget, tip)
    return widget


class ChangesPage(QWidget):
    """The Changes tab: state strip, filters, table, detail and the fixed footer."""

    def __init__(self, ctx: PanelContext) -> None:
        super().__init__()
        self.state = StateView('capabilities', 'Capabilities', ctx.shell, text_limit=600)
        self.banner = PlainLabel(wrap=True, limit=1_200, multiline=True)
        self.banner.setObjectName('capabilities.banner')
        self.filter, self.group = QComboBox(), QComboBox()
        for combo, items, tip, name in ((self.filter, FILTERS, 'capabilities.filter', 'Filter capability changes'),
                                        (self.group, GROUPINGS, 'capabilities.group_by',
                                         'Group capability changes by')):
            for value, text in items:
                combo.addItem(text, value)
            _tipped(combo, tip, name)
            combo.view().setAccessibleName(f'{name} options')
        self.search = _tipped(QLineEdit(), 'capabilities.search', 'Search capabilities by rule, namespace or function')
        self.search.setPlaceholderText('Rule, namespace or function')
        self.noise = _tipped(QCheckBox('Detection differences'), 'capabilities.show_noise',
                             'Show detection differences')
        self.unattributed = _tipped(QCheckBox('Unattributed'), 'capabilities.show_unattributed',
                                    'Show unattributed capa matches')
        self.library = _tipped(QCheckBox('Building-block rules'), 'capabilities.show_library',
                               'Show building-block rules')
        self.refresh = _button('Refresh', 'Refresh capability observations', 'capabilities.refresh')
        self.cancel = _button('Cancel', 'Cancel the running capa operation', 'capabilities.cancel')
        self.table = _tipped(ChangesTable('Capability changes by function pair'), 'capabilities.table',
                             'Capability changes by function pair')
        self.detail = SafeTextView('Selected capability change details', wrap=True, limit=8_192)
        _tipped(self.detail, 'capabilities.detail', 'Selected capability change details')
        self.unattributed_lines = PlainLabel(wrap=True, limit=4_000, multiline=True)
        self.unattributed_lines.setObjectName('capabilities.unattributed_lines')
        self.goto = _button('Go to pair', 'Go to selected function pair in the navigator', 'capabilities.goto')
        self.copy = _button('Copy provenance', 'Copy provenance of selected capability change', 'capabilities.copy')
        self.footer = PlainLabel(FOOTER, wrap=True, limit=600)
        self.footer.setObjectName('capabilities.footer')
        self.content = QWidget()
        column = QVBoxLayout(self.content)
        column.setContentsMargins(0, 0, 0, 0)
        for row in ((self.filter, self.group), (self.search,), (self.noise, self.unattributed, self.library)):
            layout = QHBoxLayout()
            for widget in row:
                layout.addWidget(widget, 1 if widget is self.search else 0)
            column.addLayout(layout)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        split.addWidget(self.detail)
        split.setChildrenCollapsible(False)
        column.addWidget(self.banner)
        column.addWidget(split, 1)
        column.addWidget(self.unattributed_lines)
        actions = QHBoxLayout()
        for button in (self.goto, self.copy):
            actions.addWidget(button)
        actions.addStretch(1)
        column.addLayout(actions)
        column.addWidget(self.footer)
        self.state.set_content(self.content)
        head = QHBoxLayout()
        head.addStretch(1)
        head.addWidget(self.refresh)
        head.addWidget(self.cancel)
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.addLayout(head)
        root.addWidget(self.state, 1)
        self.setFocusProxy(self.table)


class SetupPage(QWidget):
    """The Setup and run tab: choose, probe, preview and confirm. Nothing here starts a program by itself."""

    def __init__(self) -> None:
        super().__init__()
        self.path = _tipped(QLineEdit(), 'capabilities.path', 'capa executable path')
        self.path.setPlaceholderText('Absolute path of an installed capa')
        self.browse = _button('Browse...', 'Browse for the capa executable', 'capabilities.browse')
        self.probe = _button('Probe', 'Probe the chosen capa', 'capabilities.probe')
        self.backend = QComboBox()
        for backend in capa_exec.BACKENDS:
            self.backend.addItem(backend, backend)
        _tipped(self.backend, 'capabilities.backend', 'capa backend')
        self.backend.view().setAccessibleName('capa backend options')
        self.timeout = QSpinBox()
        self.timeout.setRange(*capa_exec.TIMEOUT_RANGE)
        self.timeout.setSuffix(' s')
        _tipped(self.timeout, 'capabilities.timeout', 'Time limit per file in seconds')
        self.run = _button('Run...', 'Prepare a capa run for review', 'capabilities.run')
        self.confirm = _button('Confirm and run', 'Confirm the shown capa run', 'capabilities.confirm_run')
        self.cancel_preview = _button('Cancel preview', 'Close the run preview', 'capabilities.cancel_preview')
        self.status = PlainLabel(wrap=True, limit=600)
        self.status.setObjectName('capabilities.setup_status')
        self.preview = SafeTextView('Run preview', wrap=True, limit=4_000)
        _tipped(self.preview, 'capabilities.preview', 'Run preview')
        self.log = SafeTextView('Probe and run log', wrap=True, limit=LOG_LIMIT)
        _tipped(self.log, 'capabilities.log', 'Probe and run log')
        form = QVBoxLayout(self)
        form.setContentsMargins(4, 4, 4, 4)
        for caption, field, extra in (('capa path', self.path, (self.browse, self.probe)),
                                      ('capa backend', self.backend, ()), ('Time limit per file', self.timeout, ())):
            row = QHBoxLayout()
            row.addWidget(labelled(field, caption, self))
            row.addWidget(field, 1)
            for widget in extra:
                row.addWidget(widget)
            form.addLayout(row)
        form.addWidget(self.status)
        buttons = QHBoxLayout()
        for widget in (self.run, self.confirm, self.cancel_preview):
            buttons.addWidget(widget)
        buttons.addStretch(1)
        form.addLayout(buttons)
        form.addWidget(self.preview, 1)
        form.addWidget(self.log, 1)
        self.setFocusProxy(self.path)


class CapabilitiesPanel(QWidget):
    """The widgets only; the controller feeds them."""

    def __init__(self, ctx: PanelContext) -> None:
        super().__init__()
        self.setObjectName('capabilities.panel')
        self.changes, self.setup = ChangesPage(ctx), SetupPage()
        self.tabs = QTabWidget()
        self.tabs.addTab(self.changes, 'Changes')
        self.tabs.addTab(self.setup, 'Setup and run')
        _tipped(self.tabs, 'capabilities.tabs', 'Capability views')
        self.tabs.tabBar().setAccessibleName('Capability view tabs')
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(self.tabs)
        self.setFocusProxy(self.tabs)
        escape = QShortcut(QKeySequence('Escape'), self.setup.preview)
        escape.setContext(Qt.ShortcutContext.WidgetShortcut)
        self.preview_escape = escape


class CapabilitiesController(ControllerBase):
    """Owns the loaded result and the requests in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, loader: Loader = capa_data.read_stored,
                 assembler: Assembler = capa_data.assemble, preparer: Preparer = capa_data.prepare,
                 prober: Prober = capa_exec.probe_tool, runner: Runner = capa_exec.run_sides,
                 publisher: Publisher = capa_exec.publish) -> None:
        register_tips({**gui_tips(), **TIPS}, TEMPLATES)
        panel = CapabilitiesPanel(ctx)
        super().__init__(panel)
        self.panel, self.ctx, self.port, self.tasks = panel, ctx, ctx.project, ctx.tasks
        self.loader, self.assembler, self.preparer = loader, assembler, preparer
        self.prober, self.runner, self.publisher = prober, runner, publisher
        self.key = None
        self.epoch = 0
        self.closed = False
        self.stored: capa_data.Stored | None = None
        self.built: Built | None = None
        self.loaded_key = None
        self.options = ViewOptions()
        self.error: tuple[str, str] | None = None
        self.running: tuple[str, int] | None = None
        self.reading = False
        self.cancelled = False
        self.failed_side: tuple[str, str] | None = None
        self.manifest: ToolManifest | None = None
        self.spec: capa_exec.RunSpec | None = None
        self.too_many: int | None = None
        self.state_id = ''
        self.goto_tip = panel.changes.goto.toolTip()
        self._restore_settings()
        self._wire()
        self._render()

    # ---- settings -----------------------------------------------------------------------------------------
    def _settings(self):
        settings = self.ctx.settings
        return settings if hasattr(settings, 'get_enum') else None

    def _restore_settings(self) -> None:
        panel, store = self.panel, self._settings()
        if store is None:
            panel.setup.timeout.setValue(capa_exec.DEFAULT_TIMEOUT)
            return
        self.options = ViewOptions(
            store.get_enum('filter', 'changes', SETTING_ENUMS['filter']),
            store.get_enum('group_by', 'namespace', SETTING_ENUMS['group_by']), '',
            store.get_bool('show_noise', False), store.get_bool('show_unattributed', False),
            store.get_bool('show_library', False))
        page = panel.changes
        for combo, value in ((page.filter, self.options.filter), (page.group, self.options.group_by)):
            combo.setCurrentIndex(max(0, combo.findData(value)))
        for box, value in ((page.noise, self.options.show_noise), (page.unattributed, self.options.show_unattributed),
                           (page.library, self.options.show_library)):
            box.setChecked(value)
        setup = panel.setup
        setup.path.setText(store.get_text('tool/path', '', capa_exec.PATH_LIMIT))
        setup.backend.setCurrentIndex(max(0, setup.backend.findData(
            store.get_enum('backend', 'vivisect', capa_exec.BACKENDS))))
        setup.timeout.setValue(store.get_int('timeout', capa_exec.DEFAULT_TIMEOUT, *capa_exec.TIMEOUT_RANGE))
        panel.tabs.setCurrentIndex(TAB_SETUP if store.get_enum('tab', 'changes', ('changes', 'setup')) == 'setup'
                                   else TAB_CHANGES)

    def _remember(self, name: str, value) -> None:
        store = self._settings()
        if store is not None:
            store.set(name, value)

    # ---- wiring -------------------------------------------------------------------------------------------
    def _wire(self) -> None:
        panel, page, setup = self.panel, self.panel.changes, self.panel.setup
        page.filter.currentIndexChanged.connect(lambda _i: self._options_changed('filter', page.filter.currentData()))
        page.group.currentIndexChanged.connect(lambda _i: self._options_changed('group_by', page.group.currentData()))
        for box, name in ((page.noise, 'show_noise'), (page.unattributed, 'show_unattributed'),
                          (page.library, 'show_library')):
            box.toggled.connect(lambda checked, n=name: self._options_changed(n, checked))
        page.search.textChanged.connect(self._search_changed)
        page.refresh.clicked.connect(self.refresh)
        page.cancel.clicked.connect(self.cancel)
        page.goto.clicked.connect(self.go)
        page.copy.clicked.connect(self.copy_provenance)
        page.table.activated_key.connect(lambda _key: self.go())
        page.table.provenance_copy.connect(self.copy_provenance)
        page.table.detail_requested.connect(lambda _key: page.detail.setFocus())
        page.table.selectionModel().currentRowChanged.connect(lambda *_: self._selection_changed())
        page.table.table_model.modelReset.connect(self._selection_changed)
        page.state.retry_requested.connect(self.retry)
        page.state.refresh_requested.connect(self.refresh)
        page.state.setup_requested.connect(lambda: panel.tabs.setCurrentIndex(TAB_SETUP))
        page.state.copy_requested.connect(lambda text: self.ctx.shell.copy_text(sanitize_text(text, 600)))
        panel.tabs.currentChanged.connect(lambda i: self._remember('tab', 'setup' if i == TAB_SETUP else 'changes'))
        setup.path.textChanged.connect(self._path_changed)
        setup.browse.clicked.connect(self.browse)
        setup.probe.clicked.connect(self.probe)
        setup.backend.currentIndexChanged.connect(lambda _i: self._setup_changed('backend'))
        setup.timeout.valueChanged.connect(lambda _v: self._setup_changed('timeout'))
        setup.run.clicked.connect(self.preview)
        setup.confirm.clicked.connect(self.confirm_run)
        setup.cancel_preview.clicked.connect(self.cancel_preview)
        panel.preview_escape.activated.connect(self.cancel_preview)

    # ---- host hooks ---------------------------------------------------------------------------------------
    def project_changed(self, key) -> None:
        self._cancel_all()
        same = key is not None and self.key is not None and key.identity() == self.key.identity()
        self.epoch += 1
        self.key = key
        self.error = self.running = self.failed_side = self.too_many = None
        self.reading = self.cancelled = False
        self.spec = None
        if not same or key is None:
            self.stored = self.built = self.loaded_key = None
            self._show_rows(None)
        self._render()
        if key is not None:
            self.reload()

    def busy_changed(self, busy: bool) -> None:
        self._enable()

    def shutdown(self) -> None:
        self.closed = True
        self.epoch += 1
        self._cancel_all()

    def _cancel_all(self) -> None:
        for channel in CHANNELS:
            self.tasks.cancel(channel)

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        if anchor.kind != 'capability':
            return NavResult.blocked('Capabilities', f'it does not open {anchor.kind} links')
        if self.built is None or self.built.arrangement is None:
            return NavResult.blocked('Capabilities', 'no capability comparison is loaded')
        table = self.panel.changes.table
        for view_row in range(table.table_model.rowCount()):
            row = table.table_model.row_at(view_row).row
            if anchor.key in (row.change.change_id, row.change.observation_key):
                table.selectRow(view_row)
                return NavResult.shown()
        return NavResult.not_found(anchor.label or anchor.key, anchor.run_id)

    # ---- loading ------------------------------------------------------------------------------------------
    def request(self) -> Request:
        return Request(self.epoch, self.key)

    def current(self, request: Request) -> bool:
        return not self.closed and request.epoch == self.epoch and request.key == self.key

    def reload(self) -> None:
        """GUI thread: read the stored evidence (it owns the connection); the view is built in a worker."""
        service, project = getattr(self.port, 'service', None), self.port.project()
        if service is None or project is None:
            return self._render()
        self.reading, self.error, self.cancelled = True, None, False
        try:
            self.stored = self.loader(service, project)
        except READ_ERRORS as exc:
            self.reading = False
            self.error = (getattr(exc, 'code', 'PT-TOOL-STORE'), getattr(exc, 'message', 'The stored data could not be read'))
            return self._render()
        self._assemble()

    def _assemble(self) -> None:
        stored, options, request = self.stored, self.options, self.request()
        unchanged = capa_data.needs_unchanged(options)
        if stored is None or not capa_data.has_results(stored) or capa_data.missing_side(stored):
            self.reading = False
            self.built = Built(request, None, None, None)
            self._show_rows(None)
            return self._render()
        self._render()
        assembler, preparer = self.assembler, self.preparer

        def work(token, _report):
            assembled = assembler(stored, unchanged, token)
            arrangement, prepared = preparer(assembled.view, options, token)
            return Built(request, assembled, arrangement, prepared)
        self.tasks.submit(LOAD, work, self._built, self._failed)

    def _built(self, built: Built) -> None:
        if not self.current(built.request):
            return
        self.reading = False
        self.built, self.loaded_key = built, built.request.key
        self._show_rows(built)
        self._render()

    def _failed(self, failure) -> None:
        self.reading = False
        self.running = None
        code = getattr(failure, 'code', 'PT-GUI-TASK')
        self.error = (code, f'{getattr(failure, "exception_class", "an error")} stopped the work')
        self._render()

    def _show_rows(self, built: Built | None) -> None:
        table = self.panel.changes.table
        if built is None or built.prepared is None:
            self.too_many = None
            table.set_prepared(prepare_table(capa_data.SPEC, capa_data.COLUMNS, ()))
        else:
            self.too_many = built.arrangement.too_many
            table.set_prepared(built.prepared)
        self._show_unattributed()

    def _show_unattributed(self) -> None:
        view = self._view()
        lines = view.unattributed_lines(self.options.search) if view and self.options.show_unattributed else ()
        label = self.panel.changes.unattributed_lines
        label.setText('Unattributed (not tied to a function):\n' + '\n'.join(lines) if lines else '')
        label.setVisible(bool(lines))

    # ---- options ------------------------------------------------------------------------------------------
    def _options_changed(self, name: str, value) -> None:
        self._remember(name, value)
        self.options = replace(self.options, **{name: value})
        self._rebuild()

    def _search_changed(self, text: str) -> None:
        self.options = replace(self.options, search=text)
        self.panel.changes.table.set_filter(text)
        self._show_unattributed()

    def _rebuild(self) -> None:
        built = self.built
        if built is None or built.assembled is None:
            return
        if capa_data.needs_unchanged(self.options) and not built.assembled.unchanged:
            return self._assemble()
        view, options, request, preparer = built.assembled.view, self.options, self.request(), self.preparer

        def work(token, _report):
            arrangement, prepared = preparer(view, options, token)
            return Built(request, built.assembled, arrangement, prepared)
        self.tasks.submit(ROWS, work, self._built, self._failed)

    # ---- selection and the detail -------------------------------------------------------------------------
    def current_row(self):
        index = self.panel.changes.table.currentIndex()
        flat = index.data(ROW_ROLE) if index.isValid() else None
        return flat.row if flat is not None else None

    def _view(self):
        return self.built.assembled.view if self.built and self.built.assembled else None

    def _selection_changed(self) -> None:
        row, view = self.current_row(), self._view()
        self.panel.changes.detail.setPlainText(view.detail(row) if row is not None and view is not None else '')
        self._enable()

    def _goto_reason(self, row) -> str | None:
        if row is None:
            return 'Select a row first.'
        if not row.change.match_id:
            return 'This row has no single stored match, so there is no pair to show.'
        return None

    def go(self) -> None:
        row = self.current_row()
        reason = self._goto_reason(row)
        if reason is not None:
            return self.ctx.announce(reason)
        anchor = AnchorRef('match', row.change.match_id, 'both', None, row.rule, 'capabilities').pinned(self.key)
        result = self.ctx.nav.navigate(anchor)
        if getattr(result, 'status', 'shown') != 'shown':
            self.ctx.announce(getattr(result, 'message', '') or 'This location is unavailable.')

    def copy_provenance(self) -> None:
        row, view = self.current_row(), self._view()
        if row is not None and view is not None:
            self.ctx.shell.copy_text(view.provenance_text(row))

    # ---- actions ------------------------------------------------------------------------------------------
    def refresh(self) -> None:
        if self.key is not None and not self.tasks.busy(RUN):
            self.reload()

    def retry(self) -> None:
        self.error = None
        self.reload()

    def cancel(self) -> None:
        had = self.running is not None or self.reading
        for channel in (LOAD, ROWS, RUN):
            self.tasks.cancel(channel)
        self.running = None
        self.reading = False
        self.cancelled = had
        self._render()

    # ---- setup, probe and run (CAP-6b) --------------------------------------------------------------------
    def _log(self, text: str) -> None:
        self.panel.setup.log.setPlainText(text)

    def _path_changed(self, _text: str) -> None:
        self._invalidate()
        self.manifest = None
        self._render()

    def _setup_changed(self, name: str) -> None:
        setup = self.panel.setup
        self._remember(name, setup.backend.currentData() if name == 'backend' else setup.timeout.value())
        self._invalidate()
        self._enable()

    def _invalidate(self) -> None:
        self.spec = None
        self.panel.setup.preview.setPlainText('')
        self._enable()

    def browse(self) -> None:
        chosen = self.ctx.shell.choose_file('Choose capa', '')
        if chosen is None:
            return
        text = str(chosen)
        problem = capa_exec.path_error(text)
        if problem:
            return self._status(problem)
        self.panel.setup.path.setText(text)

    def _status(self, text: str) -> None:
        self.panel.setup.status.setText(text)

    def probe(self) -> None:
        setup = self.panel.setup
        exe, problem = setup.path.text().strip(), capa_exec.path_error(setup.path.text().strip())
        if problem:
            return self._status(problem)
        backend, timeout, request, prober = setup.backend.currentData(), setup.timeout.value(), self.request(), self.prober
        self._status('Probing...')
        self._enable()

        def done(manifest: ToolManifest) -> None:
            if not self.current(request):
                return
            self.manifest = manifest
            self._probed(exe, manifest)
        self.tasks.submit(PROBE, lambda token, _report: prober(exe, backend, timeout, token), done, self._probe_failed)

    def _probed(self, exe: str, manifest: ToolManifest) -> None:
        if manifest.supported:
            self._remember('tool/path', exe)
            self._status('capa can be used.')
            self._log(f'capa {manifest.version}, executable sha256 {manifest.executable_sha256}, '
                      f'{manifest.rules_source} rules, backend {manifest.backend or "default"}')
        else:
            self._status(f'The configured capa cannot be used: {sanitize_text(manifest.reason or "unknown", 200)}.')
            self._log(sanitize_text(manifest.reason or '', LOG_LIMIT))
        self._render()

    def _probe_failed(self, failure) -> None:
        self.manifest = None
        self._status(f'The probe stopped: {getattr(failure, "exception_class", "an error")}.')
        self._render()

    def _artifacts(self) -> tuple[ArtifactRef, ArtifactRef] | None:
        try:
            older, newer, older_sha, newer_sha = self.port.artifact_paths()
            return (ArtifactRef('older', Path(older), older_sha, Path(older).stat().st_size),
                    ArtifactRef('newer', Path(newer), newer_sha, Path(newer).stat().st_size))
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def _run_reason(self) -> str | None:
        setup = self.panel.setup
        if self.key is None:
            return 'Open a project first.'
        if self.tasks.busy(RUN) or self.tasks.busy(PROBE):
            return 'Another capa operation is running.'
        return capa_exec.usable(self.manifest, setup.path.text().strip(), setup.backend.currentData())

    def preview(self) -> None:
        reason = self._run_reason()
        if reason:
            return self._status(reason)
        artifacts = self._artifacts()
        if artifacts is None or artifacts[0].sha256 == artifacts[1].sha256:
            return self._status('The project needs two readable, different files before capa can be run.')
        setup, service = self.panel.setup, getattr(self.port, 'service', None)
        root = str(getattr(service, 'root', '') or '')
        if not root:
            return self._status('The project folder is not available.')
        self.spec = capa_exec.RunSpec(root, setup.path.text().strip(), setup.backend.currentData(),
                                      setup.timeout.value(), artifacts)
        setup.preview.setPlainText(capa_exec.preview_text(self.spec, self.manifest))
        self._status('Review the preview, then confirm. Nothing has started.')
        setup.preview.setFocus()
        self._enable()

    def cancel_preview(self) -> None:
        self._invalidate()
        self._status('Preview closed. Nothing was started.')

    def confirm_run(self) -> None:
        spec, manifest = self.spec, self.manifest
        if spec is None or manifest is None or self._run_reason():
            return
        self.spec = None
        self.panel.setup.preview.setPlainText('')
        self.running, self.failed_side, self.error, self.cancelled = ('older', 1), None, None, False
        request, runner = self.request(), self.runner
        self.tasks.submit(RUN, lambda token, report: runner(spec, manifest, token, report),
                          lambda results: self._ran(request, results), self._failed, self._run_progress)
        self._render()

    def _run_progress(self, progress) -> None:
        side = progress.stage if progress.stage in capa_exec.SIDES else 'older'
        self.running = (side, max(1, min(2, progress.done)))
        self._render()

    def _ran(self, request: Request, results: list) -> None:
        if not self.current(request):
            return
        self.running = None
        service, project = getattr(self.port, 'service', None), self.port.project()
        if service is None or project is None:
            return self._render()
        try:
            failed = self.publisher(service, project, results)
        except READ_ERRORS as exc:
            self.error = (getattr(exc, 'code', 'PT-TOOL-STORE'), getattr(exc, 'message', 'The results could not be stored'))
            return self._render()
        if failed:
            side, run = failed[0].run.side, failed[0].run
            self.failed_side = (side, run.error or run.status)
            self._log('\n'.join(f'{r.run.side}: {r.run.status} {r.run.error or ""}'.strip() for r in failed))
        self.reload()

    # ---- rendering ----------------------------------------------------------------------------------------
    def _inputs(self) -> StateInputs:
        built = self.built
        delta = built.assembled.delta if built and built.assembled else None
        stale = bool(self.loaded_key is not None and self.key is not None and self.loaded_key != self.key and delta)
        stored = self.stored
        half = capa_data.missing_side(stored) if stored else None
        return StateInputs(
            project_open=self.key is not None, running=self.running, assembly_error=self.error, stale=stale,
            failed_side=self.failed_side or ((half, 'no completed result') if half else None),
            tool_reason=(self.manifest.reason or 'unusable') if self.manifest and not self.manifest.supported
            else None, tool_configured=bool(self.panel.setup.path.text().strip()),
            has_results=capa_data.has_results(stored), delta=delta, too_many=self.too_many)

    def _render(self) -> None:
        delta = self.built.assembled.delta if self.built and self.built.assembled else None
        state, banner = self.panel.changes.state, []
        if self.cancelled and self.error is None and self.running is None:
            sid, model, content = 'cancelled', StateModel('cancelled', CANCELLED, '', ('refresh',)), True
        elif self.reading and self.built is None and self.running is None:
            sid, model, content = 'refreshing', StateModel('loading', REFRESHING), False
        else:
            view_state = resolve_state(self._inputs())
            sid, content = view_state.id, view_state.table
            refreshing = self.reading and content
            model = StateModel(
                'refreshing' if refreshing else KINDS[sid], REFRESHING if refreshing else view_state.text,
                f'{self.error[0]}: {self.error[1]}' if sid == 'C6' and self.error else '', ACTIONS.get(sid, ()))
            banner = [view_state.banner] if view_state.banner else []
            if delta is not None and delta.truncated and not banner and content:
                banner = [TRUNCATED]
        if delta is not None and flags_banner(delta):
            banner.append(flags_banner(delta))
        state.set_state(model, has_content=content and self.built is not None)
        page = self.panel.changes
        page.banner.setText('\n'.join(banner))
        page.banner.setVisible(bool(banner))
        self.state_id = sid
        self._enable()

    def _enable(self) -> None:
        page, setup = self.panel.changes, self.panel.setup
        row = self.current_row()
        reason = self._goto_reason(row)
        page.goto.setEnabled(reason is None)
        page.goto.setToolTip(self.goto_tip if reason is None else escaped_tip(reason))
        page.copy.setEnabled(row is not None)
        working = self.running is not None or self.reading
        page.cancel.setVisible(working)
        page.refresh.setEnabled(self.key is not None and self.running is None)
        occupied = self.tasks.busy(RUN) or self.tasks.busy(PROBE)
        for widget in (setup.browse, setup.probe, setup.path, setup.backend, setup.timeout):
            widget.setEnabled(not occupied)
        setup.probe.setEnabled(not occupied and capa_exec.path_error(setup.path.text().strip()) is None)
        run_reason = self._run_reason()
        setup.run.setEnabled(run_reason is None)
        setup.confirm.setEnabled(self.spec is not None and run_reason is None)
        setup.cancel_preview.setEnabled(self.spec is not None)
