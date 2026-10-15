"""Qt presentation of the KEV dock (KEV-integration-plan s8, slice K3; GUI plan 8.10).

Responsibility: move the Qt-free ``panel_model`` and ``view_model`` to widgets. A catalog is read, looked up and
diffed on the task runner; the only network operation is the consented download, started by one click on Download for
the exact request shown. Results carry the controller epoch and are dropped when a project switch or shutdown has
moved it on, so a late worker can never publish. Nothing here opens a window of its own.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from . import ui_kev_model as pm
from .gui.anchors import AnchorRef, NavResult
from .gui.qt.docks import ControllerBase
from .gui.qt.labels import PlainLabel, SafeTextView
from .gui.qt.state_view import NoticeStrip, StateView
from .gui.qt.table import ROW_ROLE, VirtualTable
from .gui.registry import PanelContext
from .gui.state import NoticeModel, StateModel
from .gui.tips import apply_tip, register_gui_tips, register_tips
from .kev.contracts import KevError, KevPlan, plan_for
from .kev.service import KevService
from .kev.store import default_kev_dir
from .kev.tooltip_entries import KEV_TEMPLATES, KEV_TOOLTIPS
from .kev.view_model import (
    FILTER_ITEMS,
    FOOTER,
    SORT_ITEMS,
    SOURCE_CHOICES,
    STATE_TEXT,
    banner_text,
    changes_lines,
    consent_lines,
    detail_text,
    error_text,
    kept_text,
    mirror_older_text,
    status_line,
)

CATALOG_PAGE = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
CATALOG, ROWS, TRANSFER, CHANGES = 'kev.catalog', 'kev.rows', 'kev.transfer', 'kev.changes'
CHANNELS = (CATALOG, ROWS, TRANSFER, CHANGES)
DETAIL_LIMIT = 8_000
NO_MATCH = 'No CVEs match the selected KEV status filter.'
CANCELLED = 'Cancelled. Earlier results are unchanged.'
NO_PAIR = 'A comparison needs two stored catalogs.'
NAV_FAILURE = {
    'stale': 'This location belongs to an earlier project revision. Reload before opening it.',
    'not-found': 'This location is not present in the current run.',
    'ambiguous': 'Several locations match. Choose one to continue.',
    'blocked': 'This location is unavailable in the current project.'}
SOURCES = ('cisa-github', 'cisa-site')          # the mirror is the default until the CISA site has been accepted live
Chooser = Callable[[str, str], Path | None]


class KevTable(VirtualTable):
    """Ctrl+C copies the selected lookup (snapshot, source and CISA wording), not the visible row text."""

    copy_lookup = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_lookup.emit()
        else:
            super().keyPressEvent(event)


class KevPanel(QWidget):
    """The widgets. It holds no result: the controller feeds it."""

    action_requested = Signal(str)       # update, import, changes, copy, copy_url, goto, download, cancel_consent, cancel_op
    lookup_requested = Signal(str)
    view_changed = Signal()
    source_changed = Signal(str)
    first_shown = Signal()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.first_shown.emit()

    def __init__(self, announcer=None) -> None:
        super().__init__()
        self.setObjectName('kev.panel')
        self.buttons: dict[str, QPushButton] = {}
        self.state = StateView('kev', 'Exploitation context', announcer, text_limit=700)
        self.notices = NoticeStrip(announcer)
        self.status = PlainLabel(wrap=True, limit=400)
        self.status.setObjectName('kev.status')
        toolbar = QHBoxLayout()
        for action, text, name, tip in (
                ('update', 'Update from CISA...', 'Update KEV catalog from CISA', 'kev.update'),
                ('import', 'Import file...', 'Import KEV catalog file', 'kev.import'),
                ('changes', 'Show changes', 'Show changes since the previous catalog', 'kev.changes')):
            toolbar.addWidget(self._button(action, text, name, tip))
        toolbar.addStretch(1)
        self.consent = self._consent_box()
        self.progress = PlainLabel(wrap=True, limit=400)
        self.progress.setObjectName('kev.progress')
        self.cancel_op = self._button('cancel_op', 'Cancel', 'Cancel the KEV catalog operation')
        self.cancel_op.setObjectName('kev.btn_cancel_op')
        progress = QHBoxLayout()
        progress.addWidget(self.progress, 1)
        progress.addWidget(self.cancel_op)
        self.progress_row = QWidget()
        self.progress_row.setLayout(progress)
        progress.setContentsMargins(0, 0, 0, 0)
        self.lookup_box = QLineEdit()
        self.lookup_box.setObjectName('kev.lookup_box')
        self.lookup_box.setAccessibleName('CVE IDs to look up')
        self.lookup_box.setPlaceholderText('CVE-2024-38063, CVE-2023-4863')
        lookup = QHBoxLayout()
        lookup.addWidget(self.lookup_box, 1)
        lookup.addWidget(self._button('lookup', 'Look up', 'Look up the typed CVE IDs', 'kev.lookup_button'))
        self.filter = self._combo(FILTER_ITEMS, 'Filter CVEs by KEV status', 'kev.filter')
        self.sort = self._combo(SORT_ITEMS, 'Reading order of the CVE list', 'kev.sort')
        view = QHBoxLayout()
        view.addWidget(self.filter, 1)
        view.addWidget(self.sort, 1)
        self.table = KevTable('KEV status of the typed CVEs table')
        self.detail = SafeTextView('Exact CISA wording and source of the selected CVE', limit=DETAIL_LIMIT, wrap=True)
        self.detail.setObjectName('kev.detail')
        self.changes = SafeTextView('Changes between the two newest KEV catalogs', limit=DETAIL_LIMIT, wrap=True)
        self.changes.setObjectName('kev.changes_view')
        self.changes.hide()
        body = QSplitter(Qt.Orientation.Vertical)
        body.addWidget(self.table)
        body.addWidget(self.detail)
        body.setChildrenCollapsible(False)
        actions = QHBoxLayout()
        for action, text, name, tip in (('goto', 'Go to CVE context', 'Go to the CVE context of the selected CVE',
                                         'kev.goto'),
                                        ('copy', 'Copy', 'Copy KEV details of the selected CVE', 'kev.copy'),
                                        ('copy_url', 'Copy address', 'Copy the address of the CISA KEV catalog page',
                                         'kev.copy_url')):
            actions.addWidget(self._button(action, text, name, tip))
        self.nav_note = PlainLabel(wrap=True, limit=300)
        self.nav_note.setObjectName('kev.nav_note')
        actions.addWidget(self.nav_note, 1)
        self.footer = PlainLabel(FOOTER, wrap=True, limit=400)
        self.footer.setObjectName('kev.footer')
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        for item in (self.state, self.notices, self.status):
            root.addWidget(item)
        root.addLayout(toolbar)
        for item in (self.consent, self.progress_row):
            root.addWidget(item)
        root.addLayout(lookup)
        root.addLayout(view)
        root.addWidget(body, 1)
        root.addWidget(self.changes)
        root.addLayout(actions)
        root.addWidget(self.footer)
        for combo in (self.filter, self.sort):
            combo.view().setAccessibleName(f'{combo.accessibleName()} options')
        apply_tip(self.lookup_box, 'kev.lookup_box')
        apply_tip(self.table, 'kev.table')
        apply_tip(self.detail, 'kev.detail')
        self.lookup_box.returnPressed.connect(lambda: self.lookup_requested.emit(self.lookup_box.text()))
        self.filter.currentIndexChanged.connect(lambda _i: self.view_changed.emit())
        self.sort.currentIndexChanged.connect(lambda _i: self.view_changed.emit())
        self.table.detail_requested.connect(lambda _key: self.detail.setFocus())
        self.table.copy_lookup.connect(lambda: self.action_requested.emit('copy'))
        self.setFocusProxy(self.lookup_box)
        self.progress_row.hide()
        self.consent.hide()

    def _button(self, action: str, text: str, name: str, tip: str | None = None) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(name)
        button.setObjectName(tip or f'kev.btn_{action}')
        if tip is not None:
            apply_tip(button, tip)
        self.buttons[action] = button
        button.clicked.connect(lambda _checked=False, a=action: self._clicked(a))
        return button

    def _clicked(self, action: str) -> None:
        if action == 'lookup':
            self.lookup_requested.emit(self.lookup_box.text())
        else:
            self.action_requested.emit(action)

    @staticmethod
    def _combo(items, name: str, tip: str) -> QComboBox:
        combo = QComboBox()
        combo.setAccessibleName(name)
        for value, text in items:
            combo.addItem(text, value)
        apply_tip(combo, tip)
        return combo

    def _consent_box(self) -> QWidget:
        box = QWidget()
        box.setObjectName('kev.consent')
        column = QVBoxLayout(box)
        column.setContentsMargins(0, 0, 0, 0)
        self.consent_text = PlainLabel(wrap=True, limit=2_000, multiline=True, selectable=True)
        self.consent_text.setObjectName('kev.consent_text')
        self.consent_text.setAccessibleName('Exact KEV download request')
        column.addWidget(self.consent_text)
        row = QHBoxLayout()
        self.sources: dict[str, QRadioButton] = {}
        for source, tip in (('cisa-github', 'kev.source_mirror'), ('cisa-site', 'kev.source_cisa')):
            radio = QRadioButton(SOURCE_CHOICES[source])
            radio.setAccessibleName(f'Download source: {SOURCE_CHOICES[source]}')
            apply_tip(radio, tip)
            radio.toggled.connect(lambda on, s=source: on and self.source_changed.emit(s))
            self.sources[source] = radio
            row.addWidget(radio)
        self.sources['cisa-github'].setChecked(True)
        row.addStretch(1)
        row.addWidget(self._button('download', 'Download', 'Download the KEV catalog from CISA', 'kev.consent_download'))
        row.addWidget(self._button('cancel_consent', 'Cancel', 'Cancel without contacting CISA', 'kev.consent_cancel'))
        column.addLayout(row)
        return box


class KevController(ControllerBase):
    """Owns the catalog in use, the typed IDs and the requests in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, directory: Path | str | None = None, service: KevService | None = None,
                 network_allowed: Callable[[], bool] = lambda: True, chooser: Chooser | None = None) -> None:
        register_gui_tips()  # idempotent: the host has done it, a test or a bare embed has not
        register_tips(KEV_TOOLTIPS, KEV_TEMPLATES)
        panel = KevPanel(ctx.shell)
        super().__init__(panel)
        self.panel, self.ctx = panel, ctx
        self.port, self.tasks, self.nav, self.shell = ctx.project, ctx.tasks, ctx.nav, ctx.shell
        self.directory = directory
        self._service = service
        self.network_allowed = network_allowed
        self.chooser = chooser or self.shell.choose_file
        self.epoch = 0
        self.key = None
        self.snapshot: pm.Snapshot | None = None
        self.view: pm.KevView | None = None
        self.ids: tuple[str, ...] = ()
        self.operation = ''              # load, rows, fetch, import or ''
        self.error: tuple[str, str] | None = None
        self.partial = ''
        self.cancelled = False
        self.source = SOURCES[0]
        self.plan: KevPlan | None = None
        self.last_network = False
        self.loaded_once = False
        self._closed = False
        self._wire()
        self._render()

    # ---- wiring --------------------------------------------------------------------------------------

    def _wire(self) -> None:
        panel = self.panel
        panel.action_requested.connect(self._action)
        panel.lookup_requested.connect(self.lookup)
        panel.view_changed.connect(self._rows)
        panel.source_changed.connect(self._source_changed)
        panel.state.retry_requested.connect(self.retry)
        panel.state.refresh_requested.connect(lambda: self._action('update'))
        panel.state.copy_requested.connect(self.shell.copy_text)
        panel.table.selectionModel().currentRowChanged.connect(lambda *_: self._selection())
        panel.table.table_model.modelReset.connect(self._selection)
        panel.table.activated_key.connect(lambda _key: self.go())
        cancel = QShortcut(QKeySequence('Escape'), panel)
        cancel.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        cancel.activated.connect(lambda: self._action('cancel_op'))
        panel.first_shown.connect(self._first_shown)

    def _first_shown(self) -> None:
        if not self.loaded_once and not self._closed:
            self.reload()                   # the first show reads the folder; the factory read nothing

    def service(self) -> KevService:
        if self._service is None:
            self._service = KevService(self.directory or default_kev_dir())
        return self._service

    # ---- host hooks ----------------------------------------------------------------------------------

    def project_changed(self, key) -> None:
        self._advance()
        self.key = key
        self.operation, self.error, self.partial, self.cancelled, self.plan = '', None, '', False, None
        self.panel.consent.hide()
        self.panel.notices.project_changed()
        if self.loaded_once or self.panel.isVisible():
            self.reload()
        else:
            self._render()

    def shutdown(self) -> None:
        self._closed = True
        self._advance()

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        if anchor.kind != 'cve':
            return NavResult.blocked('Exploitation context', f'it does not open {anchor.kind} links')
        self.show_cves((anchor.key,))
        return NavResult.shown()

    def show_cves(self, cves) -> None:
        """Typed adapter for a KB or CVE view that passes its CVEs here."""
        self.panel.lookup_box.setText(' '.join(cves))
        self.lookup(self.panel.lookup_box.text())

    def _advance(self) -> None:
        self.epoch += 1
        for channel in CHANNELS:
            self.tasks.cancel(channel)

    # ---- loading -------------------------------------------------------------------------------------

    def reload(self) -> None:
        if self._closed:
            return
        self.loaded_once = True
        epoch, service = self.epoch, self.service()
        self.operation = 'load'
        self._render()
        self.tasks.submit(CATALOG, lambda token, _report: pm.load_snapshot(service, token),
                          lambda snapshot: self._loaded(epoch, snapshot), lambda failure: self._failed(epoch, failure))

    def _loaded(self, epoch: int, snapshot: pm.Snapshot) -> None:
        if epoch != self.epoch or self._closed:
            return
        self.snapshot = snapshot
        self.operation = ''
        self._rows()

    def _rows(self) -> None:
        if self._closed or self.snapshot is None:
            return
        epoch, provider, ids = self.epoch, self.snapshot.provider, self.ids
        filter_mode, sort_mode = self.panel.filter.currentData(), self.panel.sort.currentData()
        self.tasks.submit(ROWS, lambda token, _report: pm.prepare_view(provider, ids, filter_mode, sort_mode, token),
                          lambda view: self._rows_ready(epoch, view), lambda failure: self._failed(epoch, failure))
        self._render()

    def _rows_ready(self, epoch: int, view: pm.KevView) -> None:
        if epoch != self.epoch or self._closed:
            return
        self.view = view
        self.panel.table.set_prepared(view.prepared)
        self._render()

    def _failed(self, epoch: int, failure) -> None:
        if epoch != self.epoch or self._closed:
            return
        self.operation = ''
        self._set_error('checks', {'check': failure.code})
        self._render()

    def lookup(self, text: str) -> None:
        self.ids, truncated = pm.parse_ids(text)
        self.cancelled = False
        self.panel.notices.set_notice('kev.truncated', NoticeModel(
            'kev.truncated', 'caution', f'Only the first {pm.MAX_INPUT_IDS} CVE IDs are looked up.') if truncated else None)
        self._rows()

    # ---- update and import ---------------------------------------------------------------------------

    def _action(self, action: str) -> None:
        if self._closed:
            return
        {'update': self._update, 'import': self._import, 'changes': self._show_changes, 'download': self._download,
         'cancel_consent': self._cancel_consent, 'cancel_op': self._cancel_op, 'copy': self.copy,
         'copy_url': lambda: self.shell.copy_text(CATALOG_PAGE), 'goto': self.go}[action]()

    def _update(self) -> None:
        if not self.network_allowed() or self.operation in ('fetch', 'import'):
            return
        self.last_network, self.error, self.partial, self.cancelled = True, None, '', False
        self._plan(self.source)
        self.panel.consent.show()
        self.panel.buttons['download'].setFocus()
        self._render()

    def _plan(self, source: str) -> None:
        self.plan = plan_for(source)
        self.panel.consent_text.setText('\n'.join(consent_lines(self.plan)))

    def _source_changed(self, source: str) -> None:
        self.source = source
        if self.plan is not None:
            self._plan(source)           # consent covers only the request on screen

    def _cancel_consent(self) -> None:
        self.plan = None
        self.panel.consent.hide()
        self.panel.buttons['update'].setFocus()
        self.shell.announce('Nothing was sent.')
        self._render()

    def _download(self) -> None:
        plan, service, epoch = self.plan, self.service(), self.epoch
        if plan is None or not self.network_allowed():
            return
        self.plan = None
        self.panel.consent.hide()
        self.operation = 'fetch'
        self.panel.progress.setText(f'Downloading from {plan.host}...')
        self._render()

        def work(token, report):
            try:
                return service.fetch(plan.source, plan.host, surface='gui', cancel=token,
                                     announce=lambda text: report('download', 0, None, text))
            except KevError as error:
                return error

        self.tasks.submit(TRANSFER, work, lambda result: self._installed(epoch, result),
                          lambda failure: self._failed(epoch, failure),
                          lambda progress: self._progress(epoch, progress.message))

    def _import(self) -> None:
        if self.operation in ('fetch', 'import'):
            return
        path = self.chooser('Import KEV catalog file', 'KEV JSON (*.json)')
        if path is None:
            return
        self.last_network, self.error, self.partial, self.cancelled = False, None, '', False
        service, epoch = self.service(), self.epoch
        self.operation = 'import'
        self.panel.progress.setText(STATE_TEXT['checking'])
        self._render()

        def work(token, _report):
            try:
                return service.import_file(path)
            except KevError as error:
                return error

        self.tasks.submit(TRANSFER, work, lambda result: self._installed(epoch, result),
                          lambda failure: self._failed(epoch, failure))

    def _progress(self, epoch: int, message: str) -> None:
        if epoch == self.epoch and self.operation == 'fetch' and message:
            self.panel.progress.setText(message)

    def _installed(self, epoch: int, result) -> None:
        if epoch != self.epoch or self._closed:
            return
        self.operation = ''
        if isinstance(result, KevError):
            if result.code == 'PT-KEV-CANCEL':
                self.cancelled = True
            else:
                self._set_error(*pm.failure_reason(result))
            return self._render()
        if result.in_use.snapshot_id != result.meta.snapshot_id:
            self.partial = mirror_older_text(result.meta.catalog_version, result.in_use.catalog_version)
        self.reload()

    def _set_error(self, reason: str, values: dict) -> None:
        meta = self.snapshot.provider.meta if self.snapshot else None
        text = error_text(reason, kept_text(*pm.kept_line(meta)), **values)
        self.error = (text, f'{text} ({reason})')

    def _cancel_op(self) -> None:
        if self.operation not in ('fetch', 'import', 'load'):
            return
        self.tasks.cancel(TRANSFER)
        self.tasks.cancel(CATALOG)
        self.operation, self.cancelled = '', True
        self._render()

    def retry(self) -> None:
        """A failed network update asks again; it never reuses the earlier click."""
        self.error = None
        if self.last_network:
            self._update()
        else:
            self._import()

    # ---- changes -------------------------------------------------------------------------------------

    def _show_changes(self) -> None:
        view, epoch, service = self.panel.changes, self.epoch, self.service()
        if view.isVisible():
            view.hide()
            return

        def work(token, _report):
            try:
                comparison = service.diff()
            except KevError as error:
                return error
            return '\n'.join(changes_lines(comparison.delta, comparison.new, comparison.old.meta.catalog_version))

        self.tasks.submit(CHANGES, work, lambda text: self._changes_ready(epoch, text),
                          lambda failure: self._failed(epoch, failure))

    def _changes_ready(self, epoch: int, result) -> None:
        if epoch != self.epoch or self._closed:
            return
        self.panel.changes.setPlainText(NO_PAIR if isinstance(result, KevError) else result)
        self.panel.changes.show()

    # ---- selection, copy, go to ----------------------------------------------------------------------

    def current_row(self) -> pm.KevRow | None:
        index = self.panel.table.currentIndex()
        return index.data(ROW_ROLE) if index.isValid() else None

    def _selection(self) -> None:
        row, meta = self.current_row(), self.snapshot.provider.meta if self.snapshot else None
        self.panel.detail.setPlainText('' if row is None else detail_text(row.lookup, meta))
        self.panel.nav_note.setText('')
        self._enable()

    def copy(self) -> None:
        row = self.current_row()
        if row is None or self.snapshot is None:
            return
        text = f'{detail_text(row.lookup, self.snapshot.provider.meta)}\n{FOOTER}'
        self.shell.copy_text(text)
        self.shell.announce('Copied KEV details.')

    def go(self) -> None:
        row = self.current_row()
        if row is None or row.cell.state == 'invalid-id':
            return
        anchor = AnchorRef('cve', row.cell.cve, None, label=row.cell.cve, origin='kev').pinned(self.key)
        result = self.nav.navigate(anchor)
        status = getattr(result, 'status', 'blocked')
        self.panel.nav_note.setText('' if status == 'shown' else NAV_FAILURE.get(status, NAV_FAILURE['blocked']))

    # ---- rendering -----------------------------------------------------------------------------------

    def _provider_meta(self):
        return self.snapshot.provider.meta if self.snapshot else None

    def _state(self) -> tuple[StateModel, bool]:
        """The dominant state (error > cancelled > stale > partial > loading > ready/idle) and whether results stay."""
        meta, has = self._provider_meta(), self.view is not None and self.view.shown > 0
        provider = self.snapshot.provider if self.snapshot else None
        if self.error:
            return StateModel('error', self.error[0], self.error[1], ('retry', 'copy')), has
        if self.cancelled:
            return StateModel('cancelled', CANCELLED), has
        if self.operation:
            kind = 'refreshing' if self.snapshot else 'loading'
            text = self.panel.progress.full_text() if self.operation in ('fetch', 'import') else STATE_TEXT['loading']
            return StateModel(kind, text), has
        if meta is None and self.loaded_once:
            blocked = not self.network_allowed()
            return StateModel('blocked' if blocked else 'idle', STATE_TEXT['blocked' if blocked else 'no-catalog']), has
        if meta is not None and provider.freshness in ('stale', 'future'):
            return StateModel('stale', banner_text(provider.freshness, provider.age_days), '', ('refresh',)), has
        if self.partial:
            return StateModel('partial', self.partial), has
        if self.snapshot and not self.ids:
            return StateModel('idle', STATE_TEXT['empty-list']), has
        if self.view is not None and self.view.total and not self.view.shown:
            return StateModel('idle', NO_MATCH), has
        return StateModel('ready', ''), has

    def _render(self) -> None:
        panel, meta = self.panel, self._provider_meta()
        provider = self.snapshot.provider if self.snapshot else None
        model, has = self._state()
        panel.state.set_state(model, has_content=has)
        panel.status.setText('' if meta is None else status_line(meta, provider.freshness, provider.age_days))
        panel.status.setVisible(meta is not None)
        aging = banner_text('aging', provider.age_days) if meta and provider.freshness == 'aging' else None
        panel.notices.set_notice('kev.aging', NoticeModel('kev.aging', 'caution', aging) if aging else None)
        offline = meta is not None and not self.network_allowed()
        panel.notices.set_notice('kev.network', NoticeModel(
            'kev.network', 'notice', 'Network updates are switched off here. Import file still works.') if offline else None)
        busy = self.operation in ('fetch', 'import')
        panel.progress_row.setVisible(busy)
        self._enable()

    def _enable(self) -> None:
        buttons, busy = self.panel.buttons, self.operation in ('fetch', 'import')
        has_row = self.current_row() is not None
        buttons['update'].setEnabled(self.network_allowed() and not busy)
        buttons['import'].setEnabled(not busy)
        buttons['changes'].setEnabled(bool(self.snapshot and self.snapshot.snapshots >= 2))
        buttons['copy'].setEnabled(has_row)
        buttons['goto'].setEnabled(has_row and self.current_row().cell.state != 'invalid-id')
        buttons['download'].setEnabled(self.plan is not None and self.network_allowed())
