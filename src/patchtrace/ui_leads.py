"""Qt presentation of the Leads dock (PIL-integration-plan.md s8, slice C2; GUI plan 8.10, step M-leads).

Responsibility: render a stored `PilotAssessment` as a ranked, explained list and let the analyst move from a lead to
the code, pin, dismiss or annotate it. Everything that decides what is said lives in the Qt-free
`pilot.read_model`; this module moves it to widgets. The project database belongs to the GUI thread (a project is
locked to one writer and its connection is thread-bound), so the GUI thread reads the stored pointer rows and
review events, collects the inputs of a new run and stores its result; workers only get immutable snapshots (the
assessment to turn into rows, the evidence to rank, the matches to resolve). A request per runner channel drops late
results, and the dock never opens a window of its own.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QKeyEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from .enrichment.contracts import EnrichmentError
from .enrichment.storage import EnrichmentStore
from .gui.anchors import ANCHOR_KINDS, AnchorRef, NavResult
from .gui.qt.chips import ChipLabel
from .gui.qt.docks import ControllerBase
from .gui.qt.labels import PlainLabel, SafeTextView
from .gui.qt.table import ROW_ROLE, VirtualTable
from .gui.qt.tasks import CancelToken
from .gui.registry import PanelContext
from .gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from .gui.text import sanitize_text
from .gui.tips import apply_tip, escaped_tip, register_tips
from .pilot import review, store
from .pilot.limits import PilotError
from .pilot.panel import TEMPLATES, TIPS
from .pilot.read_model import (
    CLASS_FILTER,
    LeadRow,
    LeadsModel,
    ObservationRow,
    Presentation,
    channel_chips,
    present,
)
from .pilot.why import FOOTER

DETAIL_LIMIT = 16_384
NOTE_LIMIT = 2_048
Loader = Callable[[object, object], 'Stored']
Collector = Callable[[object, object], object]
Ranker = Callable[[object, object, Callable], object]
Publisher = Callable[[object, object, object], None]
Resolver = Callable[[Path, 'Snapshot', object], Mapping[str, str]]

LEAD_COLUMNS = (
    ColumnSpec('rank', '#', lambda r: r.rank, width_em=7, accessible=lambda r: r.accessible),
    ColumnSpec('lead', 'Lead', lambda r: r.name, width_em=26),
    ColumnSpec('class', 'Class', lambda r: r.badge, width_em=20),
    ColumnSpec('expected', 'Expected changes seen', lambda r: r.expected, width_em=10),
    ColumnSpec('channels', 'Channels', lambda r: r.channels, width_em=28),
    ColumnSpec('pairing', 'Pairing', lambda r: r.pairing, width_em=16),
    ColumnSpec('flags', 'Flags', lambda r: r.flags, width_em=24))
LEAD_SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: r.search)
OBS_COLUMNS = (
    ColumnSpec('standing', 'Standing', lambda r: r.standing, width_em=10),
    ColumnSpec('kind', 'Evidence', lambda r: r.kind, width_em=22),
    ColumnSpec('role', 'Role', lambda r: r.role, width_em=18),
    ColumnSpec('verification', 'How it is known', lambda r: r.verification, width_em=20),
    ColumnSpec('origin', 'Source', lambda r: r.origin, width_em=22),
    ColumnSpec('detail', 'Detail', lambda r: r.detail, width_em=40))
OBS_SPEC = TableSpec(row_key=lambda r: r.obs_id, search_text=lambda r: r.detail)
_FIRST = object()  # no context chosen yet: the first of the list (a CVE when there is one)


@dataclass(frozen=True, slots=True)
class Stored:
    """What the GUI thread read: the newest verifying result and the folded review events."""
    loaded: store.Loaded
    reviews: Mapping


@dataclass(frozen=True, slots=True)
class Snapshot:
    """What a worker may read of the project: its two artifacts and the comparison rows of the completed run."""
    artifacts: tuple
    matches: tuple
    run_id: str | None


def snapshot_of(project) -> Snapshot:
    run = store.completed_run(project)
    rows = tuple(m for m in project.matches if run is not None and m.run_id == run.id)
    return Snapshot(tuple(project.artifacts), rows, run.id if run else None)


def load_stored(service, project) -> Stored:
    """GUI thread: the stored result and the review events (both read the project database)."""
    enrichment = EnrichmentStore(service.store)
    loaded = store.load(enrichment, known_inputs(project))
    return Stored(loaded, review.fold(review.read(enrichment).events))


def known_inputs(project) -> dict[str, object]:
    """What can be told about a result's inputs without recomputing it (the pair and the analysis run)."""
    sides = {a.side: a.sha256 for a in project.artifacts}
    run = store.completed_run(project)
    return {'older_sha256': sides.get('older'), 'newer_sha256': sides.get('newer'),
            'ghidriff_run_id': run.id if run else None, 'raw_sha256': run.raw_sha256 if run else None}


def collect_inputs(service, cancel):
    """GUI thread: gather the evidence of a new run from what the project stores (A's `pilot.collect`)."""
    from .pilot.collect import collect
    return collect(service, EnrichmentStore(service.store), cancel=cancel)


def rank_inputs(collected, cancel, report):
    """Worker: rank the collected evidence. It reads only the immutable inputs it was handed."""
    from .pilot import keys
    from .pilot.service import localize
    report('ranking', 1, 3)
    return localize(collected, keys.default_config(), cancel)


def publish_result(service, assessment, _cancel) -> None:
    """GUI thread: store the result as the newest one of the project."""
    from .pilot import keys
    store.publish(EnrichmentStore(service.store), assessment, keys.default_config(),
                  current=store.current_guard(service.project, assessment.result_id))


def resolve_matches(root: Path, snapshot: Snapshot, cancel) -> Mapping[str, str]:
    """Worker: candidate key -> comparison row id, for the leads that can be opened in the code panes. A row whose
    address cannot be tied to the file images is left out (never guessed)."""
    from types import SimpleNamespace

    from .pilot.collect import _overview
    from .pilot.limits import Budget
    from .pilot.sources import pe
    from .pilot.sources.code import GhidriffRows
    sides = {a.side: a for a in snapshot.artifacts}
    if snapshot.run_id is None or set(sides) != {'older', 'newer'}:
        return {}
    where = SimpleNamespace(root=Path(root))
    older, newer = _overview(where, sides['older'], cancel), _overview(where, sides['newer'], cancel)
    if older is None or newer is None:
        return {}
    rows = GhidriffRows.resolve(sides['older'].sha256, sides['newer'].sha256, list(snapshot.matches),
                                pe.address_map(older, newer), budget=Budget.after(None, cancel))
    found: dict[str, str] = {}
    for match_id, row in rows.by_match.items():
        found.setdefault(row.candidate_key, match_id)
    return found


class LeadsTable(VirtualTable):
    """Adds the lead keys to the shared table: Home and End (first and last lead, not column), P (pin), Delete
    (dismiss) and Ctrl+C (the explanation, not the row text). Enter and Space are the shared table's."""

    pin_key = Signal()
    dismiss_key = Signal()
    explain_copy = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802
        if event.matches(QKeySequence.StandardKey.Copy):
            self.explain_copy.emit()
        elif event.key() in (Qt.Key.Key_Home, Qt.Key.Key_End) and not event.modifiers() & ~Qt.KeyboardModifier.KeypadModifier:
            self.selectRow(0 if event.key() == Qt.Key.Key_Home else max(0, self.table_model.rowCount() - 1))
        elif event.key() == Qt.Key.Key_P and event.modifiers() == Qt.KeyboardModifier.NoModifier:
            self.pin_key.emit()
        elif event.key() == Qt.Key.Key_Delete:
            self.dismiss_key.emit()
        else:
            super().keyPressEvent(event)


class LeadsPanel(QWidget):
    """The widgets. It holds no state of the result: the controller feeds it."""

    context_changed = Signal(str)
    class_changed = Signal(str)
    search_changed = Signal(str)
    dismissed_toggled = Signal(bool)
    action_requested = Signal(str)  # prepare, refresh, retry, copy_details, cancel

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName('leads.panel')
        self.context = QComboBox()
        self.context.setAccessibleName('Advisory context for leads')
        self.context.setObjectName('leads.context')
        self.buttons: dict[str, QPushButton] = {}
        header = QHBoxLayout()
        header.addWidget(self.context, 1)
        for action, text, name, tip in (('prepare', 'Prepare leads', 'Prepare leads for this comparison', 'leads.prepare'),
                                        ('refresh', 'Refresh', 'Refresh the stored leads', 'leads.refresh')):
            header.addWidget(self._action_button(action, text, name, tip))
        self.headline = PlainLabel(wrap=True)
        self.headline.setObjectName('leads.headline')
        self.banners = PlainLabel(wrap=True, limit=4_000, multiline=True)
        self.banners.setObjectName('leads.banners')
        strip = QHBoxLayout()
        strip.addWidget(self.headline, 1)
        for action, text, name in (('retry', 'Retry', 'Retry preparing leads'),
                                   ('copy_details', 'Copy details', 'Copy details of the leads error'),
                                   ('cancel', 'Cancel', 'Cancel preparing leads')):
            strip.addWidget(self._action_button(action, text, name))
        self.chips: dict[str, ChipLabel] = {}
        chips = QHBoxLayout()
        for spec in channel_chips_placeholder():
            chip = ChipLabel(spec, prefix='Channel')
            chip.set_tip('leads.chip', state=spec.text)
            self.chips[spec.key] = chip
            chips.addWidget(chip)
        chips.addStretch(1)
        self.filter = QComboBox()
        self.filter.setAccessibleName('Filter leads by class')
        self.filter.setObjectName('leads.filter_class')
        for value, text in CLASS_FILTER:
            self.filter.addItem(text, value)
        self.search = QLineEdit()
        self.search.setAccessibleName('Search leads by function name or address')
        self.search.setObjectName('leads.search')
        self.search.setPlaceholderText('Function name or address')
        self.dismissed = QCheckBox('Show dismissed')
        self.dismissed.setAccessibleName('Show dismissed leads')
        self.dismissed.setObjectName('leads.show_dismissed')
        filters = QHBoxLayout()
        for widget in (self.filter, self.search):
            filters.addWidget(widget, 1 if widget is self.search else 0)
        filters.addWidget(self.dismissed)
        self.table = LeadsTable('Ranked leads table')
        self.table.setObjectName('leads.table')
        self.detail = SafeTextView('Why this function: details of the selected lead', limit=DETAIL_LIMIT, wrap=True)
        self.detail.setObjectName('leads.detail')
        self.observations = VirtualTable('Evidence of the selected lead')
        self.observations.setObjectName('leads.observations')
        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.addWidget(self.detail)
        lower.addWidget(self.observations)
        self.body = QSplitter(Qt.Orientation.Vertical)
        self.body.addWidget(self.table)
        self.body.addWidget(lower)
        self.body.setChildrenCollapsible(False)
        actions = QHBoxLayout()
        for action, text, name, tip in (
                ('goto', 'Go to function', 'Go to selected lead in the code panes', 'leads.goto'),
                ('copy', 'Copy explanation', 'Copy explanation of selected lead', 'leads.copy'),
                ('pin', 'Pin', 'Pin selected lead', 'leads.pin'),
                ('dismiss', 'Dismiss...', 'Dismiss selected lead', 'leads.dismiss'),
                ('note', 'Add note...', 'Add analyst note', 'leads.note')):
            actions.addWidget(self._action_button(action, text, name, tip))
        actions.addStretch(1)
        self.footer = PlainLabel(FOOTER, wrap=True, limit=400)
        self.footer.setObjectName('leads.footer')
        self.content = QWidget()
        column = QVBoxLayout(self.content)
        column.setContentsMargins(0, 0, 0, 0)
        for layout in (chips, filters):
            column.addLayout(layout)
        column.addWidget(self.body, 1)
        column.addLayout(actions)
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        for layout in (header, strip):
            root.addLayout(layout)
        root.addWidget(self.banners)
        root.addWidget(self.content, 1)
        root.addWidget(self.footer)
        for combo in (self.context, self.filter):
            combo.view().setAccessibleName(f'{combo.accessibleName()} options')
        apply_tip(self.context, 'leads.context')
        apply_tip(self.filter, 'leads.filter_class')
        apply_tip(self.search, 'leads.search')
        apply_tip(self.dismissed, 'leads.show_dismissed')
        apply_tip(self.detail, 'leads.detail')
        apply_tip(self.table, 'leads.table')
        self.context.currentIndexChanged.connect(lambda _i: self.context_changed.emit(self.context.currentData() or ''))
        self.filter.currentIndexChanged.connect(lambda _i: self.class_changed.emit(self.filter.currentData()))
        self.search.textChanged.connect(self.search_changed)
        self.dismissed.toggled.connect(self.dismissed_toggled)
        self.table.detail_requested.connect(lambda _key: self.detail.setFocus())
        self.setFocusProxy(self.table)
        order = (self.table, self.detail, self.observations)
        cycle = QShortcut(QKeySequence('F6'), self, activated=lambda: self._cycle(order))
        cycle.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)

    def _action_button(self, action: str, text: str, name: str, tip: str | None = None) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(name)
        button.setObjectName(tip or f'leads.btn_{action}')  # the tip id, so the tooltip audit finds it
        if tip is not None:
            apply_tip(button, tip)
        self.buttons[action] = button
        button.clicked.connect(lambda _checked=False, a=action: self.action_requested.emit(a))
        return button

    def _cycle(self, order: tuple[QWidget, ...]) -> None:
        focused = next((i for i, w in enumerate(order) if w.hasFocus()), -1)
        order[(focused + 1) % len(order)].setFocus()

    def apply(self, view: Presentation, *, chips_from=None) -> None:
        self.headline.setText(view.headline)
        self.headline.setVisible(bool(view.headline))
        self.banners.setText('\n'.join(view.banners))
        self.banners.setVisible(bool(view.banners))
        self.content.setVisible(view.content)
        self.footer.setVisible(view.content)
        for action in ('retry', 'copy_details', 'cancel', 'refresh', 'prepare'):
            self.buttons[action].setVisible(action in view.actions)
        if chips_from is not None:
            for spec in chips_from:
                self.chips[spec.key].set_spec(spec)
                self.chips[spec.key].set_tip('leads.chip', state=spec.text)


def channel_chips_placeholder():
    """The seven chips before any result is loaded: every channel reads 'not run'."""
    from .gui.state import ChipSpec
    from .pilot.contracts import CHANNELS
    from .pilot.why import CHANNEL_LABELS
    return tuple(ChipSpec(c, '-', f'{CHANNEL_LABELS[c]}: not run', 'dashed', 'muted') for c in CHANNELS)


class LeadsController(ControllerBase):
    """Owns the loaded result and the requests in flight. Hooks run on the GUI thread, and only while shown."""

    def __init__(self, ctx: PanelContext, *, loader: Loader = load_stored, collector: Collector = collect_inputs,
                 ranker: Ranker = rank_inputs, publisher: Publisher = publish_result,
                 resolver: Resolver = resolve_matches, ask: Callable[[str, str], str | None] | None = None) -> None:
        register_tips(TIPS, TEMPLATES)
        panel = LeadsPanel()
        super().__init__(panel)
        self.panel = panel
        self.ctx = ctx
        self.port = ctx.project
        self.tasks = ctx.tasks
        self.loader, self.resolver = loader, resolver
        self.collector, self.ranker, self.publisher = collector, ranker, publisher
        self.ask = ask or self._ask
        self.key = None
        self.stored: Stored | None = None
        self.model: LeadsModel | None = None
        self.matches: Mapping[str, str] = {}
        self.error: tuple[str, str] | None = None
        self.progress: tuple[str, int, int | None] | None = None
        self.cve = _FIRST
        self.lead_class = 'all'
        self.show_dismissed = False
        self.too_many = 0
        self.presentation = present(project=False, has_run=False, model=None)
        self.collecting = False
        self.goto_tip = panel.buttons['goto'].toolTip()
        self._wire()
        self._render()

    # ---- wiring --------------------------------------------------------------------------------------

    def _wire(self) -> None:
        panel, table = self.panel, self.panel.table
        panel.context_changed.connect(self._context_changed)
        panel.class_changed.connect(self._class_changed)
        panel.search_changed.connect(table.set_filter)
        panel.dismissed_toggled.connect(self._dismissed_toggled)
        panel.action_requested.connect(self._action)
        table.selectionModel().currentRowChanged.connect(lambda *_: self._selection_changed())
        table.table_model.modelReset.connect(self._selection_changed)
        table.activated_key.connect(lambda _key: self.go())
        table.pin_key.connect(lambda: self._action('pin'))
        table.dismiss_key.connect(lambda: self._action('dismiss'))
        table.explain_copy.connect(lambda: self._action('copy'))
        panel.observations.activated_key.connect(self._observation_activated)

    def theme_changed(self, tokens: object) -> None:
        for chip in self.panel.chips.values():
            chip.set_tokens(tokens)

    # ---- host hooks ----------------------------------------------------------------------------------

    def project_changed(self, key) -> None:
        self.tasks.cancel('leads.build')
        self.tasks.cancel('leads.rows')
        self.tasks.cancel('leads.compute')
        self.tasks.cancel('leads.match')
        self.collecting = False
        self.key = key
        self.stored = self.model = None
        self.matches, self.error, self.progress, self.too_many, self.cve = {}, None, None, 0, _FIRST
        self.panel.table.set_prepared(prepare_table(LEAD_SPEC, LEAD_COLUMNS, ()))
        self._combo([])
        if key is not None:
            self.reload()
        else:
            self._render()

    def busy_changed(self, busy: bool) -> None:
        self._enable()

    def shutdown(self) -> None:
        for channel in ('leads.build', 'leads.rows', 'leads.compute', 'leads.match'):
            self.tasks.cancel(channel)

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        if anchor.kind == 'cve':
            if self.model is None or all(c.cve != anchor.key for c in self.model.contexts):
                return NavResult.not_found(anchor.key, anchor.run_id)
            self._select_context(anchor.key)
            return NavResult.shown()
        if anchor.kind == 'match':
            return self._show_match(anchor)
        return NavResult.blocked('Leads', f'it does not open {anchor.kind} links')

    def _show_match(self, anchor: AnchorRef) -> NavResult:
        if self.model is None:
            return NavResult.blocked('Leads', 'no leads are loaded')
        candidate = next((c for c, match in self.matches.items() if match == anchor.key), None)
        row = next((r for r in self.model.rows(self.cve) if r.lead.candidate_key == candidate), None)
        if row is None:
            return NavResult.not_found(anchor.label or anchor.key, anchor.run_id)
        self.select_key(row.key)
        return NavResult.shown()

    # ---- loading -------------------------------------------------------------------------------------

    def service(self):
        return getattr(self.port, 'service', None)

    def reload(self) -> None:
        """Read the stored result (GUI thread: it owns the project connection) and build the view in a worker."""
        service = self.service()
        project = self.port.project()
        if service is None or project is None:
            return self._render()
        try:
            self.stored = self.loader(service, project)
        except (PilotError, EnrichmentError, sqlite3.Error, OSError) as exc:
            self.stored = None
            self.error = (getattr(exc, 'code', 'PT-PILOT-STORAGE'), getattr(exc, 'message', 'The stored leads could not be read'))
            return self._render()
        self.error = None
        if self.stored.loaded.state == 'invalid':
            self.error = ('PT-PILOT-INTEGRITY', 'The stored result does not verify')
        assessment = self.stored.loaded.assessment
        if assessment is None:
            self.model = None
            return self._render()
        self._build(assessment, self.stored.reviews)

    def _build(self, assessment, reviews) -> None:
        cve, lead_class, dismissed = self.cve, self.lead_class, self.show_dismissed
        self.progress = ('reading the stored result', 0, 1) if self.model is None else self.progress
        self._render()

        def work(token, report):
            model = LeadsModel(assessment, reviews)
            wanted = model.context(cve).cve
            return model, wanted, self._prepare(model, wanted, lead_class, dismissed, token)
        self.tasks.submit('leads.build', work, self._built, self._failed, self._progress)

    def _built(self, result) -> None:
        model, cve, prepared = result
        first = self.model is None
        self.model, self.progress = model, None
        self.cve = cve
        self._combo(model.contexts, cve)
        self._apply_prepared(prepared)
        if first:
            self._start_match_lookup()
        self._render()

    @staticmethod
    def _prepare(model: LeadsModel, cve, lead_class: str, dismissed: bool, token) -> PreparedTable:
        rows = [row for row in model.rows(cve) if (lead_class == 'all' or row.lead.lead_class == lead_class)
                and (dismissed or not row.dismissed)]
        return prepare_table(LEAD_SPEC, LEAD_COLUMNS, tuple(rows), token)

    def _apply_prepared(self, prepared: PreparedTable) -> None:
        self.too_many = prepared.total if prepared.too_large else 0
        self.panel.table.set_prepared(prepared)

    def _failed(self, failure) -> None:
        self.progress = None
        self.error = (failure.code, f'{failure.exception_class} stopped the work')
        self._render()

    def _progress(self, progress) -> None:
        self.progress = (progress.stage, progress.done, progress.total)
        self._render()

    def _start_match_lookup(self) -> None:
        service = self.service()
        if service is None:
            return
        project = self.port.project()
        if project is None:
            return
        root, resolver, snapshot = Path(service.root), self.resolver, snapshot_of(project)
        self.tasks.submit('leads.match', lambda token, _report: dict(resolver(root, snapshot, token)), self._matched)

    def _matched(self, found: Mapping[str, str]) -> None:
        self.matches = found
        self._enable()

    # ---- filters -------------------------------------------------------------------------------------

    def _combo(self, contexts, selected: str | None = None) -> None:
        combo = self.panel.context
        combo.blockSignals(True)
        combo.clear()
        for context in contexts:
            combo.addItem(sanitize_text(context.label, 120), context.cve or '')
        index = max(0, combo.findData(selected or ''))
        combo.setCurrentIndex(index if contexts else -1)
        combo.blockSignals(False)

    def _select_context(self, cve: str | None) -> None:
        index = self.panel.context.findData(cve or '')
        if index >= 0:
            self.panel.context.setCurrentIndex(index)

    def _context_changed(self, cve: str) -> None:
        self.cve = cve or None
        self._refilter()

    def _class_changed(self, value: str) -> None:
        self.lead_class = value
        self._refilter()

    def _dismissed_toggled(self, checked: bool) -> None:
        self.show_dismissed = checked
        self._refilter()

    def _refilter(self) -> None:
        if self.model is None:
            return
        model, cve, lead_class, dismissed = self.model, self.cve, self.lead_class, self.show_dismissed
        self.tasks.submit('leads.rows', lambda token, _report: self._prepare(model, cve, lead_class, dismissed, token),
                          self._rows_ready, self._failed)

    def _rows_ready(self, prepared: PreparedTable) -> None:
        self._apply_prepared(prepared)
        self._render()

    # ---- selection and the detail --------------------------------------------------------------------

    def current_row(self) -> LeadRow | None:
        table = self.panel.table
        index = table.currentIndex()
        return index.data(ROW_ROLE) if index.isValid() else None

    def select_key(self, key: str) -> bool:
        table = self.panel.table
        row = table.table_model.view_row_of(key)
        if row < 0:
            return False
        table.selectRow(row)
        table.setCurrentIndex(table.table_model.index(row, 0))
        return True

    def _selection_changed(self) -> None:
        row = self.current_row()
        if row is None or self.model is None:
            self.panel.detail.setPlainText('')
            self.panel.observations.set_prepared(prepare_table(OBS_SPEC, OBS_COLUMNS, ()))
        else:
            self.panel.detail.setPlainText(self.model.detail(row))
            self.panel.observations.set_prepared(prepare_table(OBS_SPEC, OBS_COLUMNS, self.model.observations(row)))
        self._enable()

    def _enable(self) -> None:
        buttons, row = self.panel.buttons, self.current_row()
        has = row is not None
        reason = self._goto_reason(row)
        buttons['goto'].setEnabled(has and reason is None)
        buttons['goto'].setToolTip(escaped_tip(reason) if reason else self.goto_tip)
        for action in ('copy', 'pin', 'dismiss', 'note'):
            buttons[action].setEnabled(has)
        buttons['pin'].setText('Unpin' if has and row.review.pinned else 'Pin')
        buttons['pin'].setAccessibleName('Unpin selected lead' if has and row.review.pinned else 'Pin selected lead')
        buttons['dismiss'].setText('Restore' if has and row.dismissed else 'Dismiss...')
        buttons['dismiss'].setAccessibleName('Restore selected lead' if has and row.dismissed
                                             else 'Dismiss selected lead')
        busy = self.tasks.busy('leads.compute') or self.collecting
        buttons['prepare'].setEnabled(not busy and bool(self.key is not None and self.key.run_id))

    def _goto_reason(self, row: LeadRow | None) -> str | None:
        """Why Go to function is off for this lead, or None. Nothing is guessed from a name."""
        if row is None:
            return 'Select a lead first.'
        if row.lead.candidate_key not in self.matches:
            return 'This lead is not tied to a row of the comparison, so there is no function to show.'
        return None

    # ---- actions -------------------------------------------------------------------------------------

    def _action(self, name: str) -> None:
        handlers = {'prepare': self.prepare, 'refresh': self.reload, 'retry': self.retry, 'cancel': self.cancel,
                    'copy_details': self.copy_details, 'goto': self.go,
                    'copy': self.copy_explanation, 'pin': self.toggle_pin, 'dismiss': self.toggle_dismiss,
                    'note': self.add_note}
        handlers[name]()

    def retry(self) -> None:
        self.error = None
        self.reload()

    def cancel(self) -> None:
        self.tasks.cancel('leads.compute')
        self.collecting = False
        self.progress = None
        self._render()

    def prepare(self) -> None:
        """Collect the evidence (GUI thread: the project connection belongs to it), rank it in a worker, store the
        result (GUI thread) and reload. The first step is deferred one turn so that the progress line is painted."""
        if self.service() is None or self.tasks.busy('leads.compute') or self.collecting:
            return
        self.error = None
        self.progress = ('collecting evidence', 0, 3)
        self.collecting = True
        self._render()
        QTimer.singleShot(0, self._collect)

    def _collect(self) -> None:
        service = self.service()
        self.collecting = False
        if service is None or self.progress is None:
            return  # cancelled, or the project went away
        try:
            collected = self.collector(service, CancelToken())
        except (PilotError, EnrichmentError, sqlite3.Error, OSError) as exc:
            return self._refused(exc)
        self.progress = ('ranking', 1, 3)
        ranker = self.ranker

        def work(token, report):
            try:
                return ranker(collected, token, report)
            except PilotError as exc:  # a refusal in words, not just a class name
                return exc
        self.tasks.submit('leads.compute', work, self._ranked, self._failed, self._progress)
        self._render()

    def _ranked(self, assessment) -> None:
        service = self.service()
        if service is None:
            return
        if isinstance(assessment, PilotError):
            return self._refused(assessment)
        self.progress = ('storing', 2, 3)
        try:
            self.publisher(service, assessment, None)
        except (PilotError, EnrichmentError, sqlite3.Error) as exc:
            return self._refused(exc)
        self.progress = None
        self.reload()

    def _refused(self, exc: Exception) -> None:
        self.progress = None
        self.error = (getattr(exc, 'code', 'PT-PILOT-STORAGE'), getattr(exc, 'message', 'The project data could not be read'))
        self._render()

    def copy_details(self) -> None:
        code, message = self.error or ('', '')
        self.ctx.shell.copy_text(sanitize_text(f'{code}: {message}', 600))

    def copy_explanation(self) -> None:
        row = self.current_row()
        if row is not None and self.model is not None:
            self.ctx.shell.copy_text(self.model.detail(row))

    def go(self) -> None:
        """Show the selected lead's comparison row; the port has no side-specific call, so both panes show."""
        row = self.current_row()
        reason = self._goto_reason(row)
        if reason is not None:
            return self.ctx.announce(reason)
        match_id = self.matches[row.lead.candidate_key]
        if not self.ctx.nav.select_match(match_id, clear_filters=True):
            self.ctx.announce('The comparison row is not in the list; clear its filters and try again.')

    def _observation_activated(self, obs_id: str) -> None:
        found = next((o for o in self._observation_rows() if o.obs_id == obs_id), None)
        if found is None:
            return
        if found.nav is not None:
            return self._reveal(found)
        self._open_anchor(found)

    def _observation_rows(self) -> tuple[ObservationRow, ...]:
        table = self.panel.observations.table_model
        return tuple(table.row_at(i) for i in range(table.rowCount()))

    def _reveal(self, found: ObservationRow) -> None:
        row, nav = self.current_row(), found.nav
        project = self.port.project()
        match_id = self.matches.get(row.lead.candidate_key) if row else None
        match = next((m for m in project.matches if m.id == match_id), None) if project and match_id else None
        functions = getattr(match, nav.side, ()) if match is not None else ()
        if len(functions) == 1 and nav.start_line is not None:
            self.ctx.nav.reveal_lines(functions[0].id, nav.start_line, nav.end_line or nav.start_line)
        elif match_id is not None:
            self.ctx.nav.select_match(match_id, clear_filters=True)
        else:
            self.ctx.announce('This evidence has a location, but its function is not tied to a comparison row.')

    def _open_anchor(self, found: ObservationRow) -> None:
        obs = self.model.pool.get(found.obs_id) if self.model else None
        for anchor_id in (obs.anchor_ids if obs else ()):
            kind, _, value = anchor_id.partition(':')
            if kind in ANCHOR_KINDS and value:
                self.ctx.nav.navigate(AnchorRef(kind, value, label=found.detail).pinned(self.key))
                return
        self.ctx.announce('This evidence has no location to open.')

    # ---- review events (append-only) ------------------------------------------------------------------

    def toggle_pin(self) -> None:
        row = self.current_row()
        if row is not None:
            self._review(row, 'unpin' if row.review.pinned else 'pin')

    def toggle_dismiss(self) -> None:
        row = self.current_row()
        if row is None:
            return
        if row.dismissed:
            return self._review(row, 'restore')
        reason = self.ask('Dismiss lead', 'Why is this lead dismissed? Nothing is deleted; Restore brings it back.')
        if reason is not None:
            self._review(row, 'dismiss', reason)

    def add_note(self) -> None:
        row = self.current_row()
        text = self.ask('Analyst note', 'Your statement about this lead (shown as an analyst statement):') if row else None
        if row is not None and text:
            self._review(row, 'note', text)

    def _ask(self, title: str, label: str) -> str | None:
        text, accepted = QInputDialog.getMultiLineText(self.panel, title, label)
        return text if accepted else None

    def _review(self, row: LeadRow, action: str, text: str = '') -> None:
        service, project = self.service(), self.port.project()
        if service is None or project is None or self.stored is None:
            return
        try:
            review.append(EnrichmentStore(service.store), project_id=project.id, revision=project.revision,
                          candidate_key=row.lead.candidate_key, cve=row.lead.cve, action=action,
                          text=sanitize_text(text, NOTE_LIMIT, multiline=True))
            reviews = review.fold(review.read(EnrichmentStore(service.store)).events)
        except (PilotError, EnrichmentError, sqlite3.Error) as exc:
            self.ctx.announce(f'The review could not be stored: {getattr(exc, "code", "PT-PILOT-STORAGE")}.',
                              assertive=True)
            return
        self.stored = Stored(self.stored.loaded, reviews)
        self._build(self.stored.loaded.assessment, reviews)

    # ---- rendering -----------------------------------------------------------------------------------

    def _render(self) -> None:
        loaded = self.stored.loaded if self.stored else None
        stale = loaded.changed if loaded is not None and loaded.state == 'stale' else None
        context = self.model.context(self.cve) if self.model else None
        view = present(project=self.port.project() is not None, has_run=self.key is not None and bool(self.key.run_id),
                       model=self.model, stale_changed=stale, error=self.error, progress=self.progress,
                       context=context, too_many=self.too_many)
        changed = (view.state, view.headline, view.banners) != (self.presentation.state, self.presentation.headline,
                                                               self.presentation.banners)
        self.presentation = view
        self.panel.apply(view, chips_from=channel_chips(self.model.assessment) if self.model else None)
        self._enable()
        if changed:
            text = view.headline or (view.banners[0] if view.banners else '')
            if text:
                self.ctx.announce(text, assertive=view.state == 'L5')
