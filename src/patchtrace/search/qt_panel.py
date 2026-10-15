"""Qt presentation of the Search dock (WB1 S7; GUI framework 8.10).

Responsibility: let the analyst query the project's local search index, read why a lead matched and go to the code.
What is said (state copy, rows, detail, clipboard text) lives in the Qt-free `view_model`; this module moves it to
widgets. The GUI thread captures an immutable request and the project service; workers only run the injected
`searcher`, `builder` and `coverage` callables. Every result is checked against the project epoch and the query
generation before it is published, so a late result of a previous project or query is dropped. The panel opens no
window of its own and no network connection.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QPushButton, QSplitter, QVBoxLayout, QWidget

from ..gui.anchors import AnchorRef, NavResult
from ..gui.qt.docks import ControllerBase
from ..gui.qt.labels import SafeTextView
from ..gui.qt.state_view import StateView
from ..gui.qt.table import VirtualTable
from ..gui.qt.tasks import Progress as TaskProgress
from ..gui.qt.tasks import TaskFailure
from ..gui.registry import PanelContext
from ..gui.state import StateModel
from ..gui.table_spec import ColumnSpec, TableSpec, prepare_table
from ..gui.text import sanitize_text
from ..gui.tips import apply_tip, register_gui_tips, register_tips
from . import view_model as vm
from .contracts import CoverageEntry, SearchRequest, SearchResult
from .errors import SearchError
from .query import parse_query
from .tooltip_entries import TEMPLATES, TIPS

DEBOUNCE_MS = 250
PAGE = 200
FETCH_MARGIN = 3  # fetch the next page when the scroll bar is this close to its end
SIDES = (('Both', None), ('Older', 'older'), ('Newer', 'newer'))
SCOPES = (('Everything indexed', 'indexed'), ('Changed only', 'changed'))
MODES = tuple((m.capitalize(), m) for m in ('auto', 'words', 'exact', 'prefix', 'substring', 'similar'))
SORTS = tuple((s.capitalize(), s) for s in ('relevance', 'change', 'name', 'address'))
ROUTES = {'function': 'function', 'string': 'string', 'import': 'import'}  # locator scheme -> anchor kind
CHANNELS = ('search.query', 'search.build', 'search.coverage')
_QUERY_HINT = 'Use words, "quoted phrases" and -excluded words; see the placeholder for filters.'

# Cells: Side, Kind, Match, Where, Change, Why (widths from the spec, in em).
COLUMNS = tuple(ColumnSpec(key, title, lambda r, i=i: r.cells[i], width_em=width, accessible=lambda r: r.accessible)
                for i, (key, title, width) in enumerate(zip(
                    ('side', 'kind', 'match', 'where', 'change', 'why'), vm.HEADERS, (10, 14, 36, 26, 20, 40),
                    strict=True)))
TABLE_SPEC = TableSpec(row_key=lambda r: r.hit_id, search_text=lambda r: r.cells[2])


@dataclass(frozen=True, slots=True)
class Outcome:
    """What a worker returns: a result, or the code and message of a `SearchError` (the runner would keep the class)."""
    result: SearchResult | None = None
    code: str = ''
    message: str = ''


def _guarded(call: Callable[[], object]) -> Outcome:
    try:
        return Outcome(result=call())
    except SearchError as exc:
        return Outcome(code=exc.code, message=exc.message)


def default_search(service, request: SearchRequest, cancel) -> SearchResult:
    from .paths import default_cache_root
    from .service import SearchService
    return SearchService(service, default_cache_root()).search(request, build=False, cancel=cancel)


def default_build(service, cancel, progress) -> None:
    from .paths import default_cache_root
    from .service import SearchService
    SearchService(service, default_cache_root()).build(cancel=cancel, progress=progress)


def default_coverage(service) -> tuple[CoverageEntry, ...]:
    from .paths import default_cache_root
    from .service import SearchService
    return SearchService(service, default_cache_root()).coverage()


class SearchWidgets(QWidget):
    """The widgets. They hold no result state: the controller feeds them."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName('search.panel')
        self.query = QLineEdit()
        self.query.setObjectName('search.query')
        self.query.setAccessibleName(vm.ACCESSIBLE_NAMES['search.query'])
        self.query.setPlaceholderText('Names, strings, APIs, code; kind:string, -word')
        self.side = self._combo('search.side', SIDES)
        self.scope = self._combo('search.scope', SCOPES)
        self.mode = self._combo('search.mode', MODES)
        self.sort = self._combo('search.sort', SORTS)
        self.buttons: dict[str, QPushButton] = {}
        top = QHBoxLayout()
        top.addWidget(self.query, 1)
        for combo in (self.side, self.scope, self.mode, self.sort):
            top.addWidget(combo)
        actions = QHBoxLayout()
        for action, text, name, tip in (
                ('rebuild', 'Build index', 'Build the search index', 'search.rebuild'),
                ('coverage', 'Coverage', 'Show which groups are indexed', 'search.coverage'),
                ('cancel', 'Cancel', 'Cancel the running search or build', 'search.cancel'),
                ('goto', 'Go to code', 'Go to the selected result in the code panes', 'search.goto'),
                ('other_side', 'Other side', 'Show the other build of the selected result', 'search.other_side'),
                ('copy', 'Copy', 'Copy the selected result', 'search.copy')):
            actions.addWidget(self._button(action, text, name, tip))
        actions.addStretch(1)
        self.table = VirtualTable(vm.ACCESSIBLE_NAMES['search.table'])
        self.table.setObjectName('search.table')
        self.table.horizontalHeader().setSectionsClickable(False)  # sorting reissues the query, never sorts a page
        self.detail = SafeTextView(vm.ACCESSIBLE_NAMES['search.detail'], wrap=True)
        self.detail.setObjectName('search.detail')
        self.body = QSplitter(Qt.Orientation.Vertical)
        self.body.addWidget(self.table)
        self.body.addWidget(self.detail)
        self.body.setChildrenCollapsible(False)
        self.content = QWidget()
        column = QVBoxLayout(self.content)
        column.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self.body, 1)
        self.state = StateView('search', 'Search', text_limit=vm.QUERY_ECHO * 8)
        self.state.set_content(self.content)
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.addLayout(top)
        root.addLayout(actions)
        root.addWidget(self.state, 1)
        for widget, tip in ((self.query, 'search.query'), (self.side, 'search.side'), (self.scope, 'search.scope'),
                            (self.mode, 'search.mode'), (self.sort, 'search.sort'), (self.table, 'search.table'),
                            (self.detail, 'search.detail')):
            apply_tip(widget, tip)
        self.setFocusProxy(self.query)
        QShortcut(QKeySequence('Esc'), self.query, activated=self.query.clear).setContext(
            Qt.ShortcutContext.WidgetShortcut)
        QShortcut(QKeySequence('F6'), self, activated=self._cycle).setContext(
            Qt.ShortcutContext.WidgetWithChildrenShortcut)

    def _combo(self, tip: str, items) -> QComboBox:
        combo = QComboBox()
        combo.setObjectName(tip)
        combo.setAccessibleName(vm.ACCESSIBLE_NAMES[tip])
        for text, value in items:
            combo.addItem(text, value)
        combo.view().setAccessibleName(f'{combo.accessibleName()} options')
        return combo

    def _button(self, action: str, text: str, name: str, tip: str) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(name)
        button.setObjectName(tip)
        apply_tip(button, tip)
        self.buttons[action] = button
        return button

    def _cycle(self) -> None:
        order = (self.query, self.table, self.detail)
        focused = next((i for i, w in enumerate(order) if w.hasFocus()), -1)
        order[(focused + 1) % len(order)].setFocus()


class SearchController(ControllerBase):
    """Owns the query, the rows of the current generation and the requests in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, searcher: Callable = default_search, builder: Callable = default_build,
                 coverage: Callable = default_coverage) -> None:
        register_gui_tips()  # idempotent: the host has done it, a test or a bare embed has not
        register_tips(TIPS, TEMPLATES)
        panel = SearchWidgets()
        super().__init__(panel)
        self.panel, self.ctx, self.port, self.tasks = panel, ctx, ctx.project, ctx.tasks
        self.searcher, self.builder, self.coverage = searcher, builder, coverage
        self.key = None
        self.epoch = 0
        self.generation = 0
        self.buffer: vm.ResultsBuffer | None = None
        self.hits: dict[str, object] = {}
        self.result: SearchResult | None = None
        self.request: SearchRequest | None = None
        self.progress: vm.Progress | None = None
        self.failure: vm.Failure | None = None
        self.invalid = ''
        self.cancelled = False
        self.indexed = True
        self.fetching = False
        self.debounce = QTimer(self)
        self.debounce.setSingleShot(True)
        self.debounce.setInterval(DEBOUNCE_MS)
        self._wire()
        self._render()

    # ---- wiring --------------------------------------------------------------------------------------

    def _wire(self) -> None:
        panel = self.panel
        panel.query.textChanged.connect(self._typed)
        panel.query.returnPressed.connect(self.submit)
        self.debounce.timeout.connect(self.submit)
        for combo in (panel.side, panel.scope, panel.mode, panel.sort):
            combo.currentIndexChanged.connect(lambda _i: self.submit())
        panel.buttons['rebuild'].clicked.connect(lambda _c=False: self.build())
        panel.buttons['coverage'].clicked.connect(lambda _c=False: self.show_coverage())
        panel.buttons['cancel'].clicked.connect(lambda _c=False: self.cancel())
        panel.buttons['goto'].clicked.connect(lambda _c=False: self.go())
        panel.buttons['other_side'].clicked.connect(lambda _c=False: self.go(other=True))
        panel.buttons['copy'].clicked.connect(lambda _c=False: self.copy())
        table = panel.table
        table.activated_key.connect(lambda _key: self.go())
        table.detail_requested.connect(lambda _key: panel.detail.setFocus())
        table.selectionModel().currentRowChanged.connect(lambda *_: self._selection_changed())
        table.table_model.modelReset.connect(self._selection_changed)
        table.verticalScrollBar().valueChanged.connect(self._scrolled)
        state = panel.state
        state.retry_requested.connect(self.submit)
        state.refresh_requested.connect(self.build)
        state.copy_requested.connect(self.ctx.shell.copy_text)

    # ---- host hooks ----------------------------------------------------------------------------------

    def project_changed(self, key) -> None:
        self._cancel_all()
        self.epoch += 1
        self.key = key
        self.indexed, self.fetching, self.cancelled = True, False, False
        self._reset_results()
        if key is not None:
            self._probe_index()
        self._render()

    def busy_changed(self, busy: bool) -> None:
        self._enable()

    def focus_target(self) -> QWidget | None:
        return self.panel.query

    def shutdown(self) -> None:
        self.debounce.stop()
        self._cancel_all()
        self.epoch += 1

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        return NavResult.blocked('Search', f'it does not open {anchor.kind} links')

    # ---- query ---------------------------------------------------------------------------------------

    def _typed(self, _text: str) -> None:
        self.debounce.start()

    def service(self):
        return getattr(self.port, 'service', None)

    def _plan(self):
        panel = self.panel
        plan = parse_query(panel.query.text(), mode=panel.mode.currentData())
        update = {'scope': panel.scope.currentData()}
        if (side := panel.side.currentData()) is not None:
            update['sides'] = (side,)
        return plan.model_copy(update=update)

    def submit(self) -> None:
        """Parse the query (the only grammar entry) and search the first page under a new generation."""
        self.debounce.stop()
        self.tasks.cancel('search.query')
        self.fetching = False
        self.invalid = ''
        if self.key is None or self.service() is None:
            return self._render()
        if not self.panel.query.text().strip():
            self._reset_results()
            return self._render()
        try:
            plan = self._plan()
        except SearchError as exc:
            self.invalid = f'Search query is invalid: {sanitize_text(exc.message, 200)}. {_QUERY_HINT}'
            return self._render()
        self.generation += 1
        self.cancelled = False
        self.failure = None
        self.buffer = vm.ResultsBuffer(self.generation, cap=vm.ROW_CAP)
        self.request = SearchRequest(plan=plan, sort=self.panel.sort.currentData(), limit=PAGE,
                                     generation=self.generation)
        self._run(self.request)

    def fetch_more(self) -> None:
        buffer = self.buffer
        if buffer is None or self.request is None or self.fetching or not buffer.can_fetch_more:
            return
        self.fetching = True
        self._run(self.request.model_copy(update={'cursor': buffer.cursor}))

    def _scrolled(self, value: int) -> None:
        if value >= self.panel.table.verticalScrollBar().maximum() - FETCH_MARGIN:
            self.fetch_more()

    def _run(self, request: SearchRequest) -> None:
        service, searcher = self.service(), self.searcher
        epoch, generation = self.epoch, request.generation
        self.tasks.submit('search.query', lambda token, _report: _guarded(lambda: searcher(service, request, token)),
                          lambda out: self._arrived(epoch, generation, out), self._failed)
        self._render()

    def _arrived(self, epoch: int, generation: int, outcome: Outcome) -> None:
        if epoch != self.epoch or generation != self.generation or self.buffer is None:
            return  # a late result of an earlier project or query
        self.fetching = False
        if outcome.result is None:
            self.failure = vm.Failure(outcome.code, outcome.message)
            return self._render()
        self.failure, self.result = None, outcome.result
        if self.buffer.accept(generation, outcome.result) < 0:
            return
        for hit in outcome.result.hits:
            self.hits[hit.hit_id] = hit
        self._fill_table()
        self._render()

    def _failed(self, failure: TaskFailure) -> None:
        self.fetching = False
        self.failure = vm.Failure(failure.code, failure.exception_class)
        self._render()

    # ---- index ---------------------------------------------------------------------------------------

    def _probe_index(self) -> None:
        service, coverage, epoch = self.service(), self.coverage, self.epoch
        if service is None:
            return
        self.tasks.submit('search.coverage', lambda _token, _report: coverage(service),
                          lambda entries: self._probed(epoch, entries), self._failed)

    def _probed(self, epoch: int, entries) -> None:
        if epoch == self.epoch:
            self.indexed = any(e.status in ('indexed', 'truncated') for e in entries)
            self._render()

    def build(self) -> None:
        service, builder, epoch = self.service(), self.builder, self.epoch
        if self.key is None or service is None:
            return
        self.cancelled = False
        self.progress = vm.Progress('index', 0, 1)

        def work(token, report):
            return _guarded(lambda: builder(service, token, lambda group, done, total: report(group, done, total)))

        self.tasks.submit('search.build', work, lambda out: self._built(epoch, out), self._failed, self._build_progress)
        self._render()

    def _build_progress(self, progress: TaskProgress) -> None:
        self.progress = vm.Progress(progress.stage, progress.done, progress.total or 1)
        self._render()

    def _built(self, epoch: int, outcome: Outcome) -> None:
        if epoch != self.epoch:
            return
        self.progress = None
        self.indexed = True
        if outcome.code:
            self.failure = vm.Failure(outcome.code, outcome.message)
            return self._render()
        self._probe_index()
        if self.panel.query.text().strip():
            self.submit()
        else:
            self._render()

    def show_coverage(self) -> None:
        """Coverage goes to the detail pane: a dialog would be a second window."""
        if self.result is None:
            return self._after_coverage(())
        self._after_coverage(self.result.coverage)

    def _after_coverage(self, entries) -> None:
        lines = [f'{e.group} | {e.side or "-"} | {e.status} | {e.docs} documents | {e.reason or "no reason recorded"}'
                 for e in entries]
        self.panel.detail.setPlainText('Coverage\n' + ('\n'.join(lines) or 'No search has run yet.'))

    def cancel(self) -> None:
        self._cancel_all()
        self.progress, self.fetching, self.cancelled = None, False, True
        self._render()

    def _cancel_all(self) -> None:
        for channel in CHANNELS:
            self.tasks.cancel(channel)

    # ---- rows and detail -----------------------------------------------------------------------------

    def _reset_results(self) -> None:
        self.buffer = self.result = self.request = None
        self.progress = self.failure = None
        self.invalid = ''
        self.hits = {}
        self.generation += 1
        self.panel.table.set_prepared(prepare_table(TABLE_SPEC, COLUMNS, ()))
        self.panel.detail.setPlainText('')

    def _fill_table(self) -> None:
        self.panel.table.set_prepared(prepare_table(TABLE_SPEC, COLUMNS, tuple(self.buffer.rows)))

    def _selected_hit(self):
        key = self.panel.table.current_key()
        return self.hits.get(key) if key else None

    def _selection_changed(self) -> None:
        hit = self._selected_hit()
        if hit is not None:
            self.panel.detail.setPlainText(vm.detail_text(hit))
        self._enable()

    def copy(self) -> None:
        hit = self._selected_hit()
        if hit is not None:
            self.ctx.shell.copy_text(vm.copy_text(hit))

    # ---- navigation ----------------------------------------------------------------------------------

    def go(self, other: bool = False) -> NavResult | None:
        """Open the selected lead, or its counterpart, through the navigation port; a miss changes nothing."""
        hit = self._selected_hit()
        if hit is None:
            return None
        anchor = self._anchor(hit, other)
        if isinstance(anchor, NavResult):
            result = anchor
        else:
            result = self.ctx.nav.navigate(anchor.pinned(self.key))
        if isinstance(result, NavResult) and result.status != 'shown':
            self.ctx.shell.announce(result.message)
        return result if isinstance(result, NavResult) else None

    def _anchor(self, hit, other: bool) -> AnchorRef | NavResult:
        first = hit.evidence[0]
        loc = first.locator
        if other:
            sides = {c.side: c for c in (hit.expansion.counterparts if hit.expansion else ())}
            wanted = 'older' if loc.side == 'newer' else 'newer'
            if wanted not in sides:
                return NavResult.not_found(first.title, self.key.run_id if self.key else None)
            ref = sides[wanted]
            return AnchorRef('function', ref.function_id, ref.side, label=sanitize_text(ref.name, 200), origin='search')
        kind = ROUTES.get(loc.scheme)
        key = loc.function_id or loc.source_ref
        if kind is None or not key:
            return NavResult.blocked(first.title, f'no route to a {loc.scheme} result yet')
        return AnchorRef(kind, key, loc.side, label=sanitize_text(first.title, 200), origin='search')

    # ---- rendering -----------------------------------------------------------------------------------

    def _line(self) -> vm.PanelState:
        panel = self.panel
        if self.invalid:
            return vm.PanelState('invalid', self.invalid)
        if self.cancelled:
            return vm.PanelState('Q12', 'Cancelled. Earlier results are unchanged.')
        shown = len(self.buffer.rows) if self.buffer else 0
        line = vm.panel_state(has_project=self.key is not None, query=panel.query.text(), result=self.result,
                              progress=self.progress, failure=self.failure, shown=shown,
                              scope=panel.scope.currentData(), indexed=self.indexed)
        if self.buffer is not None and self.buffer.note and line.id == 'Q4':
            return vm.PanelState('Q4', f'{line.text} {self.buffer.note}', line.actions)
        return line

    def _model(self, line: vm.PanelState) -> tuple[StateModel, bool]:
        kinds = {'Q0': 'no-project', 'Q1': 'idle', 'Q2': 'loading', 'Q3': 'idle', 'Q4': 'ready', 'Q5': 'idle',
                 'Q6': 'partial', 'Q7': 'partial', 'Q8': 'stale', 'Q9': 'unsupported', 'Q10': 'error',
                 'Q12': 'cancelled', 'invalid': 'idle'}
        kind = kinds[line.id]
        has_rows = bool(self.buffer and self.buffer.rows)
        if kind == 'loading' and has_rows:
            kind = 'refreshing'
        actions = ('retry', 'copy') if kind == 'error' else ('refresh',) if kind == 'stale' else ()
        return StateModel(kind, line.text, line.text, actions), has_rows

    def _render(self) -> None:
        line = self._line()
        model, has_rows = self._model(line)
        self.panel.state.set_state(model, has_content=has_rows)
        self._enable()

    def _enable(self) -> None:
        buttons = self.panel.buttons
        working = self.tasks.busy('search.query') or self.tasks.busy('search.build')
        has_project = self.key is not None
        hit = self._selected_hit()
        buttons['rebuild'].setEnabled(has_project and not self.tasks.busy('search.build'))
        buttons['coverage'].setEnabled(has_project)
        buttons['cancel'].setEnabled(working)
        buttons['goto'].setEnabled(hit is not None)
        buttons['other_side'].setEnabled(hit is not None and bool(hit.expansion and hit.expansion.counterparts))
        buttons['copy'].setEnabled(hit is not None)
        self.panel.query.setEnabled(has_project)
