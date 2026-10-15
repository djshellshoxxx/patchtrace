"""Qt presentation of the Strings dock (WB3 S7b; GUI framework 1.1). Everything that decides what is said lives in the
Qt-free `view_model` and `copy`; this module moves it to widgets. The GUI thread captures an immutable `Request`
(paths and hashes, never the live project or a connection); the scan and the filtering run on `TaskRunner`
channels, and a result is applied only when the project key and the request generation still match. Nothing here
runs a target, opens the network or opens a window of its own.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..gui.anchors import AnchorRef, NavResult
from ..gui.projection import ProjectKey
from ..gui.qt.docks import ControllerBase
from ..gui.qt.labels import PlainLabel, SafeTextView
from ..gui.qt.state_view import StateView
from ..gui.qt.table import ROW_ROLE, VirtualTable
from ..gui.registry import PanelContext
from ..gui.state import StateModel, dominant
from ..gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from ..gui.text import sanitize_text
from ..gui.tips import apply_tip, register_gui_tips, register_tips
from . import copy
from .contracts import Side, StringChange, StringsDelta, StringsError
from .panel import TIPS
from .scan import ScanError
from .view_model import (
    CLIPBOARD_ROWS,
    FilterResult,
    StringRowVM,
    StringsFilter,
    apply_filter,
    build_rows,
    copy_escaped,
    differing,
)

DETAIL_LIMIT = 8_192
CHANNELS = ('strings-scan', 'strings-view')
CHANGE_FILTERS = (('changed', 'Differences'), ('all', 'All changes'), ('only-newer', 'Only in newer'),
                  ('only-older', 'Only in older'), ('edited', 'Edited'))
Report = Callable[..., None]
# The card's copy says cancellation waits for the current file; the runner drops the result at once.
RUNNING = ('Reading strings from the {side} build ({n} of 2)... {elapsed}. Cancel stops the operation; nothing is '
           'saved from a cancelled run.')


@dataclass(frozen=True, slots=True)
class Request:
    """What a worker may know of the project: the key it was captured under and the two verified artifacts."""
    key: ProjectKey
    older: Path
    newer: Path
    older_sha256: str
    newer_sha256: str
    min_length: int = 4


@dataclass(frozen=True, slots=True)
class Loaded:
    delta: StringsDelta
    rows: tuple[StringRowVM, ...]
    changes: dict[str, StringChange]
    partial: tuple[tuple[str, str], ...] = ()  # (side, row limit) of each scan that stopped early


Loader = Callable[[Request, object, Report], Loaded]


def scan_builtin(request: Request, token, report: Report) -> Loaded:
    """Worker: read both files with the built-in scan (data reads only) and compare. No function pairing is
    available to a worker, so no string carries a function link."""
    from ..intelligence.tools.normalize import FunctionPairing
    from .cli import table_from_source
    from .delta import compute_delta
    from .scan import DEFAULT_MAX_ROWS, BuiltinScanSource
    tables, partial = {}, []
    for n, (side, path, sha) in enumerate((('older', request.older, request.older_sha256),
                                           ('newer', request.newer, request.newer_sha256)), 1):
        report(side, n, 2)
        source = BuiltinScanSource(path, artifact_sha256=sha, side=side, min_length=request.min_length,
                                   cancel=token.is_set)
        tables[side] = table_from_source(source.load())
        if any(s.state in ('truncated', 'failed') for s in tables[side].basis.stages.values()):
            partial.append((side, str(DEFAULT_MAX_ROWS)))
    delta = compute_delta(tables['older'], tables['newer'], pairing=FunctionPairing.empty())
    sources = {'older': 'built-in scan', 'newer': 'built-in scan'}
    return Loaded(delta, build_rows(delta, sources), {c.id: c for c in delta.changes}, tuple(partial))


def _cell(value: str, empty: str) -> str:
    return empty if value in ('', '-') else value


COLUMNS = (
    ColumnSpec('change', 'Change', lambda r: r.change, width_em=20),
    ColumnSpec('string', 'String', lambda r: r.text, width_em=50),
    ColumnSpec('type', 'Type', lambda r: r.type, width_em=16),
    ColumnSpec('older', 'Older', lambda r: _cell(r.older, 'No file offset'), width_em=22),
    ColumnSpec('newer', 'Newer', lambda r: _cell(r.newer, 'No file offset'), width_em=22),
    ColumnSpec('function', 'Function', lambda r: r.function or 'No supported function link', width_em=28),
    ColumnSpec('cues', 'Cues', lambda r: r.cue_text, width_em=24),
    ColumnSpec('source', 'Source', lambda r: r.source or 'Not run', width_em=20))
SPEC = TableSpec(row_key=lambda r: r.id, search_text=lambda r: r.text)


def prepare_rows(rows: tuple[StringRowVM, ...], flt: StringsFilter, token) -> tuple[FilterResult, PreparedTable]:
    result = apply_filter(rows, flt)
    return result, prepare_table(SPEC, COLUMNS, result.rows, token)


class StringsPanel(QWidget):
    """The widgets only; the controller feeds it."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName('strings.panel')
        self.buttons: dict[str, QPushButton] = {}
        top = QHBoxLayout()
        top.addWidget(self._button('scan', 'Scan both builds', 'Scan both builds with the built-in scan',
                                   'strings.run.builtin'))
        top.addWidget(self._button('cancel', 'Cancel', 'Cancel the string scan', 'strings.cancel'))
        self.change = self._combo('strings.filter.change', 'Filter strings by kind of change', CHANGE_FILTERS)
        self.scope = self._combo('strings.filter.scope', 'Choose differences or all strings',
                                 tuple(copy.SCOPES.items()))
        self.search = QLineEdit()
        self.search.setObjectName('strings.filter.text')
        self.search.setAccessibleName('Filter strings by text')
        self.search.setPlaceholderText('Text to find')
        self.noise = QCheckBox('Hide noise-like strings')
        self.noise.setObjectName('strings.filter.noise')
        self.noise.setAccessibleName('Hide noise-like strings')
        for widget in (self.change, self.scope):
            top.addWidget(widget)
        top.addWidget(self.search, 1)
        top.addWidget(self.noise)
        self.table = VirtualTable('Strings table')
        self.table.setObjectName('strings.table')
        self.detail = SafeTextView('Details of the selected string', limit=DETAIL_LIMIT, wrap=True)
        self.detail.setObjectName('strings.detail')
        body = QSplitter(Qt.Orientation.Vertical)
        body.addWidget(self.table)
        body.addWidget(self.detail)
        body.setChildrenCollapsible(False)
        actions = QHBoxLayout()
        for action, text, name, tip in (
                ('copy', 'Copy escaped', 'Copy the selected strings in escaped form', 'strings.copy.safe'),
                ('function', 'Open function', 'Open the function that uses the selected string',
                 'strings.open.function'),
                ('hex', 'Open in hex', 'Open the bytes of the selected string in the hex view', 'strings.open.hex')):
            actions.addWidget(self._button(action, text, name, tip))
        actions.addStretch(1)
        self.footer = PlainLabel(wrap=True, limit=400)
        self.footer.setObjectName('strings.basis')
        column = QVBoxLayout(self)
        column.setContentsMargins(4, 4, 4, 4)
        column.addLayout(top)
        column.addWidget(body, 1)
        column.addLayout(actions)
        column.addWidget(self.footer)
        for widget, tip in ((self.search, 'strings.filter.text'), (self.noise, 'strings.filter.noise'),
                            (self.table, 'strings.table'), (self.detail, 'strings.detail')):
            apply_tip(widget, tip)
        self.setFocusProxy(self.table)

    def _button(self, action: str, text: str, name: str, tip: str) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(name)
        button.setObjectName(tip)
        apply_tip(button, tip)
        self.buttons[action] = button
        return button

    @staticmethod
    def _combo(tip: str, name: str, items) -> QComboBox:
        combo = QComboBox()
        combo.setObjectName(tip)
        combo.setAccessibleName(name)
        for value, text in items:
            combo.addItem(text, value)
        combo.view().setAccessibleName(f'{name} options')
        apply_tip(combo, tip)
        return combo


class StringsController(ControllerBase):
    """Owns the loaded comparison and the requests in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, loader: Loader = scan_builtin,
                 clock: Callable[[], float] = time.monotonic) -> None:
        register_gui_tips()  # the state buttons use them; the host does this too and it is idempotent
        register_tips(TIPS)
        self.panel = StringsPanel()
        self.view = StateView('strings', 'Strings', ctx.shell, text_limit=600)
        self.view.set_content(self.panel)
        super().__init__(self.view)
        self.ctx, self.port, self.tasks, self.loader, self.clock = ctx, ctx.project, ctx.tasks, loader, clock
        self.key: ProjectKey | None = None
        self.loaded: Loaded | None = None
        self.loaded_key: ProjectKey | None = None
        self.prepared: FilterResult | None = None
        self.by_id: dict[str, StringRowVM] = {}
        self.error: tuple[str, str] | None = None
        self.progress: tuple[str, int] | None = None
        self.started = 0.0
        self.cancelled = self.stale = self.closed = False
        self.generation = 0
        self._wire()
        self._render()

    # ---- wiring --------------------------------------------------------------------------------------

    def _wire(self) -> None:
        panel, table = self.panel, self.panel.table
        panel.buttons['scan'].clicked.connect(self.scan)
        panel.buttons['cancel'].clicked.connect(self.cancel)
        panel.buttons['copy'].clicked.connect(self.copy_escaped)
        panel.buttons['function'].clicked.connect(self.open_function)
        panel.buttons['hex'].clicked.connect(self.open_hex)
        for combo in (panel.change, panel.scope):
            combo.currentIndexChanged.connect(lambda _i: self._refilter())
        panel.noise.toggled.connect(lambda _c: self._refilter())
        panel.search.textChanged.connect(self._text_changed)
        table.selectionModel().currentRowChanged.connect(lambda *_: self._selection())
        table.table_model.modelReset.connect(self._selection)
        table.activated_key.connect(lambda _k: self.open_function())
        table.detail_requested.connect(lambda _k: panel.detail.setFocus())
        self.view.retry_requested.connect(self.scan)
        self.view.refresh_requested.connect(self.scan)
        self.view.copy_requested.connect(self.ctx.shell.copy_text)

    def focus_target(self) -> QWidget:
        return self.panel.table

    # ---- host hooks ----------------------------------------------------------------------------------

    def project_changed(self, key: ProjectKey | None) -> None:
        same = (key is not None and self.key is not None and key.identity() == self.key.identity()
                and self.loaded is not None)
        self._cancel_all()
        self.key = key
        self.error, self.progress, self.cancelled = None, None, False
        if same:
            self.stale = key != self.loaded_key
        else:
            self.stale = False
            self.loaded = self.loaded_key = self.prepared = None
            self.by_id = {}
            self.panel.table.set_prepared(prepare_table(SPEC, COLUMNS, ()))
        self._render()

    def shutdown(self) -> None:
        self.closed = True
        self._cancel_all()

    def _cancel_all(self) -> None:
        self.generation += 1
        for channel in CHANNELS:
            self.tasks.cancel(channel)

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        if anchor.kind != 'string':
            return NavResult.blocked('Strings', f'it does not open {anchor.kind} links')
        found = [row for row in (self.loaded.rows if self.loaded else ())
                 if anchor.key in (row.id, row.value_sha256) and (anchor.side is None or anchor.side in row.sides)]
        label = anchor.label or anchor.key
        if not found:
            return NavResult.not_found(label, anchor.run_id)
        if len(found) > 1:
            return NavResult.ambiguous(label, (AnchorRef('string', r.id, r.sides[0], anchor.run_id, r.text)
                                               for r in found[:20]))
        if self._select(found[0].id):
            return NavResult.shown()
        return NavResult.blocked('Strings', 'the string is hidden by the current filters; choose All changes and '
                                            'All strings')

    # ---- scanning ------------------------------------------------------------------------------------

    def scan(self) -> None:
        key = self.key
        if key is None or self.closed:
            return
        try:
            older, newer, older_sha, newer_sha = self.port.artifact_paths()
        except (OSError, ValueError, LookupError) as exc:
            self.error = ('PT-STR-INPUT', f'the project needs an older and a newer artifact ({type(exc).__name__})')
            return self._render()
        request = Request(key, Path(older), Path(newer), older_sha, newer_sha)
        self.generation += 1
        generation = self.generation
        self.error, self.cancelled, self.stale = None, False, False
        self.progress, self.started = ('older', 1), self.clock()
        self._render()
        loader = self.loader

        def work(token, report):
            try:
                return loader(request, token, report)
            except (StringsError, ScanError) as exc:  # typed and user-safe; anything else is a TaskFailure
                return exc.code, getattr(exc, 'message', str(exc))
        self.tasks.submit(
            'strings-scan', work, lambda result: self._loaded(generation, request, result),
            lambda failure: self._failed(generation, failure),
            lambda progress: self._progressed(generation, progress))

    def cancel(self) -> None:
        if self.progress is None:
            return
        self.generation += 1
        self.tasks.cancel('strings-scan')
        self.progress, self.cancelled = None, True
        self._render()

    def _current(self, generation: int, key: ProjectKey | None) -> bool:
        return generation == self.generation and not self.closed and key is not None and key == self.key

    def _progressed(self, generation: int, progress) -> None:
        if generation == self.generation:
            self.progress = (progress.stage, progress.done)
            self._render()

    def _failed(self, generation: int, failure) -> None:
        if generation == self.generation:
            self.progress, self.error = None, (failure.code, f'{failure.exception_class} stopped the scan.')
            self._render()

    def _loaded(self, generation: int, request: Request, result) -> None:
        if not self._current(generation, request.key):
            return  # a late result of an earlier project, epoch or request never publishes
        self.progress = None
        if isinstance(result, tuple):
            self.error = result
            return self._render()
        self.loaded, self.loaded_key, self.stale = result, request.key, False
        self.by_id = {row.id: row for row in result.rows}
        self._refilter()

    # ---- filtering -----------------------------------------------------------------------------------

    def current_filter(self) -> StringsFilter:
        panel = self.panel
        return StringsFilter(change=panel.change.currentData(), scope=panel.scope.currentData(),
                             hide_noise=panel.noise.isChecked())

    def _text_changed(self, text: str) -> None:
        self.panel.table.set_filter(sanitize_text(text, 200))
        self._render()

    def _refilter(self) -> None:
        loaded = self.loaded
        if loaded is None:
            return self._render()
        generation, key, flt, rows = self.generation, self.key, self.current_filter(), loaded.rows
        self.tasks.submit('strings-view', lambda token, _report: prepare_rows(rows, flt, token),
                          lambda result: self._viewed(generation, key, result),
                          lambda failure: self._failed(generation, failure))

    def _viewed(self, generation: int, key: ProjectKey | None, result: tuple[FilterResult, PreparedTable]) -> None:
        if not self._current(generation, key):
            return
        self.prepared = result[0]
        self.panel.table.set_prepared(result[1])
        self._render()

    # ---- selection and actions -----------------------------------------------------------------------

    def current_row(self) -> StringRowVM | None:
        index = self.panel.table.currentIndex()
        return index.data(ROW_ROLE) if index.isValid() else None

    def _select(self, row_id: str) -> bool:
        table = self.panel.table
        view_row = table.table_model.view_row_of(row_id)
        if view_row < 0:
            return False
        table.selectRow(view_row)
        return True

    def _selection(self) -> None:
        row = self.current_row()
        buttons = self.panel.buttons
        self.panel.detail.setPlainText(self._detail(row) if row else '')
        buttons['copy'].setEnabled(row is not None)
        buttons['function'].setEnabled(row is not None and len(row.function_ids) == 1)
        buttons['hex'].setEnabled(self._current_scan() and self._offset(row) is not None)

    @staticmethod
    def _detail(row: StringRowVM) -> str:
        return '\n'.join((row.sentence, row.description, f'Older offsets: {row.older}', f'Newer offsets: {row.newer}',
                          f'Value SHA-256: {row.value_sha256}', f'String: {row.text}'))

    def _offset(self, row: StringRowVM | None) -> tuple[Side, int] | None:
        change = self.loaded.changes.get(row.id) if self.loaded and row else None
        for side in ('newer', 'older'):
            observation = getattr(change, side, None)
            if observation is not None and observation.offsets:
                return side, observation.offsets[0]
        return None

    def _current_scan(self) -> bool:
        """Bytes are opened only for the files that were scanned: the project key must be the one of the scan."""
        return self.key is not None and self.key == self.loaded_key and not self.stale

    def copy_escaped(self) -> None:
        keys = self.panel.table.selected_keys(CLIPBOARD_ROWS)
        rows = [self.by_id[k] for k in keys if k in self.by_id]
        if rows:
            self.ctx.shell.copy_text(copy_escaped(rows))

    def open_function(self) -> None:
        row = self.current_row()
        if row is None or len(row.function_ids) != 1 or self.key is None:
            return
        anchor = AnchorRef('function', row.function_ids[0], row.sides[0], label=row.function).pinned(self.key)
        result = self.ctx.nav.navigate(anchor)
        if getattr(result, 'status', 'shown') != 'shown':
            self.ctx.shell.status(sanitize_text(getattr(result, 'message', '')))

    def open_hex(self) -> None:
        found = self._offset(self.current_row())
        if found is None or not self._current_scan():
            return
        side, offset = found
        self.ctx.nav.show_raw_offset(side, offset)
        self.ctx.shell.announce(f'Offset {offset} is in the {side} file; the other pane shows the same offset of '
                                'its own file, which is a different place.')

    # ---- states --------------------------------------------------------------------------------------

    def _conditions(self) -> dict[str, str]:
        loaded, found = self.loaded, {}
        if self.key is None:
            return {'no-project': copy.STATES['no-project']}
        if self.progress is not None:
            side, n = self.progress
            elapsed = f'{max(0, int(self.clock() - self.started))} s'
            found['refreshing' if loaded else 'loading'] = RUNNING.format(side=sanitize_text(side, 20), n=n,
                                                                         elapsed=elapsed)
        if self.error:
            found['error'] = copy.STATES['failed'].format(code=sanitize_text(self.error[0], 40),
                                                          message=sanitize_text(self.error[1], 200))
        if self.cancelled:
            found['cancelled'] = 'Extraction cancelled. Earlier results are unchanged.'
        if self.stale:
            found['stale'] = copy.STATES['stale']
        if loaded is None:
            return found or {'idle': copy.STATES['no-data']}
        if not loaded.delta.comparable:
            found['blocked'] = copy.STATES['blocked'].format(
                reason=sanitize_text('; '.join(loaded.delta.basis_notes) or 'the settings differ', 300))
        elif loaded.partial:
            found['partial'] = copy.STATES['incomplete'].format(side=loaded.partial[0][0], limit=loaded.partial[0][1])
        if self.panel.table.too_large:
            found['too-large'] = (f'Too many strings to display ({self.prepared and len(self.prepared.rows) or 0}). Narrow the filter or choose Differences.'
                                  )
        if loaded.delta.comparable and self.prepared is not None:
            count = differing(loaded.rows)
            found.setdefault('ready', copy.STATES['ready'].format(n=count) if count
                             else copy.STATES['ready-none'])
        return found

    def _render(self) -> None:
        conditions = self._conditions()
        kind = dominant(conditions)
        actions = {'error': ('retry', 'copy'), 'stale': ('refresh',)}.get(kind, ())
        has_content = self.loaded is not None and self.loaded.delta.comparable
        self.view.set_state(StateModel(kind, conditions.get(kind, ''), conditions.get(kind, ''), actions),
                            has_content=has_content)
        buttons, running = self.panel.buttons, self.progress is not None
        buttons['scan'].setEnabled(self.key is not None and not running)
        buttons['scan'].setText('Re-scan both builds' if self.loaded else 'Scan both builds')
        buttons['cancel'].setEnabled(running)
        self.panel.footer.setText(self._footer())
        self._selection()

    def _footer(self) -> str:
        if self.loaded is None:
            return 'No scan loaded.'
        shown, hidden = len(self.prepared.rows) if self.prepared else 0, self.prepared.hidden_noise if self.prepared else 0
        return (f'{shown} of {len(self.loaded.rows)} rows listed; {hidden} noise-like hidden. '
                f'Older {self.loaded.delta.older_basis_digest[:12]}, newer {self.loaded.delta.newer_basis_digest[:12]}.')
