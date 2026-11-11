"""Qt presentation of the Build environment panel (DIE D5, GUI plan 8.10). Everything that decides what is said lives
in the Qt-free `buildenv.view_model` and `buildenv.panel_model`; this module moves it to widgets.

The project database belongs to the GUI thread, so the GUI thread takes the artifacts and the stored Detect It Easy
results (`take_request`); the worker only reads the hash-checked files from that immutable request. A result is
applied only when the controller epoch and the project key still match those captured at submit time, so a late
result of another project or of a closed panel is dropped. The panel runs no tool and opens no network."""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from ..gui.anchors import AnchorRef, NavResult
from ..gui.qt.docks import ControllerBase
from ..gui.qt.labels import SafeTextView
from ..gui.qt.state_view import StateView
from ..gui.qt.table import VirtualTable
from ..gui.registry import PanelContext
from ..gui.state import StateModel, state_model
from ..gui.table_spec import prepare_table
from ..gui.tips import apply_tip, register_gui_tips, register_tips
from .contracts import BuildEnvError
from .delta import compute_delta
from .panel_model import (
    COLUMNS,
    NOTICE_KEY,
    SPEC,
    Outcome,
    ReadRequest,
    anchor_fact,
    card_text,
    detail_text,
    notice_of,
    read_pair,
    state_of,
    take_request,
)
from .tooltip_entries import TEMPLATES, TIPS
from .view_model import BuildEnvViewModel, build_view, reading_view

CHANNEL = 'build_env.read'
DETAIL_LIMIT = 16_384
CANCELLED = 'Cancelled. Earlier results are unchanged.'
SETUP_HINT = ('Detect It Easy is set up outside PatchTrace. Install it, then run `patchtrace intel-tools run '
              '--engines diec` on this project and use Read again. Nothing is downloaded.')


class BuildEnvController(ControllerBase):
    """Owns the last good view and the one read in flight. Hooks run on the GUI thread."""

    def __init__(self, ctx: PanelContext, *, taker: Callable = take_request, reader: Callable = read_pair) -> None:
        register_gui_tips()
        register_tips(TIPS, TEMPLATES)
        super().__init__(QWidget())
        self.ctx, self.port, self.tasks = ctx, ctx.project, ctx.tasks
        self.taker, self.reader = taker, reader
        self.key = None
        self.epoch = 0
        self.closed = False
        self.outcome: Outcome | None = None
        self.good: BuildEnvViewModel | None = None
        self.error: str | None = None
        self.cancelled = False
        self.progress: tuple[str, int, int] | None = None
        self.technical = False
        self._build_widgets()
        self._render()

    # ---- widgets -------------------------------------------------------------------------------------

    def _build_widgets(self) -> None:
        root = self._widget
        root.setObjectName('build_env.card')
        root.setAccessibleName('Build environment')
        self.view = StateView('build_env', 'Build environment', self.ctx.shell, text_limit=600)
        self.view.setAccessibleName('Build environment state')
        self.table = VirtualTable('Build facts table')
        self.table.setObjectName('build_env.table')
        apply_tip(self.table, 'build_env.table')
        self.detail = SafeTextView('Build environment details', limit=DETAIL_LIMIT, wrap=True)
        self.detail.setObjectName('build_env.detail')
        apply_tip(self.detail, 'build_env.detail')
        self.buttons = {
            action: self._button(action, text, name) for action, text, name in (
                ('reread', 'Read again', 'Read the build environment again'),
                ('cancel', 'Cancel', 'Cancel reading the build environment'),
                ('copy', 'Copy', 'Copy the build environment as text'))}
        self.technical_box = QCheckBox('Technical details')
        self.technical_box.setAccessibleName('Show technical details')
        self.technical_box.setObjectName('build_env.technical')
        apply_tip(self.technical_box, 'build_env.technical')
        bar = QHBoxLayout()
        for button in self.buttons.values():
            bar.addWidget(button)
        bar.addWidget(self.technical_box)
        bar.addStretch(1)
        content = QWidget()
        column = QVBoxLayout(content)
        column.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self.table, 3)
        column.addWidget(self.detail, 2)
        self.view.set_content(content)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.addLayout(bar)  # outside the state view's content: Cancel must work while nothing is shown yet
        layout.addWidget(self.view, 1)
        root.setFocusProxy(self.table)
        self.view.retry_requested.connect(self.read)
        self.view.refresh_requested.connect(self.read)
        self.view.setup_requested.connect(lambda: self.ctx.shell.status(SETUP_HINT))
        self.view.copy_requested.connect(self._copy_text)
        self.technical_box.toggled.connect(self._technical_toggled)
        self.table.detail_requested.connect(lambda _key: self.detail.setFocus())

    def _button(self, action: str, text: str, name: str) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(name)
        button.setObjectName(f'build_env.{action}')
        apply_tip(button, f'build_env.{action}')
        button.clicked.connect(lambda _checked=False, a=action: self._action(a))
        return button

    def _action(self, action: str) -> None:
        if action == 'reread':
            self.read()
        elif action == 'cancel':
            self.cancel()
        elif self.good is not None:
            self._copy_text(card_text(self.good))

    def _copy_text(self, text: str) -> None:
        self.ctx.shell.copy_text(text)

    # ---- host hooks ----------------------------------------------------------------------------------

    def project_changed(self, key) -> None:
        self.tasks.cancel(CHANNEL)
        self.epoch += 1
        self.key = key
        self.outcome = self.good = self.error = self.progress = None
        self.cancelled = False
        self.ctx.shell.notice(NOTICE_KEY, None)
        self._show_rows()
        if key is None:
            self._render()
        else:
            self.read()

    def shutdown(self) -> None:
        self.closed = True
        self.epoch += 1
        self.progress = None
        self.tasks.cancel(CHANNEL)
        self.ctx.shell.notice(NOTICE_KEY, None)

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        if anchor.kind != 'build_fact':
            return NavResult.blocked('Build environment', f'it does not open {anchor.kind} links')
        if self.good is None:
            return NavResult.blocked('Build environment', 'no build facts are loaded')
        fact = anchor_fact(self.outcome, anchor.side, anchor.key)
        row = self.table.table_model.view_row_of(fact) if fact else -1
        if row < 0:
            return NavResult.not_found(anchor.label or anchor.key, anchor.run_id)
        self.table.selectRow(row)
        self.table.scrollTo(self.table.currentIndex())
        return NavResult.shown()

    # ---- reading -------------------------------------------------------------------------------------

    def read(self) -> None:
        """GUI thread: take the request from the project, then read the files on the runner."""
        service, project = getattr(self.port, 'service', None), self.port.project()
        if self.closed or service is None or project is None or self.key is None:
            return self._render()
        try:
            request = self.taker(service, project, self.key)
        except Exception:  # noqa: BLE001 - any storage failure becomes one stable code, never a crash
            self.error = 'PT-BUILD-STORAGE'
            return self._render()
        self.error, self.cancelled, self.progress = None, False, ('older', 0, 2)
        epoch, reader = self.epoch, self.reader
        self.tasks.submit(CHANNEL, lambda token, report: reader(request, token, report),
                          lambda outcome: self._done(epoch, request, outcome), lambda _f: self._failed(epoch),
                          self._on_progress)
        self._render()

    def cancel(self) -> None:
        self.tasks.cancel(CHANNEL)
        self.epoch += 1
        self.progress, self.cancelled = None, True
        self._render()

    def _current(self, epoch: int, request: ReadRequest | None = None) -> bool:
        return not self.closed and epoch == self.epoch and (request is None or request.key == self.key)

    def _on_progress(self, progress) -> None:
        if self.progress is not None:
            total = progress.total or 2
            self.progress = (progress.stage, min(progress.done + 1, total), total)
            self._render()

    def _failed(self, epoch: int) -> None:
        if self._current(epoch):
            self.error, self.progress = 'PT-BUILD-INPUT', None
            self._render()

    def _done(self, epoch: int, request: ReadRequest, outcome: Outcome) -> None:
        if not self._current(epoch, request):
            return
        self.progress = None
        if outcome.cancelled:
            self.cancelled = True
        elif outcome.error:
            self.error = outcome.error
        else:
            self.outcome = outcome
            self._rebuild()
            self.ctx.shell.notice(NOTICE_KEY, notice_of(self.good.banners) if self.good else None)
        self._render()

    # ---- view ----------------------------------------------------------------------------------------

    def _rebuild(self) -> None:
        outcome = self.outcome
        try:
            delta = compute_delta(outcome.older, outcome.newer) if outcome.older and outcome.newer else None
        except BuildEnvError:
            self.error, delta = 'PT-BUILD-MISMATCH', None
            return
        self.good = build_view(outcome.older, outcome.newer, delta, stale=outcome.stale, technical=self.technical)
        self._show_rows()

    def _technical_toggled(self, checked: bool) -> None:
        self.technical = checked
        if self.outcome is not None:
            self._rebuild()
            self._render()

    def _status(self) -> StateModel:
        if self.error:
            return StateModel('error', build_view(None, None, None, error_code=self.error).state_text,
                              actions=('retry', 'copy'))
        if self.progress is not None:
            side, done, total = self.progress
            text = reading_view(side, done, total).state_text
            return StateModel('refreshing' if self.good else 'loading', text)
        if self.cancelled:
            return StateModel('cancelled', CANCELLED)
        if self.good is not None:
            return state_of(self.good)
        if self.key is None:
            return state_of(build_view(None, None, None, project_open=False))
        return state_model('idle', 'Build environment', hint='Choose Read again.')

    def _show_rows(self) -> None:
        rows = self.good.rows if self.good else ()
        self.table.set_prepared(prepare_table(SPEC, COLUMNS, rows))
        self.detail.setPlainText(detail_text(self.good) if self.good else '')

    def _render(self) -> None:
        reading = self.progress is not None
        self.buttons['reread'].setEnabled(self.key is not None and not reading)
        self.buttons['cancel'].setVisible(reading)
        self.buttons['copy'].setEnabled(self.good is not None)
        self.view.set_state(self._status(), has_content=self.good is not None)
