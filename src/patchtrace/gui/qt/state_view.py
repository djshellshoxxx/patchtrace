"""The panel state strip and the window notice strip (GUI plan 8.4 `StateView`, `NoticeStrip`; copy in 8.4).

A blank panel reads as "no findings", so every panel shows one of the twelve states with words. ``StateView`` wraps
a panel's content: the status text and the action buttons sit above it and the content is shown only in the states
that have earlier or current results. Buttons are built once, hidden when not applicable and named per panel
("Retry loading Search") so that their names are unique in the window. Asynchronous changes are announced through
the injected announcer; the status label keeps an empty accessible name because a name change reaches UI
Automation only while the label is focused.

The host must have called ``gui.tips.register_gui_tips()`` before it builds a panel (the buttons use those tips).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QSizePolicy, QVBoxLayout, QWidget

from ..state import ACTION_LABELS, NOTICE_CHARS, NoticeModel, StateModel, action_name, dominant, state_model
from ..text import LABEL_LIMIT, sanitize_text
from ..tips import apply_tip
from .labels import PlainLabel, SafeTextView

# Where earlier or current results may still be shown. `ready` always shows its content; the others only when the
# panel says it has some (an error, a stale or a cancelled load leaves the earlier results in place).
CONTENT_KINDS = frozenset({'ready', 'partial', 'stale', 'refreshing', 'error', 'cancelled'})
_ACTION_TIPS = {'retry': 'gui.state_retry', 'copy': 'gui.state_copy', 'setup': 'gui.state_setup',
                'refresh': 'gui.state_refresh'}
_ACTION_ORDER = ('retry', 'copy', 'setup', 'refresh')


class Announcer(Protocol):
    def announce(self, text: str, assertive: bool = False) -> None: ...


class StateView(QWidget):
    retry_requested = Signal()
    setup_requested = Signal()
    refresh_requested = Signal()
    copy_requested = Signal(str)  # the details text; the host copies it (ShellPort.copy_text)

    def __init__(self, panel_id: str, title: str, announcer: Announcer | None = None,
                 parent: QWidget | None = None, *, text_limit: int = LABEL_LIMIT, multiline: bool = False) -> None:
        """`text_limit` and `multiline` are for a panel whose own state copy is longer than a line (default: one line)."""
        super().__init__(parent)
        self._title = sanitize_text(title)
        self._announcer = announcer
        self._model = StateModel('idle', '')
        self._content: QWidget | None = None
        self._has_content = False
        self.setObjectName(f'{panel_id}.state_view')
        self._status = PlainLabel(wrap=True, limit=text_limit, multiline=multiline)
        self._status.setObjectName(f'{panel_id}.state_status')
        self._status.setAccessibleName('')  # read when focused; changes are announced instead
        self._buttons = {action: self._button(panel_id, action) for action in _ACTION_ORDER}
        self._strip = QWidget()
        row = QHBoxLayout(self._strip)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self._status, 1)
        for button in self._buttons.values():
            row.addWidget(button)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.addWidget(self._strip, 0, Qt.AlignmentFlag.AlignTop)  # stays on top while there is no content
        self._apply(state_model('idle', self._title), False)  # the first words are not an event to announce

    def _button(self, panel_id: str, action: str) -> QPushButton:
        button = QPushButton(ACTION_LABELS[action])
        button.setAccessibleName(action_name(action, self._title))
        apply_tip(button, _ACTION_TIPS[action], name=f'{panel_id}.state_{action}')
        button.clicked.connect(getattr(self, f'_on_{action}'))
        button.hide()
        return button

    @property
    def kind(self) -> str:
        return self._model.kind

    @property
    def model(self) -> StateModel:
        return self._model

    def action_button(self, action: str) -> QPushButton:
        return self._buttons[action]

    def status_label(self) -> PlainLabel:
        return self._status

    def set_content(self, widget: QWidget) -> None:
        """The panel's own widget, shown below the strip in the states that keep results."""
        if self._content is not None:
            self._layout.removeWidget(self._content)
            self._content.hide()  # removed from the layout but still a child: it would float over the strip
        self._content = widget
        self._layout.addWidget(widget, 1)
        self._apply_content_visibility()

    def show_conditions(self, conditions: Mapping[str, Mapping[str, object]], *, has_content: bool = False) -> None:
        """Show the dominant state of several that apply at once (error > stale > partial > ready ...).
        ``conditions`` maps a state kind to the fields its copy needs."""
        kind = dominant(conditions)
        self.set_state(state_model(kind, self._title, **conditions.get(kind, {})), has_content=has_content)

    def set_state(self, model: StateModel, *, has_content: bool = False) -> None:
        changed = (model.kind, model.text) != (self._model.kind, self._model.text)
        self._apply(model, has_content)
        if changed and model.text and self._announcer is not None:
            self._announcer.announce(model.text, assertive=model.kind == 'error')

    def _apply(self, model: StateModel, has_content: bool) -> None:
        self._model, self._has_content = model, has_content
        self._status.setText(model.text)
        self._strip.setVisible(bool(model.text))
        for action, button in self._buttons.items():
            button.setVisible(action in model.actions)
        self._apply_content_visibility()

    def _apply_content_visibility(self) -> None:
        if self._content is not None:
            show = self._model.kind == 'ready' or (self._has_content and self._model.kind in CONTENT_KINDS)
            self._content.setVisible(show)

    def _on_retry(self) -> None:
        self.retry_requested.emit()

    def _on_setup(self) -> None:
        self.setup_requested.emit()

    def _on_refresh(self) -> None:
        self.refresh_requested.emit()

    def _on_copy(self) -> None:
        self.copy_requested.emit(self._model.detail or self._model.text)


_LEVEL_PREFIX = {'caution': 'Caution: ', 'notice': 'Note: '}  # the level is words, not only colour


class NoticeStrip(QWidget):
    """The window-level strip above the central workspace: one wrapped line with Details and Dismiss, hidden when
    there is nothing to say, never modal. A dismissed notice stays dismissed for its scope (project or session) and
    returns only when its text changes."""

    dismissed = Signal(str)  # the notice key

    def __init__(self, announcer: Announcer | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._announcer = announcer
        self._notices: dict[str, NoticeModel] = {}
        self._dismissed: dict[str, tuple[str, str]] = {}  # key -> (scope, text that was dismissed)
        self._current: NoticeModel | None = None
        self._announced: tuple[str, str] | None = None
        self.setObjectName('gui.notice')
        self.setAccessibleName('Notices')
        self._label = PlainLabel(wrap=True, limit=NOTICE_CHARS + 16)
        self._label.setAccessibleName('')
        self._details_button = QPushButton('Details')
        self._details_button.setCheckable(True)
        self._details_button.setAccessibleName('Show notice details')
        self._dismiss_button = QPushButton('Dismiss')
        self._dismiss_button.setAccessibleName('Dismiss notice')
        apply_tip(self, 'gui.notice')
        apply_tip(self._details_button, 'gui.notice_details', name='gui.notice_details')
        apply_tip(self._dismiss_button, 'gui.notice_dismiss', name='gui.notice_dismiss')
        self._details = SafeTextView('Notice details', wrap=True)
        apply_tip(self._details, 'gui.notice_text', name='gui.notice_text')
        self._details.setMaximumHeight(self.fontMetrics().lineSpacing() * 8)
        self._details.hide()
        top = QHBoxLayout()
        top.addWidget(self._label, 1)
        top.addWidget(self._details_button)
        top.addWidget(self._dismiss_button)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self._details)
        self._details_button.toggled.connect(self._details.setVisible)
        self._dismiss_button.clicked.connect(self._on_dismiss)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        self._refresh()

    @property
    def current(self) -> NoticeModel | None:
        """The notice on display, or None while the strip is hidden."""
        return self._current

    def set_notice(self, key: str, notice: NoticeModel | None) -> None:
        if notice is not None and notice.key != key:
            raise ValueError(f'notice key {notice.key!r:.40} differs from {key!r:.40}')
        if notice is None:
            self._notices.pop(key, None)
        else:
            self._notices[key] = notice
        self._refresh()

    def project_changed(self) -> None:
        """Project-scope dismissals end with the project; session-scope ones stay."""
        self._dismissed = {key: value for key, value in self._dismissed.items() if value[0] == 'session'}
        self._refresh()

    def _visible_notices(self) -> list[NoticeModel]:
        return [notice for key, notice in self._notices.items()
                if self._dismissed.get(key, (None, None))[1] != notice.text]

    def _refresh(self) -> None:
        shown = self._visible_notices()
        self._current = next((n for n in shown if n.level == 'caution'), shown[0] if shown else None)
        self.setVisible(self._current is not None)
        if self._current is None:
            self._details_button.setChecked(False)
            return
        notice = self._current
        extra = f' (+{len(shown) - 1} more)' if len(shown) > 1 else ''
        self._label.setText(f'{_LEVEL_PREFIX[notice.level]}{notice.text}{extra}')
        self._details.setPlainText(notice.detail)
        self._details_button.setVisible(bool(notice.detail))
        if not notice.detail:
            self._details_button.setChecked(False)
        self._dismiss_button.setVisible(notice.dismissible)
        if self._announcer is not None and self._announced != (notice.key, notice.text):
            self._announcer.announce(self._label.full_text())
        self._announced = (notice.key, notice.text)

    def _on_dismiss(self) -> None:
        notice = self._current
        if notice is None or not notice.dismissible:
            return
        self._dismissed[notice.key] = (notice.scope, notice.text)
        self._refresh()
        self.dismissed.emit(notice.key)
