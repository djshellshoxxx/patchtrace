"""Opt-in paired physical-offset controls; workers receive only readers and scalar values."""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject
from PySide6.QtGui import QKeySequence, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from .gui.qt.codediff import clear_selections, compose_selections, row_selection
from .gui.qt.labels import PlainLabel, labelled
from .gui.qt.theme import DARK
from .raw_alignment_view import AlignmentView, WindowRequest, build_alignment_view
from .tooltips import apply_tooltip


class RawAlignmentController(QObject):
    CHANNEL = 'raw-paired-alignment'

    def __init__(self, window, pane, layout):
        super().__init__(window)
        self.window = window
        self.pane = pane
        self.tasks = window.panels.tasks
        self.generation = 0
        self.context = None
        self.result: AlignmentView | None = None
        self.pending = False
        self.closed = False
        self._allocating_status = False
        self.menus = {}
        self.toggle = QCheckBox('Align paired physical offsets (bounded)')
        apply_tooltip(self.toggle, 'viewer.raw_align')
        layout.addWidget(self.toggle)
        self.controls = QWidget()
        controls = QVBoxLayout(self.controls)
        controls.setContentsMargins(0, 0, 0, 0)
        inputs = QHBoxLayout()
        self.offsets = {}
        for side in ('older', 'newer'):
            field = QLineEdit('0')
            field.setMaximumWidth(150)
            field.setMaxLength(18)
            inputs.addWidget(labelled(field, f'{side.title()} file offset (hex)'))
            inputs.addWidget(field)
            self.offsets[side] = field
            apply_tooltip(field, f'viewer.raw_align_{side}')
            field.textChanged.connect(self._input_changed)
            field.returnPressed.connect(self.request)
        self.size = QSpinBox()
        self.size.setRange(16, 4096)
        self.size.setSingleStep(16)
        self.size.setValue(4096)
        inputs.addWidget(labelled(self.size, 'Window bytes'))
        inputs.addWidget(self.size)
        apply_tooltip(self.size, 'viewer.raw_align_size')
        self.size.valueChanged.connect(self._input_changed)
        self.run = QPushButton('Align windows')
        apply_tooltip(self.run, 'viewer.raw_align_run')
        self.run.clicked.connect(self.request)
        inputs.addWidget(self.run)
        controls.addLayout(inputs)
        navigation = QHBoxLayout()
        self.spans = QComboBox()
        self.spans.setAccessibleName('Paired byte alignment spans')
        self.spans.setMinimumContentsLength(12)
        self.spans.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        apply_tooltip(self.spans, 'viewer.raw_align_spans')
        self.spans.currentIndexChanged.connect(self.select_span)
        navigation.addWidget(self.spans, 1)
        self.previous = QPushButton('Previous span')
        self.next = QPushButton('Next span')
        for button, step, tip in ((self.previous, -1, 'previous'), (self.next, 1, 'next')):
            apply_tooltip(button, f'viewer.raw_align_{tip}')
            button.clicked.connect(lambda checked=False, step=step: self.spans.setCurrentIndex(
                max(0, min(self.spans.count() - 1, self.spans.currentIndex() + step))))
            navigation.addWidget(button)
        controls.addLayout(navigation)
        self.status = PlainLabel('Enter independent physical offsets and align the bounded windows.',
                                 wrap=True, multiline=True, limit=2000)
        controls.addWidget(self.status)
        self.status.installEventFilter(self)
        layout.addWidget(self.controls)
        self.toggle.toggled.connect(self._toggle_changed)
        self.toggle.hide()
        self.controls.hide()
        pane.installEventFilter(self)
        for side, view in window.views.items():
            view.installEventFilter(self)
            view.viewport().installEventFilter(self)
            menu = QMenu(window)
            action = menu.addAction('Copy original window bytes')
            apply_tooltip(action, f'viewer.copy_{side}')
            action.triggered.connect(lambda checked=False, side=side: self._copy_from_menu(side))
            self.menus[side] = menu
        QApplication.instance().aboutToQuit.connect(self.shutdown)
        window.inspection_status.connect(self._inspection_status)
        self._navigation()

    def active(self):
        return self.toggle.isChecked() and self.window.mode.currentIndex() in (3, 4)

    def _key(self):
        window = self.window
        match = window.current_match()
        return (window._project_inspection_key(), id(window._current_inspection()),
                window.project.revision if window.project else None,
                match.id if match else None, window.mode.currentIndex(), self.toggle.isChecked(),
                tuple(field.text() for field in self.offsets.values()), self.size.value())

    def sync(self):
        key = self._key()
        if key != self.context:
            self.invalidate()
            self.context = key
        eligible = self.window.mode.currentIndex() in (3, 4)
        self.toggle.setVisible(eligible)
        self.controls.setVisible(self.active())
        for widget in (self.window.raw_scope, self.window.raw_page, self.window.raw_goto):
            widget.setVisible(self.window._raw_mode() and not self.active())

    def invalidate(self):
        self.generation += 1
        self.tasks.cancel(self.CHANNEL)
        self.pending = False
        self.result = None
        for menu in self.menus.values():
            menu.hide()
        self.spans.clear()
        self._navigation()
        if self.active():
            self.window._raw_sides = {}
            self.window.match_label.setText('Paired physical windows · result cleared')
            self.window.match_label.setToolTip('No current paired window bytes.')
            for view in self.window.views.values():
                clear_selections(view, 'diff')
                view.setPlainText('[Paired windows not aligned; choose offsets and Align windows.]')
            self._status('Paired window result cleared. Choose physical offsets and Align windows.')

    def _status(self, text):
        self.status.setText(text)
        self._allocate_status()

    def _allocate_status(self):
        if self._allocating_status:
            return
        self._allocating_status = True
        try:
            # Splitters need not propagate a nested label's height-for-width.
            # Use its current wrapped height as a minimum, releasing it for shorter text.
            for _ in range(2):
                width = self.status.width()
                self.status.setMinimumHeight(0)
                self.status.setMinimumHeight(max(0, self.status.heightForWidth(width)))
                self.status.updateGeometry()
                self.controls.layout().invalidate()
                self.controls.layout().activate()
                self.controls.updateGeometry()
                self.pane.layout().invalidate()
                self.pane.layout().activate()
                if self.status.width() == width:
                    break
        finally:
            self._allocating_status = False

    def _toggle_changed(self):
        self.sync()
        self.window.render_match()

    def _input_changed(self):
        self.invalidate()
        self.context = self._key()

    def _inspection_status(self, _message):
        failure = self.window._inspection_error
        if not self.closed and self.active() and failure and failure[0] == self.window._project_inspection_key():
            self.invalidate()
            self._status('Verified artifact inspection failed: ' + failure[1])

    def render(self):
        """Called by the desktop only for an active raw view."""
        if self.result is not None:
            self._display(self.result)
            self.select_span(self.spans.currentIndex())
        elif not self.pending:
            self.request()

    def request(self):
        self.sync()
        if self.closed or not self.active() or self.pane.isHidden() or not self.window.current_match():
            return
        self.invalidate()
        inspection = self.window._current_inspection()
        if inspection is None:
            failure = self.window._inspection_error
            if failure and failure[0] == self.window._project_inspection_key():
                self._inspection_status('')
                return
            self._status('Waiting for verified artifact inspection.')
            self.window.start_inspection()
            return
        readers = [inspection.reader(side) for side in ('older', 'newer')]
        if any(reader is None for reader in readers):
            reasons = '; '.join(f'{side}: {info.error_code or "unavailable"}'
                                for side, info in inspection.sides.items() if inspection.reader(side) is None)
            self._status('Alignment unavailable: verified bytes missing · ' + reasons)
            return
        try:
            offsets = [int(field.text().strip(), 16) for field in self.offsets.values()]
            if any(offset < 0 or offset > reader.size for offset, reader in zip(offsets, readers, strict=True)):
                raise ValueError('Physical offsets must be within each file, including EOF')
            if self.size.value() % 16:
                raise ValueError('Window bytes must be a multiple of 16')
        except ValueError as exc:
            self._status(f'Invalid paired window: {exc}')
            return
        request = WindowRequest(*readers, *offsets, self.size.value(),
                                self.window.RAW_MODES[self.window.mode.currentIndex()])
        generation, key = self.generation, self._key()
        self.context = key
        self.pending = True
        self._status('Reading and aligning verified physical windows…')

        def work(token, report):
            token.raise_if_cancelled()
            return build_alignment_view(request, token.checkpoint)

        self.tasks.submit(self.CHANNEL, work,
                          on_result=lambda result: self._ready(result, generation, key),
                          on_error=lambda error: self._failed(error, generation, key))

    def _current(self, generation, key):
        return (not self.closed and self.active() and not self.pane.isHidden()
                and generation == self.generation and key == self._key())

    def _ready(self, result, generation, key):
        if not self._current(generation, key):
            return
        self.pending = False
        self.result = result
        self.spans.blockSignals(True)
        self.spans.clear()
        self.spans.addItems([row.label for row in result.spans])
        self.spans.blockSignals(False)
        self._display(result)
        self.select_span(self.spans.currentIndex())

    def _failed(self, error, generation, key):
        if self._current(generation, key):
            self.pending = False
            self._status(f'Paired window unavailable: {error.text}; re-inspect if the artifact changed.')

    def _display(self, result):
        for side in ('older', 'newer'):
            self.window.views[side].setPlainText(getattr(result, f'{side}_text'))
        self.window.match_label.setText('Paired physical windows · original on-disk bytes · display-only gaps')
        self.window.match_label.setToolTip(result.older.caption + '\n\n' + result.newer.caption)
        self._status(result.summary)
        self._navigation()

    def _navigation(self):
        index = self.spans.currentIndex()
        self.previous.setEnabled(index > 0)
        self.next.setEnabled(0 <= index < self.spans.count() - 1)
        self.spans.setEnabled(self.spans.count() > 0)

    def select_span(self, index):
        self._navigation()
        if self.result is None or not 0 <= index < len(self.result.spans):
            return
        span = self.result.spans[index]
        for view in self.window.views.values():
            selection = row_selection(view, span.line, span.end_line, DARK.hunk_replace)
            compose_selections(view, 'diff', [selection] if selection else [])
            cursor = QTextCursor(view.document().findBlockByNumber(span.line))
            view.setTextCursor(cursor)
            view.centerCursor()

    def copy_text(self, side):
        if self.result is None or self.context != self._key() or self.pane.isHidden() or self.closed:
            return None
        return getattr(self.result, side).copy_text

    def copy(self, side, provenance, artifact):
        text = self.copy_text(side)
        if text is None:
            self.window.statusBar().showMessage('No current paired window bytes; nothing copied.')
            return
        text = provenance + f'{side}: {artifact.name}\nArtifact SHA-256: {artifact.sha256}\n\n{text}'
        QApplication.clipboard().setText(text)
        self.window.statusBar().showMessage('Copied original window bytes with provenance; display gaps excluded.')

    def _copy_from_menu(self, side):
        if self.active():
            self.window.copy_code(side)

    def eventFilter(self, watched, event):  # noqa: N802
        if self.closed:
            return False
        if watched is self.status and event.type() in (
                QEvent.Type.Resize, QEvent.Type.FontChange, QEvent.Type.StyleChange):
            self._allocate_status()
        if watched is self.pane and event.type() == QEvent.Type.Hide:
            self.invalidate()
        if event.type() == QEvent.Type.KeyPress and self.active() and event.matches(QKeySequence.StandardKey.Copy):
            for side, view in self.window.views.items():
                if watched is view:
                    self.window.copy_code(side)
                    return True
        if event.type() == QEvent.Type.ContextMenu and self.active():
            for side, view in self.window.views.items():
                if watched is view or watched is view.viewport():
                    menu = self.menus[side]
                    menu.actions()[0].setEnabled(self.copy_text(side) is not None)
                    menu.popup(event.globalPos())
                    return True
        return super().eventFilter(watched, event)

    def shutdown(self):
        if not self.closed:
            self.invalidate()
            self.closed = True
            self.pane.removeEventFilter(self)
            for view in self.window.views.values():
                view.removeEventFilter(self)
                view.viewport().removeEventFilter(self)
