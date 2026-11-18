"""Explicit whole-comparison timeout editing; no execution or settings writes."""
from __future__ import annotations

import re

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QWidget

from .gui.qt.labels import PlainLabel
from .tooltips import apply_tooltip

ERROR = 'Enter a whole number from 10 to 86400 seconds.'


class TimeoutEdit(QLineEdit):
    """Keep rejected input visible instead of QSpinBox's focus-out correction."""

    def value(self) -> int:
        text = self.text().strip()
        if not re.fullmatch(r'[0-9]{1,5}', text) or not 10 <= int(text) <= 86400:
            raise ValueError(ERROR)
        return int(text)

    def setValue(self, value: int) -> None:
        self.setText(str(value))


class TimeoutChoice:
    def __init__(self, form, seconds: int):
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        self.edit = TimeoutEdit()
        self.edit.setValue(seconds)
        self.presets = QComboBox()
        for label, value in [('Custom', None), ('1 hour (3600 seconds)', 3600),
                             ('2 hours (7200 seconds)', 7200), ('4 hours (14400 seconds)', 14400)]:
            self.presets.addItem(label, value)
        self.presets.setAccessibleName('Comparison timeout preset')
        self.edit.setAccessibleName('Comparison timeout in seconds')
        apply_tooltip(self.presets, 'setup.timeout_preset')
        apply_tooltip(self.edit, 'setup.timeout')
        layout.addWidget(self.edit)
        layout.addWidget(self.presets)
        form.addRow('Comparison timeout (seconds)', row)
        self.error = PlainLabel('')
        self.error.setWordWrap(True)
        self.error.setObjectName('setup.timeout_error')
        self.error.setAccessibleName('Comparison timeout validation')
        form.addRow(self.error)
        self.note = PlainLabel('Whole comparison budget, not a per-function timeout. '
                               'A longer budget is not a performance fix.')
        self.note.setWordWrap(True)
        form.addRow(self.note)
        self.presets.activated.connect(self._choose)
        self.edit.textChanged.connect(self._edited)
        self._edited()

    def _choose(self, index: int) -> None:
        seconds = self.presets.itemData(index)
        if seconds is not None:
            self.edit.setValue(seconds)

    def _edited(self, _text: str = '') -> None:
        try:
            seconds = self.edit.value()
        except ValueError:
            seconds = None
        self.presets.setCurrentIndex(max(0, self.presets.findData(seconds)))
        self.error.setText('' if seconds is not None else ERROR)

    def validate(self) -> bool:
        try:
            self.edit.value()
        except ValueError:
            self.error.setText(ERROR)
            self.edit.setFocus()
            self.edit.selectAll()
            return False
        return True
