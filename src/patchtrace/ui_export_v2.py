"""Report v2 controls of the Export dialog (SPEC-50 section 8): contract, profile and section choices bound to the
Qt-free `report2.export_vm.ExportViewModel`, which owns every rule.

Kept out of `ui.py` (the GUI-framework seam budget): the dialog calls `attach` once and asks for `export_kwargs`.
The widgets are set as attributes of the dialog (`vm`, `contract`, `profile`, `sections_list`, `hint`) so the dialog's
existing tooltip and test surface stays the same.
"""
from __future__ import annotations

from collections.abc import Callable
from itertools import pairwise

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QWidget,
)

from .gui.qt.labels import PlainLabel
from .report2 import export_vm
from .tooltips import apply_tooltips

FIRST_ROW = 2   # directly after the Format and Destination rows


def attach(dialog: QDialog, form: QFormLayout, project, sections, refresh: Callable[[], None]) -> None:
    """Add the report v2 rows to `form` and bind them to a new view-model stored as `dialog.vm`. `refresh` re-renders
    the preview after every choice; it runs once more at the end of the dialog's own constructor."""
    dialog.vm = export_vm.ExportViewModel(project, sections)
    dialog.contract, dialog.profile = QComboBox(), QComboBox()
    dialog.contract.addItems(export_vm.CONTRACTS)
    dialog.profile.addItems(export_vm.PROFILES)
    dialog.sections_list = QListWidget()
    dialog.sections_list.setMaximumHeight(150)
    dialog.hint = PlainLabel(wrap=True)   # wraps, never elides: the hint and the warning are read in full
    for name, widget in (('contract', dialog.contract), ('profile', dialog.profile),
                         ('sections', dialog.sections_list)):
        widget.setAccessibleName(export_vm.ACCESSIBLE_NAMES[name])
    for offset, (label, widget) in enumerate((('&Contract', dialog.contract), ('&Profile', dialog.profile),
                                              ('&Sections', dialog.sections_list))):
        form.insertRow(FIRST_ROW + offset, label, widget)
    form.insertRow(FIRST_ROW + 3, dialog.hint)
    apply_tooltips(dialog, {'contract': 'export.contract', 'profile': 'export.profile',
                            'sections_list': 'export.sections'})

    def choose(setter, index):
        show(dialog, setter(index))
        refresh()

    def toggle(item):
        dialog.vm.set_section_checked(item.data(Qt.ItemDataRole.UserRole),
                                      item.checkState() == Qt.CheckState.Checked)
        refresh()

    dialog.contract.currentIndexChanged.connect(lambda index: choose(dialog.vm.set_contract, index))
    dialog.profile.currentIndexChanged.connect(lambda index: choose(dialog.vm.set_profile, index))
    dialog.sections_list.itemChanged.connect(toggle)
    show(dialog)


def show(dialog: QDialog, notice: str | None = None) -> None:
    """Reflect the view-model in the widgets (signals blocked) and in the code and notes checkboxes; the local-profile
    warning shows once per dialog and only for report v2."""
    widgets = (dialog.contract, dialog.profile, dialog.sections_list)
    for widget in widgets:
        widget.blockSignals(True)
    dialog.contract.setCurrentIndex(dialog.vm.contract_index)
    dialog.profile.setCurrentIndex(dialog.vm.profile_index)
    dialog.sections_list.clear()
    for row in dialog.vm.section_rows():
        item = QListWidgetItem(f'{row.label} ({row.count})' if row.enabled else f'{row.label}: {row.reason}')
        item.setData(Qt.ItemDataRole.UserRole, row.key)
        item.setFlags((item.flags() | Qt.ItemFlag.ItemIsUserCheckable) if row.enabled
                      else item.flags() & ~(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable))
        item.setCheckState(Qt.CheckState.Checked if row.checked else Qt.CheckState.Unchecked)
        dialog.sections_list.addItem(item)
    for widget in widgets:
        widget.blockSignals(False)
    sharing = bool(dialog.vm.profile_index)
    for name in ('code', 'notes'):    # the dialog's own checkboxes exist once its constructor has finished
        checkbox = getattr(dialog, name, None)
        if checkbox is not None:
            checkbox.setEnabled(not sharing)
    warning = dialog.vm.take_local_warning() if dialog.vm.report_version == 2 else None
    dialog.hint.setText(' '.join(filter(None, (notice, dialog.vm.profile_hint() or warning))))
    _configure_keyboard(dialog)


class _FocusedButtonDefaults(QObject):
    """Keep Qt's Enter/Space handling, but never leave a default action behind in an export field."""

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if isinstance(watched, QDialogButtonBox) and event.type() == QEvent.Type.ShowToParent:
            # QDialogButtonBox assigns its first AcceptRole button as default in showEvent,
            # even with autoDefault disabled. ShowToParent follows that native initialization.
            for button in watched.buttons():
                button.setDefault(button.hasFocus())
        elif isinstance(watched, QPushButton):
            if event.type() == QEvent.Type.FocusIn:
                watched.setDefault(True)
            elif event.type() == QEvent.Type.FocusOut:
                watched.setDefault(False)
        return super().eventFilter(watched, event)


def _configure_keyboard(dialog: QDialog) -> None:
    """Run once, on the constructor's final show() call after the legacy controls and buttons exist."""
    if not hasattr(dialog, 'buttons') or hasattr(dialog, '_export_keyboard'):
        return
    browse = dialog.findChild(QPushButton, 'export.browse')
    write = dialog.buttons.button(QDialogButtonBox.StandardButton.Ok)
    cancel = dialog.buttons.button(QDialogButtonBox.StandardButton.Cancel)
    dialog._export_keyboard = _FocusedButtonDefaults(dialog)
    dialog.buttons.installEventFilter(dialog._export_keyboard)
    for button in (browse, write, cancel):
        button.setAutoDefault(False)
        button.setDefault(False)
        button.installEventFilter(dialog._export_keyboard)
    controls = (dialog.format, dialog.destination, browse, dialog.contract, dialog.profile,
                dialog.sections_list, dialog.code, dialog.notes, dialog.selection, dialog.preview, write, cancel)
    for before, after in pairwise(controls):
        QWidget.setTabOrder(before, after)


def report_sections(service, log: Callable[[str], None]):
    """Report v2 sections read from the stored producers on the owner thread; a failure only leaves v2 bare."""
    try:
        from .report2.adapters import collect_from_service
        return collect_from_service(service)
    except Exception as exc:  # noqa: BLE001 - the dialog still opens and report v1 is unaffected
        log(f'Export sections unavailable: {type(exc).__name__}')
        return None
