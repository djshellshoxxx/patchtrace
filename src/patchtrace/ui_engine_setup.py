"""BinDiff + BinExport run setup for the Engines tab (track G, multi-engine-evidence-panel.md §16).

Two reusable GUI-thread pieces, embedded in the C6 Engines tab and usable unchanged by the planned SPEC-31
dock tab:

* :class:`BinDiffSetupPanel` - widgets only: executable combo + Browse + Probe BinDiff, older/newer
  ``.BinExport`` pickers, the explicit unbound confirmation with its warning, Validate/Cancel, two plain status
  lines and on-demand technical details. It emits intents and never runs anything.
* :class:`BinDiffSetupController` - discovery, probe and validation on unparented :class:`TaskThread` workers
  (module registry ``_LIVE_THREADS``, generation counters, ``shutdown`` joins), plus the resulting BinDiff
  capability and :class:`BinDiffSetup` for runs.

Every BinDiff/BinExport decision is the CLI's, reached through the pure helpers of
``secondary.evidence_panel_service``. Thread rules (C6 §5.3): workers get immutable inputs and emit signals
only; they never touch widgets, ``QSettings``, the clipboard, the project service or SQLite. Every string shown
is plain text (``Qt.PlainText`` labels, ``QPlainTextEdit.setPlainText``); tooltips come from the registry.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QWidget,
)
from shiboken6 import isValid

from .runtime_discovery import discover_local_runtimes
from .secondary.evidence_panel_service import (
    PROBE_TEXT,
    VALIDATION_TEXT,
    BinDiffProbeView,
    BinDiffSetup,
    BinExportValidation,
    ValidationRequest,
    probe_bindiff,
    setup_capability,
    validate_binexports,
)
from .secondary.evidence_view import sanitize_text
from .tooltips import apply_tooltip

SETTING_PATH = 'engines/bindiff/path'           # written only after a successful explicit probe
SETTING_OPEN = 'engines/bindiff/setup_open'     # section shown or hidden
PATH_LIMIT = 4096
MAX_CANDIDATES = 16
EXECUTABLE_FILTER = 'BinDiff executable (bindiff bindiff.exe);;All files (*)'
BINEXPORT_FILTER = 'BinExport files (*.BinExport *.binexport);;All files (*)'
WARNING_TEXT = ("Warning: tick this only for files you exported yourself from exactly this project's older and "
                'newer files. Without a SHA-256 id PatchTrace cannot check which file an export came from, so a '
                'wrong file gives meaningless pairings. Your confirmation is stored with the BinDiff result; a '
                'SHA-256 id that does not match is still refused.')
HELP_TEXT = ('How to produce .BinExport files: in Ghidra use File > Export > "Binary BinExport (v2) for BinDiff"; '
             'in IDA 9.4 or newer use Edit > Plugins > BinExport. Export each project file once, with the same '
             '"Subtract Imagebase" choice. Older is BinDiff\'s primary, newer its secondary. Nothing is uploaded '
             'and the binaries are never run.')
DETAILS_EMPTY = 'No probe or validation result yet.'
ACCESSIBLE_NAMES = {
    'toggle': 'Show BinDiff run setup',
    'section': 'BinDiff run setup',
    'bindiff_path': 'BinDiff executable path',
    'bindiff_browse': 'Browse for the BinDiff executable',
    'bindiff_probe': 'Probe the BinDiff executable',
    'older_binexport': 'Older BinExport file path',
    'older_browse': 'Browse for the older BinExport file',
    'newer_binexport': 'Newer BinExport file path',
    'newer_browse': 'Browse for the newer BinExport file',
    'accept_unbound': 'Accept BinExport files without a SHA-256 executable id',
    'unbound_warning': 'Warning about BinExport files without a SHA-256 executable id',
    'validate': 'Validate the BinExport files',
    'cancel_validation': 'Cancel BinExport validation',
    'validation_progress': 'BinExport validation progress',
    'show_details': 'Show technical details of the BinDiff setup',
    'details': 'BinDiff setup technical details',
}
_LIVE_THREADS: set[QThread] = set()  # a running QThread must never be garbage collected


def thread_alive(thread) -> bool:
    return thread is not None and isValid(thread) and thread.isRunning()


def choose_file(parent, title: str, start: str, filters: str) -> str:
    """Modal file dialog (module level so tests can replace it). Returns '' when cancelled."""
    path, _ = QFileDialog.getOpenFileName(parent, title, start, filters)
    return path or ''


def discover_bindiff() -> tuple[str, ...]:
    """Read-only discovery (SPEC-29 §8): fixed install folders and `PATCHTRACE_BINDIFF`; never PATH, never run."""
    return tuple(str(path) for path in discover_local_runtimes().bindiff_executables)


def _setting_text(settings, key: str) -> str:
    if settings is None:
        return ''
    try:
        value = settings.value(key, '')
    except Exception:  # noqa: BLE001 - corrupted settings fall back to defaults
        return ''
    return sanitize_text(value, PATH_LIMIT).strip() if isinstance(value, str) else ''


def _setting_bool(settings, key: str) -> bool:
    if settings is None:
        return False
    try:
        value = settings.value(key, False)
    except Exception:  # noqa: BLE001
        return False
    return value if isinstance(value, bool) else str(value).strip().lower() in ('true', '1')


def _save(settings, key: str, value) -> None:
    if settings is None:
        return
    try:
        settings.setValue(key, value)
    except Exception:  # noqa: BLE001
        pass


class _PlainLabel(QLabel):
    """File strings and messages are always text, never Qt rich text (same rule as ui_evidence.PlainLabel)."""

    def __init__(self, text: str = '', parent=None):
        super().__init__(text, parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setOpenExternalLinks(False)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self.setWordWrap(True)


@dataclass(frozen=True)
class TaskFailure:
    """A task raised unexpectedly; only the exception class name crosses the thread boundary."""
    name: str


class TaskThread(QThread):
    """Runs ``task(cancel, report)`` once on immutable inputs and emits its result with the generation.

    No Qt parent: destroying a running QThread (deleted parent, or garbage collection of an unreferenced
    started thread) aborts the process, so ``_LIVE_THREADS`` holds it until ``finished`` and it is deleted
    later (pattern of ``ui_evidence``/``ui_series``). A cancelled task emits nothing."""
    done = Signal(object, int)
    progress = Signal(object, int)

    def __init__(self, task: Callable, generation: int):
        super().__init__()
        self.cancel = threading.Event()
        self.task = task
        self.generation = generation
        _LIVE_THREADS.add(self)
        self.finished.connect(self._release)

    def _release(self) -> None:
        _LIVE_THREADS.discard(self)
        self.deleteLater()

    def run(self):
        generation, cancel = self.generation, self.cancel

        def report(value) -> None:
            if not cancel.is_set():
                self.progress.emit(value, generation)
        try:
            result = self.task(cancel, report)
        except Exception as exc:  # noqa: BLE001 - class name only; messages may carry paths
            result = TaskFailure(type(exc).__name__)
        if not cancel.is_set():
            self.done.emit(result, generation)


class BinDiffSetupPanel(QGroupBox):
    """The "BinDiff run setup" section. Widgets only: no project, service, thread or tool logic.

    ``toggle_button`` is created here but placed by the host (C6: the Engines tab controls row); it shows and
    hides this section. The host must give the section a parent before it is shown."""
    probe_requested = Signal(str)
    validate_requested = Signal()
    cancel_requested = Signal()
    executable_edited = Signal()
    inputs_edited = Signal()
    opened = Signal(bool)

    def __init__(self, settings=None, parent=None):
        super().__init__('BinDiff run setup', parent)
        self.settings = settings
        self.has_project = False
        self.locked = False
        self.probing = False
        self.validating = False
        apply_tooltip(self, 'engine_setup.section')
        self.setAccessibleName(ACCESSIBLE_NAMES['section'])
        self.toggle_button = QPushButton('BinDiff setup')
        self.toggle_button.setCheckable(True)
        self._control(self.toggle_button, 'toggle')
        grid = QGridLayout(self)
        grid.setContentsMargins(6, 6, 6, 6)
        grid.setColumnStretch(1, 1)
        self.path = QComboBox()
        self.path.setEditable(True)
        self.path.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.path.setCompleter(None)  # no inline completion: the text is exactly what the user typed or picked
        self.path.lineEdit().setMaxLength(PATH_LIMIT)
        self.path.lineEdit().setPlaceholderText('absolute path of bindiff (bindiff.exe on Windows)')
        self._control(self.path, 'bindiff_path')
        self.browse_exe = self._control(QPushButton('Browse...'), 'bindiff_browse')
        self.probe_button = self._control(QPushButton('Probe BinDiff'), 'bindiff_probe')
        self.probe_status = _PlainLabel(PROBE_TEXT['empty'])
        self.probe_status.setObjectName('engine_setup_probe_status')  # empty accessible name: setText announces
        self.older = self._control(QLineEdit(), 'older_binexport')
        self.older.setMaxLength(PATH_LIMIT)
        self.older.setPlaceholderText('export of the older file (BinDiff primary)')
        self.older_browse = self._control(QPushButton('Browse...'), 'older_browse')
        self.newer = self._control(QLineEdit(), 'newer_binexport')
        self.newer.setMaxLength(PATH_LIMIT)
        self.newer.setPlaceholderText('export of the newer file (BinDiff secondary)')
        self.newer_browse = self._control(QPushButton('Browse...'), 'newer_browse')
        self.accept_box = self._control(QCheckBox('Accept .BinExport files without a SHA-256 executable id'),
                                        'accept_unbound')
        self.warning = _PlainLabel(WARNING_TEXT)
        apply_tooltip(self.warning, 'engine_setup.unbound_warning')
        self.warning.setAccessibleName(ACCESSIBLE_NAMES['unbound_warning'])
        self.validate_button = self._control(QPushButton('Validate .BinExport files'), 'validate')
        self.cancel_button = self._control(QPushButton('Cancel validation'), 'cancel_validation')
        self.progress = QProgressBar()
        self.progress.setObjectName('engine_setup_progress')
        self.progress.setRange(0, 0)  # indeterminate: C3 reports no counts; the status line names the step
        self.progress.setAccessibleName(ACCESSIBLE_NAMES['validation_progress'])
        self.progress.setVisible(False)
        self.validation_status = _PlainLabel(VALIDATION_TEXT['no-project'])
        self.validation_status.setObjectName('engine_setup_validation_status')  # empty accessible name
        self.show_details = self._control(QCheckBox('Show technical details'), 'show_details')
        self.details = self._control(QPlainTextEdit(), 'details')
        self.details.setReadOnly(True)
        self.details.setPlainText(DETAILS_EMPTY)
        self.details.setMaximumBlockCount(400)
        self.details.setVisible(False)
        self.help = _PlainLabel(HELP_TEXT)
        self.help.setObjectName('engine_setup_help')
        labels = []
        for text, buddy in (('BinDiff executable:', self.path), ('Older .BinExport:', self.older),
                            ('Newer .BinExport:', self.newer)):
            label = _PlainLabel(text)
            label.setWordWrap(False)
            label.setBuddy(buddy)
            labels.append(label)
        grid.addWidget(labels[0], 0, 0)
        grid.addWidget(self.path, 0, 1)
        grid.addWidget(self.browse_exe, 0, 2)
        grid.addWidget(self.probe_button, 0, 3)
        grid.addWidget(self.probe_status, 1, 0, 1, 4)
        grid.addWidget(labels[1], 2, 0)
        grid.addWidget(self.older, 2, 1)
        grid.addWidget(self.older_browse, 2, 2)
        grid.addWidget(labels[2], 3, 0)
        grid.addWidget(self.newer, 3, 1)
        grid.addWidget(self.newer_browse, 3, 2)
        grid.addWidget(self.accept_box, 4, 0, 1, 4)
        grid.addWidget(self.warning, 5, 0, 1, 4)
        actions = QHBoxLayout()
        actions.addWidget(self.validate_button)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.progress, 1)
        grid.addLayout(actions, 6, 0, 1, 4)
        grid.addWidget(self.validation_status, 7, 0, 1, 4)
        grid.addWidget(self.show_details, 8, 0, 1, 4)
        grid.addWidget(self.details, 9, 0, 1, 4)
        grid.addWidget(self.help, 10, 0, 1, 4)
        self.details.setMinimumHeight(self.details.fontMetrics().lineSpacing() * 6)
        chain = self.focus_chain()
        for first, second in zip(chain, chain[1:], strict=False):
            QWidget.setTabOrder(first, second)
        self.toggle_button.toggled.connect(self._toggled)
        self.path.editTextChanged.connect(self._executable_changed)
        self.browse_exe.clicked.connect(self._browse_executable)
        self.probe_button.clicked.connect(lambda: self.probe_requested.emit(self.executable()))
        self.older.textChanged.connect(self._input_changed)
        self.newer.textChanged.connect(self._input_changed)
        self.older_browse.clicked.connect(lambda: self._browse_binexport(self.older, 'older'))
        self.newer_browse.clicked.connect(lambda: self._browse_binexport(self.newer, 'newer'))
        self.accept_box.toggled.connect(lambda _checked: self.inputs_edited.emit())
        self.validate_button.clicked.connect(self.validate_requested)
        self.cancel_button.clicked.connect(self.cancel_requested)
        self.show_details.toggled.connect(self.details.setVisible)
        self.toggle_button.blockSignals(True)
        self.toggle_button.setChecked(_setting_bool(settings, SETTING_OPEN))
        self.toggle_button.blockSignals(False)
        self.setVisible(False)  # shown by the toggle once the host has parented the section
        self._update_enabled()

    def _control(self, widget, key: str):
        apply_tooltip(widget, f'engine_setup.{key}')
        widget.setAccessibleName(ACCESSIBLE_NAMES[key])
        return widget

    def focus_chain(self) -> list[QWidget]:
        """Keyboard order of the section (spec §16.8); the host chains ``toggle_button`` before it."""
        return [self.path, self.browse_exe, self.probe_button, self.older, self.older_browse, self.newer,
                self.newer_browse, self.accept_box, self.validate_button, self.cancel_button, self.show_details,
                self.details]

    # -- values (GUI thread) --
    def executable(self) -> str:
        return self.path.currentText().strip()

    def older_path(self) -> str:
        return self.older.text().strip()

    def newer_path(self) -> str:
        return self.newer.text().strip()

    def accept_unbound(self) -> bool:
        return self.accept_box.isChecked()

    def is_open(self) -> bool:
        return self.toggle_button.isChecked()

    # -- setters (GUI thread) --
    def set_open(self, value: bool) -> None:
        self.toggle_button.setChecked(value)  # emits toggled -> _toggled

    def attach(self) -> None:
        """Called by the host once the section has a parent: apply the remembered open state."""
        if self.parentWidget() is not None:
            self.setVisible(self.is_open())

    def set_executable(self, text: str) -> None:
        self.path.setEditText(text)

    def set_candidates(self, paths: Sequence[str]) -> None:
        current = self.path.currentText()
        self.path.blockSignals(True)
        self.path.clear()
        self.path.addItems([sanitize_text(p, PATH_LIMIT) for p in paths])
        self.path.setCurrentIndex(-1)
        self.path.setEditText(current)
        self.path.blockSignals(False)

    def set_probe_status(self, text: str, busy: bool = False) -> None:
        self.probing = busy
        if text != self.probe_status.text():
            self.probe_status.setText(text)
        self._update_enabled()

    def set_validation_status(self, text: str, busy: bool = False) -> None:
        self.validating = busy
        if text != self.validation_status.text():
            self.validation_status.setText(text)
        self.progress.setVisible(busy)
        self._update_enabled()

    def set_details(self, text: str) -> None:
        self.details.setPlainText(text or DETAILS_EMPTY)

    def set_state(self, *, has_project: bool, locked: bool) -> None:
        if (has_project, locked) == (self.has_project, self.locked):
            return
        self.has_project, self.locked = has_project, locked
        self._update_enabled()

    def clear_inputs(self) -> None:
        """A different project: its files need other exports. Emits one ``inputs_edited``."""
        for widget in (self.older, self.newer, self.accept_box):
            widget.blockSignals(True)
        self.older.clear()
        self.newer.clear()
        self.accept_box.setChecked(False)
        for widget in (self.older, self.newer, self.accept_box):
            widget.blockSignals(False)
        self.inputs_edited.emit()

    # -- behaviour --
    def _toggled(self, checked: bool) -> None:
        _save(self.settings, SETTING_OPEN, bool(checked))
        if self.parentWidget() is not None:
            self.setVisible(checked)
        self.opened.emit(bool(checked))

    def _executable_changed(self, _text: str) -> None:
        self._update_enabled()
        self.executable_edited.emit()

    def _input_changed(self, _text: str) -> None:
        if self.accept_box.isChecked():  # the confirmation was for the files that were chosen before
            self.accept_box.blockSignals(True)
            self.accept_box.setChecked(False)
            self.accept_box.blockSignals(False)
        self.inputs_edited.emit()

    def _browse_executable(self) -> None:
        current = self.executable()
        start = str(Path(current).parent) if current else ''
        path = choose_file(self, 'Choose the bindiff executable', start, EXECUTABLE_FILTER)
        if path:
            self.set_executable(path)

    def _browse_binexport(self, field: QLineEdit, side: str) -> None:
        other = self.newer if field is self.older else self.older
        hint = field.text().strip() or other.text().strip()
        start = str(Path(hint).parent) if hint else ''
        path = choose_file(self, f'Choose the {side} .BinExport file', start, BINEXPORT_FILTER)
        if path:
            field.setText(path)

    def _update_enabled(self) -> None:
        usable = self.has_project and not self.locked
        self.toggle_button.setEnabled(self.has_project)
        for widget in (self.path, self.browse_exe, self.older, self.older_browse, self.newer, self.newer_browse,
                       self.accept_box):
            widget.setEnabled(usable)
        self.probe_button.setEnabled(usable and not self.probing and bool(self.executable()))
        self.validate_button.setEnabled(usable and not self.validating)
        self.cancel_button.setEnabled(self.validating)
        self.show_details.setEnabled(self.has_project)
        self.details.setEnabled(self.has_project)


class BinDiffSetupController(QObject):
    """Discovery, probe and validation workers plus the BinDiff capability and run setup they produce.

    ``changed`` is emitted only when the capability or the run setup actually changes. Injected callables
    (tests): ``prober(path, cancel)``, ``validator(request, cancel, progress=)``, ``discoverer()``."""
    changed = Signal()

    def __init__(self, panel: BinDiffSetupPanel, *, settings=None, prober: Callable | None = None,
                 validator: Callable | None = None, discoverer: Callable | None = None, parent=None):
        super().__init__(parent)
        self.panel = panel
        self.settings = settings
        self.prober = prober or probe_bindiff
        self.validator = validator or validate_binexports
        self.discoverer = discoverer or discover_bindiff
        self.identity: tuple[str, str, str] | None = None   # (project id, older SHA-256, newer SHA-256)
        self.probe_result: BinDiffProbeView | None = None
        self.validation: BinExportValidation | None = None
        self.discovered_paths: tuple[str, ...] = ()
        self.discovery_started = False
        self.probe_generation = self.validation_generation = self.discovery_generation = 0
        self.probe_thread: TaskThread | None = None
        self.validation_thread: TaskThread | None = None
        self.validation_cancel: threading.Event | None = None
        self.threads: list[tuple[QThread, threading.Event]] = []
        self._last: tuple | None = None
        queued = Qt.ConnectionType.QueuedConnection
        panel.probe_requested.connect(self.start_probe)
        panel.validate_requested.connect(self.start_validation)
        panel.cancel_requested.connect(self.cancel_validation)
        panel.executable_edited.connect(self._executable_edited)
        panel.inputs_edited.connect(self._inputs_edited)
        panel.opened.connect(self._opened, queued)
        saved = _setting_text(settings, SETTING_PATH)
        if saved and not panel.executable():
            panel.set_executable(saved)
        panel.set_probe_status(self._probe_text())
        panel.set_validation_status(self._idle_validation_text())
        self._last = self._state()
        if panel.is_open():
            self._opened(True)

    # -- queries (GUI thread) --
    def current_probe(self) -> BinDiffProbeView | None:
        probe = self.probe_result
        return probe if probe is not None and probe.executable == self.panel.executable() else None

    def request(self) -> ValidationRequest | None:
        if self.identity is None:
            return None
        older, newer = self.panel.older_path(), self.panel.newer_path()
        if not older or not newer:
            return None
        return ValidationRequest(Path(older), Path(newer), self.identity[1], self.identity[2],
                                 self.panel.accept_unbound())

    def capability(self):
        """None while BinDiff is not configured (the default probe result stays); else §16.6."""
        request = self.request()
        return setup_capability(self.current_probe(), self.validation, request.key if request else None)

    def run_setup(self) -> BinDiffSetup | None:
        capability, request = self.capability(), self.request()
        if capability is None or not capability.supported or request is None:
            return None
        return BinDiffSetup(self.panel.executable(), request.older_path, request.newer_path, request.accept_unbound)

    # -- host hooks --
    def set_project(self, identity: tuple[str, str, str] | None) -> None:
        if identity == self.identity:
            return
        previous, self.identity = self.identity, identity
        if previous is not None and (identity is None or identity[0] != previous[0]):
            self.panel.clear_inputs()  # another project: its files need other exports (emits inputs_edited)
        else:
            self._inputs_edited()      # same project, other artifact pair (e.g. swapped orientation)

    def shutdown(self) -> None:
        """Cancel and join every worker: destroying a running QThread aborts the process. No terminate()."""
        self.probe_generation += 1
        self.validation_generation += 1
        self.discovery_generation += 1
        for _thread, cancel in self.threads:
            cancel.set()
        for thread, _cancel in self.threads:
            if isValid(thread):
                thread.wait()
        self.threads = []
        self.probe_thread = self.validation_thread = None
        self.validation_cancel = None

    # -- discovery --
    def _opened(self, is_open: bool) -> None:
        if not is_open or self.discovery_started or self.panel.executable():
            return
        self.discovery_started = True
        self.discovery_generation += 1
        discoverer = self.discoverer
        thread = TaskThread(lambda cancel, report: tuple(str(p) for p in discoverer())[:MAX_CANDIDATES],
                            self.discovery_generation)
        thread.done.connect(self._discovered, Qt.ConnectionType.QueuedConnection)
        self._start(thread)

    def _discovered(self, result, generation: int) -> None:
        if generation != self.discovery_generation or isinstance(result, TaskFailure):
            return
        self.discovered_paths = tuple(result)
        self.panel.set_candidates(self.discovered_paths)
        if len(self.discovered_paths) == 1 and not self.panel.executable():
            self.panel.set_executable(self.discovered_paths[0])  # prefill only: nothing is run
        self.panel.set_probe_status(self._probe_text(), self._probing())

    # -- probe --
    def start_probe(self, path: str | None = None) -> None:
        path = (self.panel.executable() if path is None else path).strip()
        if not path:
            return
        self.probe_generation += 1
        prober = self.prober
        thread = TaskThread(lambda cancel, report: prober(path, cancel), self.probe_generation)
        thread.done.connect(self._probe_done, Qt.ConnectionType.QueuedConnection)
        self.probe_thread = thread
        self._start(thread)
        self.panel.set_probe_status(PROBE_TEXT['probing'], True)

    def _probe_done(self, result, generation: int) -> None:
        if generation != self.probe_generation:
            return  # a newer probe or an edited path supersedes this result
        self.probe_thread = None
        if isinstance(result, TaskFailure):
            self.probe_result = None
            self.panel.set_probe_status(f'Not usable: the probe stopped unexpectedly ({result.name}).')
        else:
            self.probe_result = result
            if result.supported and result.executable:
                _save(self.settings, SETTING_PATH, result.executable)  # configured path is authoritative
            self.panel.set_probe_status(self._probe_text())
        self._refresh()

    def _probing(self) -> bool:
        return self.probe_thread is not None and thread_alive(self.probe_thread)

    def _probe_text(self) -> str:
        if self._probing():
            return PROBE_TEXT['probing']
        probe = self.current_probe()
        if probe is not None:
            return probe.message
        text, found = self.panel.executable(), self.discovered_paths
        if len(found) > 1 and (not text or text in found):
            return PROBE_TEXT['found-many'].format(n=len(found))
        if len(found) == 1 and text == found[0]:
            return PROBE_TEXT['found-one']
        return PROBE_TEXT['unchecked'] if text else PROBE_TEXT['empty']

    def _executable_edited(self) -> None:
        if self.probe_thread is not None:  # the running probe answers a different path now
            self.probe_generation += 1
            self.probe_thread = None
        self.panel.set_probe_status(self._probe_text())
        self._refresh()

    # -- validation --
    def start_validation(self) -> None:
        if self.validation_cancel is not None:
            return  # one validation at a time; Cancel first
        if self.identity is None:
            self.panel.set_validation_status(VALIDATION_TEXT['no-project'])
            return
        request = self.request()
        if request is None:
            self.panel.set_validation_status(VALIDATION_TEXT['missing'])
            return
        self.validation = None
        self.validation_generation += 1
        validator = self.validator
        thread = TaskThread(lambda cancel, report: validator(request, cancel, progress=report),
                            self.validation_generation)
        thread.progress.connect(self._validation_progress, Qt.ConnectionType.QueuedConnection)
        thread.done.connect(self._validation_done, Qt.ConnectionType.QueuedConnection)
        self.validation_thread, self.validation_cancel = thread, thread.cancel
        self._start(thread)
        self.panel.set_validation_status(VALIDATION_TEXT['step'].format(side='older', n=1), True)
        self._refresh()

    def _validation_progress(self, step, generation: int) -> None:
        if generation != self.validation_generation:
            return
        if step == 'pair':
            text = VALIDATION_TEXT['pair']
        else:
            text = VALIDATION_TEXT['step'].format(side=step, n=2 if step == 'newer' else 1)
        self.panel.set_validation_status(text, True)

    def _validation_done(self, result, generation: int) -> None:
        if generation != self.validation_generation:
            return
        self.validation_thread = self.validation_cancel = None
        if isinstance(result, TaskFailure):
            result = BinExportValidation('failed', (), stopped=result.name)
        self.validation = result
        self.panel.set_validation_status(result.message)
        self._refresh()

    def cancel_validation(self) -> None:
        if self.validation_cancel is None:
            return
        self.validation_cancel.set()  # C3 kills the checker tree; the late result is dropped by generation
        self.validation_generation += 1
        self.validation_thread = self.validation_cancel = None
        self.validation = None
        self.panel.set_validation_status(VALIDATION_TEXT['cancelled'])
        self._refresh()

    def _inputs_edited(self) -> None:
        if self.validation_cancel is not None:
            self.validation_cancel.set()
        self.validation_generation += 1
        self.validation_thread = self.validation_cancel = None
        self.validation = None
        self.panel.set_validation_status(self._idle_validation_text())
        self._refresh()

    def _idle_validation_text(self) -> str:
        return VALIDATION_TEXT['idle'] if self.identity is not None else VALIDATION_TEXT['no-project']

    # -- plumbing --
    def _start(self, thread: TaskThread) -> None:
        self.threads = [(t, c) for t, c in self.threads if thread_alive(t)]
        self.threads.append((thread, thread.cancel))
        thread.start()

    def _state(self) -> tuple:
        return self.capability(), self.run_setup()

    def _refresh(self) -> None:
        parts = []
        probe = self.current_probe()
        if probe is not None:
            parts.append('BinDiff probe\n' + probe.technical)
        if self.validation is not None:
            parts.append('BinExport validation\n' + self.validation.technical)
        self.panel.set_details('\n\n'.join(parts))
        state = self._state()
        if state != self._last:
            self._last = state
            self.changed.emit()
