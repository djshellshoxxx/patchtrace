"""Setup rows and settings glue for the symbol choice (SPEC-53 GHR-4), kept out of `ui.py`.

Settings keys: `backend/allow_symbol_downloads` (online consent), `backend/symbol_mode` (`off|local|online`,
written on save; absent means the legacy boolean decides) and `backend/symbol_dirs` (semicolon-separated folders).
"""
from __future__ import annotations

from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QRadioButton,
    QWidget,
)

from .symbols.modes import MAX_PDB_DIRS, SYMBOL_MODES, parse_symbol_dirs
from .tooltips import apply_tooltip


class SymbolChoice:
    """Mutually exclusive symbol modes and a bounded local PDB folder list."""

    def __init__(self, form, settings, online: QRadioButton):
        self.group = QButtonGroup()
        self.off = QRadioButton('Do not load symbols (default)')
        self.local = QRadioButton('Use matching local PDB files (no network)')
        self.online = online
        self.off.setAccessibleName('setup.symbols.off')
        self.local.setAccessibleName('setup.symbols.local')
        self.online.setAccessibleName('setup.symbols.online')
        for button in (self.off, self.local, self.online):
            self.group.addButton(button)
            form.addRow(button)

        saved_mode = str(settings.value('backend/symbol_mode', ''))
        if saved_mode not in SYMBOL_MODES:
            saved_mode = 'online' if settings.value('backend/allow_symbol_downloads', False, type=bool) else 'off'
        {'off': self.off, 'local': self.local, 'online': self.online}[saved_mode].setChecked(True)

        self.folder_list = QListWidget()
        self.folder_list.setAccessibleName('setup.symbols.dirs')
        # Keep the semicolon-delimited settings/config seam for existing callers; the visible control is the list.
        self.dirs = QLineEdit(str(settings.value('backend/symbol_dirs', '')), self.folder_list)
        self.dirs.hide()
        self.add_button = QPushButton('Add folder…')
        self.remove_button = QPushButton('Remove selected')
        self.empty_hint = QLabel('No PDB folders chosen. Local mode will analyse without symbol names.')
        self.empty_hint.setWordWrap(True)
        row = QWidget()
        buttons = QHBoxLayout(row)
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.remove_button)
        form.addRow('Local PDB folders', self.folder_list)
        form.addRow(row)
        form.addRow(self.empty_hint)
        self._sync_list_from_field()

        apply_tooltip(self.off, 'setup.symbol_off')
        apply_tooltip(self.local, 'setup.symbol_local')
        apply_tooltip(self.online, 'setup.symbol_downloads')
        apply_tooltip(self.dirs, 'setup.symbol_dirs')
        apply_tooltip(self.folder_list, 'setup.symbol_dirs')
        apply_tooltip(self.add_button, 'setup.symbol_dirs')
        apply_tooltip(self.remove_button, 'setup.symbol_dirs')
        self.off.toggled.connect(self.changed)
        self.local.toggled.connect(self.changed)
        self.online.toggled.connect(self.changed)
        self.dirs.textChanged.connect(self._sync_list_from_field)
        self.add_button.clicked.connect(self.choose_folder)
        self.remove_button.clicked.connect(self.remove_selected_folder)
        self.changed()

    def changed(self, *_):
        enabled = self.local.isChecked()
        self.folder_list.setEnabled(enabled)
        self.add_button.setEnabled(enabled and self.folder_list.count() < MAX_PDB_DIRS)
        self.remove_button.setEnabled(enabled and self.folder_list.count() > 0)
        self.empty_hint.setVisible(enabled and self.folder_list.count() == 0)

    def mode(self) -> str:
        return 'online' if self.online.isChecked() else 'local' if self.local.isChecked() else 'off'

    def _sync_list_from_field(self, *_):
        values = parse_symbol_dirs(self.dirs.text())
        current = tuple(self.folder_list.item(i).text() for i in range(self.folder_list.count()))
        if values != current:
            self.folder_list.clear()
            self.folder_list.addItems(list(values))
        self.add_button.setEnabled(self.local.isChecked() and self.folder_list.count() < MAX_PDB_DIRS)
        self.remove_button.setEnabled(self.local.isChecked() and self.folder_list.count() > 0)
        self.empty_hint.setVisible(self.local.isChecked() and self.folder_list.count() == 0)

    def _sync_field_from_list(self):
        self.dirs.setText(';'.join(self.folder_list.item(i).text() for i in range(self.folder_list.count())))

    def add_folder(self, path: str):
        """Add a unique folder while keeping the settings list within its documented cap."""
        value = str(path).strip()
        if not value:
            return
        current = parse_symbol_dirs(self.dirs.text())
        if value in current or len(current) >= MAX_PDB_DIRS:
            return
        self.dirs.setText(';'.join((*current, value)))

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self.folder_list, 'Select a local PDB folder')
        self.add_folder(path)

    def remove_selected_folder(self):
        row = self.folder_list.currentRow()
        if row >= 0:
            self.folder_list.takeItem(row)
            self._sync_field_from_list()
            self.changed()

    def kwargs(self) -> dict:
        return config_kwargs(self.mode() == 'local', self.dirs.text())

    def save(self, settings) -> None:
        settings.setValue('backend/allow_symbol_downloads', self.online.isChecked())
        settings.setValue('backend/symbol_mode', self.mode())
        settings.setValue('backend/symbol_dirs', self.dirs.text().strip())

    @staticmethod
    def saved(settings, online_consent: bool) -> dict:
        """BackendConfig keywords from the saved Setup mode."""
        mode = configured_symbol_mode(settings, online_consent)
        return config_kwargs(mode == 'local', str(settings.value('backend/symbol_dirs', '')))


def config_kwargs(local: bool, dirs_text: str) -> dict:
    """BackendConfig keywords for local PDB mode; blank symbol_mode preserves legacy behavior."""
    return {'symbol_mode': 'local', 'symbol_pdb_dirs': parse_symbol_dirs(dirs_text)} if local else {}


def configured_symbol_mode(settings, online_consent: bool) -> str:
    """Read the Setup ceiling, migrating the legacy consent boolean and failing closed on contradictions."""
    saved = str(settings.value('backend/symbol_mode', ''))
    if not saved:
        return 'online' if online_consent else 'off'
    if saved not in SYMBOL_MODES:
        return 'off'
    if (saved == 'online') != online_consent:
        return 'off'
    return saved



def effective_backend_symbol_mode(settings, profile) -> str:
    """Resolve the saved Setup ceiling and the profile restriction without enabling implicit network access."""
    consent = settings.value('backend/allow_symbol_downloads', False, type=bool)
    configured = configured_symbol_mode(settings, consent)
    return effective_profile_symbol_mode(configured, profile.symbol_policy, profile.is_default)


def effective_profile_symbol_mode(configured: str, policy: str, is_default: bool) -> str:
    """A named profile can narrow Setup's symbol mode but cannot turn symbols on beyond its ceiling."""
    if is_default:
        return configured if configured in SYMBOL_MODES else 'off'
    requested = {'disabled': 'off', 'local': 'local', 'online': 'online'}.get(policy, 'off')
    rank = {'off': 0, 'local': 1, 'online': 2}
    configured = configured if configured in rank else 'off'
    return min((configured, requested), key=rank.__getitem__)
