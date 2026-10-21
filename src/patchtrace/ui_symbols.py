"""Setup rows and settings glue for the symbol choice (SPEC-53 GHR-4), kept out of `ui.py` (its line ceiling only
goes down). Qt widgets only; the mode rules live in `symbols.modes`.

Settings keys: `backend/allow_symbol_downloads` (online consent, unchanged), `backend/symbol_mode` (`off|local|online`,
written on save; absent means the legacy boolean decides) and `backend/symbol_dirs` (semicolon-separated folders).
Local mode needs no network consent, so it is independent of the analysis profile's online policy and is never
combined with online lookups.
"""
from __future__ import annotations

from PySide6.QtWidgets import QCheckBox, QLineEdit

from .symbols.modes import parse_symbol_dirs
from .tooltips import apply_tooltip


class SymbolChoice:
    """The local-PDB checkbox and folder field of the Setup dialog, exclusive with the online checkbox."""

    def __init__(self, form, settings, online: QCheckBox):
        self.online = online
        form.addRow(online)
        self.local = QCheckBox('Use matching PDB files from the folders below (no network)')
        self.local.setChecked(str(settings.value('backend/symbol_mode', '')) == 'local')
        self.dirs = QLineEdit(str(settings.value('backend/symbol_dirs', '')))
        self.dirs.setPlaceholderText('PDB folders, separated by semicolons (at most 16)')
        form.addRow(self.local)
        form.addRow('PDB folders', self.dirs)
        apply_tooltip(self.local, 'setup.symbol_local')
        apply_tooltip(self.dirs, 'setup.symbol_dirs')
        online.toggled.connect(self.changed)
        self.local.toggled.connect(self.changed)
        self.changed()

    def changed(self, *_):
        online = self.online.isChecked()
        self.local.setEnabled(not online)
        self.dirs.setEnabled(self.local.isChecked() and not online)

    def mode(self) -> str:
        return 'online' if self.online.isChecked() else 'local' if self.local.isChecked() else 'off'

    def kwargs(self) -> dict:
        return config_kwargs(self.mode() == 'local', self.dirs.text())

    def save(self, settings) -> None:
        settings.setValue('backend/allow_symbol_downloads', self.online.isChecked())
        settings.setValue('backend/symbol_mode', self.mode())
        settings.setValue('backend/symbol_dirs', self.dirs.text().strip())

    @staticmethod
    def saved(settings, online_consent: bool) -> dict:
        """BackendConfig keywords from the saved settings (local mode only without online consent)."""
        local = not online_consent and str(settings.value('backend/symbol_mode', '')) == 'local'
        return config_kwargs(local, str(settings.value('backend/symbol_dirs', '')))


def config_kwargs(local: bool, dirs_text: str) -> dict:
    """BackendConfig keywords for the saved choice (empty `symbol_mode` keeps the legacy boolean in charge)."""
    return {'symbol_mode': 'local', 'symbol_pdb_dirs': parse_symbol_dirs(dirs_text)} if local else {}

