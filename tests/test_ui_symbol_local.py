"""SPEC-53 GHR-4 (partial): Setup choice for local PDB mode, persistence and backend_config wiring (offscreen)."""
from __future__ import annotations

from PySide6.QtWidgets import QDialog, QListWidget, QRadioButton
from test_ui import window  # noqa: F401  (fixture reuse)

from patchtrace.symbols.modes import parse_symbol_dirs
from patchtrace.ui import SetupDialog


def test_parse_symbol_dirs():
    assert parse_symbol_dirs(' C:\\a ; /b;;C:\\a ') == ('C:\\a', '/b')
    assert parse_symbol_dirs('') == ()


def test_local_mode_off_by_default_and_exclusive_with_online(window, tmp_path):  # noqa: F811
    dialog = SetupDialog(window.settings, window)
    assert isinstance(dialog.symbols.off, QRadioButton)
    assert isinstance(dialog.symbols.local, QRadioButton)
    assert isinstance(dialog.symbols.online, QRadioButton)
    assert dialog.symbols.off.accessibleName() == 'setup.symbols.off'
    assert dialog.symbols.local.accessibleName() == 'setup.symbols.local'
    assert dialog.symbols.online.accessibleName() == 'setup.symbols.online'
    assert not dialog.symbols.local.isChecked() and dialog.symbols.mode() == 'off'
    assert dialog.config().symbol_mode == '' and dialog.config().symbol_pdb_dirs == ()
    dialog.symbols.local.setChecked(True)
    dialog.symbols.dirs.setText(f'{tmp_path};{tmp_path}')
    cfg = dialog.config()
    assert dialog.symbols.mode() == 'local' and cfg.symbol_mode == 'local' and cfg.symbol_pdb_dirs == (str(tmp_path),)
    assert not cfg.allow_symbol_downloads
    dialog.allow_symbol_downloads.setChecked(True)
    assert dialog.symbols.mode() == 'online'
    assert dialog.symbols.local.isEnabled() and not dialog.symbols.folder_list.isEnabled()
    assert dialog.config().symbol_mode == '' and dialog.config().allow_symbol_downloads


def test_symbol_folder_list_add_remove_and_persisted_value(window, tmp_path):  # noqa: F811
    dialog = SetupDialog(window.settings, window)
    symbols = dialog.symbols
    assert isinstance(symbols.folder_list, QListWidget)
    symbols.local.setChecked(True)
    assert not symbols.empty_hint.isHidden()
    symbols.add_folder(str(tmp_path))
    symbols.add_folder(str(tmp_path))
    assert symbols.folder_list.count() == 1
    assert symbols.empty_hint.isHidden()
    assert symbols.dirs.text() == str(tmp_path)
    symbols.folder_list.setCurrentRow(0)
    symbols.remove_selected_folder()
    assert symbols.folder_list.count() == 0 and symbols.dirs.text() == ''


def test_symbol_folder_list_enforces_maximum(window):  # noqa: F811
    dialog = SetupDialog(window.settings, window)
    symbols = dialog.symbols
    symbols.local.setChecked(True)
    for index in range(17):
        symbols.add_folder(f'/pdb/{index}')
    assert symbols.folder_list.count() == 16 and not symbols.add_button.isEnabled()


def test_symbol_modes_migrate_legacy_online_setting(window):  # noqa: F811
    window.settings.remove('backend/symbol_mode')
    window.settings.setValue('backend/allow_symbol_downloads', True)
    dialog = SetupDialog(window.settings, window)
    assert dialog.symbols.mode() == 'online' and dialog.symbols.online.isChecked()


def test_local_mode_persists_and_reaches_backend_config(window, tmp_path, monkeypatch):  # noqa: F811
    assert window.backend_config().symbol_mode == ''
    def accept(self):
        self.symbols.local.setChecked(True)
        self.symbols.dirs.setText(str(tmp_path))
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(SetupDialog, 'exec', accept)
    window.setup()
    assert window.settings.value('backend/symbol_mode') == 'local'
    cfg = window.backend_config()
    assert cfg.symbol_mode == 'local' and cfg.symbol_pdb_dirs == (str(tmp_path),) and not cfg.allow_symbol_downloads
    window.settings.setValue('backend/allow_symbol_downloads', True)  # contradictory persisted modes fail closed
    cfg = window.backend_config()
    assert cfg.symbol_mode == '' and not cfg.allow_symbol_downloads
    window.settings.setValue('backend/symbol_mode', 'online')  # a consistent saved online choice has consent
    cfg = window.backend_config()
    assert cfg.symbol_mode == '' and cfg.allow_symbol_downloads
