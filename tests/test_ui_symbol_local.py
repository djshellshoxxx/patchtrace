"""SPEC-53 GHR-4 (partial): Setup choice for local PDB mode, persistence and backend_config wiring (offscreen)."""
from __future__ import annotations

from PySide6.QtWidgets import QDialog
from test_ui import window  # noqa: F401  (fixture reuse)

from patchtrace.symbols.modes import parse_symbol_dirs
from patchtrace.ui import SetupDialog


def test_parse_symbol_dirs():
    assert parse_symbol_dirs(' C:\\a ; /b;;C:\\a ') == ('C:\\a', '/b')
    assert parse_symbol_dirs('') == ()


def test_local_mode_off_by_default_and_exclusive_with_online(window, tmp_path):  # noqa: F811
    dialog = SetupDialog(window.settings, window)
    assert not dialog.symbol_local.isChecked() and dialog.symbol_mode() == 'off'
    assert dialog.config().symbol_mode == '' and dialog.config().symbol_pdb_dirs == ()
    dialog.symbol_local.setChecked(True)
    dialog.symbol_dirs.setText(f'{tmp_path};{tmp_path}')
    cfg = dialog.config()
    assert dialog.symbol_mode() == 'local' and cfg.symbol_mode == 'local' and cfg.symbol_pdb_dirs == (str(tmp_path),)
    assert not cfg.allow_symbol_downloads
    dialog.allow_symbol_downloads.setChecked(True)
    assert dialog.symbol_mode() == 'online' and not dialog.symbol_local.isEnabled() and not dialog.symbol_dirs.isEnabled()
    assert dialog.config().symbol_mode == '' and dialog.config().allow_symbol_downloads


def test_local_mode_persists_and_reaches_backend_config(window, tmp_path, monkeypatch):  # noqa: F811
    assert window.backend_config().symbol_mode == ''
    def accept(self):
        self.symbol_local.setChecked(True)
        self.symbol_dirs.setText(str(tmp_path))
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(SetupDialog, 'exec', accept)
    window.setup()
    assert window.settings.value('backend/symbol_mode') == 'local'
    cfg = window.backend_config()
    assert cfg.symbol_mode == 'local' and cfg.symbol_pdb_dirs == (str(tmp_path),) and not cfg.allow_symbol_downloads
    window.settings.setValue('backend/allow_symbol_downloads', True)     # online consent wins; never both
    assert window.backend_config().symbol_mode == '' and window.backend_config().allow_symbol_downloads
