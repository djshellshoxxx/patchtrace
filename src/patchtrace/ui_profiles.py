"""Profile selection and storage paths for desktop Setup and analysis.

Separated from the main window module to reduce coupling. The public imports
in patchtrace.ui remain available for compatibility.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QMessageBox

from .tooltips import apply_tooltip

PROFILE_SETTING = 'analysis/profile'


def confirm_profile_leave(panel) -> bool:
    """Preserve the unsaved editor unless the user discards it or a save succeeds."""
    if not panel.is_dirty():
        return True
    box = QMessageBox(QMessageBox.Icon.Question, 'Unsaved profile changes',
                      f'Profile {panel._editing} has unsaved changes.\n\n'
                      'Save them, discard them, or keep editing this profile.',
                      QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard
                      | QMessageBox.StandardButton.Cancel, panel)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    box.setEscapeButton(QMessageBox.StandardButton.Cancel)
    for button, tip in ((QMessageBox.StandardButton.Save, 'profile.save'),
                        (QMessageBox.StandardButton.Discard, 'profile.discard'),
                        (QMessageBox.StandardButton.Cancel, 'profile.keep_editing')):
        apply_tooltip(box.button(button), tip)
    choice = box.exec()
    if choice == QMessageBox.StandardButton.Save:
        return panel.save_profile()
    return choice == QMessageBox.StandardButton.Discard


def _select_name(panel, name: str) -> None:
    blocked = panel.list.blockSignals(True)
    try:
        for index in range(panel.list.count()):
            if panel.list.item(index).data(Qt.ItemDataRole.UserRole) == name:
                panel.list.setCurrentRow(index)
                return
    finally:
        panel.list.blockSignals(blocked)


def profile_selection_changed(panel) -> None:
    """A list transition must not overwrite the editor or recurse through save/reload."""
    if getattr(panel, '_profile_switch_active', False):
        return
    requested, previous = panel.selected_name(), panel._editing
    panel._profile_switch_active = True
    try:
        if not confirm_profile_leave(panel):
            _select_name(panel, previous)
            return
        # Saving may rename the previous profile and reload the list. Select the
        # requested name again without retaining any deleted QListWidgetItem.
        _select_name(panel, requested)
        panel._show_current()
    finally:
        panel._profile_switch_active = False


def profiles_dir(settings) -> Path:
    """Profiles live beside an INI/file-backed QSettings; native Windows settings are in the
    registry, so the headless default directory (shared with the CLI) is used instead."""
    from .enrichment.profiles import default_profiles_dir
    name = settings.fileName()
    if settings.format() == QSettings.Format.IniFormat or (name and Path(name).is_absolute()
                                                           and not name.startswith('\\HKEY')):
        return Path(name).parent / 'profiles'
    return default_profiles_dir()


def selected_profile(settings, directory: Path):
    """(profile, warning). A missing or invalid selected profile falls back to the default, loudly."""
    from .enrichment.profiles import DEFAULT_PROFILE, ProfileError, ProfileStore
    name = settings.value(PROFILE_SETTING, 'default')
    if not isinstance(name, str) or name == 'default':
        return DEFAULT_PROFILE, ''
    try:
        return ProfileStore(directory).get(name), ''
    except ProfileError as exc:
        return DEFAULT_PROFILE, f'Profile {name!r} unavailable ({exc}); using default.'

