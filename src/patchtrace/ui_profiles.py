"""Profile selection and storage paths for desktop Setup and analysis.

Separated from the main window module to reduce coupling. The public imports
in patchtrace.ui remain available for compatibility.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings, QSignalBlocker, Qt
from PySide6.QtWidgets import QListWidgetItem, QMessageBox

from .tooltips import apply_tooltip

PROFILE_SETTING = 'analysis/profile'


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


def reload_panel(panel, select: str | None = None) -> None:
    """Refresh after a deliberate store operation without a second dirty prompt."""
    profiles, errors = panel.store.list()
    panel.load_errors.setText('\n'.join(f'Skipped invalid file: {error}' for error in errors))
    with QSignalBlocker(panel.list):
        panel.list.clear()
        for profile in profiles:
            item = QListWidgetItem(profile.name + (' (built-in, read-only)' if profile.is_default else ''))
            item.setData(Qt.ItemDataRole.UserRole, profile.name)
            panel.list.addItem(item)
        names = [profile.name for profile in profiles]
        panel.list.setCurrentRow(names.index(select) if select in names else 0)
    panel._show_current()


def resolve_unsaved_profile(panel) -> bool:
    """Return permission to navigate only after the current draft is resolved."""
    if not panel.is_dirty():
        return True
    buttons = QMessageBox.StandardButton
    box = QMessageBox(QMessageBox.Icon.Question, 'Unsaved profile changes',
                      f'Profile {panel._editing} has unsaved changes.\n\n'
                      'Save them before continuing, discard them, or cancel to keep editing.',
                      buttons.Save | buttons.Discard | buttons.Cancel, panel)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setDefaultButton(buttons.Cancel)
    box.setEscapeButton(buttons.Cancel)
    for button, action in ((buttons.Save, 'save'), (buttons.Discard, 'discard'), (buttons.Cancel, 'cancel')):
        apply_tooltip(box.button(button), f'profile.navigation.{action}')
    choice = box.exec()
    if choice == buttons.Save:
        return panel.save_profile()
    return choice == buttons.Discard


def change_profile_selection(panel, current, previous) -> None:
    """Keep the active editor and selection together while resolving a dirty draft."""
    if current is None:
        return
    destination = current.data(Qt.ItemDataRole.UserRole)
    previous_name = previous.data(Qt.ItemDataRole.UserRole) if previous is not None else 'default'
    if panel.is_dirty():
        with QSignalBlocker(panel.list):
            panel.list.setCurrentItem(previous)
        if not resolve_unsaved_profile(panel):
            return
        # Saving may rename the old profile and recreate every QListWidgetItem.
        previous_name = panel.selected_name()
        item = next((panel.list.item(row) for row in range(panel.list.count())
                     if panel.list.item(row).data(Qt.ItemDataRole.UserRole) == destination), None)
        if item is None:
            panel.error.setText(f'Profile {destination!r} is no longer available.')
            return
        with QSignalBlocker(panel.list):
            panel.list.setCurrentItem(item)
    if not panel._show_current():
        # The destination may be removed or corrupted after the list was loaded.
        item = next((panel.list.item(row) for row in range(panel.list.count())
                     if panel.list.item(row).data(Qt.ItemDataRole.UserRole) == previous_name), None)
        with QSignalBlocker(panel.list):
            panel.list.setCurrentItem(item)

