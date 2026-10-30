"""Profile selection and storage paths for desktop Setup and analysis.

Separated from the main window module to reduce coupling. The public imports
in patchtrace.ui remain available for compatibility.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings

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

