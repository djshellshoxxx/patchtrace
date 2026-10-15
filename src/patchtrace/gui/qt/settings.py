"""Per-panel QSettings access with validated reads (GUI plan section 7: persisted state is QSettings only).

Keys live under ``<panel id>/``. Every getter checks type, range, enum membership and length and returns the
default for a missing or corrupt value; it never raises. Untrusted strings are capped at 256 characters and a
key that looks like a credential is refused: settings never hold secrets."""
from __future__ import annotations

import re
from collections.abc import Collection

from PySide6.QtCore import QSettings

MAX_TEXT = 256
MAX_LIST = 32
_PANEL_ID = re.compile(r'^[a-z][a-z0-9_]{0,31}$')
_KEY = re.compile(r'^[a-z][a-z0-9_]*(/[a-z][a-z0-9_]*)*$')
_SECRET = re.compile(r'secret|token|password|passwd|credential|api_?key|auth', re.IGNORECASE)
_TRUE, _FALSE = {'true', '1'}, {'false', '0'}


class PanelSettings:
    def __init__(self, settings: QSettings, panel_id: str) -> None:
        if not _PANEL_ID.match(panel_id):
            raise ValueError(f'invalid panel id {panel_id!r}')
        self._settings = settings
        self.panel_id = panel_id

    def _key(self, key: str) -> str:
        if not _KEY.match(key) or _SECRET.search(key):
            raise ValueError(f'invalid or credential-like settings key {key!r}')
        return f'{self.panel_id}/{key}'

    def _raw(self, key: str):
        return self._settings.value(self._key(key))

    def get_int(self, key: str, default: int, minimum: int, maximum: int) -> int:
        value = self._raw(key)
        if isinstance(value, bool) or not isinstance(value, int | str):
            return default
        try:
            number = int(value)
        except ValueError:
            return default
        return number if minimum <= number <= maximum else default

    def get_bool(self, key: str, default: bool) -> bool:
        value = self._raw(key)
        if isinstance(value, bool):
            return value
        text = value.strip().lower() if isinstance(value, str) else ''
        return True if text in _TRUE else False if text in _FALSE else default

    def get_enum(self, key: str, default: str, allowed: Collection[str]) -> str:
        value = self._raw(key)
        return value if isinstance(value, str) and value in allowed else default

    def get_text(self, key: str, default: str = '', max_length: int = MAX_TEXT) -> str:
        value = self._raw(key)
        return value if isinstance(value, str) and len(value) <= min(max_length, MAX_TEXT) else default

    def get_list(self, key: str, default: tuple[str, ...] = (), max_items: int = MAX_LIST) -> tuple[str, ...]:
        value = self._raw(key)
        if isinstance(value, str):
            value = [value]  # an INI file returns a one-item list as a plain string
        if not isinstance(value, list | tuple) or len(value) > min(max_items, MAX_LIST):
            return default
        if not all(isinstance(item, str) and len(item) <= MAX_TEXT for item in value):
            return default
        return tuple(value)

    def set(self, key: str, value: int | bool | str | list[str] | tuple[str, ...]) -> None:
        """Write a scalar, a string of at most 256 characters or a short list of such strings."""
        if isinstance(value, tuple):
            value = list(value)
        if isinstance(value, str) and len(value) > MAX_TEXT:
            raise ValueError(f'settings text for {key!r} exceeds {MAX_TEXT} characters')
        if isinstance(value, list) and (len(value) > MAX_LIST or any(
                not isinstance(item, str) or len(item) > MAX_TEXT for item in value)):
            raise ValueError(f'settings list for {key!r} is too long or not text')
        self._settings.setValue(self._key(key), value)

    def remove(self, key: str) -> None:
        self._settings.remove(self._key(key))

    def clear(self) -> None:
        self._settings.remove(self.panel_id)
