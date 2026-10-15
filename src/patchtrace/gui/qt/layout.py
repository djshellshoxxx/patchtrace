"""Saving and restoring the dock layout (GUI plan 8.3, error code PT-GUI-LAYOUT).

The only persisted layout state is QSettings: `layout/schema`, `layout/state` (at most 64 KiB) and
`layout/state_sha256`. A blob is trusted only when all three agree; anything else means "use the defaults" and says
so, because a window restored from a corrupt blob can hide every panel. Bump `LAYOUT_SCHEMA` only when a dock id is
renamed or removed.
"""
from __future__ import annotations

import hashlib
import re

from PySide6.QtCore import QByteArray, QSettings
from PySide6.QtWidgets import QMainWindow, QToolBar

LAYOUT_SCHEMA = 1
MAX_STATE_BYTES = 64 * 1024
LAYOUT_CODE = 'PT-GUI-LAYOUT'
FAILED_TEXT = 'Panel layout could not be restored; defaults were used.'
RESET_TEXT = 'Panel layout reset to defaults.'
_KEYS = ('layout/schema', 'layout/state', 'layout/state_sha256')


def name_window_parts(window: QMainWindow) -> None:
    """saveState needs an objectName on the window and on every toolbar (Qt otherwise warns and skips them)."""
    if not window.objectName():
        window.setObjectName('main')
    for index, bar in enumerate(window.findChildren(QToolBar)):
        if not bar.objectName():
            slug = re.sub(r'[^a-z0-9]+', '_', bar.windowTitle().lower()).strip('_') or str(index)
            bar.setObjectName(f'toolbar.{slug}')


def _blob(value: object) -> bytes | None:
    return bytes(value) if isinstance(value, QByteArray | bytes | bytearray) else None


def save_layout(window: QMainWindow, settings: QSettings) -> None:
    state = bytes(window.saveState(LAYOUT_SCHEMA))
    if len(state) > MAX_STATE_BYTES:
        return  # a blob we would refuse to read back is not worth storing
    settings.setValue('layout/schema', LAYOUT_SCHEMA)
    settings.setValue('layout/state', QByteArray(state))
    settings.setValue('layout/state_sha256', hashlib.sha256(state).hexdigest())


def stored_state(settings: QSettings) -> bytes | None:
    """The saved layout when schema, size and SHA-256 all check out; None when nothing valid is stored."""
    state = _blob(settings.value('layout/state'))
    digest = settings.value('layout/state_sha256')
    schema = settings.value('layout/schema')
    if (not state or len(state) > MAX_STATE_BYTES or str(schema) != str(LAYOUT_SCHEMA)
            or digest != hashlib.sha256(state).hexdigest()):
        return None
    return state


def restore_layout(window: QMainWindow, settings: QSettings) -> str | None:
    """Restore the saved layout. Returns the status line to show when a layout existed but was refused, else None
    (a first run has nothing stored and nothing to say)."""
    if not any(settings.contains(key) for key in _KEYS):
        return None
    state = stored_state(settings)
    try:
        restored = state is not None and window.restoreState(QByteArray(state), LAYOUT_SCHEMA)
    except Exception:  # noqa: BLE001 - a bad blob must never stop the window from opening
        restored = False
    if restored:
        return None
    clear_layout(settings)
    return FAILED_TEXT


def clear_layout(settings: QSettings) -> None:
    for key in _KEYS:
        settings.remove(key)
