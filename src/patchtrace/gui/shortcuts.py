"""Key-sequence vocabulary and collision rules for panels and commands (GUI plan 8.3, section 6). Pure: no Qt.

Sequences are compared in one canonical spelling, so 'ctrl+shift+e' and 'Shift+Ctrl+E' collide. Only single chords
of letters, digits, function keys and a few named keys are understood; anything else is not a shortcut here.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

MODIFIERS = ('Ctrl', 'Alt', 'Shift', 'Meta')  # canonical order
_MODIFIER_NAMES = {'ctrl': 'Ctrl', 'control': 'Ctrl', 'alt': 'Alt', 'shift': 'Shift', 'meta': 'Meta'}
_NAMED_KEYS = {'esc': 'Escape', 'escape': 'Escape', 'up': 'Up', 'down': 'Down', 'left': 'Left', 'right': 'Right',
               'tab': 'Tab', 'return': 'Return', 'enter': 'Enter', 'space': 'Space', 'home': 'Home', 'end': 'End',
               'pgup': 'PageUp', 'pageup': 'PageUp', 'pgdown': 'PageDown', 'pagedown': 'PageDown',
               'del': 'Delete', 'delete': 'Delete', 'ins': 'Insert', 'insert': 'Insert', 'backspace': 'Backspace'}
_FUNCTION_KEY = re.compile(r'[Ff](?:[1-9]|1[0-9]|2[0-4])')

# Taken by the main window today (GUI-integration-plan 8.3; Ctrl+Shift+E is the evidence dock and is claimed by the
# evidence spec, not reserved) and by the framework itself. Values name the owner in a collision message.
RESERVED: Mapping[str, str] = {
    'Ctrl+N': 'New', 'Ctrl+O': 'Open', 'Ctrl+S': 'Save', 'Ctrl+E': 'Export', 'Ctrl+I': 'Interpret selection',
    'Ctrl+R': 'Rank changes', 'F1': 'Workflow and dependencies', 'F5': 'Run comparison', 'Escape': 'Cancel job',
    'Alt+Up': 'Previous difference', 'Alt+Down': 'Next difference'}
FRAMEWORK: Mapping[str, str] = {
    'Ctrl+Shift+P': 'Command palette', 'F6': 'Next panel', 'Shift+F6': 'Previous panel',
    'Alt+Left': 'Navigate back', 'Alt+Right': 'Navigate forward'}


def _key(text: str) -> str | None:
    if len(text) == 1 and text.isascii() and text.isalnum():
        return text.upper()
    if _FUNCTION_KEY.fullmatch(text):
        return text.upper()
    return _NAMED_KEYS.get(text.lower())


def normalize(sequence: str) -> str | None:
    """The canonical spelling of a single chord ('Ctrl+Alt+Shift+Meta+<key>'), or None when it is not one."""
    if not isinstance(sequence, str):
        return None
    *modifiers, key = (part.strip() for part in sequence.split('+'))
    names = [_MODIFIER_NAMES.get(part.lower()) for part in modifiers]
    key = _key(key)
    if key is None or None in names or len(set(names)) != len(names):
        return None
    return '+'.join([*(m for m in MODIFIERS if m in names), key])


def panel_shortcut_error(sequence: str) -> str | None:
    """Why `sequence` cannot be a panel toggle (they are all Ctrl+Shift+<letter>), or None."""
    key = normalize(sequence)
    if key is None:
        return 'is not a key sequence'
    modifiers, _, letter = key.rpartition('+')
    if modifiers != 'Ctrl+Shift' or not (len(letter) == 1 and letter.isalpha()):
        return 'must be Ctrl+Shift+<letter>'
    return None


class ShortcutTable:
    """Who owns which key sequence. Claiming a taken sequence reports the owner and changes nothing."""

    def __init__(self, seeds: Mapping[str, str] | None = None):
        self._owners: dict[str, str] = dict({**RESERVED, **FRAMEWORK} if seeds is None else seeds)

    def claim(self, owner: str, sequence: str) -> str | None:
        """Take `sequence` for `owner`. None when it is now (or already was) the owner's; else the other owner."""
        key = normalize(sequence)
        if key is None:
            raise ValueError(f'not a key sequence: {sequence!r:.40}')
        holder = self._owners.setdefault(key, owner)
        return None if holder == owner else holder

    def owner(self, sequence: str) -> str | None:
        key = normalize(sequence)
        return None if key is None else self._owners.get(key)
