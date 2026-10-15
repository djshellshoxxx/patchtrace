"""The one rule for characters that untrusted text may not carry into a stored or displayed field: control (C0, DEL and
C1), format (bidirectional, zero-width, byte order mark, soft hyphen, tag) and surrogate code points. Each sink picks
its own replacement: `pe_overview` a `?`, `intelligence.tools.process.sanitize` a space."""
from __future__ import annotations

import unicodedata

_HOSTILE = frozenset({'Cc', 'Cf', 'Cs'})


def is_hostile(char: str) -> bool:
    return unicodedata.category(char) in _HOSTILE


def escape_text(text: str, keep: str = '') -> str:
    """Visible `\\xNN`, `\\uNNNN` or `\\UNNNNNNNN` spelling of every hostile character, for text a person reads in a
    terminal or an export; characters listed in `keep` (for example a newline the renderer itself wrote) pass."""
    def spell(char: str) -> str:
        if char in keep or not is_hostile(char):
            return char
        code = ord(char)
        return f'\\x{code:02x}' if code < 0x100 else (f'\\u{code:04x}' if code < 0x10000 else f'\\U{code:08x}')
    return ''.join(spell(char) for char in text)
