"""The one rule for characters that untrusted text may not carry into a stored or displayed field: control (C0, DEL and
C1), format (bidirectional, zero-width, byte order mark, soft hyphen, tag) and surrogate code points. Each sink picks
its own replacement: `pe_overview` a `?`, `intelligence.tools.process.sanitize` a space."""
from __future__ import annotations

import unicodedata

_HOSTILE = frozenset({'Cc', 'Cf', 'Cs'})


def is_hostile(char: str) -> bool:
    return unicodedata.category(char) in _HOSTILE
