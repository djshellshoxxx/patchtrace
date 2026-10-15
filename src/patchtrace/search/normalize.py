"""Text normalisation for names, queries and indexed display text (WB1 section 6, 7).

`fold` is for names only (compat forms, case); `sanitize_text` escapes what must never reach an index or a UI
verbatim. Its rules equal `intelligence.tools.common.display_text` (a test cross-checks them), except that code
and multi-line text may keep real newlines.
"""
from __future__ import annotations

import re
import unicodedata

from patchtrace.search.errors import SearchError

_INVISIBLE = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'})
_ESCAPES = {'\n': '\\n', '\t': '\\t', '\r': '\\r'}
_AUTO_NAME = re.compile(r'(?:thunk_)?(?:FUN|LAB|DAT|PTR|SUB|sub|loc|off|unk)_[0-9a-fA-F]{4,}')


def nfc(text: str) -> str:
    return unicodedata.normalize('NFC', text)


def fold(text: str) -> str:
    """NFKC + casefold: the stored and queried form of a name."""
    return unicodedata.normalize('NFKC', text).casefold()


def is_auto_name(name: str) -> bool:
    """Ghidra/IDA placeholder names (`FUN_140001a40`, `sub_401000`, `LAB_...`): ranked last, never fuzzy."""
    return _AUTO_NAME.fullmatch(name) is not None


def sanitize_text(value: str, limit: int, *, multiline: bool = False) -> str:
    """Plain-text rendering of untrusted text: control, format (bidi, zero-width), surrogate, private-use and
    unassigned characters are escaped and the result is capped at `limit` characters. STX and ETX (the snippet
    markers) are control characters, so they never occur in sanitised text."""
    out: list[str] = []
    size = 0
    for char in value:
        if char == ' ' or unicodedata.category(char) not in _INVISIBLE or (multiline and char == '\n'):
            piece = char
        elif char in _ESCAPES:
            piece = _ESCAPES[char]
        elif ord(char) < 0x100:
            piece = f'\\x{ord(char):02x}'
        elif ord(char) < 0x10000:
            piece = f'\\u{ord(char):04x}'
        else:
            piece = f'\\U{ord(char):08x}'
        if size + len(piece) > limit - 3:
            out.append('...')
            break
        out.append(piece)
        size += len(piece)
    return ''.join(out)


def query_error(message: str) -> SearchError:
    return SearchError('PT-SEARCH-QUERY', message, recoverable=True)


def clean_query_text(text: str) -> str:
    """NFC text with runs of whitespace collapsed; refuses what cannot be searched or safely shown."""
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        raise query_error('the query contains an unpaired surrogate') from None
    for char in text:
        if unicodedata.category(char) in _INVISIBLE and char not in '\t\n\r':
            raise query_error(f'the query contains a control or invisible character (U+{ord(char):04X})')
    return ' '.join(nfc(text).split())
