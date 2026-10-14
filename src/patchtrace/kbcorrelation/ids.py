"""KB and CVE identifier rules (`kb-syntax/1`). Pure stdlib.

Canonical KB syntax: ``KB`` followed by 4-10 ASCII digits, upper-case prefix, leading zeros kept. A KB id is an
opaque label: it is never converted to a number (``KB0001234`` and ``KB1234`` are different ids). Bare digits and
a lower-case or spaced prefix are accepted only by :func:`normalise_kb_edge`, which belongs at the CLI and GUI edge;
every stored or exchanged record uses the canonical form.
"""
from __future__ import annotations

import re

KB_SYNTAX = 'kb-syntax/1'
KB_PATTERN = r'^KB[0-9]{4,10}$'
KB_MIN_DIGITS, KB_MAX_DIGITS = 4, 10

_KB = re.compile(r'KB[0-9]{4,10}')
_KB_EDGE = re.compile(r'(?:[Kk][Bb][ \t-]?)?([0-9]{4,10})')
_KB_TOKEN = re.compile(r'(?<![A-Za-z0-9])KB([0-9]{4,10})(?![A-Za-z0-9])')
_CVE = re.compile(r'CVE-([0-9]{4})-([0-9]{4,19})')
_CVE_ALPHA = re.compile(r'[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,19}')


class KbSyntaxError(ValueError):
    """Raised for text that is not a KB or CVE identifier; the message never echoes the input."""


def is_canonical_kb(value: object) -> bool:
    return type(value) is str and _KB.fullmatch(value) is not None


def canonical_kb(value: str) -> str:
    """Return ``value`` unchanged when it is already canonical, else raise."""
    if not is_canonical_kb(value):
        raise KbSyntaxError(f'not a canonical KB id ({KB_SYNTAX}: KB + {KB_MIN_DIGITS}-{KB_MAX_DIGITS} ASCII digits)')
    return value


def normalise_kb_edge(raw: object) -> str:
    """Edge normaliser (CLI/GUI input only): trims spaces and tabs, accepts ``kb``/``KB`` (optionally followed by
    one space, tab or dash) and bare digits, and returns the canonical id with leading zeros kept."""
    if type(raw) is not str:
        raise KbSyntaxError('KB input must be text')
    match = _KB_EDGE.fullmatch(raw.strip(' \t'))
    if match is None:
        raise KbSyntaxError(f'not a KB id ({KB_SYNTAX}: KB + {KB_MIN_DIGITS}-{KB_MAX_DIGITS} ASCII digits)')
    return 'KB' + match.group(1)


def kb_sort_key(value: str) -> tuple[int, str]:
    """Total order without a numeric cast: digit count first, then the digit string."""
    canonical_kb(value)
    return len(value), value


def find_kb_tokens(text: str) -> tuple[str, ...]:
    """Exact upper-case ``KB`` tokens of 4-10 digits in free text, sorted and unique. Anything glued to
    letters or digits (``XKB1234``, ``KB1234x``) is not a token."""
    return tuple(sorted({'KB' + m.group(1) for m in _KB_TOKEN.finditer(text)}, key=kb_sort_key))


def is_cve(value: object) -> bool:
    return type(value) is str and _CVE.fullmatch(value) is not None


def normalise_cve(raw: object) -> str:
    """Canonical ``CVE-YYYY-NNNN+`` (upper case; trims spaces and tabs). Digits are ASCII only."""
    if type(raw) is not str:
        raise KbSyntaxError('CVE input must be text')
    text = raw.strip(' \t')
    if _CVE_ALPHA.fullmatch(text) is None:
        raise KbSyntaxError('not a CVE id (CVE-YYYY-NNNN with 4-19 ASCII digits)')
    return text.upper()


def cve_sort_key(value: str) -> tuple[int, int, str]:
    match = _CVE.fullmatch(value)
    if match is None:
        raise KbSyntaxError('not a CVE id')
    return int(match.group(1)), len(match.group(2)), match.group(2)
