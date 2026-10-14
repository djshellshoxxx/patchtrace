"""Decompiled string literals (WB3-S4, link tier L4). Pure: no Qt, no I/O.

Ghidra prints image strings as `"..."` (wide `L"..."`) and escapes everything outside printable text (spec F13);
the escapes cannot be parsed back unambiguously, so a literal is never unescaped as a whole. It is cut at every
escape except `\\t \\\\ \\" \\'`, because FLOSS 3.1.1 itself ends a string at CR, LF and any other byte outside its
character class (`"bad header (%s)\\n"` yields the segment `bad header (%s)`). The four kept escapes map one-to-one
to a single character, so a segment's text is exactly the value FLOSS would hold and links by value hash.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .limits import MAX_LITERAL_LINES, MAX_LITERALS_PER_FUNCTION

TRUNCATED_MARKER = re.compile(r'[ \t]*/\* TRUNCATED STRING LITERAL \*/')
TRUNCATION_DOTS = '...'
# The decompiler writes `\xNN`, `\xNNNN` or `\xNNNNNNNN` by code point, so digits after an escape may be text.
_TOKEN = re.compile(r'\\(x[0-9a-fA-F]{1,8}|[\\"\'t]|.)|([^\\]+)|\\', re.DOTALL)
_KEPT = {'\\': '\\', '"': '"', "'": "'", 't': '\t'}
_UNPRINTABLE = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'})
_IDENT = re.compile(r'[A-Za-z0-9_]')


@dataclass(frozen=True)
class Segment:
    text: str
    open_end: bool  # no cut follows: in a truncated literal this segment is only a prefix of the real string


@dataclass(frozen=True)
class Literal:
    body: str
    wide: bool
    truncated: bool
    line: int


@dataclass(frozen=True)
class LiteralScan:
    literals: tuple[Literal, ...]
    capped: bool


def segments(body: str, *, truncated: bool = False) -> tuple[Segment, ...]:
    """Cut `body` (the text between the quotes, still escaped) into FLOSS-shaped segments."""
    if truncated and body.endswith(TRUNCATION_DOTS):
        body = body[:-len(TRUNCATION_DOTS)]
    out: list[Segment] = []
    current: list[str] = []

    def flush(open_end: bool) -> None:
        if current:
            out.append(Segment(''.join(current), open_end))
            current.clear()
    for match in _TOKEN.finditer(body):
        escape, text = match.group(1), match.group(2)
        if text is not None:
            current.append(text)
        elif escape in _KEPT:
            current.append(_KEPT[escape])
        else:
            flush(False)
            if escape and escape[0] == 'x' and len(escape) > 1 and (rest := escape[1 + _hex_width(escape[1:]):]):
                current.append(rest)
    flush(True)
    return tuple(out)


def _hex_width(digits: str) -> int:
    """How many of `digits` belong to the escape: the longest width whose code point Ghidra would have escaped
    (unprintable and wide enough for that width); otherwise two. The rest is ordinary text."""
    for width, low, high in ((8, 0x10000, 0x10FFFF), (4, 0x100, 0xFFFF)):
        if len(digits) >= width and low <= (value := int(digits[:width], 16)) <= high \
                and unicodedata.category(chr(value)) in _UNPRINTABLE:
            return width
    return min(2, len(digits))


def extract_literals(code: str) -> LiteralScan:
    """String literals of decompiled C in source order. Comments and character literals are skipped."""
    literals: list[Literal] = []
    i, line, n = 0, 1, len(code)
    while i < n:
        char = code[i]
        if char == '\n':
            line += 1
            if line > MAX_LITERAL_LINES:
                return LiteralScan(tuple(literals), True)
        elif code.startswith('//', i):
            i = _line_end(code, i)
            continue
        elif code.startswith('/*', i):
            end = code.find('*/', i + 2)
            end = n if end < 0 else end + 2
            line += code.count('\n', i, end)
            i = end
            continue
        elif char == "'":
            i = _skip_quoted(code, i, "'")[0]
            continue
        elif char == '"':
            end, closed = _skip_quoted(code, i, '"')
            if closed:
                if len(literals) >= MAX_LITERALS_PER_FUNCTION:
                    return LiteralScan(tuple(literals), True)
                marker = TRUNCATED_MARKER.match(code, end)
                wide = i > 0 and code[i - 1] == 'L' and not (i > 1 and _IDENT.match(code[i - 2]))
                literals.append(Literal(code[i + 1:end - 1], wide, marker is not None, line))
                end = marker.end() if marker else end
            i = end
            continue
        i += 1
    return LiteralScan(tuple(literals), False)


def _line_end(code: str, start: int) -> int:
    end = code.find('\n', start)
    return len(code) if end < 0 else end


def _skip_quoted(code: str, start: int, quote: str) -> tuple[int, bool]:
    """(index after the closing quote, True), or (the line end, False) when the literal is unterminated."""
    i, n = start + 1, len(code)
    while i < n and code[i] != '\n':
        if code[i] == '\\':
            i += 1 if code.startswith('\n', i + 1) else 2
            continue
        if code[i] == quote:
            return i + 1, True
        i += 1
    return min(i, n), False
