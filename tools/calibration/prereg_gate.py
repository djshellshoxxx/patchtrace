"""Recorded protocol identity for training CLI selection (LBL-30; dev-only).

Adapted narrowly from preserved PR #85. This module validates a recorded digest;
it does not assert owner approval or consume the single-use final evaluation.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from . import prereg

_SHA = re.compile(r'(?<![A-Za-z0-9])[0-9a-f]{64}(?![A-Za-z0-9])')
_FENCE = re.compile(r'^ {0,3}(`{3,}|~{3,})(.*)$')
_BACKTICKS = re.compile(r'`+')
_RAW_HTML = re.compile(r'<(?:[!?]|/?[A-Za-z][A-Za-z0-9-]*(?=[\s/>]|$))')


class PreregGateError(ValueError):
    """The requested protocol cannot support a preregistration identity claim."""


@dataclass(frozen=True)
class Selection:
    sha: str | None
    rehearsal_sha: str | None = None


def _check_plain_markup(line: str) -> None:
    """Refuse raw HTML and unsupported multiline code rather than guessing visibility.

    Same-line code spans can contain literal HTML/path placeholders. Delimiters
    match by exact backtick-run length; shorter runs inside a span are literal.
    """
    plain = ''
    position = 0
    while opening := _BACKTICKS.search(line, position):
        plain += line[position:opening.start()]
        closing = next((match for match in _BACKTICKS.finditer(line, opening.end())
                        if len(match[0]) == len(opening[0])), None)
        if closing is None:
            raise PreregGateError('unsupported QA format: inline code spans must close on the same line')
        position = closing.end()
    plain += line[position:]
    if _RAW_HTML.search(plain):
        raise PreregGateError('unsupported QA format: raw HTML outside code examples/comments is refused')


def _visible_lines(text: str) -> Iterator[str]:
    """Exclude fenced/indented examples and comments rather than treating them as records.

    Fences are closed only by the same character with at least the opening
    length. Comment syntax inside a fence is literal and cannot hide later rows.
    This is a conservative record scan, not a general Markdown renderer.
    """
    fence = ''
    commented = False
    for line in text.splitlines():
        record_at_start = line.startswith('|')
        if fence:
            closing = line.lstrip(' ')
            marker = closing.rstrip(' \t')
            if (len(line) - len(closing) <= 3 and len(marker) >= len(fence)
                    and all(c == fence[0] for c in marker)):
                fence = ''
            continue
        visible = ''
        while line:
            if commented:
                end = line.find('-->')
                if end < 0:
                    break
                line, commented = line[end + 3:], False
            else:
                start = line.find('<!--')
                if start < 0:
                    visible += line
                    break
                visible += line[:start]
                line, commented = line[start + 4:], True
        opening = _FENCE.match(visible)
        if opening:
            fence = opening[1]
            continue
        if visible.expandtabs(4).startswith('    '):
            continue
        _check_plain_markup(visible)
        if record_at_start:
            yield visible


def _recorded_sha(text: str) -> str:
    rows = []
    for line in _visible_lines(text):
        line = line.strip()
        if not line.startswith('|') or not line.endswith('|'):
            continue
        cells = [cell.strip() for cell in line[1:-1].split('|')]
        if prereg.QA_ROW in cells:
            rows.append((cells.count(prereg.QA_ROW), _SHA.findall(line)))
    if len(rows) != 1 or rows[0][0] != 1 or len(rows[0][1]) != 1:
        raise PreregGateError(f'need one unambiguous {prereg.QA_ROW} QA table row with one SHA-256')
    return rows[0][1][0]


def select(path: Path | None, qa_path: Path, *, allow_unlocked: bool = False) -> Selection:
    """Validate exact LF bytes before corpus access, or explicitly select rehearsal.

    A rehearsal digest appears only in the command summary. The report and train
    key receive None and therefore retain the existing unlocked placeholder.
    """
    if path is None:
        if allow_unlocked:
            raise PreregGateError('--unlocked-prereg requires --prereg FILE')
        return Selection(None)
    try:
        actual = prereg.prereg_sha256(path)
    except (prereg.PreregError, OSError) as exc:
        raise PreregGateError(f'preregistration unreadable or invalid: {exc}') from None
    if allow_unlocked:
        return Selection(None, actual)
    try:
        text = qa_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        text = ''
    except (OSError, UnicodeError) as exc:
        raise PreregGateError(f'QA lock record unreadable: {exc}') from None
    if actual != _recorded_sha(text):
        raise PreregGateError(f'{prereg.QA_ROW} SHA-256 mismatch: protocol bytes differ from recorded digest')
    return Selection(actual)
