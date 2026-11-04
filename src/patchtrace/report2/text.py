"""Normalization of untrusted text (SPEC-50 7.3), the escaping matrix (7.4) and the fence helper.

`normalize_text` applies the caps once while a contract is built. The escapers re-run the idempotent neutralization
(surrogates, bidirectional and control characters) so a renderer can never emit a raw control even when a caller skipped
the first step. Deviations from 7.3, recorded in the spec status line: every format (Cf) character, U+2028 and U+2029
count as controls (the `hostile_text` rule), CRLF folds to LF in verbatim text, and U+FFFD is written by a regex because
`encode('utf-8', 'replace')` would write `?`.
"""
from __future__ import annotations

import html
import json
import re
import unicodedata

from ..reports import ExportError

CAP_NAME, CAP_EVIDENCE, CAP_ADVISORY, CAP_NOTES = 512, 8192, 4096, 16384
MAX_MATCHES, MAX_ADVISORIES, MAX_BUILD_FACTS, MAX_EVIDENCE_ROWS = 10000, 1000, 5000, 2000
URL_MODES = ('text', 'defanged', 'removed')

_SURROGATE = re.compile('[\ud800-\udfff]')
_BIDI = re.compile('[‎‏‪-‮⁦-⁩؜]')
_UNSAFE = frozenset({'Cc', 'Cf', 'Zl', 'Zp'})
_ID = re.compile('[a-z0-9-]{1,64}')
_MD_SPECIAL = re.compile(r'([\\`*_{}\[\]()#+.!|>~:@/=-])')


def _is_unsafe(char: str, verbatim: bool) -> bool:
    return unicodedata.category(char) in _UNSAFE and not (verbatim and char in '\n\t')


def neutralize(value: str, *, verbatim: bool = False) -> str:
    """Steps 1, 3 and 4 of 7.3; idempotent, no length cap."""
    value = _SURROGATE.sub('�', value)
    if verbatim:
        value = value.replace('\r\n', '\n')
    value = _BIDI.sub(lambda m: f'<U+{ord(m.group()):04X}>', value)
    if value.isascii() and value.isprintable():
        return value
    return ''.join('?' if _is_unsafe(c, verbatim) else c for c in value)


def normalize_text(value: str, *, verbatim: bool = False, max_chars: int) -> str:
    out = neutralize(value, verbatim=verbatim)
    if len(out) > max_chars:
        return f'{out[:max_chars]}[truncated {len(out) - max_chars} chars]'
    return out


def encode_report(value: str) -> bytes:
    """The one UTF-8 boundary: a string that still holds a lone surrogate is refused, never half-written."""
    try:
        return value.encode('utf-8')
    except UnicodeError:
        raise ExportError('PT-EXPORT-ENCODING: report text is not encodable as UTF-8') from None


def json_dumps(value, *, indent: int | None = None) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=indent)


def safe_id(value: str) -> str:
    """Generated element ids are the only values an HTML attribute may carry."""
    if not _ID.fullmatch(value):
        raise ValueError('generated id must match ^[a-z0-9-]{1,64}$')
    return value


def html_text(value: str) -> str:
    return html.escape(neutralize(value), quote=True)


def html_pre(value: str) -> str:
    return html.escape(neutralize(value, verbatim=True), quote=True)


def _one_line(value: str) -> str:
    return ' '.join(neutralize(value, verbatim=True).split())


def markdown_escape(value: str) -> str:
    return _MD_SPECIAL.sub(r'\\\1', html.escape(value, quote=False))


def md_heading(value: str) -> str:
    return markdown_escape(_one_line(value))


def md_cell(value: str) -> str:
    return markdown_escape(_one_line(value))


def md_paragraph(value: str) -> str:
    return markdown_escape(_one_line(value))


def fence_for(value: str) -> str:
    longest = max((len(run) for run in re.findall('`+', value)), default=0)
    return '`' * max(3, longest + 1)


def md_fence(value: str) -> str:
    body = neutralize(value, verbatim=True)
    fence = fence_for(body)
    return f'{fence}\n{body}\n{fence}'


def display_url(value: str, mode: str) -> str:
    """URLs are inert text, never links; `defanged` and `removed` follow the redaction profile."""
    if mode not in URL_MODES:
        raise ValueError(f'urls must be one of {URL_MODES}')
    if mode == 'removed':
        return '[URL REMOVED]'
    out = neutralize(value)
    return re.sub('(?i)http', 'hxxp', out).replace('.', '[.]') if mode == 'defanged' else out
