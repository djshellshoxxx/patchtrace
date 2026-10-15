"""Index-time identifier splitting (WB1 section 7 'Tokenization decisions').

`unicode61` splits `_ @ ? :` but not CamelCase, so `copy` would miss `RtlCopyMemory` [F8]. The `words` and
`idents` columns hold the split forms; the raw folded name stays in its own column. Pure and memoised.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from patchtrace.search.normalize import fold

MAX_NAME_WORDS = 128
_TOKEN = re.compile(r'(?<![^\W_])(?P<hex>0[xX][0-9a-fA-F]+)(?![^\W_])|[^\W_]+')
_HEX_RUN = re.compile(r'(?=[a-fA-F]*[0-9])(?:[0-9a-f]{4,}|[0-9A-F]{4,})')  # an address like `140001a40` stays whole
_IDENT = re.compile(r'(?<![0-9A-Za-z_])[A-Za-z_][A-Za-z0-9_]*')
_MSVC = re.compile(r'\?([^@?$][^@?]*)((?:@[^@?]+)*)@@')


def _kind(char: str) -> str:
    if char.isupper():
        return 'U'
    if char.islower():
        return 'L'
    return 'D' if unicodedata.category(char).startswith('N') else 'O'


def _split_run(run: str) -> list[str]:
    if _HEX_RUN.fullmatch(run):
        return [run.lower()]
    kinds = [_kind(char) for char in run]
    words, start = [], 0
    for i in range(1, len(run)):
        prev, cur = kinds[i - 1], kinds[i]
        acronym_end = prev == 'U' and cur == 'U' and i + 1 < len(run) and kinds[i + 1] == 'L'
        if acronym_end or (prev != cur and not (prev == 'U' and cur == 'L')):
            words.append(run[start:i])
            start = i
    words.append(run[start:])
    return [fold(word) for word in words]


@lru_cache(maxsize=65_536)
def split_identifier(name: str) -> tuple[str, ...]:
    """Lower-case words of an identifier: CamelCase, acronym and letter/digit boundaries; `0x..` stays whole."""
    words: list[str] = []
    for match in _TOKEN.finditer(name):
        words.extend([match.group().casefold()] if match.group('hex') else _split_run(match.group()))
    return tuple(words)


def msvc_light(name: str) -> str | None:
    """`?Validate@CFoo@@QEAAHXZ` -> `CFoo::Validate`; None for anything else (special names, templates)."""
    if name.startswith('??'):
        return None
    match = _MSVC.match(name)
    if match is None:
        return None
    scopes = [part for part in match.group(2).split('@') if part]
    return '::'.join([*reversed(scopes), match.group(1)])


def name_words(*names: str) -> str:
    """The `fts_name.words` value: split words of every given name form (raw, demangled) and the MSVC-light
    `Class::method` form, deduplicated in first-seen order."""
    seen: dict[str, None] = {}
    for name in names:
        light = msvc_light(name)
        for form in (name, light) if light else (name,):
            seen.update(dict.fromkeys(split_identifier(form)))
    return ' '.join(list(seen)[:MAX_NAME_WORDS])


def code_idents(text: str, max_words: int = 20_000) -> str:
    """The `fts_code.idents` value: deduplicated split words of every identifier in decompiled text."""
    seen: dict[str, None] = {}
    for match in _IDENT.finditer(text):
        seen.update(dict.fromkeys(split_identifier(match.group())))
        if len(seen) >= max_words:
            break
    return ' '.join(list(seen)[:max_words])
