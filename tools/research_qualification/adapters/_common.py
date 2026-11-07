"""Shared bounds, input loading, name normalisation and ranking for the diff-engine adapters.

Everything here treats the input as hostile data: it is only ever decoded and parsed, never executed, evaluated or
used to build a path. Any problem raises ValueError with a message that says what was wrong.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable

from .. import pathguard

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_CHARS = 1024 * 1024
MAX_NAME_CHARS = 512
MAX_FUNCTIONS = 500_000

Source = str | bytes | os.PathLike

_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]')
_TRAVERSAL = re.compile(r'(^|[\\/])\.\.([\\/]|$)')
# x86 stdcall/fastcall decoration on a plain C identifier only: `_name@8` or `@name@8`. Anything else is kept.
_DECORATED = re.compile(r'^[_@]([A-Za-z_][A-Za-z0-9_]*)@\d{1,3}$')


def normalise_name(raw: object) -> str | None:
    """Return the function name as reported, minus clear x86 calling-convention decoration; None when blank.

    Kept verbatim: C++ scopes (`A::b`), `sub_XXXX` / `FUN_XXXX` (auto names, the address is the identity), `__x`
    and `_x` (no way to tell decoration from a real name). Raises ValueError for control or bidi characters,
    path traversal segments and over-long names; nothing is ever invented or guessed.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError(f'function name must be text, got {type(raw).__name__}')
    name = raw.strip()
    if not name:
        return None
    if len(name) > MAX_NAME_CHARS:
        raise ValueError(f'function name longer than {MAX_NAME_CHARS} characters')
    if _CONTROL.search(name):
        raise ValueError('function name contains control or bidirectional-override characters')
    if _TRAVERSAL.search(name):
        raise ValueError(f'function name looks like a path traversal: {name[:60]!r}')
    match = _DECORATED.match(name)
    return match.group(1) if match else name


def load_text(source: Source, what: str) -> str:
    """str -> the content itself; bytes -> content; PathLike -> confined file read. Size, NUL and line capped."""
    if isinstance(source, os.PathLike):
        path = pathguard.confine(source, what)
        if not path.is_file():
            raise ValueError(f'{what} is not a regular file: {path}')
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f'{what} exceeds {MAX_INPUT_BYTES} bytes')
        source = path.read_bytes()
    if isinstance(source, bytes | bytearray):
        if len(source) > MAX_INPUT_BYTES:
            raise ValueError(f'{what} exceeds {MAX_INPUT_BYTES} bytes')
        try:
            source = bytes(source).decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ValueError(f'{what} is not valid UTF-8 text') from exc
    if not isinstance(source, str):
        raise ValueError(f'{what} must be text, bytes or a path, got {type(source).__name__}')
    if len(source) > MAX_INPUT_BYTES:
        raise ValueError(f'{what} exceeds {MAX_INPUT_BYTES} characters')
    if '\x00' in source:
        raise ValueError(f'{what} contains NUL bytes (binary data, not a text report)')
    if not source.strip():
        raise ValueError(f'{what} is empty')
    if max(map(len, source.splitlines()), default=0) > MAX_LINE_CHARS:
        raise ValueError(f'{what} has a line longer than {MAX_LINE_CHARS} characters')
    return source


def rank(changed: Iterable[tuple[str, float]], one_sided: Iterable[str] = ()) -> list[str]:
    """Names by descending magnitude then name, then one-sided (added/removed only) names by name.

    A name already placed higher is not repeated. Raises ValueError past MAX_FUNCTIONS.
    """
    best: dict[str, float] = {}
    for name, magnitude in changed:
        if magnitude != magnitude or magnitude < 0:
            raise ValueError(f'invalid change magnitude for {name!r}')
        if magnitude > best.get(name, -1.0):
            best[name] = magnitude
        if len(best) > MAX_FUNCTIONS:
            raise ValueError(f'more than {MAX_FUNCTIONS} changed functions')
    ordered = sorted(best, key=lambda n: (-best[n], n))
    seen = set(ordered)
    extra = sorted({n for n in one_sided if n not in seen})
    if len(ordered) + len(extra) > MAX_FUNCTIONS:
        raise ValueError(f'more than {MAX_FUNCTIONS} functions')
    return ordered + extra


def unit_float(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f'{what} must be a number')
    try:
        f = float(value)
    except OverflowError as exc:
        raise ValueError(f'{what} is out of range') from exc
    if f != f or f < 0.0 or f > 1.0:
        raise ValueError(f'{what} must be within 0..1, got {value!r}')
    return f


__all__ = ['MAX_FUNCTIONS', 'MAX_INPUT_BYTES', 'MAX_LINE_CHARS', 'MAX_NAME_CHARS', 'normalise_name',
           'load_text', 'rank', 'unit_float']
