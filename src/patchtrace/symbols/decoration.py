"""Qualified name and type-encoding tail of an MSVC-decorated name (WBQ S10, plan section 7).

This is not a demangler: it only splits `?name@scope@@<type encoding>` so that two builds of an export can be
compared as "same qualified name, different tail". The split is checked against LLVM's Microsoft demangler on
tests/fixtures/wbq/ms_kat.tsv. Total on any text: no exception, no I/O, nothing is loaded or run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .kinds import DecorationKind, core_name, kind_of

_NAME_TABLE_SIZE = 10  # the digits 0-9 of a back reference
_PLAIN_PIECE = re.compile(r'[A-Za-z0-9_$]+')
# A 510-character name can repeat a 252-character scope 252 times through back references (65,000 characters);
# this is also the plan's display cap. Names without back references never reach it (at most about 1,013).
MAX_QUALIFIED_NAME_CHARS = 1024


@dataclass(frozen=True, slots=True)
class Decoration:
    """What can be read from a symbol name; `original` is the input and stays its identity.

    `qualified_name` and `tail` are set only for an MSVC name whose scope chain is plain identifiers (a
    constructor or destructor counts). `complex` marks an MSVC name that uses templates, operators, special
    names or local and anonymous scopes, or whose back references would expand past MAX_QUALIFIED_NAME_CHARS,
    so no name is derived; a malformed name is neither derived nor complex.
    """

    kind: DecorationKind
    original: str
    qualified_name: str | None = None
    tail: str | None = None
    complex: bool = False


def parse_decoration(name: str) -> Decoration:
    core = core_name(name)
    if core is None:
        return Decoration('plain', name)
    kind = kind_of(core)
    if kind != 'msvc':
        return Decoration(kind, name)
    qualified_name, tail, complex_name = _msvc_facts(core)
    return Decoration(kind, name, qualified_name, tail, complex_name)


def _msvc_facts(core: str) -> tuple[str | None, str | None, bool]:
    """(qualified_name, tail, complex) of a name that starts with `?`.

    The chain is written innermost first, `name@scope@scope@`, and ended by one more `@`. A digit repeats one of
    the first ten distinct names met so far, and an equal name is never entered twice (both as in LLVM).
    `??0` and `??1` have no name: the class, the first scope, is the constructor or destructor.
    """
    position, structor = 1, ''
    if core.startswith('??'):
        structor = core[2:3]
        if structor not in ('0', '1'):
            return None, None, True
        position = 3
    table: list[str] = []
    pieces: list[str] = []
    while position < len(core) and core[position] != '@':
        char = core[position]
        if char == '?':
            return None, None, True
        if '0' <= char <= '9':
            if int(char) >= len(table):
                return None, None, False
            pieces.append(table[int(char)])
            position += 1
            continue
        end = core.find('@', position)
        if end < 0:
            return None, None, False
        piece = core[position:end]
        if _PLAIN_PIECE.fullmatch(piece) is None:
            return None, None, True
        if piece not in table and len(table) < _NAME_TABLE_SIZE:
            table.append(piece)
        pieces.append(piece)
        position = end + 1
    tail = core[position + 1:]
    if not pieces or not tail or position >= len(core):
        return None, None, False
    if structor:
        pieces.insert(0, ('~' if structor == '1' else '') + pieces[0])
    if sum(map(len, pieces)) + 2 * (len(pieces) - 1) > MAX_QUALIFIED_NAME_CHARS:  # before the join builds it
        return None, None, True
    return '::'.join(reversed(pieces)), tail, False
