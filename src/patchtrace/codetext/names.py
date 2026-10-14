"""Ghidra name classes shared by the code tokenizer and the operand rules (WBQ S7, `codetext/1`). Pure.

When two builds of one function are compared, two kinds of name change for reasons that say nothing about behaviour:

* address-derived names (`FUN_140001000`, `DAT_14000b000`, `thunk_FUN_...`): the hex tail is a location, so the
  name moves whenever the code around it moves;
* decompiler temporaries (`uVar1`, `local_18`, `param_2`, `in_RAX`): numbered by first use, so they renumber when
  a statement is inserted.

Every other name (`CreateFileW`, `strcpy`, a variable someone renamed) was chosen by a person or an import table and
is never classed as noise. The patterns follow Ghidra's `SymbolUtilities` (Apache-2.0, read only): dynamic names are
`PREFIX_<address>` with at least four hex digits, external placeholders add `EXT_`. The temporary pattern is the one
`unified/facts/pseudo.py` already uses for `canon/1`, so both agree on what a temporary is.
"""
from __future__ import annotations

import re
from typing import Literal, NamedTuple

_PREFIXES = ('FUN', 'SUB', 'LAB', 'DAT', 'UNK', 'OFF', 'PTR', 'BYTE', 'WORD', 'DWORD', 'QWORD', 'FLOAT', 'DOUBLE',
             'ADDR', 'EXT')
# Optional pieces in order: the decompiler's underscore before a global, `thunk_`, `EXT_`, pointer labels
# (`PTR_FUN_<address of the pointer cell>`), then the mandatory `PREFIX_<hex>`. Use with `fullmatch`.
AUTO_NAME = re.compile(
    rf'_?(?:thunk_)?(?:EXT_)?(?P<pointer>(?:PTR_)*)(?P<prefix>{"|".join(_PREFIXES)})_(?P<address>[0-9a-fA-F]{{4,16}})',
    re.ASCII)
# Use with `fullmatch`.
TEMP_NAME = re.compile(
    r'(?:[a-z]{1,4}Var\d+|[a-z]{1,4}Stack_[0-9a-fA-F]+|local_(?:res)?[0-9a-fA-F]+|param_\d+|in_[A-Za-z0-9_]+'
    r'|unaff_[A-Za-z0-9_]+|extraout_[A-Za-z0-9_]+|stack0x[0-9a-fA-F]+)', re.ASCII)
_FUNCTION_PREFIXES = frozenset({'FUN', 'SUB'})


class AutoName(NamedTuple):
    kind: Literal['function', 'label', 'data']
    address: int


def parse_auto_name(name: str) -> AutoName | None:
    """What an address-derived name points at, or None for any other name.

    A `PTR_` name is the label of a pointer cell, so it is data even when it says `PTR_FUN_...`; the hex tail is the
    cell's own address, not the function's."""
    match = AUTO_NAME.fullmatch(name)
    if match is None:
        return None
    prefix = match['prefix']
    if match['pointer'] or prefix == 'PTR':
        kind = 'data'
    elif prefix in _FUNCTION_PREFIXES:
        kind = 'function'
    else:
        kind = 'label' if prefix == 'LAB' else 'data'
    return AutoName(kind, int(match['address'], 16))


def is_temp_name(name: str) -> bool:
    return TEMP_NAME.fullmatch(name) is not None


def classify_name(name: str) -> Literal['auto_name', 'temp'] | None:
    """The token kind of a name that is generated rather than chosen, else None."""
    if AUTO_NAME.fullmatch(name):
        return 'auto_name'
    if TEMP_NAME.fullmatch(name):
        return 'temp'
    return None
