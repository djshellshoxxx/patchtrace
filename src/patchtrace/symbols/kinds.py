"""Decoration kinds and the bounded, wrapper-free core name they are read from (WBQ S10, plan section 7)."""
from __future__ import annotations

import re
from typing import Literal, get_args

DecorationKind = Literal['msvc', 'itanium', 'rust', 'rtti', 'string-literal', 'plain']
KINDS: tuple[DecorationKind, ...] = get_args(DecorationKind)

# The repository's name cap. Accepted names are printable ASCII, so characters are bytes.
MAX_NAME_BYTES = 512

_IMPORT_PREFIX = '__imp_'
_PRINTABLE_ASCII = re.compile(r'[\x21-\x7e]+')
_LINK_THUNK = re.compile(r'@ILT\+[0-9]{1,9}\((.+)\)')
# Rust v0 paths start with one of these tags, which keeps MSVC's `_RTC_*` runtime checks out.
_RUST_V0 = re.compile(r'_R[0-9]*[CMXYNIB]')
_RUST_LEGACY = re.compile(r'_ZN.*17h[0-9a-f]{16}E')


def core_name(name: str) -> str | None:
    """`name` without linker wrappers, or None if it is empty, over the cap or not printable ASCII.

    The wrappers are an `@ILT+n(...)` thunk label, a `__imp_` prefix and a trailing `@N` byte count. A byte count
    only counts after a character other than `@`: real names end in `@@8` (RTTI) and `@@9` (no type information).
    """
    if not name or len(name) > MAX_NAME_BYTES or _PRINTABLE_ASCII.fullmatch(name) is None:
        return None
    thunk = _LINK_THUNK.fullmatch(name)
    core = thunk.group(1) if thunk else name
    if core.startswith(_IMPORT_PREFIX) and len(core) > len(_IMPORT_PREFIX):
        core = core[len(_IMPORT_PREFIX):]
    at = core.rfind('@')
    count = core[at + 1:]
    if at > 0 and core[at - 1] != '@' and count.isdigit() and len(count) <= 4:
        core = core[:at]
    return core


def kind_of(core: str) -> DecorationKind:
    """The scheme a core name starts like; it does not say that the rest is valid."""
    if core.startswith('??_C@_'):
        return 'string-literal'
    if core.startswith(('.?AV', '.?AU')):
        return 'rtti'
    if core.startswith('?'):
        return 'msvc'
    if _RUST_V0.match(core) or _RUST_LEGACY.fullmatch(core):
        return 'rust'
    if core.startswith('_Z'):
        return 'itanium'
    return 'plain'
