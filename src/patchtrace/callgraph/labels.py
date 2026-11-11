"""Pure parsing of Ghidra/Ghidriff function labels (A1 resolution ladder inputs)."""
from __future__ import annotations

import re
from typing import NamedTuple

_DEFAULT = re.compile(r'^FUN_([0-9a-fA-F]+)$')
_COUNT_SUFFIX = re.compile(r'^(.+)-([0-9]{1,9})$')  # ASCII, bounded: int() of 4300+ digits raises (#105 CG-2)
_ORDINAL = re.compile(r'^#(\d+)$')
_LIB_SUFFIXES = ('.dll', '.drv', '.so')
_EXTERNAL_PREFIX = 'EXTERNAL:'
THUNK_PREFIX = 'thunk_'


class ExternalName(NamedTuple):
    library: str  # lower-cased stem
    name: str

    @property
    def key(self) -> str:
        return f'{self.library}::{self.name}'


def default_address(label: str) -> int | None:
    """Address of a `FUN_<hex>` default name (build-local; never comparable across builds)."""
    m = _DEFAULT.match(label)
    return int(m.group(1), 16) if m else None


def is_default_name(label: str) -> bool:
    return _DEFAULT.match(label) is not None


def thunk_target(label: str) -> str | None:
    """`thunk_X` -> `X` (only for the opt-in thunk rung; callers flag the result thunk-suspect)."""
    if label.startswith(THUNK_PREFIX) and len(label) > len(THUNK_PREFIX):
        return label[len(THUNK_PREFIX):]
    return None


def split_count_suffix(label: str) -> tuple[str, int] | None:
    """`name-N` (--use-calling-counts) -> (`name`, N); None when there is no numeric suffix."""
    m = _COUNT_SUFFIX.match(label)
    return (m.group(1), int(m.group(2))) if m else None


def is_external_address(address: object) -> bool:
    return isinstance(address, str) and address.startswith(_EXTERNAL_PREFIX)


def _library_stem(library: str) -> str:
    stem = library.strip().lower()
    for suffix in _LIB_SUFFIXES:
        if stem.endswith(suffix):
            return stem[:-len(suffix)]
    return stem


def parse_external(label: str) -> ExternalName | None:
    """`LIB.DLL::name` -> (`lib`, `name`); None without a non-empty library and name."""
    library, sep, name = label.partition('::')
    if not sep or not library.strip() or not name:
        return None
    return ExternalName(_library_stem(library), name)


def api_variants(name: str, library: str | None = None) -> tuple[str, ...]:
    """Lookup spellings of an API per capa: the symbol, the symbol minus a trailing A/W
    (length >= 2 after stripping), and `lib.#N` for ordinals. Deduplicated, order kept."""
    variants: list[str] = []
    ordinal = _ORDINAL.match(name)
    if ordinal:
        if library:
            variants.append(f'{_library_stem(library)}.#{ordinal.group(1)}')
    else:
        variants.append(name)
        if len(name) > 2 and name[-1] in 'AW':
            variants.append(name[:-1])
    return tuple(dict.fromkeys(variants))
