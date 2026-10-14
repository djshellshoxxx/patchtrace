"""PE facts for localization: the image layouts that turn Ghidriff addresses into RVAs, and the import delta of a pair.

Both come from PatchTrace's own bounded `pe_overview` parse of the hash-verified bytes (origin `D_pe_tables`), never from
an engine. An import table that is cut at the parser limit or cannot be read is unknown, never an empty table: an
import is called added only against a complete older table and removed only against a complete newer one. Names are
compared exactly (API names are case sensitive); only DLL names are lower-cased.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

from ...pe_overview import PeOverview
from ...unified.addressing import AddressMap, PeLayout
from ..contracts import clean_line

ImportState = Literal['available', 'partial', 'unavailable']
_UNREADABLE = '<'  # the parser spells an unreadable name or thunk `<unreadable ...>` / `<invalid thunk ...>`
_EMPTY: dict[str, tuple[str, ...]] = {}


def address_map(older: PeOverview, newer: PeOverview) -> AddressMap | None:
    """The two image layouts of a pair, or None when either file has no readable ImageBase and SizeOfImage."""
    layouts = []
    for overview in (older, newer):
        if overview.image_base is None or not overview.size_of_image:
            return None
        layouts.append(PeLayout(image_base=overview.image_base, size_of_image=overview.size_of_image))
    return AddressMap(layouts[0], layouts[1])


@dataclass(frozen=True)
class _Side:
    """One file's imports: complete (`known`), cut at the parser limit (`truncated`), `readable` at all."""
    names: frozenset[str]
    by_name: dict[str, tuple[str, ...]]
    readable: bool
    truncated: bool
    skipped: bool


def _side(overview: PeOverview) -> _Side:
    info = overview.imports
    if info is None:
        directory = overview.directory('Import')
        absent = directory is not None and not directory.present  # a file without imports has an empty table
        return _Side(frozenset(), _EMPTY, absent, False, False)
    qualified: set[str] = set()
    dlls: dict[str, set[str]] = defaultdict(set)
    skipped = False
    for dll in info.dlls:
        library = dll.name.lower()
        if library.startswith(_UNREADABLE):
            skipped = True
            continue
        for name in dll.functions:
            if name.startswith(_UNREADABLE):
                skipped = True
                continue
            qualified.add(f'{library}!{name}')
            dlls[name].add(library)
    return _Side(frozenset(qualified), {n: tuple(sorted(found)) for n, found in dlls.items()}, True, info.truncated,
                 skipped)


@dataclass(frozen=True)
class ImportDelta:
    """What the newer file's import table gained and lost as `dll!name`, plus the means to name an API's DLL.

    `state` is `partial` when a table was cut or held unreadable names (what is listed is still true, but absence on
    that side proves nothing) and `unavailable` when a table could not be read at all."""
    state: ImportState
    reason: str | None
    added: frozenset[str] = frozenset()
    removed: frozenset[str] = frozenset()
    _tables: dict[str, dict[str, tuple[str, ...]]] = field(default_factory=dict, repr=False, compare=False)

    def qualify(self, side: Literal['older', 'newer'], name: str) -> str | None:
        """`dll!name` when exactly one DLL of that file imports `name`; None when none or several do."""
        found = self._tables.get(side, _EMPTY).get(name, ())
        return f'{found[0]}!{name}' if len(found) == 1 else None


def import_delta(older: PeOverview, newer: PeOverview) -> ImportDelta:
    sides = {'older': _side(older), 'newer': _side(newer)}
    broken = [name for name, side in sides.items() if not side.readable]
    if broken:
        return ImportDelta('unavailable', clean_line(f'the import table of the {" and ".join(broken)} file could '
                                                     'not be read', 200))
    old, new = sides['older'], sides['newer']
    notes = [f'the {name} import table is incomplete' for name, side in sides.items()
             if side.truncated or side.skipped]
    tables = {name: MappingProxyType(side.by_name) for name, side in sides.items()}
    added = frozenset() if old.truncated or old.skipped else new.names - old.names
    removed = frozenset() if new.truncated or new.skipped else old.names - new.names
    return ImportDelta('partial' if notes else 'available', clean_line('; '.join(notes), 200) if notes else None,
                       added, removed, tables)
