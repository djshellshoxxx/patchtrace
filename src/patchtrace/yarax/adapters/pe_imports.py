"""`ImportSource` over `pe_overview` import tables of the two builds (plan s7).

Offers imports present in one build only, and one positive gate per API a capability names (resolved to its DLL in
that build). Only the regular import table is read: a delay-loaded import is not seen, and a side whose table is
missing or was cut cannot prove an absence, so its separation is `unknown`, never `neither`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ...pe_overview.models import PeOverview
from ..contracts import CapabilityFeature, ImportFeature, PairSource, Separation, Side
from ..features import SIDE_ONLY, separation_of
from ..ports import CapabilitySource

MAX_DIFF_IMPORTS = 64
Symbol = tuple[str, str]   # (lower-case DLL name, function name or '#ordinal')


@dataclass(frozen=True)
class _Table:
    """Imports of one build. A symbol is absent only where the table is known complete."""
    names: dict[str, str]               # lower-case DLL -> name as written in the file
    symbols: frozenset[Symbol]
    complete: frozenset[str]            # DLLs whose function list was read in full
    readable: bool
    whole: bool = False                 # the DLL list itself was read in full

    def has(self, symbol: Symbol) -> bool | None:
        if symbol in self.symbols:
            return True
        if not self.readable:
            return None
        if symbol[0] in self.names:
            return False if symbol[0] in self.complete else None
        return False if self.whole else None


def _table(overview: PeOverview | None) -> _Table:
    imports = overview.imports if overview is not None else None
    if imports is None:
        return _Table({}, frozenset(), frozenset(), False)
    names = {dll.name.lower(): dll.name for dll in imports.dlls}
    symbols = frozenset((dll.name.lower(), f) for dll in imports.dlls for f in dll.functions if not f.startswith('<'))
    complete = frozenset(dll.name.lower() for dll in imports.dlls if not dll.truncated)
    return _Table(names, symbols, complete, True, not imports.truncated)


def _split(symbol: str) -> tuple[str | None, int | None]:
    return (None, int(symbol[1:])) if symbol.startswith('#') and symbol[1:].isdigit() else (symbol, None)


class PeImportSource:
    def __init__(self, older: PeOverview | None, newer: PeOverview | None,
                 capabilities: CapabilitySource | None = None):
        self._tables: dict[Side, _Table] = {'older': _table(older), 'newer': _table(newer)}
        self._capabilities = capabilities

    def import_features(self, pair: PairSource) -> tuple[ImportFeature, ...]:
        gates = self._gates(pair)
        found = {symbol: feature for side in ('older', 'newer') for symbol, feature in self._diff(side)}
        found.update(gates)   # a gate says why the import matters, so it wins over the plain difference
        return tuple(feature for _symbol, feature in sorted(found.items()))

    def _separation(self, symbol: Symbol) -> Separation:
        return separation_of(self._tables['older'].has(symbol), self._tables['newer'].has(symbol))

    def _feature(self, side: Side, symbol: Symbol, origin: Literal['pe-imports', 'capa-api']) -> ImportFeature:
        name, ordinal = _split(symbol[1])
        return ImportFeature(dll=self._tables[side].names[symbol[0]], name=name, ordinal=ordinal, origin=origin,
                             separation=self._separation(symbol))

    def _diff(self, side: Side) -> list[tuple[Symbol, ImportFeature]]:
        other = self._tables['newer' if side == 'older' else 'older']
        rows = [(s, self._feature(side, s, 'pe-imports')) for s in sorted(self._tables[side].symbols)
                if s not in other.symbols]
        return [(s, f) for s, f in rows if f.separation == SIDE_ONLY[side]][:MAX_DIFF_IMPORTS]

    def _gates(self, pair: PairSource) -> dict[Symbol, ImportFeature]:
        if self._capabilities is None:
            return {}
        out: dict[Symbol, ImportFeature] = {}
        for capability in self._capabilities.capability_features(pair):
            side = _capability_side(capability)
            for api in capability.api_gates if side else ():
                symbol = self._resolve(side, api)
                if symbol is not None:
                    out[symbol] = self._feature(side, symbol, 'capa-api')
        return out

    def _resolve(self, side: Side, api: str) -> Symbol | None:
        """`kernel32.CreateFileW` or `CreateFile` to the one import of that build it names; ambiguity gives None.

        capa drops the ANSI/wide suffix of Windows APIs, so `Name`, `NameA` and `NameW` are tried in that order.
        """
        hint, _dot, name = api.rpartition('.')
        stem = hint.lower().removesuffix('.dll')
        for candidate in (name, name + 'A', name + 'W'):
            hits = [s for s in self._tables[side].symbols
                    if s[1] == candidate and (not stem or s[0].removesuffix('.dll') == stem)]
            if hits:
                return hits[0] if len(hits) == 1 else None
        return None


def _capability_side(capability: CapabilityFeature) -> Side | None:
    return {'older-only': 'older', 'newer-only': 'newer'}.get(capability.separation)
