"""`symbol-map/1` builder (SPEC-33 s5.3): merges a PDB index (stdlib MSF reader or llvm-pdbutil), optional Ghidra
function bodies and `.pdata` sizes into one strict document per image. Pure: no process, no network, no Qt.

Merge rule: PDB functions are the union of function publics and private procedures keyed by RVA; the name is the
single public name (alphabetically first when ICF gives several, the rest counted as `aliases`). Size: a Ghidra body
at the same RVA wins, then the private procedure length, then `.pdata` (non-chained entries); otherwise null. Without
a PDB index, Ghidra names are used (imported mangled name first), and `Ordinal_<n>`, `entry` and dotted names drop.
With an index, Ghidra-only functions are counted in `stats.dropped`, never named from a guess.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from . import msf
from .contracts import (
    MAX_SYMBOLS,
    GFunction,
    GhidraRaw,
    Image,
    PdbRef,
    Producer,
    Stats,
    Symbol,
    SymbolMap,
    load_symbol_map,
)
from .fetch import sha256_file
from .paths import TIER, Layout, TierWError, write_json
from .pe_tables import PeView

_UNNAMED = re.compile(r'^(Ordinal_\d+|entry|\..*)$')
IMPORTED = 'IMPORTED'


def pdata_sizes(entries) -> dict[int, int]:
    """{begin RVA: length} from RuntimeFunction-like entries; chained entries describe the parent's tail, skipped."""
    return {e.begin: e.end - e.begin for e in entries if not e.chained and e.end > e.begin}


def _ghidra_name(function: GFunction) -> tuple[str, int] | None:
    imported = sorted({n.name for n in function.names if n.source == IMPORTED and not _UNNAMED.match(n.name)})
    if not imported:
        return None
    mangled = [n for n in imported if n.startswith('?')]
    primary = sorted(n.name for n in function.names
                     if n.source == IMPORTED and n.primary and not _UNNAMED.match(n.name))
    name = mangled[0] if mangled else primary[0] if primary else imported[0]
    return name, len(imported) - 1


def _ranges(function: GFunction | None) -> tuple[tuple[tuple[int, int], ...], int | None]:
    if function is None or not function.ranges:
        return (), None
    return function.ranges, sum(end - start for start, end in function.ranges)


def _sized(rva: int, ghidra: GFunction | None, proc_size: int | None, pdata: Mapping[int, int]):
    ranges, size = _ranges(ghidra)
    if size is not None:
        return ranges, size, 'ghidra-body'
    for value, source in ((proc_size, 'pdb-proc'), (pdata.get(rva), 'pdata')):
        if value:
            return ((rva, rva + value),), value, source
    return (), None, None


def _pdb_symbols(index: msf.PdbIndex, ghidra: Mapping[int, GFunction], pdata: Mapping[int, int]) -> list[Symbol]:
    out = []
    for fn in index.functions():
        ranges, size, source = _sized(fn.rva, ghidra.get(fn.rva), fn.size, pdata)
        out.append(Symbol(name=fn.name, rva=fn.rva, size=size, size_source=source, kind=fn.kind,
                          aliases=fn.aliases, thunk=fn.thunk or bool(ghidra.get(fn.rva) and ghidra[fn.rva].thunk),
                          ranges=ranges))
    return out


def _ghidra_symbols(raw: GhidraRaw, pdata: Mapping[int, int]) -> tuple[list[Symbol], int]:
    out, unnamed = [], 0
    for fn in raw.functions:
        named = _ghidra_name(fn)
        if named is None:
            unnamed += 1
            continue
        ranges, size, source = _sized(fn.rva, fn, None, pdata)
        out.append(Symbol(name=named[0], rva=fn.rva, size=size, size_source=source, kind='unknown',
                          aliases=named[1], thunk=fn.thunk, ranges=ranges))
    return out, unnamed


def build_symbol_map(*, image: Image, pdb: PdbRef, producer: Producer, index: msf.PdbIndex | None,
                     ghidra: GhidraRaw | None, pdata: Mapping[int, int], tier: str = TIER) -> SymbolMap:
    if index is None and ghidra is None:
        raise TierWError('PT-TIERW-INPUT', 'a symbol map needs a PDB index or Ghidra output')
    by_rva = {f.rva: f for f in ghidra.functions} if ghidra else {}
    warnings = list(index.warnings if index else ()) + list(ghidra.warnings if ghidra else ())
    dropped = unnamed = 0
    if index is not None:
        symbols = _pdb_symbols(index, by_rva, pdata)
        known = {s.rva for s in symbols}
        dropped = sum(1 for rva in by_rva if rva not in known)
        unnamed = ghidra.unnamed if ghidra else 0
    else:
        symbols, unnamed = _ghidra_symbols(ghidra, pdata)
        unnamed += ghidra.unnamed
    if len(symbols) > MAX_SYMBOLS:
        dropped += len(symbols) - MAX_SYMBOLS
        symbols = symbols[:MAX_SYMBOLS]
        warnings.append('symbol list truncated at the 1,000,000 symbol limit')
    if ghidra and ghidra.truncated:
        warnings.append(f'Ghidra export truncated {ghidra.truncated} functions')
    symbols.sort(key=lambda s: s.rva)
    return SymbolMap(contract='symbol-map/1', tier=tier, image=image, pdb=pdb, producer=producer,
                     symbols=tuple(symbols), stats=Stats(functions=len(symbols), unnamed=unnamed, dropped=dropped),
                     warnings=tuple(warnings[:2000]))


def pdb_ref(index: msf.PdbIndex | None, name: str | None, pdb_sha256: str | None) -> PdbRef:
    if index is None:
        return PdbRef()
    return PdbRef(name=name, guid=index.info.guid, age=index.info.age, sha256=pdb_sha256,
                  stripped=index.info.stripped)


def store_symbol_map(layout: Layout, doc: SymbolMap) -> Path:
    """Write `<root>/tier-w/symbols/<sha256>.<producer>.json` and prove it loads back identically."""
    document = doc.model_dump(mode='json')
    path = write_json(layout.symbols(doc.image.sha256, doc.producer.tool), document)
    if load_symbol_map(path.read_bytes()) != doc:
        raise TierWError('PT-TIERW-VERIFY', 'symbol map did not round-trip')
    return path


def export_msf(pe_path: Path, pdb_path: Path, layout: Layout, *, tier: str = TIER) -> Path:
    """Stdlib-only producer (`msf`): PDB publics/procedures with `.pdata` sizes for one stored PE and its PDB."""
    with PeView(pe_path) as view:
        image = Image(file_name=Path(pe_path).name, sha256=view.sha256, image_base=view.image_base,
                      size_of_image=view.size_of_image, machine=view.machine)
        index = msf.read_pdb(pdb_path, fallback_sections=view.sections())
        pdata = pdata_sizes(view.runtime_functions())
    pdb = pdb_ref(index, Path(pdb_path).name, sha256_file(pdb_path))
    producer = Producer(tool='msf', version='stdlib-1', detail='')
    doc = build_symbol_map(image=image, pdb=pdb, producer=producer, index=index, ghidra=None, pdata=pdata, tier=tier)
    return store_symbol_map(layout, doc)
