"""The ladder as a fusion source (04 s1, 05 s1.1; 01 s5 `compute`): the analyst's 1:1 corrections as P00 anchors going
in, and a `Correspondence` over two real sidecars coming out as the `AdapterOutput` the arbiter takes.

Fusion never sees function ids, only RVAs: the atoms of sources `pt-ladder` and `pt-bytes` (one per pair, with the pass,
tier and evidence class of the pair) and the display names of the paired functions. What the row model cannot hold yet
is counted instead of dropped: the N:M groups of the ladder (`duplicate`, `icf`, `inlined-into`, `outlined-from`) and
the leftovers appear in `limitations`, so a reader sees that the ladder knew more than the rows show.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..contracts import Atom
from ..ir import schema
from ..ir.reader import IrReader
from ..ladder.types import Correspondence
from . import AdapterOutput, Ledger, NodeRecord, clean_name

_IMPORT = schema.FN_FLAGS['import']
_KIND = {schema.KIND_CODES['normal']: 'function', schema.KIND_CODES['thunk']: 'thunk',
         schema.KIND_CODES['external']: 'external'}


def anchor_pairs(atoms: Iterable[Atom], older: IrReader, newer: IrReader) -> tuple[tuple[tuple[int, int], ...], int]:
    """The tier-M 1:1 corrections as (older fid, newer fid), sorted, and the number of corrections that name an address
    which is no function entry of the IR (they stay manual atoms for fusion; the ladder cannot use them)."""
    found, skipped = set(), 0
    for atom in atoms:
        if atom.tier != 'M' or atom.cardinality != '1:1' or atom.older_rva is None or atom.newer_rva is None:
            continue
        fids = (older.functions.rva_to_fid.get(atom.older_rva), newer.functions.rva_to_fid.get(atom.newer_rva))
        if None in fids:
            skipped += 1
        else:
            found.add(fids)
    return tuple(sorted(found)), skipped


def _node(side: str, reader: IrReader, fid: int) -> NodeRecord:
    table = reader.functions
    kind = 'import' if table.get('flags', fid) & _IMPORT else _KIND[table.get('kind', fid)]
    return NodeRecord(side, table.get('rva', fid), clean_name(table.name[fid]), kind)  # type: ignore[arg-type]


def ladder_output(corr: Correspondence, older: IrReader, newer: IrReader, *, anchors_skipped: int = 0) -> AdapterOutput:
    """Atoms, names and limitations of one ladder run. A `partial` run (deadline or cancel) names its stop reason: it is
    a degrading limitation, so the result is `partial` too."""
    ledger = Ledger()
    if corr.status == 'partial':
        ledger.flag(f'ladder-partial:{corr.stop_reason}')
    for slug, count in corr.limits_hit:
        ledger.count(f'ladder-limit-{slug}', count)
    ledger.count('ladder-groups-not-shown', len(corr.groups))
    ledger.count('ladder-anchors-outside-ir', anchors_skipped)
    nodes = {(pair.older_fid, pair.newer_fid) for pair in corr.pairs}
    records = [_node('older', older, o) for o, _ in sorted(nodes)] + [_node('newer', newer, n) for _, n in sorted(nodes)]
    return AdapterOutput(atoms=corr.atoms(), nodes=tuple(records), limitations=ledger.render())
