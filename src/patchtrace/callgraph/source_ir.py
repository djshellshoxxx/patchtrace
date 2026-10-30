"""Whole-program `CallSource` over `program-ir/1` readers (tier `addresses`): every function's own call rows."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Literal, Protocol

from .contracts import Claim, Completeness, Side
from .limits import CANCEL_CLAIM_INTERVAL, CancelCheck, GraphError
from .text import sanitize

MAX_IR_EDGES = 600_000  # GL-01 (IR sources: 150k nodes, 600k edges)


class IrGraphReader(Protocol):
    """The part of `unified.ir.reader.IrReader` this source reads (the C3 edge accessor is `calls(fid)`)."""
    functions: object  # `.n`, `.name[fid]`, `.rva[fid]`

    def calls(self, fid: int) -> list: ...  # CallRow(site, callee, import_key, kind 'call'|'jump')


def default_label(image_base: int, rva: int) -> str:
    return f'FUN_{image_base + rva:08x}'


def import_label(import_key: str) -> str:
    """`kernel32.dll!CreateFileW` -> `kernel32.dll::CreateFileW` (the resolver's external spelling)."""
    library, _, name = import_key.partition('!')
    return f'{library}::{name}'


class IrCallSource:
    source_id = 'program-ir'
    tier: Literal['labels', 'addresses'] = 'addresses'
    completeness: Completeness = 'whole-program'

    def __init__(self, readers: Mapping[Side, IrGraphReader], image_bases: Mapping[Side, int], *,
                 include_jumps: bool = True, max_edges: int = MAX_IR_EDGES) -> None:
        self._readers, self._bases = readers, image_bases
        self._include_jumps, self._max_edges = include_jumps, max_edges
        self._kinds: dict[Side, dict[tuple[str, str], set[str]]] = {'older': {}, 'newer': {}}
        self._jumps = 0
        self._capped = False

    @property
    def limitations(self) -> tuple[str, ...]:
        """Valid once `claims` has been consumed."""
        notes = []
        if self._jumps:
            notes.append(f'{self._jumps} tail-call jump edges are listed as calls (kinds are kept per edge).')
        if self._capped:
            notes.append(f'IR edges were capped at {self._max_edges:,}; the graph is incomplete.')
        return tuple(notes)

    def edge_kinds(self, side: Side) -> dict[tuple[str, str], frozenset[str]]:
        """`call`/`jump` kinds of each (caller label, callee label) claimed so far."""
        return {edge: frozenset(kinds) for edge, kinds in self._kinds[side].items()}

    def _labels(self, side: Side) -> list[str]:
        table, base = self._readers[side].functions, self._bases[side]
        return [sanitize(table.name[fid] or default_label(base, table.rva[fid])) for fid in range(table.n)]

    def claims(self, side: Side, cancel: CancelCheck) -> Iterable[Claim]:
        reader, labels = self._readers[side], self._labels(side)
        self._kinds[side], emitted = {}, 0
        for fid, caller in enumerate(labels):
            for row in reader.calls(fid):
                if row.kind == 'jump' and not self._include_jumps:
                    continue
                if row.callee is not None:
                    callee = labels[row.callee]
                elif row.import_key is not None:
                    callee = sanitize(import_label(row.import_key))
                else:
                    continue  # an unresolved indirect call has no target
                if emitted >= self._max_edges:
                    self._capped = True
                    return
                emitted += 1
                if cancel is not None and emitted % CANCEL_CLAIM_INTERVAL == 0 and cancel():
                    raise GraphError('PT-GRAPH-CANCEL', 'cancelled')
                kinds = self._kinds[side].setdefault((caller, callee), set())
                if row.kind == 'jump' and 'jump' not in kinds:
                    self._jumps += 1
                kinds.add(row.kind)
                yield Claim(caller, callee, 'called')

    def listed(self, side: Side) -> Iterable[str]:
        return self._labels(side)
