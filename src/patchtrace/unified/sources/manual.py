"""Manual corrections (06 s6, D-29, 02 s10 item 6): the analyst's `ProjectService.correct_match` results as tier-M claims.

One function per side -> a tier-M edge; a function on one side only -> a one-sided declaration (`removed`,
`unmatched`, `added`); anything larger -> a manual group (`split`/`merged` decide `matched`, `ambiguous` decides
`ambiguous`). The correction itself is never re-validated here: the service already guarantees a function belongs to
one match. `manual_digest` (02 s5) covers the corrections, so any change of them makes a different `result_key`.
"""
from __future__ import annotations

from .. import keys
from ..addressing import AddressMap, parse_va_text
from ..contracts import Atom, SourceRef
from ..limits import Budget
from . import (
    AdapterOutput,
    Availability,
    Ledger,
    NodeRecord,
    SnapshotMatch,
    SourceGroup,
    SourceInputs,
    atom_order,
    clean_name,
    function_rva,
)

VERSION = 'manual/1'


def _manual(inputs: SourceInputs) -> list[SnapshotMatch]:
    return sorted((m for m in inputs.matches if m.manual), key=lambda m: m.id)


def _basis(matches: list[SnapshotMatch], addr: AddressMap) -> str:
    older = [v for m in matches for f in m.older if (v := parse_va_text(f.address)) is not None]
    newer = [v for m in matches for f in m.newer if (v := parse_va_text(f.address)) is not None]
    return addr.set_basis(older, newer)


def manual_digest_of(inputs: SourceInputs, addr: AddressMap) -> str:
    """`keys.manual_digest` over the corrections: RVAs when the addresses convert, else their lower-case text."""
    matches = _manual(inputs)
    basis = _basis(matches, addr)

    def label(function, side: str):
        value = parse_va_text(function.address)
        if basis != 'not-comparable' and value is not None:
            rva = addr.to_rva(side, value, basis)
            if rva is not None:
                return rva
        return (function.address or f'name:{function.name}').strip().lower()
    return keys.manual_digest([(m.category, [label(f, 'older') for f in m.older], [label(f, 'newer') for f in m.newer])
                               for m in matches])


class ManualAdapter:
    id = 'manual'

    def available(self, inputs: SourceInputs) -> Availability:
        return Availability('ok') if _manual(inputs) else Availability('missing', 'no-manual-corrections')

    def source_refs(self, inputs: SourceInputs, addr: AddressMap) -> tuple[SourceRef, ...]:
        if not _manual(inputs):
            return ()
        return (SourceRef(source='manual', entry_id=manual_digest_of(inputs, addr), file_sha256=None,
                          version=VERSION),)

    def atoms(self, inputs: SourceInputs, addr: AddressMap, budget: Budget) -> AdapterOutput:
        matches = _manual(inputs)
        if not matches:
            return AdapterOutput()
        ledger = Ledger()
        basis = _basis(matches, addr)
        refs = self.source_refs(inputs, addr)
        if basis == 'not-comparable':
            ledger.flag('manual-address-basis-not-comparable')
            return AdapterOutput(limitations=ledger.render(), source_refs=refs)
        atoms: list[Atom] = []
        groups: list[SourceGroup] = []
        nodes: dict[tuple[str, int], str | None] = {}
        for match in matches:
            budget.tick()
            older = [(rva, f) for f in match.older if (rva := function_rva(f, 'older', addr, basis, ledger)) is not None]
            newer = [(rva, f) for f in match.newer if (rva := function_rva(f, 'newer', addr, basis, ledger)) is not None]
            for side, items in (('older', older), ('newer', newer)):
                for rva, function in items:
                    nodes[(side, rva)] = nodes.get((side, rva)) or clean_name(function.name)
            if len(older) == 1 and len(newer) == 1:
                atoms.append(self._atom(older[0][0], newer[0][0], '1:1', match.id))
            elif older and newer:
                cards = '1:N' if len(older) == 1 else 'N:1' if len(newer) == 1 else 'N:M'
                group_atoms = tuple(sorted((self._atom(o, n, cards, match.id) for o, _ in older for n, _ in newer),
                                           key=atom_order))
                groups.append(SourceGroup(
                    kind=f'manual-{match.category}', source='manual', older=tuple(sorted(o for o, _ in older)),
                    newer=tuple(sorted(n for n, _ in newer)),
                    decision='ambiguous' if match.category == 'ambiguous' else 'matched',
                    reason=f'manual-{match.category}', atoms=group_atoms))
            else:
                atoms.extend(self._atom(o, None, '1:1', match.id) for o, _ in older)
                atoms.extend(self._atom(None, n, '1:1', match.id) for n, _ in newer)
        node_records = tuple(NodeRecord(side, rva, name) for (side, rva), name in sorted(nodes.items()))
        return AdapterOutput(atoms=tuple(sorted(atoms, key=atom_order)),
                             groups=tuple(sorted(groups, key=lambda g: (g.older, g.newer, g.kind))),
                             nodes=node_records, limitations=ledger.render(), source_refs=refs)

    @staticmethod
    def _atom(older: int | None, newer: int | None, cardinality: str, ref: str) -> Atom:
        return Atom(source='manual', step='manual-correction', tier='M', cardinality=cardinality, cls='E-MANUAL',
                    older_rva=older, newer_rva=newer, ref=ref[:128])
