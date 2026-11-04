"""Manual corrections (06 s6, D-29, 02 s10 item 6): the analyst's `ProjectService.correct_match` results as tier-M claims.

An affirmative one-function-per-side relation -> a tier-M edge; an ambiguous relation stays an ambiguous group.
A function on one side only -> a one-sided declaration (`removed`,
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

VERSION = 'manual/2'


def _manual(inputs: SourceInputs) -> list[SnapshotMatch]:
    return sorted((m for m in inputs.matches if m.manual), key=lambda m: m.id)


def _basis(matches: list[SnapshotMatch], addr: AddressMap) -> str:
    older = [v for m in matches for f in m.older if (v := parse_va_text(f.address)) is not None]
    newer = [v for m in matches for f in m.newer if (v := parse_va_text(f.address)) is not None]
    return addr.set_basis(older, newer)


def manual_digest_of(inputs: SourceInputs, addr: AddressMap, budget: Budget | None = None) -> str:
    """Every validated manual snapshot field can affect atoms, names or facts; bind all of them."""
    if budget is not None:
        budget.check()
    if inputs._manual_digest is not None:
        return inputs._manual_digest
    matches = _manual(inputs)
    if not matches:
        return keys.manual_digest([])
    snapshot = []
    for match in matches:
        if budget is not None:
            budget.check()
        snapshot.append(match.model_dump(mode='json'))
    digest = keys.source_content_digest('manual', snapshot, budget=budget)
    object.__setattr__(inputs, '_manual_digest', digest)
    return digest


class ManualAdapter:
    id = 'manual'

    def available(self, inputs: SourceInputs) -> Availability:
        return Availability('ok') if _manual(inputs) else Availability('missing', 'no-manual-corrections')

    def source_refs(self, inputs: SourceInputs, addr: AddressMap, budget: Budget | None = None) -> tuple[SourceRef, ...]:
        if not _manual(inputs):
            return ()
        return (SourceRef(source='manual', entry_id=manual_digest_of(inputs, addr, budget), file_sha256=None,
                          version=VERSION),)

    def atoms(self, inputs: SourceInputs, addr: AddressMap, budget: Budget) -> AdapterOutput:
        budget.check()
        matches = _manual(inputs)
        if not matches:
            return AdapterOutput()
        ledger = Ledger()
        basis = _basis(matches, addr)
        refs = self.source_refs(inputs, addr, budget)
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
            if (match.older and not older) or (match.newer and not newer):
                # a side the analyst named but whose address is unusable: a pairing must never degrade into a
                # one-sided (removed/added) claim, so the correction is not applied and the result is partial
                ledger.count('manual-unresolved')
                continue
            for side, items in (('older', older), ('newer', newer)):
                for rva, function in items:
                    nodes[(side, rva)] = nodes.get((side, rva)) or clean_name(function.name)
            pairing = match.category != 'unmatched'  # `unmatched` says there is no counterpart: never an affirmative pairing
            if len(older) == 1 and len(newer) == 1 and pairing and match.category != 'ambiguous':
                atoms.append(self._atom(older[0][0], newer[0][0], '1:1', match.id))
            elif older and newer and pairing:
                cards = ('1:1' if len(older) == len(newer) == 1 else
                         '1:N' if len(older) == 1 else 'N:1' if len(newer) == 1 else 'N:M')
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
