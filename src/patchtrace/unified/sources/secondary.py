"""Stored secondary engine sets (BinDiff, rz-diff) as atoms (06 s3, s4, s10 items 2, 4, 5). Pure readers.

The sets are the `SecondaryMatchSet`s the owner read from `secondary.store.current_sets()`; nothing is run here.
BinDiff tiers come from the algorithm name alone, never from similarity or confidence (R02 s7); rz-diff is always
tier W (D-23). `native` carries the upstream display text, which no rule reads.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from ...secondary.contracts import SecondaryMatch, SecondaryMatchSet
from ..addressing import AddressMap
from ..contracts import Atom, SourceRef
from ..limits import UnifiedError
from ..registry import REGISTRY, STEP_MAX, Registry
from . import (
    AdapterOutput,
    Availability,
    Ledger,
    LoadedSecondary,
    NodeRecord,
    SourceInputs,
    atom_order,
    clean_name,
    native,
)

MAX_SET_BYTES = 256 * 1024 * 1024


def write_loaded(path: Path, loaded: LoadedSecondary) -> tuple[str, int]:
    """One JSON file per stored set (entry id + the validated set); returns (sha256, bytes)."""
    import hashlib
    data = json.dumps({'entry_id': loaded.entry_id, 'match_set': json.loads(loaded.match_set.model_dump_json())},
                      sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    Path(path).write_bytes(data)
    return hashlib.sha256(data).hexdigest(), len(data)


def read_loaded(path: Path, *, expected_sha256: str, expected_size: int) -> LoadedSecondary:
    import hashlib
    try:
        info = Path(path).stat()
        if info.st_size > MAX_SET_BYTES or info.st_size != expected_size:
            raise UnifiedError('PT-UNIFIED-INPUT', 'A secondary set file does not match its request',
                               reason='secondary-size-mismatch')
        data = Path(path).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise UnifiedError('PT-UNIFIED-INPUT', 'A secondary set file does not match its request',
                               reason='secondary-hash-mismatch')
        document = json.loads(data.decode('utf-8'))
        entry_id = document['entry_id']
        if not isinstance(entry_id, str) or not entry_id:
            raise ValueError('entry id')
        return LoadedSecondary(entry_id=entry_id,
                               match_set=SecondaryMatchSet.model_validate_json(json.dumps(document['match_set'])))
    except UnifiedError:
        raise
    except (OSError, ValueError, KeyError, TypeError, ValidationError):
        raise UnifiedError('PT-UNIFIED-INPUT', 'A secondary set file is unreadable', reason='secondary-invalid') from None


def usable_sets(inputs: SourceInputs, selected) -> list[LoadedSecondary]:
    """The stored sets of the selected engines that belong to this artifact pair (the `select_current` rule)."""
    return [s for s in inputs.secondary if s.match_set.engine in selected
            and (s.match_set.older_sha256, s.match_set.newer_sha256) == (inputs.older_sha256, inputs.newer_sha256)]


def bindiff_flags(inputs: SourceInputs, addr: AddressMap) -> dict[tuple[int, int], tuple[str, ...]]:
    """BinDiff flags per exact (older rva, newer rva) pair, for channel C8; sets that are for another pair or whose
    addresses are not comparable contribute nothing (never a guess)."""
    found: dict[tuple[int, int], tuple[str, ...]] = {}
    for loaded in sorted(usable_sets(inputs, {'bindiff'}), key=lambda s: s.entry_id):
        match_set = loaded.match_set
        rows = [*match_set.matches, *(a.candidate for a in match_set.alternatives if a.source == 'bindiff')]
        basis = addr.set_basis({r.older_address for r in rows if r.older_address is not None},
                               {r.newer_address for r in rows if r.newer_address is not None})
        if basis == 'not-comparable':
            continue
        for row in match_set.matches:
            if row.older_address is None or row.newer_address is None:
                continue
            older, newer = addr.to_rva('older', row.older_address, basis), addr.to_rva('newer', row.newer_address, basis)
            if older is not None and newer is not None:
                found.setdefault((older, newer), tuple(row.flags))
    return found


def source_ref_of(loaded: LoadedSecondary) -> SourceRef:
    match_set = loaded.match_set
    return SourceRef(source=match_set.engine, entry_id=loaded.entry_id[:128], file_sha256=match_set.file_sha256,
                     version=match_set.engine_version[:64])


class SecondaryAdapter:
    id = 'secondary'

    def __init__(self, registry: Registry = REGISTRY):
        self.registry = registry

    def available(self, inputs: SourceInputs) -> Availability:
        return Availability('ok') if inputs.secondary else Availability('missing', 'no-secondary-sets')

    def atoms(self, inputs: SourceInputs, addr: AddressMap, budget) -> AdapterOutput:
        ledger = Ledger()
        atoms: list[Atom] = []
        refs: list[SourceRef] = []
        nodes: dict[tuple[str, int], str | None] = {}
        order = {s.id: i for i, s in enumerate(self.registry.sources)}
        for loaded in sorted(inputs.secondary, key=lambda s: (order.get(s.match_set.engine, 99), s.entry_id)):
            match_set = loaded.match_set
            engine = match_set.engine
            refs.append(source_ref_of(loaded))  # every set looked at is an input, a refused one included
            if (match_set.older_sha256, match_set.newer_sha256) != (inputs.older_sha256, inputs.newer_sha256):
                ledger.flag(f'{engine}-pair-mismatch')
                continue
            rows = list(match_set.matches)
            for alt in match_set.alternatives:
                if alt.source == engine == 'bindiff':
                    rows.append(alt.candidate)
            older_values = {r.older_address for r in rows if r.older_address is not None}
            newer_values = {r.newer_address for r in rows if r.newer_address is not None}
            basis = addr.set_basis(older_values, newer_values)
            if basis == 'not-comparable':
                ledger.flag(f'{engine}-address-basis-not-comparable')
                continue
            if engine == 'bindiff':
                if any(r.basicblocks is None for r in rows):
                    ledger.flag('bindiff-stub-rows-not-identified')
                ledger.count('bindiff-stub-rows-demoted', sum(r.basicblocks == 0 for r in rows))
            if engine == 'rz-diff':
                if not match_set.engine_version.startswith('0.9.'):
                    ledger.flag(f'rz-diff-untested-version:{clean_name(match_set.engine_version, 40)}')
                ledger.count('secondary-alternatives-unused', len(match_set.alternatives))
            builder = self._bindiff if engine == 'bindiff' else self._rzdiff
            builder(loaded, addr, basis, budget, atoms, nodes)
        node_records = tuple(NodeRecord(side, rva, name) for (side, rva), name in sorted(nodes.items()))
        return AdapterOutput(atoms=tuple(sorted(atoms, key=atom_order)), nodes=node_records,
                             limitations=ledger.render(), source_refs=tuple(refs))

    # -- BinDiff ---------------------------------------------------------------------------------------------------

    def _bindiff(self, loaded: LoadedSecondary, addr, basis, budget, atoms: list[Atom], nodes) -> None:
        match_set = loaded.match_set
        for row in match_set.matches:
            budget.tick()
            step, tier, cls = self.registry.bindiff_meta(row.algorithm)
            self._emit(atoms, nodes, row, addr, basis, step, tier, cls, '1:1', loaded.entry_id, extra=True)
        for alt in match_set.alternatives:
            if alt.source != 'bindiff':
                continue
            budget.tick()
            step, _tier, cls = self.registry.bindiff_meta(alt.candidate.algorithm)
            self._emit(atoms, nodes, alt.candidate, addr, basis, f'{step} alt-rank-{alt.rank}'[:STEP_MAX], 'C', cls,
                       '1:1', loaded.entry_id, extra=False)

    def _emit(self, atoms, nodes, row: SecondaryMatch, addr, basis, step, tier, cls, cardinality, entry_id,
              *, extra: bool) -> None:
        older = None if row.older_address is None else addr.to_rva('older', row.older_address, basis)
        newer = None if row.newer_address is None else addr.to_rva('newer', row.newer_address, basis)
        if (row.older_address is not None and older is None) or (row.newer_address is not None and newer is None):
            return
        if older is None and newer is None:
            return
        if extra:
            for side, rva, name in (('older', older, row.older_name), ('newer', newer, row.newer_name)):
                if rva is not None:
                    nodes[(side, rva)] = nodes.get((side, rva)) or clean_name(name)
        stub = row.engine == 'bindiff' and row.basicblocks == 0
        if stub:
            tier = 'C'  # a zero-block record is a stub or thunk: it names a pair but proves nothing alone (06 s3)
        atoms.append(Atom(source=row.engine, step=step, tier=tier, cardinality=cardinality, cls=cls, older_rva=older,
                          newer_rva=newer, ref=entry_id[:128],
                          native=native(('similarity', row.similarity_text), ('confidence', row.confidence_text),
                                        ('algorithm', row.algorithm),
                                        ('demoted', 'stub-basicblocks-0' if stub else None))))

    # -- rz-diff ---------------------------------------------------------------------------------------------------

    def _rzdiff(self, loaded: LoadedSecondary, addr, basis, budget, atoms: list[Atom], nodes) -> None:
        match_set = loaded.match_set
        step, tier, cls = self.registry.rzdiff_meta
        shared: dict[int, int] = {}
        for row in match_set.matches:
            if row.older_address is not None and row.newer_address is not None:
                shared[row.newer_address] = shared.get(row.newer_address, 0) + 1
        for row in match_set.matches:
            budget.tick()
            both = row.older_address is not None and row.newer_address is not None
            cardinality = 'non-exclusive' if both and shared[row.newer_address] > 1 else '1:1'
            older = None if row.older_address is None else addr.to_rva('older', row.older_address, basis)
            newer = None if row.newer_address is None else addr.to_rva('newer', row.newer_address, basis)
            if older is None and newer is None:
                continue
            for side, rva, name in (('older', older, row.older_name), ('newer', newer, row.newer_name)):
                if rva is not None:
                    nodes[(side, rva)] = nodes.get((side, rva)) or clean_name(name)
            atoms.append(Atom(source='rz-diff', step=step, tier=tier, cardinality=cardinality, cls=cls,
                              older_rva=older, newer_rva=newer, ref=loaded.entry_id[:128],
                              native=native(('similarity', row.similarity_text), ('type', row.match_type))))
