"""Ghidriff adapter (06 s2, s10 item 3): the primary engine's pairings as atoms. The tool itself is never run.

Edges come from the non-manual `modified` matches and from the preserved raw `matches.address_matches` table; the
connected components of that relation graph are 1:1 edges (one atom each) or `ghidriff-1n` groups, never
cross-multiplied. `added`/`deleted` are one-sided tier-W observations. Ratios and diff types are display text and
hints only; no rule reads them (R03 s2).
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from ...enrichment.identity import parse_address
from ...persistence import strict_json
from ..addressing import AddressMap, is_external_key, parse_va_text
from ..contracts import Atom, SourceRef
from ..limits import DEFAULT_LIMITS, Budget, UnifiedLimits
from ..registry import REGISTRY, STEP_MAX, Registry
from . import (
    AdapterOutput,
    Availability,
    Ledger,
    NodeRecord,
    RawGhidriff,
    SourceGroup,
    SourceInputs,
    atom_order,
    clean_name,
    function_rva,
    native,
)

MAX_RAW_BYTES = 100 * 1024 * 1024  # service.MAX_RAW_BYTES / backend.JSON_LIMIT


def load_raw(path: Path | None, expected_sha256: str | None, limits: UnifiedLimits = DEFAULT_LIMITS) -> RawGhidriff:
    """Verify (size, SHA-256 of the recorded run) and shape-check the preserved raw table; never raises for data
    problems, the status says why the table is unusable (06 s2 failure kinds)."""
    if path is None or expected_sha256 is None:
        return RawGhidriff(status='missing', sha256=expected_sha256)
    try:
        info = Path(path).stat()
        if Path(path).is_symlink() or not Path(path).is_file():
            return RawGhidriff(status='missing', sha256=expected_sha256)
        if info.st_size > MAX_RAW_BYTES:
            return RawGhidriff(status='unparsable', sha256=expected_sha256)
        data = Path(path).read_bytes()
    except OSError:
        return RawGhidriff(status='missing', sha256=expected_sha256)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        return RawGhidriff(status='hash-mismatch', sha256=expected_sha256)
    try:
        document = strict_json(data.decode('utf-8'))
    except (UnicodeError, ValueError):
        return RawGhidriff(status='unparsable', sha256=expected_sha256)
    matches = document.get('matches') if isinstance(document, dict) else None
    if matches is None or (isinstance(matches, dict) and 'address_matches' not in matches):
        return RawGhidriff(status='missing', sha256=expected_sha256)
    table = matches.get('address_matches') if isinstance(matches, dict) else None
    if not _valid_table(table):
        return RawGhidriff(status='unparsable', sha256=expected_sha256)
    return RawGhidriff(status='ok', address_matches=table, sha256=expected_sha256)


def _valid_table(table: object) -> bool:
    if not isinstance(table, dict):
        return False
    for key, targets in table.items():
        if not isinstance(key, str) or not isinstance(targets, list):
            return False
        for target in targets:
            if (not isinstance(target, list) or len(target) != 2 or not isinstance(target[0], str)
                    or not isinstance(target[1], list) or not all(isinstance(t, str) for t in target[1])):
                return False
    return True


class _Edge:
    __slots__ = ('types', 'ref', 'ratio')

    def __init__(self) -> None:
        self.types: set[str] = set()
        self.ref: str | None = None
        self.ratio: str | None = None


class GhidriffAdapter:
    id = 'ghidriff'

    def __init__(self, registry: Registry = REGISTRY):
        self.registry = registry

    def available(self, inputs: SourceInputs) -> Availability:
        if inputs.run.raw.status != 'ok':
            return Availability('stale' if inputs.run.raw.status == 'hash-mismatch' else 'missing',
                                inputs.run.raw.status)
        return Availability('ok')

    def source_ref(self, inputs: SourceInputs) -> SourceRef:
        """(run id, raw file hash, backend version). An unusable raw file is part of the identity as well: its three
        failure kinds give three different limitations, so they must give three different result ids (the store
        refuses one id with two contents: `result-drift`)."""
        raw = inputs.run.raw
        mark = '' if raw.status == 'ok' else f' [raw-{raw.status}]'
        return SourceRef(source='ghidriff', entry_id=inputs.run.run_id,
                         file_sha256=raw.sha256 if raw.status == 'ok' else None,
                         version=inputs.run.backend_version[:64 - len(mark)] + mark)

    def atoms(self, inputs: SourceInputs, addr: AddressMap, budget: Budget) -> AdapterOutput:
        ledger = Ledger()
        raw = inputs.run.raw
        if raw.status != 'ok':
            ledger.flag({'missing': 'raw-missing', 'hash-mismatch': 'raw-hash-mismatch',
                         'unparsable': 'raw-unparsable'}[raw.status])
        matches = sorted((m for m in inputs.matches if not m.manual), key=lambda m: m.id)
        # pass 1: parse every address once so the basis is decided per SET
        records = self._records(matches)
        relations = self._relations(raw.address_matches if raw.status == 'ok' else None, ledger, budget)
        older_values = sorted({v for side, v in records if side == 'older'} | {o for o, _n, _t in relations})
        newer_values = sorted({v for side, v in records if side == 'newer'} | {n for _o, n, _t in relations})
        basis = addr.set_basis(older_values, newer_values)
        refs = (self.source_ref(inputs),)
        if basis == 'not-comparable':
            ledger.flag('ghidriff-address-basis-not-comparable')
            return AdapterOutput(limitations=ledger.render(), source_refs=refs)

        edges: dict[tuple[int, int], _Edge] = {}
        nodes: dict[tuple[str, int], str | None] = {}
        one_sided: list[Atom] = []
        for match in matches:
            budget.tick()
            self._collect(match, addr, basis, edges, nodes, one_sided, ledger)
        for old_value, new_value, types in relations:
            budget.tick()
            o, n = addr.to_rva('older', old_value, basis), addr.to_rva('newer', new_value, basis)
            if o is None or n is None:
                continue
            edge = edges.setdefault((o, n), _Edge())
            edge.types.update(types)
            edge.ref = edge.ref or f'raw:{o:x}'
            nodes.setdefault(('older', o), None)
            nodes.setdefault(('newer', n), None)
        atoms, groups = self._components(edges)
        node_records = tuple(NodeRecord(side, rva, name) for (side, rva), name in sorted(nodes.items()))
        return AdapterOutput(atoms=tuple(sorted([*atoms, *one_sided], key=atom_order)), groups=groups,
                             nodes=node_records, limitations=ledger.render(), source_refs=refs)

    # -- inputs ------------------------------------------------------------------------------------------------------

    @staticmethod
    def _records(matches) -> list[tuple[str, int]]:
        found = []
        for match in matches:
            for side, functions in (('older', match.older), ('newer', match.newer)):
                for function in functions:
                    value = parse_va_text(function.address)
                    if value is not None:
                        found.append((side, value))
        return found

    @staticmethod
    def _relations(table: Mapping | None, ledger: Ledger, budget: Budget) -> list[tuple[int, int, tuple[str, ...]]]:
        """Parsed (old VA, new VA, types) triples; a relation with any external end is skipped whole (06 s10)."""
        out: list[tuple[int, int, tuple[str, ...]]] = []
        if not table:
            return out
        for key in sorted(table):
            budget.tick()
            targets = table[key]
            if is_external_key(key) or any(is_external_key(t[0]) for t in targets):
                ledger.count('externals-skipped')
                continue
            old = parse_address(key)
            parsed = [(parse_address(t[0]), tuple(t[1])) for t in targets]
            if old is None or any(p is None for p, _ in parsed):
                ledger.count('no-address')
                continue
            out.extend((old, new, types) for new, types in parsed if new is not None)
        return out

    def _collect(self, match, addr, basis, edges, nodes, one_sided: list[Atom], ledger: Ledger) -> None:
        if match.category == 'modified' and len(match.older) == 1 and len(match.newer) == 1:
            old, new = match.older[0], match.newer[0]
            o = function_rva(old, 'older', addr, basis, ledger)
            n = function_rva(new, 'newer', addr, basis, ledger)
            if o is None or n is None:
                return
            edge = edges.setdefault((o, n), _Edge())
            edge.types.update(match.match_types)
            edge.ref = match.id
            edge.ratio = old.ratio_text or new.ratio_text
            nodes[('older', o)] = nodes.get(('older', o)) or clean_name(old.name)
            nodes[('newer', n)] = nodes.get(('newer', n)) or clean_name(new.name)
        elif match.category in ('added', 'removed') and (len(match.newer) == 1) != (len(match.older) == 1):
            side, function = ('newer', match.newer[0]) if match.newer else ('older', match.older[0])
            rva = function_rva(function, side, addr, basis, ledger)
            if rva is None:
                return
            nodes[(side, rva)] = nodes.get((side, rva)) or clean_name(function.name)
            one_sided.append(Atom(source='ghidriff', step='added' if side == 'newer' else 'deleted', tier='W',
                                  cardinality='1:1', cls='E-UNKNOWN', older_rva=rva if side == 'older' else None,
                                  newer_rva=rva if side == 'newer' else None, ref=match.id[:128]))
        else:
            ledger.count('ghidriff-shape-skipped')

    # -- relation graph ----------------------------------------------------------------------------------------------

    def _components(self, edges: dict[tuple[int, int], _Edge]) -> tuple[list[Atom], tuple[SourceGroup, ...]]:
        parent: dict[tuple[str, int], tuple[str, int]] = {}

        def find(x):
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for o, n in edges:
            parent[find(('o', o))] = find(('n', n))
        members: dict[tuple[str, int], list[tuple[int, int]]] = {}
        for edge in sorted(edges):
            members.setdefault(find(('o', edge[0])), []).append(edge)
        degree_o: dict[int, int] = {}
        degree_n: dict[int, int] = {}
        for o, n in edges:
            degree_o[o] = degree_o.get(o, 0) + 1
            degree_n[n] = degree_n.get(n, 0) + 1
        atoms: list[Atom] = []
        groups: list[SourceGroup] = []
        for component in sorted(members.values()):
            if len(component) == 1:
                atoms.append(self._atom(component[0], edges[component[0]], '1:1'))
                continue
            group_atoms = []
            for o, n in component:
                card = ('N:M' if degree_o[o] > 1 and degree_n[n] > 1 else '1:N' if degree_o[o] > 1 else 'N:1')
                group_atoms.append(self._atom((o, n), edges[(o, n)], card))
            groups.append(SourceGroup(kind='ghidriff-1n', source='ghidriff',
                                      older=tuple(sorted({o for o, _ in component})),
                                      newer=tuple(sorted({n for _, n in component})), decision='ambiguous',
                                      reason='one-to-many', atoms=tuple(sorted(group_atoms, key=atom_order))))
        return atoms, tuple(sorted(groups, key=lambda g: (g.older, g.newer)))

    def _atom(self, edge: tuple[int, int], info: _Edge, cardinality: str) -> Atom:
        step, tier, cls = self.registry.ghidriff_strongest(info.types)
        names = ', '.join(sorted(info.types)) if info.types else None
        return Atom(source='ghidriff', step=step[:STEP_MAX] or 'unknown', tier=tier, cardinality=cardinality, cls=cls,
                    older_rva=edge[0], newer_rva=edge[1], native=native(('ratio', info.ratio), ('match types', names)),
                    ref=info.ref)
