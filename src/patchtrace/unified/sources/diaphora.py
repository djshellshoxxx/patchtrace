"""Stored Diaphora match sets as atoms (06 s5, SPEC-DA-01 Mode A). Pure readers of the `diaphora/1` sets the owner
read from the project's `diaphora-matches` rows; the adapter never opens a `.diaphora` SQLite file and never runs a tool.

* only rows whose DA-01 address status is `verified-rva` carry an address basis; `external-ea-only` and `ambiguous`
  rows are skipped and counted (`diaphora-external-ea-skipped:n`, `diaphora-ambiguous-address-skipped:n`);
* `best` -> tier B, `partial` / `unreliable` -> tier C, `multimatch` -> an N:M group (ambiguous), unmatched -> tier W
  one-sided observations. The ratio is upstream text in `native` and no rule reads it;
* a `user-attested` set (pair binding not verified by a manifest) yields display-only tier-W ONE-SIDED atoms flagged
  `unverified`. One-sided atoms are attached to rows as observations by the arbiter: they never form an edge, so they
  cannot support a row and cannot be "against" another (R-15: a misattributed set must not contest every row);
* the set must be for exactly the plan pair in the plan orientation; a reversed or other pair is skipped with the
  degrading limitation `diaphora-pair-mismatch` (it stays an input of the result key).

Evidence class (05 s1.1: "Diaphora pseudo-code rules (registry maps DA-01 descriptions)"): the heuristic text is
upstream free text, so a class is taken only when the text names exactly one of two information kinds
deterministically: pseudo-code / microcode -> E-DECOMP, graph / isomorphism / basic block -> E-CFG. Text naming both,
neither, or nothing is E-UNKNOWN, the conservative class that never corroborates another source.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from pydantic import ValidationError

from ...diaphora.contracts import DiaphoraMatch, DiaphoraMatchSet, DiaphoraUnmatched
from ...enrichment.identity import domain_id
from ...persistence import strict_json
from .. import keys
from ..addressing import AddressMap
from ..contracts import Atom, SourceRef
from ..limits import Budget, UnifiedError
from . import (
    AdapterOutput,
    Availability,
    Ledger,
    LoadedDiaphora,
    NodeRecord,
    SourceGroup,
    SourceInputs,
    atom_order,
    clean_name,
    native,
    read_request_file,
)

MAX_SET_BYTES = 256 * 1024 * 1024
RVA_MAX = 2**32 - 1
ADAPTER_VERSION = 'ad1'     # part of the SourceRef version: a changed mapping is another result id
TIERS = {'best': 'B', 'partial': 'C', 'unreliable': 'C', 'multimatch': 'C'}
_DECOMP = re.compile(r'pseudo[- ]?code|microcode')
_CFG = re.compile(r'graph|isomorphism|basic[- ]?block')
_BAD_VERSION = re.compile(r'[^A-Za-z0-9._+-]')


def heuristic_class(text: str) -> str:
    low = text.lower()
    decomp, cfg = bool(_DECOMP.search(low)), bool(_CFG.search(low))
    return 'E-DECOMP' if decomp and not cfg else 'E-CFG' if cfg and not decomp else 'E-UNKNOWN'


def _body(loaded: LoadedDiaphora) -> str:
    """Canonical text of the validated set: rows in (index, content) order, so the row order of a stored body never
    changes the identity (G-U4)."""
    match_set = loaded.match_set
    ordered = match_set.model_copy(update={
        'matches': tuple(sorted(match_set.matches, key=lambda m: (m.index, m.model_dump_json()))),
        'unmatched': tuple(sorted(match_set.unmatched, key=lambda u: (u.index, u.model_dump_json())))})
    return ordered.model_dump_json()


def source_ref_of(loaded: LoadedDiaphora, budget: Budget | None = None) -> SourceRef:
    """Content-bound identity: the validated set (every row, the trust level) plus the stored entry id."""
    if loaded._source_ref is not None:
        return loaded._source_ref
    match_set = loaded.match_set
    entry_digest = keys.source_content_digest('diaphora-entry-id', loaded.entry_id, budget=budget)
    content_id = domain_id('unified-source-content', 3,
                           {'source': 'diaphora', 'entry_id_digest': entry_digest,
                            'validated_body_sha256': keys.text_sha256(_body(loaded), budget)})
    version = f'{_BAD_VERSION.sub("_", match_set.engine_version)[:40]}+{ADAPTER_VERSION}'
    ref = SourceRef(source='diaphora', entry_id=content_id, file_sha256=match_set.result_sha256, version=version)
    object.__setattr__(loaded, '_source_ref', ref)
    return ref


def write_loaded(path: Path, loaded: LoadedDiaphora) -> tuple[str, int]:
    """One JSON file per stored set (entry id + the validated set); returns (sha256, bytes)."""
    data = json.dumps({'entry_id': loaded.entry_id, 'body_json': _body(loaded)}, sort_keys=True,
                      separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    Path(path).write_bytes(data)
    return hashlib.sha256(data).hexdigest(), len(data)


def read_loaded(path: Path, *, expected_sha256: str, expected_size: int,
                budget: Budget | None = None) -> LoadedDiaphora:
    """Bounded, re-hashed, strict-JSON reader of a worker input file (any mismatch is `PT-UNIFIED-INPUT`)."""
    try:
        data = read_request_file(path, expected_sha256=expected_sha256, expected_size=expected_size,
                                 max_bytes=MAX_SET_BYTES, label='Diaphora', reason='diaphora', budget=budget)
        text = data.decode('utf-8')
        strict_json(text)
        document = json.loads(text)
        entry_id, body = document['entry_id'], document['body_json']
        if (set(document) != {'entry_id', 'body_json'} or not isinstance(entry_id, str) or not entry_id
                or not isinstance(body, str)):
            raise ValueError('document shape')
        strict_json(body)
        match_set = DiaphoraMatchSet.model_validate_json(body)
        if budget is not None:
            budget.check()
        return LoadedDiaphora(entry_id=entry_id, match_set=match_set)
    except UnifiedError:
        raise
    except (OSError, ValueError, KeyError, TypeError, ValidationError):
        raise UnifiedError('PT-UNIFIED-INPUT', 'A Diaphora set file is unreadable', reason='diaphora-invalid') from None


def _edge_cardinality(older_degree: int, newer_degree: int) -> str:
    return ('N:M' if older_degree > 1 and newer_degree > 1 else '1:N' if older_degree > 1 else
            'N:1' if newer_degree > 1 else '1:1')


def _unmatched_key(u: DiaphoraUnmatched):
    return (u.side, u.rva if u.rva is not None else -1, u.index)


def _match_key(m: DiaphoraMatch):
    return (m.older_rva if m.older_rva is not None else -1, m.newer_rva if m.newer_rva is not None else -1,
            m.category, m.index)


def _usable(row: DiaphoraMatch | DiaphoraUnmatched, rvas: tuple[int | None, ...], ledger: Ledger) -> bool:
    if row.address_status == 'external-ea-only':
        ledger.count('diaphora-external-ea-skipped')
        return False
    if row.address_status != 'verified-rva':
        ledger.count('diaphora-ambiguous-address-skipped')
        return False
    if any(r is None or r > RVA_MAX for r in rvas):
        ledger.count('diaphora-rva-out-of-range')
        return False
    return True


class DiaphoraAdapter:
    id = 'diaphora'

    def available(self, inputs: SourceInputs) -> Availability:
        return Availability('ok') if inputs.diaphora else Availability('missing', 'no-diaphora-sets')

    def atoms(self, inputs: SourceInputs, addr: AddressMap, budget: Budget) -> AdapterOutput:
        budget.check()
        ledger = Ledger()
        atoms: list[Atom] = []
        groups: list[SourceGroup] = []
        nodes: dict[tuple[str, int], str | None] = {}
        refs: list[SourceRef] = []
        sets = [(loaded, source_ref_of(loaded, budget)) for loaded in inputs.diaphora]
        for loaded, ref in sorted(sets, key=lambda item: (item[0].entry_id, item[1].entry_id)):
            refs.append(ref)    # every set looked at is an input, a refused one included
            match_set = loaded.match_set
            pair = (match_set.older_sha256, match_set.newer_sha256)
            if pair != (inputs.older_sha256, inputs.newer_sha256):
                ledger.flag('diaphora-pair-mismatch')
                if pair == (inputs.newer_sha256, inputs.older_sha256):
                    ledger.flag('diaphora-orientation-reversed')
                continue
            if match_set.trust == 'manifest-bound':
                self._verified(loaded, budget, ledger, atoms, groups, nodes)
            else:
                self._display_only(loaded, budget, ledger, atoms)
        node_records = tuple(NodeRecord(side, rva, name) for (side, rva), name in sorted(nodes.items()))  # type: ignore[arg-type]
        return AdapterOutput(atoms=tuple(sorted(atoms, key=atom_order)),
                             groups=tuple(sorted(groups, key=lambda g: (g.older, g.newer, g.kind))),
                             nodes=node_records, limitations=ledger.render(), source_refs=tuple(refs))

    def _verified(self, loaded, budget, ledger, atoms: list[Atom], groups: list[SourceGroup], nodes) -> None:
        multi: list[DiaphoraMatch] = []
        for m in sorted(loaded.match_set.matches, key=_match_key):
            budget.tick()
            if not _usable(m, (m.older_rva, m.newer_rva), ledger):
                continue
            nodes[('older', m.older_rva)] = nodes.get(('older', m.older_rva)) or clean_name(m.older_name)
            nodes[('newer', m.newer_rva)] = nodes.get(('newer', m.newer_rva)) or clean_name(m.newer_name)
            if m.category == 'multimatch':
                multi.append(m)
            else:
                atoms.append(self._atom(loaded, m, '1:1'))
        self._multimatch(loaded, multi, budget, atoms, groups)
        for u in sorted(loaded.match_set.unmatched, key=_unmatched_key):
            budget.tick()
            if not _usable(u, (u.rva,), ledger):
                continue
            nodes[(u.side, u.rva)] = nodes.get((u.side, u.rva)) or clean_name(u.name)
            atoms.append(Atom(source='diaphora', step='unmatched', tier='W', cardinality='1:1', cls='E-UNKNOWN',
                              older_rva=u.rva if u.side == 'older' else None,
                              newer_rva=u.rva if u.side == 'newer' else None,
                              ref=f'{loaded.entry_id}:u{u.index}'[:128], native=native(('category', 'unmatched'))))

    @staticmethod
    def _atom(loaded, m: DiaphoraMatch, cardinality: str) -> Atom:
        step = clean_name(m.heuristic, 64) or 'unknown'
        return Atom(source='diaphora', step=step, tier=TIERS[m.category],  # type: ignore[arg-type]
                    cardinality=cardinality, cls=heuristic_class(m.heuristic),  # type: ignore[arg-type]
                    older_rva=m.older_rva, newer_rva=m.newer_rva, ref=f'{loaded.entry_id}:{m.index}'[:128],
                    native=native(('category', m.category), ('ratio', m.ratio_text)))

    def _multimatch(self, loaded, rows: list[DiaphoraMatch], budget, atoms: list[Atom],
                    groups: list[SourceGroup]) -> None:
        """Connected components of the multimatch rows: a lone pair is a plain tier-C edge, a larger component is one
        ambiguous N:M group that is kept whole (never cross-multiplied into loose edges)."""
        parent: dict[tuple[str, int], tuple[str, int]] = {}

        def find(x):
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for m in rows:
            budget.tick()
            parent[find(('o', m.older_rva))] = find(('n', m.newer_rva))
        components: dict[tuple[str, int], list[DiaphoraMatch]] = {}
        for m in rows:
            components.setdefault(find(('o', m.older_rva)), []).append(m)
        for members in components.values():
            budget.check()
            edges = {(m.older_rva, m.newer_rva) for m in members}
            if len(edges) == 1:
                atoms.extend(self._atom(loaded, m, '1:1') for m in members)
                continue
            older_degree = {o: sum(1 for e in edges if e[0] == o) for o, _ in edges}
            newer_degree = {n: sum(1 for e in edges if e[1] == n) for _, n in edges}
            group_atoms = tuple(sorted((self._atom(loaded, m, _edge_cardinality(older_degree[m.older_rva],
                                                                                  newer_degree[m.newer_rva]))
                                        for m in members), key=atom_order))
            groups.append(SourceGroup(kind='diaphora-multimatch', source='diaphora',
                                      older=tuple(sorted({e[0] for e in edges})),
                                      newer=tuple(sorted({e[1] for e in edges})), decision='ambiguous',
                                      reason='diaphora-multimatch', atoms=group_atoms))

    @staticmethod
    def _display_only(loaded, budget, ledger, atoms: list[Atom]) -> None:
        """R-15: tier-W one-sided atoms only, class E-UNKNOWN; no edge atom, no node name, nothing a rule can count."""
        ledger.flag('diaphora-unverified-set')
        flag = ('unverified', 'user-attested pair, not verified')
        shown = 0
        for m in sorted(loaded.match_set.matches, key=_match_key):
            budget.tick()
            if not _usable(m, (m.older_rva, m.newer_rva), ledger):
                continue
            shown += 1
            for side, rva, other in (('older', m.older_rva, m.newer_rva), ('newer', m.newer_rva, m.older_rva)):
                atoms.append(Atom(
                    source='diaphora', step='unverified-pair', tier='W', cardinality='1:1', cls='E-UNKNOWN',
                    older_rva=rva if side == 'older' else None, newer_rva=rva if side == 'newer' else None,
                    ref=f'{loaded.entry_id}:{m.index}'[:128],
                    native=native(flag, ('category', m.category),
                                  ('counterpart', f'{"newer" if side == "older" else "older"} rva 0x{other:X}'),
                                  ('ratio', m.ratio_text))))
        for u in sorted(loaded.match_set.unmatched, key=_unmatched_key):
            budget.tick()
            if not _usable(u, (u.rva,), ledger):
                continue
            shown += 1
            atoms.append(Atom(source='diaphora', step='unverified-unmatched', tier='W', cardinality='1:1',
                              cls='E-UNKNOWN', older_rva=u.rva if u.side == 'older' else None,
                              newer_rva=u.rva if u.side == 'newer' else None,
                              ref=f'{loaded.entry_id}:u{u.index}'[:128],
                              native=native(flag, ('category', 'unmatched'))))
        ledger.count('diaphora-unverified-rows', shown)
