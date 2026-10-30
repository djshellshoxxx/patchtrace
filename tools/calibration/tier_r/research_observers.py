"""Experimental raw engine observations; no labels, implicit credit, or engine execution."""
from __future__ import annotations

import re
from collections.abc import Mapping

from .contracts import MAX_FUNCTIONS
from .report_schemas import MAX_PREDICTIONS
from .research_audit import Observation

_ADDRESS = re.compile(r'(?:(?:ram|memory):)?(?:0x)?([0-9a-fA-F]{1,16})\Z')
_EXTERNAL = re.compile(r'EXTERNAL:[0-9a-fA-F]{1,16}\Z')


def ghidriff_image_projection(raw: Mapping) -> tuple[dict, dict]:
    """Explicit image-VA scope projection, with input/image/unscored-external counts.

    Caller retains immutable raw bytes/hash and validates artifact binding first.
    Only syntactically valid EXTERNAL->EXTERNAL address-table edges are unscored;
    cross/unknown namespaces and external function change records are rejected.
    Functions and all other raw fields are preserved. Counts include duplicate
    evidence before the strict observer collapses it. No raw object is mutated.
    """
    table, records = _structures(raw)

    def namespace(address: object) -> str:
        if isinstance(address, str) and len(address) <= 40:
            if _ADDRESS.fullmatch(address):
                return 'image'
            if _EXTERNAL.fullmatch(address):
                return 'external'
        raise ValueError('invalid or unknown Ghidriff address namespace')

    keys = {'input': len(table), 'image': 0, 'external': 0}
    edges = {'input': 0, 'image': 0, 'external': 0}
    projected_table = {}
    for source, targets in table.items():
        kind = namespace(source)
        if not isinstance(targets, list):
            raise ValueError('Ghidriff address targets must be a list')
        keys[kind] += 1
        edges['input'] += len(targets)
        if edges['input'] + sum(len(items) for items in records) > MAX_PREDICTIONS:
            raise ValueError('Ghidriff observation limit exceeded')
        for target in targets:
            if not isinstance(target, list) or len(target) != 2:
                raise ValueError('Ghidriff target requires address and match types')
            _types(target[1])
            if namespace(target[0]) != kind:
                raise ValueError('cross-namespace Ghidriff correspondence')
            edges[kind] += 1
        if kind == 'image':
            projected_table[source] = targets
    modified, added, deleted = records
    endpoints = []
    for item in modified:
        if not isinstance(item, Mapping):
            raise ValueError('Ghidriff modified record must be a mapping')
        endpoints.extend((item.get('old'), item.get('new')))
    endpoints.extend(added)
    endpoints.extend(deleted)
    for item in endpoints:
        if not isinstance(item, Mapping):
            raise ValueError('Ghidriff function must be a mapping')
        if namespace(item.get('address')) != 'image':
            raise ValueError('external function change records require a separate observation scope')
    projected = dict(raw)
    projected['matches'] = dict(raw['matches'], address_matches=projected_table)
    return projected, {'address_keys': keys, 'address_edges': edges,
                       'scope': 'image VA only; validated EXTERNAL pairs are unscored; caller retains raw hash'}


def _structures(raw: Mapping) -> tuple[Mapping, list[list]]:
    if not isinstance(raw, Mapping):
        raise ValueError('Ghidriff document must be a mapping')
    matches, functions = raw.get('matches'), raw.get('functions')
    if not isinstance(matches, Mapping) or not isinstance(functions, Mapping):
        raise ValueError('Ghidriff matches and functions mappings are required')
    table = matches.get('address_matches')
    if not isinstance(table, Mapping):
        raise ValueError('Ghidriff address_matches must be a mapping')
    records = [functions.get(category) for category in ('modified', 'added', 'deleted')]
    if any(not isinstance(items, list) for items in records):
        raise ValueError('Ghidriff modified/added/deleted must be lists')
    if len(table) > MAX_FUNCTIONS or sum(len(items) for items in records) > MAX_FUNCTIONS:
        raise ValueError('Ghidriff function row limit exceeded')
    return table, records


def _types(types: object) -> None:
    if (not isinstance(types, list) or len(types) > 64
            or any(not isinstance(kind, str) or len(kind) > 128 for kind in types)):
        raise ValueError('invalid Ghidriff match types')


def _rva(value: object, base: int) -> int:
    match = _ADDRESS.fullmatch(value) if isinstance(value, str) and len(value) <= 40 else None
    if match is None:
        raise ValueError('invalid or unsupported Ghidriff virtual address')
    rva = int(match[1], 16) - base
    if not 0 <= rva < 2**32:
        raise ValueError('Ghidriff address does not fit its side-specific RVA basis')
    return rva


def _function(record: object, base: int) -> int:
    if not isinstance(record, Mapping):
        raise ValueError('Ghidriff function must be a mapping')
    return _rva(record.get('address'), base)


def ghidriff_observations(raw: Mapping, *, old_base: int, new_base: int) -> list[Observation]:
    """Read actual PDiff observations without labels or implicit unchanged credit.

    Caller first validates artifact binding through the existing Ghidriff importer.
    Address-table pairs have unknown change status; explicit modified/added/deleted
    rows carry True as the engine's change signal, not a semantic-materiality claim.
    Duplicate same-pair evidence collapses. Ambiguous identity or paired/unpaired
    conflicts raise ValueError because Observation cannot encode identity ambiguity.
    Unsupported address spaces also fail closed. Retain raw bytes/hash on rejection.

    Only consumed structures are checked here; unrelated code/metadata is ignored.
    File-byte limits belong to the caller; row budgets reuse existing Tier R limits.
    """
    if any(type(base) is not int or not 0 <= base < 2**64 for base in (old_base, new_base)):
        raise ValueError('image bases must be uint64 integers')
    table, records = _structures(raw)
    pairs: dict[tuple[int, int], bool | None] = {}
    forward: dict[int, int] = {}
    reverse: dict[int, int] = {}
    old_only: set[int] = set()
    new_only: set[int] = set()
    count = sum(len(items) for items in records)

    def pair(old: int, new: int, changed: bool | None) -> None:
        if (old in forward and forward[old] != new) or (new in reverse and reverse[new] != old):
            raise ValueError('ambiguous Ghidriff correspondence cannot be scored as a unique pair')
        forward[old], reverse[new] = new, old
        key = (old, new)
        if key not in pairs or changed is True:
            pairs[key] = changed

    for address, targets in table.items():
        old = _rva(address, old_base)
        if not isinstance(targets, list):
            raise ValueError('Ghidriff address targets must be a list')
        count += len(targets)
        if count > MAX_PREDICTIONS:
            raise ValueError('Ghidriff observation limit exceeded')
        for target in targets:
            if not isinstance(target, list) or len(target) != 2:
                raise ValueError('Ghidriff target requires address and match types')
            address, types = target
            _types(types)
            pair(old, _rva(address, new_base), None)
    modified, added, deleted = records
    for item in modified:
        if not isinstance(item, Mapping):
            raise ValueError('Ghidriff modified record must be a mapping')
        pair(_function(item.get('old'), old_base), _function(item.get('new'), new_base), True)
    for items, base, target in ((added, new_base, new_only), (deleted, old_base, old_only)):
        for item in items:
            target.add(_function(item, base))
    if old_only.intersection(forward) or new_only.intersection(reverse):
        raise ValueError('conflicting paired and unmatched Ghidriff observations')
    observations: list[Observation] = [(old, new, pairs[(old, new)]) for old, new in sorted(pairs)]
    observations.extend((old, None, True) for old in sorted(old_only))
    observations.extend((None, new, True) for new in sorted(new_only))
    return observations
