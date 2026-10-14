"""Independence components (05 s1.1): union-find over the joining D-tags of the registry's families. Pure.

Two families that share a joining tag are one component; `K0` is the component holding F-MANUAL, the others are
`K1`, `K2`, ... in order of their alphabetically first family, so the numbering never depends on input order.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache

from ..limits import UnifiedError
from ..registry import Family, Registry


@dataclass(frozen=True)
class Components:
    by_family: Mapping[str, str]
    members: Mapping[str, tuple[str, ...]]

    def of(self, registry: Registry, source: str, step: str) -> str:
        """Component of an atom by (source, step); an unregistered source is a bug in an adapter."""
        family = registry.family_of(source, step)
        if family is None or family not in self.by_family:
            raise UnifiedError('PT-UNIFIED-INTERNAL', 'An atom names a source the registry does not know',
                               reason='unknown-source')
        return self.by_family[family]


def build_components(families: Sequence[Family]) -> Components:
    names = sorted(f.name for f in families)
    parent = {name: name for name in names}

    def find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    owner: dict[str, str] = {}
    for family in sorted(families, key=lambda f: f.name):
        for tag in family.joining:
            if tag in owner:
                parent[find(family.name)] = find(owner[tag])
            else:
                owner[tag] = family.name
    groups: dict[str, list[str]] = {}
    for name in names:
        groups.setdefault(find(name), []).append(name)
    ordered = sorted(groups.values(), key=lambda members: members[0])
    labelled: dict[str, tuple[str, ...]] = {}
    number = 1
    for members in ordered:
        if 'F-MANUAL' in members:
            labelled['K0'] = tuple(members)
        else:
            labelled[f'K{number}'] = tuple(members)
            number += 1
    by_family = {family: label for label, members in labelled.items() for family in members}
    return Components(by_family=by_family, members=dict(sorted(labelled.items(), key=lambda kv: int(kv[0][1:]))))


@lru_cache(maxsize=16)
def _cached(families: tuple[Family, ...]) -> Components:
    return build_components(families)


def components_for(registry: Registry) -> Components:
    return _cached(registry.families)
