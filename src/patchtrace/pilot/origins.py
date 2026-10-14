"""Shared-origin components: evidence derived from the same upstream data counts once (s4, s7 tier step 3).

An origin tag names the data an observation was derived from (`D_vendor_text` for every repetition of an advisory's
claim, `D_ghidra` for B1, ChangeFacts and Ghidriff call labels, `D_pe_tables`, `D_vivisect`, `D_bytes`). Two
observations are dependent when their tag sets share a tag, transitively; the number of connected components is the
number of independent witnesses. This is the one implementation of "shared origin counts once" until the insight
fabric (FAB) generalises it: FAB adopts or replaces this file and `ports.py` only. Locality never counts here.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType

from ..enrichment.identity import domain_id
from .contracts import LeadComponents
from .limits import PilotError

ORIGINS_VERSION = 1
DOMAIN = 'pilot-origins'
_TAG = re.compile(r'D_[a-z0-9_]{1,32}')

# Known tags: the SPEC-27/31 dependency vocabulary plus the PIL additions (`D_vendor_text`, `D_vivisect`).
TAGS = ('D_analyst', 'D_bytes', 'D_callgraph', 'D_compiler', 'D_ghidra', 'D_ghidra_decode', 'D_hexrays', 'D_ida',
        'D_pe_tables', 'D_rizin', 'D_symbols', 'D_vendor_text', 'D_vivisect')

# Evidence source -> origin tags. NVD, MSRC and KEV `cwes` repeat the advisory's CWE: one origin, counted once.
SOURCE_TAGS = MappingProxyType({
    'advisory-text': ('D_vendor_text',), 'nvd-cwe': ('D_vendor_text',), 'msrc-cwe': ('D_vendor_text',),
    'kev-cwe': ('D_vendor_text',),
    'b1': ('D_ghidra',), 'change-facts': ('D_ghidra',), 'call-label': ('D_ghidra',),
    'pe-import': ('D_pe_tables',),
    'capa': ('D_vivisect',), 'capa-ghidra': ('D_ghidra',),
    'floss': ('D_bytes',), 'die': ('D_compiler',),
    'names': ('D_symbols',), 'pairing': ('D_ghidra',), 'analyst': ('D_analyst',)})


def components(origin_sets: Iterable[Iterable[str]]) -> tuple[tuple[str, ...], ...]:
    """Connected components of origin tags: sets that share a tag are joined, transitively.

    Returns the components as sorted tuples of tags, sorted by their smallest tag. Order of the sets and duplicates
    do not matter, and a set whose tags all occur already can only merge components, never add one. An empty set (an
    observation of unknown origin) is refused: unknown provenance must never add independence."""
    parent: dict[str, str] = {}

    def find(tag: str) -> str:
        root = tag
        while parent[root] != root:
            root = parent[root]
        while parent[tag] != root:
            parent[tag], tag = root, parent[tag]
        return root

    for tags in origin_sets:
        if isinstance(tags, str):
            raise TypeError('an origin set is a collection of tags, not a string')
        items = sorted(set(tags))
        if not items:
            raise ValueError('an observation without origin tags cannot be placed in a component')
        for tag in items:
            if not isinstance(tag, str) or not _TAG.fullmatch(tag):
                raise ValueError('origin tags look like D_name (lower-case letters, digits and underscores)')
            parent.setdefault(tag, tag)
        base = find(items[0])
        for tag in items[1:]:
            root = find(tag)
            if root != base:
                low, high = sorted((root, base))
                parent[high] = low
                base = low
    groups: dict[str, list[str]] = {}
    for tag in parent:
        groups.setdefault(find(tag), []).append(tag)
    return tuple(sorted(tuple(sorted(group)) for group in groups.values()))


def lead_components(origin_sets: Iterable[Iterable[str]]) -> LeadComponents:
    """`Lead.components`: the component count and the smallest tag of each component."""
    found = components(origin_sets)
    return LeadComponents(count=len(found), tags=tuple(component[0] for component in found))


class DefaultOriginRegistry:
    """PIL's own origin-tag table (`SOURCE_TAGS`); its digest is part of every result identity."""

    def __init__(self, table: Mapping[str, Iterable[str]] | None = None, version: int = ORIGINS_VERSION):
        if type(version) is not int or version < 1:
            raise ValueError('the origins version must be a positive int')
        built: dict[str, tuple[str, ...]] = {}
        for source, tags in (SOURCE_TAGS if table is None else table).items():
            items = tuple(sorted(set(tags)))
            if not items or not all(_TAG.fullmatch(tag) for tag in items):
                raise ValueError(f'origin source {source!r} needs well-formed D_ tags')
            built[source] = items
        self._table = MappingProxyType(built)
        self._version = version

    @property
    def version(self) -> int:
        return self._version

    def tags_for(self, source: str) -> tuple[str, ...]:
        try:
            return self._table[source]
        except KeyError:
            raise PilotError('PT-PILOT-INPUT', 'Unknown evidence source for origin tags',
                             reason='unknown-origin-source') from None

    def components(self, origin_sets: Iterable[Iterable[str]]) -> tuple[tuple[str, ...], ...]:
        return components(origin_sets)

    def digest(self) -> str:
        sources = {name: list(tags) for name, tags in sorted(self._table.items())}
        return domain_id(DOMAIN, 1, {'version': self._version, 'sources': sources})


def digest() -> str:
    """Digest of the default registry (`PilotInputs.origins_digest`)."""
    return DefaultOriginRegistry().digest()
