"""Shared-origin components: evidence derived from the same upstream data counts once (FAB-integration-plan.md s6, s7).

An origin tag names the data a witness was derived from (`D_vendor_text` for every repetition of an advisory's claim,
`D_ghidra` for B1, ChangeFacts and Ghidra call labels, `D_pe_tables`, `D_vivisect`, `D_bytes`). Two witnesses are
dependent when their tag sets share a tag, transitively; the number of connected components is the number of
independent witnesses. This is the one implementation of the calculus and the one table: PIL's `pilot/origins.py`
re-exports them since FAB-3 and keeps only its own error type and identity domain. Locality never counts here, and a
witness without origin tags is refused: unknown provenance must never add independence.

The default table is PIL's original rows plus the FAB-2 rows of plan s10: KEV's catalog listing, WBQ's PE self-report
family and WB3's `emulation` and `ir` lineage groups. CAP's lineage tags wait for CAP-7 (plan s11, question 3), and
every other source is added by one data change, requested by its owner. A row added here moves `digest()`, and with it
the PIL origins digest (`tests/test_fabric_adopt.py` pins that one too).
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from ..enrichment.identity import domain_id
from .limits import FabricError

if TYPE_CHECKING:  # annotation only
    from .contracts import Anchor
    from .ports import OriginRegistry

ORIGINS_VERSION = 1
DOMAIN = 'fabric-origins'
_TAG = re.compile(r'D_[a-z0-9_]{1,32}')

# Known tags: the SPEC-27/31 dependency vocabulary plus the PIL additions (`D_vendor_text`, `D_vivisect`) and the FAB-2
# additions (`D_emulation`, `D_kev`, `D_pe_self_report`).
TAGS = ('D_analyst', 'D_bytes', 'D_callgraph', 'D_compiler', 'D_emulation', 'D_ghidra', 'D_ghidra_decode', 'D_hexrays',
        'D_ida', 'D_kev', 'D_pe_self_report', 'D_pe_tables', 'D_rizin', 'D_symbols', 'D_vendor_text', 'D_vivisect')

# Evidence source -> origin tags. NVD, MSRC and KEV `cwes` repeat the advisory's CWE: one origin, counted once.
# FAB-2 rows: `kev-catalog` is CISA's own listing (dates, ransomware use), not vendor text; `pe-self-report` is the
# author-controlled PE family (VERSIONINFO, manifest, Rich header, CodeView name); `emulation` is WB3's emulation
# lineage (a run id does not change the origin). `ir` takes Ghidra's origin because Ghidra is the primary IR producer
# (UE plan H1; BinExport2 and rizin are the others): that can merge IR strings with Ghidra evidence, never separate
# them, so it never adds independence. A per-producer tag replaces it once the producer is recorded per IR key.
SOURCE_TAGS = MappingProxyType({
    'advisory-text': ('D_vendor_text',), 'nvd-cwe': ('D_vendor_text',), 'msrc-cwe': ('D_vendor_text',),
    'kev-cwe': ('D_vendor_text',), 'kev-catalog': ('D_kev',),
    'b1': ('D_ghidra',), 'change-facts': ('D_ghidra',), 'call-label': ('D_ghidra',),
    'pe-import': ('D_pe_tables',), 'pe-self-report': ('D_pe_self_report',),
    'capa': ('D_vivisect',), 'capa-ghidra': ('D_ghidra',),
    'floss': ('D_bytes',), 'die': ('D_compiler',), 'emulation': ('D_emulation',), 'ir': ('D_ghidra',),
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
            raise ValueError('a witness without origin tags cannot be placed in a component')
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


def independent_count(origin_sets: Iterable[Iterable[str]]) -> int:
    """The number of independent witnesses among the given origin sets."""
    return len(components(origin_sets))


def anchor_components(anchor: Anchor) -> tuple[tuple[str, ...], ...]:
    """The origin components over the witnesses of one anchor (a count, never a score)."""
    return components(witness.origins for witness in anchor.witnesses)


class DefaultOriginRegistry:
    """The fabric's origin-tag table (`SOURCE_TAGS`); its digest is part of every stored batch identity."""

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
            raise FabricError('PT-FAB-ORIGIN', 'Unknown evidence source for origin tags',
                              reason='unknown-origin-source') from None

    def components(self, origin_sets: Iterable[Iterable[str]]) -> tuple[tuple[str, ...], ...]:
        return components(origin_sets)

    def payload(self) -> dict[str, object]:
        """The table as it is hashed: the version and the sorted tags per source. A consumer may hash it under its own
        identity domain (PIL does), so its ids stay in its namespace while the table has one definition."""
        sources = {name: list(tags) for name, tags in sorted(self._table.items())}
        return {'version': self._version, 'sources': sources}

    def digest(self) -> str:
        return domain_id(DOMAIN, 1, self.payload())


def digest() -> str:
    """Digest of the default registry."""
    return DefaultOriginRegistry().digest()


def check_origins(anchor: Anchor, registry: OriginRegistry) -> None:
    """Every witness must carry exactly the registry's tags of its source: a producer cannot claim independence by
    inventing or dropping tags (`PT-FAB-ORIGIN`)."""
    for witness in anchor.witnesses:
        if tuple(witness.origins) != registry.tags_for(witness.source):
            raise FabricError('PT-FAB-ORIGIN', 'The origin tags differ from the registry tags of the source',
                              reason='origin-mismatch')
