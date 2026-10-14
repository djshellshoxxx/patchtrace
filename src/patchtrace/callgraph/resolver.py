"""A1 resolution ladder: a call-list label on one side to a typed graph node (first match wins, `via` kept)."""
from __future__ import annotations

from dataclasses import dataclass

from ..enrichment.identity import domain_id
from .contracts import GraphNode, NodeFlag, NodeKind, NodeTier, NodeVia, Side
from .labels import default_address, parse_external, split_count_suffix, thunk_target
from .project_input import Entry, ProjectInput
from .text import sanitize

MAX_CANDIDATES = 20
_LIBRARY_EXTENSIONS = ('.dll', '.drv', '.sys', '.exe', '.ocx', '.so')
_EXTERNAL_PREFIX = 'EXTERNAL:'
_UNRESOLVED = 'not-in-emitted-or-matched-sets'


def _safe_key(text: str) -> str:
    # JSON carries lone surrogates that neither UTF-8 nor pydantic accept; they become visible escapes.
    return text.encode('utf-8', 'backslashreplace').decode('utf-8')


@dataclass(frozen=True)
class _Hit:
    kind: NodeKind
    key: str
    via: NodeVia
    tier: NodeTier
    entry: Entry | None = None
    address: int | None = None
    flags: tuple[NodeFlag, ...] = ()
    candidates: tuple[str, ...] = ()
    reason: str = ''


class Resolver:
    """Resolves labels of one side. `resolve_thunks` turns on the opt-in `thunk_X` rung (default off)."""

    def __init__(self, data: ProjectInput, side: Side, resolve_thunks: bool = False) -> None:
        self._side = side
        self._sha = data.older_sha256 if side == 'older' else data.newer_sha256
        self._thunks = resolve_thunks
        self._records: dict[str, list[Entry]] = {}
        for entry in data.side_entries(side):
            self._records.setdefault(entry.label, []).append(entry)
        raw = data.raw.matches
        if raw is None:
            self._names, self._addresses = {}, {}
        elif side == 'older':
            self._names, self._addresses = raw.names, raw.addresses
        else:
            self._names, self._addresses = raw.reverse_names, raw.reverse_addresses
        self._cache: dict[str, GraphNode] = {}

    def resolve(self, label: str) -> GraphNode:
        node = self._cache.get(label)
        if node is None:
            node = self._cache[label] = self._node(label, self._ladder(label))
        return node

    def _ladder(self, label: str) -> _Hit:
        hit = self._exact(label)
        if hit is None and self._thunks and (target := thunk_target(label)) is not None:
            hit = self._thunk(label, target)
        if hit is None:
            hit = self._count_suffix(label)
        return hit or _Hit('label-only', label, 'unresolved', 'label', reason=_UNRESOLVED)

    def _exact(self, label: str) -> _Hit | None:
        """Rungs 1-4. An import-looking label is external even when name_matches pairs it: the pair map
        still reports the pairing, but the node keeps its import kind."""
        records = self._records.get(label, [])
        if len(records) > 1:
            ids = sorted(e.function_id for e in records)
            return _Hit('ambiguous', label, 'emitted-record', 'record', candidates=tuple(ids[:MAX_CANDIDATES]))
        if records:
            entry = records[0]
            if entry.external:
                return _Hit('external', self._external_key(label), 'external', 'record', entry, flags=('import',))
            return _Hit('function', label, 'emitted-record', 'record', entry, entry.address)
        if self._looks_external(label):
            return _Hit('external', self._external_key(label), 'external', 'label', flags=('import',))
        partners = self._names.get(label)
        if partners:
            return self._paired(label, 'name-match', [name for name, _ in partners], None)
        address = default_address(label)
        if address is not None and (targets := self._addresses.get(address)):
            return self._paired(label, 'address-match', [f'{a:x}' for a, _ in targets], address)
        return None

    @staticmethod
    def _paired(label: str, via: NodeVia, partners: list[str], address: int | None) -> _Hit:
        if len(partners) > 1:
            return _Hit('ambiguous', label, via, 'pairing', candidates=tuple(sorted(partners)[:MAX_CANDIDATES]))
        return _Hit('paired-unchanged', label, via, 'pairing', address=address)

    @staticmethod
    def _looks_external(label: str) -> bool:
        if label.startswith(_EXTERNAL_PREFIX):
            return True
        library, sep, _ = label.partition('::')
        return bool(sep) and parse_external(label) is not None and library.strip().lower().endswith(_LIBRARY_EXTENSIONS)

    @staticmethod
    def _external_key(label: str) -> str:
        parsed = parse_external(label)
        return parsed.key if parsed else label

    def _thunk(self, label: str, target: str) -> _Hit | None:
        inner = self._exact(target)
        if inner is None or inner.kind == 'ambiguous':
            return None
        return _Hit(inner.kind, label, 'thunk', inner.tier, inner.entry, inner.address,
                    (*inner.flags, 'thunk-suspect'), reason='thunk resolved to its target')

    def _count_suffix(self, label: str) -> _Hit | None:
        split = split_count_suffix(label)
        inner = self._exact(split[0]) if split else None
        if inner is None or inner.kind == 'ambiguous':  # the stem must resolve to exactly one thing
            return None
        return _Hit(inner.kind, label, 'count-suffix', inner.tier, inner.entry, inner.address,
                    (*inner.flags, 'inferred-count-suffix'), reason='stem of a --use-calling-counts name')

    def _node(self, label: str, hit: _Hit) -> GraphNode:
        identity = {'sha': self._sha, 'side': self._side, 'kind': hit.kind, 'key': _safe_key(hit.key)}
        entry = hit.entry
        return GraphNode(
            id=domain_id('callgraph-node', 1, identity), side=self._side, kind=hit.kind,
            label=sanitize(_safe_key(label)), via=hit.via, tier=hit.tier,
            function_id=entry.function_id if entry else None, match_id=entry.match_id if entry else None,
            address=hit.address, flags=hit.flags,
            candidates=tuple(sanitize(_safe_key(c), 128) for c in hit.candidates), reason=hit.reason)
