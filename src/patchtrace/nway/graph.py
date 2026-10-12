"""Pure chain extraction over adjacent pair projects (SPEC-09 §3). No Qt, I/O or network.

Each pair project is an independent pairwise result. A node of build k is joined across the
(k-1→k) and (k→k+1) projects by exact (address, name) identity within that same build —
never by address equality across different builds. Only unambiguous 1:1 relations extend a
chain; anything else ends it and is reported as an event so no many-to-many transitivity is
ever implied. Runtime is O(matches + functions).
"""
from __future__ import annotations

from collections.abc import Sequence

from ..enrichment.identity import domain_id
from ..models import ComparisonProject, FunctionMatch, FunctionRecord
from .contracts import (
    MAX_BUILDS,
    MAX_NODES,
    MIN_BUILDS,
    Chain,
    ChainEvent,
    FunctionNode,
    NwayError,
    PairEdge,
)

ONE_TO_ONE = frozenset({'modified', 'unchanged'})
# Display order only (strongest first, following Ghidriff correlator order); never a score.
# Analyst corrections rank first because they override the engine by contract.
MATCH_TYPE_ORDER = ('manual', 'SymbolsHash', 'ExternalsName', 'ExactBytesFunctionHasher',
                    'ExactInstructionsFunctionHasher', 'ExactMnemonicsFunctionHasher',
                    'StructuralGraphExactHash', 'StructuralGraphHash', 'BulkInstructionHash',
                    'BulkMnemonicHash', 'BulkBasicBlockMnemonicHash', 'NamespaceNameParamHash',
                    'NameParamHash', 'SigCallingCalledHasher', 'StringsRefsHasher',
                    'StrUniqueFuncRefsHasher', 'SwitchSigHasher', 'BSIM', 'Implied Match', 'Decomp Match')
UNKNOWN_TYPE = 'unknown'

Key = tuple[int | None, str]


def series_id(hashes: Sequence[str]) -> str:
    return domain_id('series', 1, list(hashes))


def validate_builds(hashes: Sequence[str]) -> None:
    if not MIN_BUILDS <= len(hashes) <= MAX_BUILDS:
        raise NwayError('PT-NWAY-INPUT', f'a series needs {MIN_BUILDS}–{MAX_BUILDS} builds, got {len(hashes)}')
    if len(set(hashes)) != len(hashes):
        raise NwayError('PT-NWAY-INPUT', 'build hashes must be unique; remove repeated builds')


def validate_pair(project: ComparisonProject, older_sha: str, newer_sha: str) -> None:
    sides = {a.side: a.sha256 for a in project.artifacts}
    if (sides.get('older'), sides.get('newer')) != (older_sha, newer_sha):
        raise NwayError('PT-NWAY-PAIR', f'pair project {project.name!r} does not contain exactly the ordered pair '
                        f'{older_sha[:12]}→{newer_sha[:12]}')


def parse_address(text: str | None) -> int | None:
    if not text:
        return None
    body = text[2:] if text[:2].lower() == '0x' else text
    if not body or len(body) > 16 or any(c not in '0123456789abcdefABCDEF' for c in body):
        return None
    return int(body, 16)


def _key(func: FunctionRecord) -> Key:
    return parse_address(func.address), func.name


def _ratio_text(match: FunctionMatch) -> str | None:
    value = match.older[0].metadata.get('upstream_similarity') if match.older else None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    # repr round-trips the upstream JSON number exactly; no rounding or recomputation.
    return repr(value)


class _Pair:
    """Relations of one pair project indexed by node key, with manual corrections winning."""

    def __init__(self, project: ComparisonProject):
        older: dict[Key, list[FunctionMatch]] = {}
        newer: dict[Key, list[FunctionMatch]] = {}
        for match in project.matches:
            for side, index in (('older', older), ('newer', newer)):
                for func in getattr(match, side):
                    index.setdefault(_key(func), []).append(match)
        self.older = {k: self._prefer_manual(v) for k, v in older.items()}
        self.newer = {k: self._prefer_manual(v) for k, v in newer.items()}
        self.funcs: dict[tuple[str, Key], FunctionRecord] = {}
        for match in project.matches:
            for side in ('older', 'newer'):
                for func in getattr(match, side):
                    self.funcs.setdefault((side, _key(func)), func)

    @staticmethod
    def _prefer_manual(matches: list[FunctionMatch]) -> list[FunctionMatch]:
        manual = [m for m in matches if m.manual]
        return manual or matches

    def successor(self, key: Key) -> FunctionMatch | None:
        """The 1:1 relation from an older node, or None if the relation is absent or not 1:1."""
        relations = self.older.get(key, [])
        if len(relations) != 1:
            return None
        match = relations[0]
        if match.category not in ONE_TO_ONE or len(match.older) != 1 or len(match.newer) != 1:
            return None
        if len(self.newer.get(_key(match.newer[0]), [])) != 1:
            return None
        return match


def _shape_event(relations: list[FunctionMatch]) -> str | None:
    """Event that ends a chain at a boundary, or None when the pair has no record (a gap)."""
    if not relations:
        return None
    if len(relations) > 1:
        return 'ambiguous'
    match = relations[0]
    if match.category in {'added', 'removed', 'split', 'merged', 'ambiguous', 'unmatched'}:
        return match.category
    if len(match.older) > 1:
        return 'merged'
    if len(match.newer) > 1:
        return 'split'
    # A 1:1 relation that was rejected only because its far endpoint is contested.
    return 'ambiguous'


def _rank(match_type: str) -> int:
    try:
        return MATCH_TYPE_ORDER.index(match_type)
    except ValueError:
        return len(MATCH_TYPE_ORDER)


def _weakest(edges: Sequence[PairEdge]) -> str:
    firsts = [edge.match_types[0] if edge.match_types else UNKNOWN_TYPE for edge in edges]
    return max(firsts, key=lambda t: (t == UNKNOWN_TYPE, _rank(t), t))


def _node(ordinal: int, key: Key) -> FunctionNode:
    return FunctionNode(ordinal=ordinal, address=key[0], name=key[1])


def extract_chains(hashes: Sequence[str], pairs: Sequence[ComparisonProject],
                   direct: ComparisonProject | None = None) -> tuple[list[Chain], int]:
    """Return (chains sorted deterministically, distinct node count)."""
    validate_builds(hashes)
    n = len(hashes)
    if len(pairs) != n - 1:
        raise NwayError('PT-NWAY-PAIR', f'expected {n - 1} adjacent pair projects, got {len(pairs)}')
    for i, project in enumerate(pairs):
        validate_pair(project, hashes[i], hashes[i + 1])
    if direct is not None:
        validate_pair(direct, hashes[0], hashes[-1])
    indexed = [_Pair(p) for p in pairs]
    nodes = {(0, k) for k in indexed[0].older}
    for i, pair in enumerate(indexed):
        nodes.update((i + 1, k) for k in pair.newer)
        nodes.update((i, k) for k in pair.older)
    if len(nodes) > MAX_NODES:
        raise NwayError('PT-NWAY-LIMIT', f'series has {len(nodes)} function nodes; the limit is {MAX_NODES}')
    sid = series_id(hashes)
    direct_pair = _Pair(direct) if direct is not None else None
    chains = []
    for ordinal, key in sorted(nodes, key=lambda item: (item[0], item[1][0] is None, item[1][0] or 0, item[1][1])):
        # A node with a 1:1 predecessor is interior to another chain; starting here would duplicate it.
        if ordinal > 0 and _has_predecessor(indexed[ordinal - 1], key):
            continue
        path, matches = [key], []
        k = ordinal
        while k < n - 1:
            match = indexed[k].successor(path[-1])
            if match is None:
                break
            matches.append(match)
            path.append(_key(match.newer[0]))
            k += 1
        if len(path) < MIN_BUILDS:
            continue
        chains.append(_build_chain(sid, ordinal, path, matches, indexed, direct_pair, n))
    return chains, len(nodes)


def _has_predecessor(pair: _Pair, key: Key) -> bool:
    relations = pair.newer.get(key, [])
    return len(relations) == 1 and len(relations[0].older) == 1 and \
        pair.successor(_key(relations[0].older[0])) is relations[0]


def _build_chain(sid: str, start: int, path: list[Key], matches: list[FunctionMatch], indexed: list[_Pair],
                 direct: _Pair | None, n: int) -> Chain:
    nodes = [_node(start + i, key) for i, key in enumerate(path)]
    edges = [PairEdge(from_node=nodes[i], to_node=nodes[i + 1], category=m.category,
                      match_types=tuple(m.match_types), ratio_text=_ratio_text(m), manual=m.manual, match_id=m.id)
             for i, m in enumerate(matches)]
    end = start + len(path) - 1
    events: list[ChainEvent] = []
    gaps: list[int] = []
    if start > 0:
        kind = _shape_event(indexed[start - 1].newer.get(path[0], []))
        if kind is None:
            gaps.append(start - 1)
        else:
            events.append(ChainEvent(kind=kind, ordinal=start, detail=f'relation from build {start - 1}'))
    codes = [matches[0].older[0].code] + [m.newer[0].code for m in matches]
    for j in range(2, len(codes)):
        if codes[j] is None or codes[j] == codes[j - 1]:
            continue
        earlier = [i for i in range(j - 1) if codes[i] == codes[j]]
        if earlier:
            events.append(ChainEvent(kind='reverted', ordinal=start + j,
                                     detail=f'code text equals build {start + earlier[-1]}'))
    if end < n - 1:
        kind = _shape_event(indexed[end].older.get(path[-1], []))
        if kind is None:
            gaps.append(end + 1)
        else:
            events.append(ChainEvent(kind=kind, ordinal=end + 1, detail=f'relation from build {end}'))
    status = 'inferred'
    if direct is not None and start == 0:
        relations = direct.older.get(path[0], [])
        one = direct.successor(path[0])
        if one is not None and end == n - 1 and _key(one.newer[0]) == path[-1]:
            status = 'confirmed'
        elif one is not None and _key(one.newer[0]) != path[-1] and end == n - 1:
            status = 'contradicted'
        elif relations and end == n - 1 and one is None and not any(
                {_key(f) for f in r.newer} == {path[-1]} for r in relations):
            # Direct pair records the start as removed/split/merged away from the chain's end.
            status = 'contradicted'
    chain_id = domain_id('series-chain', 1, {'series_id': sid,
                                             'nodes': [[x.ordinal, x.address, x.name] for x in nodes]})
    return Chain(chain_id=chain_id, nodes=tuple(nodes), edges=tuple(edges), hops=len(edges),
                 weakest_match_type=_weakest(edges), status=status, gaps=tuple(gaps), events=tuple(events))
