"""Pure chain extraction over adjacent pair projects (SPEC-09 §3). No Qt, I/O or network.

Each pair project is an independent pairwise result. A node of build k is joined across the
(k-1→k) and (k→k+1) projects within that same build: by address when the record has one (one
binary cannot hold two functions at one address), otherwise by exact name among address-less
records. Addresses are never compared across different builds.

Normalized pair matches cover only modified/added/deleted functions, so unchanged pairs come
from the run's preserved Ghidriff `matches.address_matches`. Those engine relations never
override a normalized or manual relation touching either endpoint. Only unambiguous 1:1 relations extend a
chain; anything else ends it and is reported as an event so no many-to-many transitivity is
ever implied. Runtime is O(matches + functions).
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ..enrichment.identity import domain_id, parse_address
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

MAX_NAME_CHARS = 4096  # the FunctionNode contract bound
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

Key = int | tuple[None, str]


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




@dataclass(frozen=True)
class RawFunction:
    """An endpoint known only from upstream address_matches: no name, code or metadata."""
    address: str
    name: str | None = None
    code: None = None
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RawRelation:
    id: str
    category: str
    older: list
    newer: list
    match_types: list
    manual: bool = False


def _key(func) -> Key:
    address = parse_address(func.address)
    return address if address is not None else (None, func.name)


def _key_parts(key: Key) -> tuple[int | None, str | None]:
    return (key, None) if isinstance(key, int) else (None, key[1])


_EXTERNAL = re.compile(r'EXTERNAL:[0-9A-Fa-f]+')


def _is_external(text: object) -> bool:
    """Ghidra's placeholder for an imported (external) location: real Ghidriff output keys it `EXTERNAL:<hex>`."""
    return isinstance(text, str) and _EXTERNAL.fullmatch(text.strip()) is not None


def _read_address_matches(raw: Mapping) -> tuple[dict[int, list[tuple[int, list[str]]]], int]:
    """Parse raw address_matches into {source: [(target, match types)]} and count the EXTERNAL skips.

    An entry whose source or any target is an `EXTERNAL:<hex>` import location is skipped and counted once:
    it is not a function of either image and cannot be chained. Other unparsable addresses are errors.
    """
    table = raw.get('address_matches')
    if not isinstance(table, Mapping):
        raise NwayError('PT-NWAY-PAIR', 'raw matches.address_matches must be an object')
    parsed: dict[int, list[tuple[int, list[str]]]] = {}
    skipped = 0
    for old_text, targets in table.items():
        if _is_external(old_text):
            skipped += 1
            continue
        old = parse_address(old_text)
        if old is None or not isinstance(targets, list):
            raise NwayError('PT-NWAY-PAIR', 'raw address_matches has an invalid address or target list')
        entries = []
        touches_external = False
        for target in targets:
            if (not isinstance(target, list) or len(target) != 2 or not isinstance(target[0], str)
                    or not isinstance(target[1], list) or not all(isinstance(t, str) for t in target[1])):
                raise NwayError('PT-NWAY-PAIR', 'raw address_matches target must be [address, [match types]]')
            if _is_external(target[0]):
                touches_external = True
                continue
            new = parse_address(target[0])
            if new is None:
                raise NwayError('PT-NWAY-PAIR', 'raw address_matches has an invalid target address')
            entries.append((new, target[1]))
        if touches_external:  # a partial 1:N relation would look 1:1 and chain a wrong hop
            skipped += 1
            continue
        if old in parsed:
            raise NwayError('PT-NWAY-PAIR', 'raw address_matches repeats a source address')
        parsed[old] = entries
    return parsed, skipped


def external_limitations(raw: Mapping) -> tuple[str, ...]:
    """Limitation text for raw address_matches entries skipped as EXTERNAL:<hex> locations; () when none."""
    skipped = _read_address_matches(raw)[1]
    if not skipped:
        return ()
    noun = 'entry' if skipped == 1 else 'entries'
    return (f'{skipped} raw address_matches {noun} at EXTERNAL:<hex> import locations skipped: '
            'not functions of either build, so no edges',)


def _raw_relations(raw: Mapping, run_id: str, taken_old: set, taken_new: set) -> list[RawRelation]:
    """Engine relations from Ghidriff address_matches for endpoints no normalized match touches.

    EXTERNAL entries are skipped and counted by `_read_address_matches`; they never become relations.
    """
    parsed = _read_address_matches(raw)[0]
    claims: dict[int, int] = {}
    for entries in parsed.values():
        for new in {new for new, _ in entries}:
            claims[new] = claims.get(new, 0) + 1
    relations = []
    for old in sorted(parsed):
        entries = parsed[old]
        targets = sorted({new for new, _ in entries})
        if old in taken_old or any(new in taken_new for new in targets):
            continue  # normalized and manual relations always win over raw engine relations
        one = len(targets) == 1 and len(entries) == 1 and claims[targets[0]] == 1
        relations.append(RawRelation(
            id=f'raw:{run_id}:{old:x}', category='unchanged' if one else 'ambiguous',
            older=[RawFunction(f'{old:x}')], newer=[RawFunction(f'{new:x}') for new in targets],
            match_types=list(entries[0][1]) if one else []))
    return relations


def _ratio_text(match) -> str | None:
    value = match.older[0].metadata.get('upstream_similarity') if match.older else None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    # repr round-trips the upstream JSON number exactly; no rounding or recomputation.
    return repr(value)


class _Pair:
    """Relations of one pair project indexed by node key, with manual corrections winning."""

    def __init__(self, project: ComparisonProject, raw: Mapping | None = None):
        older: dict[Key, list[FunctionMatch]] = {}
        newer: dict[Key, list[FunctionMatch]] = {}
        relations: list = list(project.matches)
        if raw is not None:
            taken_old = {_key(f) for m in project.matches for f in m.older}
            taken_new = {_key(f) for m in project.matches for f in m.newer}
            run_id = project.matches[0].run_id if project.matches else 'run'
            relations += _raw_relations(raw, run_id, taken_old, taken_new)
        for match in relations:
            for side, index in (('older', older), ('newer', newer)):
                for func in getattr(match, side):
                    index.setdefault(_key(func), []).append(match)
        self.older = {k: self._prefer_manual(v) for k, v in older.items()}
        self.newer = {k: self._prefer_manual(v) for k, v in newer.items()}
        # Names/code of normalized records, used to describe nodes reached by raw relations.
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
        incoming = self.newer.get(_key(match.newer[0]), [])
        if len(incoming) != 1 or incoming[0] is not match:
            return None  # the node's surviving (e.g. manually corrected) relation is a different match
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


def _describe(indexed: list[_Pair], ordinal: int, key: Key) -> FunctionRecord | None:
    """A normalized record for this node from either adjacent pair, if any exists."""
    sources = []
    if ordinal > 0:
        sources.append(indexed[ordinal - 1].funcs.get(('newer', key)))
    if ordinal < len(indexed):
        sources.append(indexed[ordinal].funcs.get(('older', key)))
    return next((s for s in sources if s is not None), None)


def _node(ordinal: int, key: Key, record) -> FunctionNode:
    address, name = _key_parts(key)
    if record is not None:
        name = record.name
    if name is not None and len(name) > MAX_NAME_CHARS:
        raise NwayError('PT-NWAY-INPUT', f'a function name exceeds {MAX_NAME_CHARS} characters')
    if address is None and not name:
        raise NwayError('PT-NWAY-INPUT', 'a function has neither an address nor a name')
    return FunctionNode(ordinal=ordinal, address=address, name=name or None)


def extract_chains(hashes: Sequence[str], pairs: Sequence[ComparisonProject],
                   direct: ComparisonProject | None = None, raw_matches: Sequence[Mapping | None] | None = None,
                   direct_raw: Mapping | None = None) -> tuple[list[Chain], int]:
    """Return (chains sorted deterministically, distinct node count).

    raw_matches[i] is the upstream `matches` object of pair i's current run, or None if absent.
    """
    validate_builds(hashes)
    n = len(hashes)
    if len(pairs) != n - 1:
        raise NwayError('PT-NWAY-PAIR', f'expected {n - 1} adjacent pair projects, got {len(pairs)}')
    for i, project in enumerate(pairs):
        validate_pair(project, hashes[i], hashes[i + 1])
    if direct is not None:
        validate_pair(direct, hashes[0], hashes[-1])
    raw_matches = list(raw_matches) if raw_matches is not None else [None] * len(pairs)
    if len(raw_matches) != len(pairs):
        raise NwayError('PT-NWAY-PAIR', 'raw matches must be given per pair project')
    indexed = [_Pair(p, r) for p, r in zip(pairs, raw_matches, strict=True)]
    nodes = {(0, k) for k in indexed[0].older}
    for i, pair in enumerate(indexed):
        nodes.update((i + 1, k) for k in pair.newer)
        nodes.update((i, k) for k in pair.older)
    if len(nodes) > MAX_NODES:
        raise NwayError('PT-NWAY-LIMIT', f'series has {len(nodes)} function nodes; the limit is {MAX_NODES}')
    sid = series_id(hashes)
    direct_pair = _Pair(direct, direct_raw) if direct is not None else None
    chains = []
    for ordinal, key in sorted(nodes, key=lambda item: (item[0], *_sort_key(item[1]))):
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


def _sort_key(key: Key) -> tuple:
    return (0, key, '') if isinstance(key, int) else (1, 0, key[1])


def _has_predecessor(pair: _Pair, key: Key) -> bool:
    relations = pair.newer.get(key, [])
    return len(relations) == 1 and len(relations[0].older) == 1 and \
        pair.successor(_key(relations[0].older[0])) is relations[0]


def _build_chain(sid: str, start: int, path: list[Key], matches: list[FunctionMatch], indexed: list[_Pair],
                 direct: _Pair | None, n: int) -> Chain:
    records = [_describe(indexed, start + i, key) for i, key in enumerate(path)]
    nodes = [_node(start + i, key, record) for i, (key, record) in enumerate(zip(path, records, strict=True))]
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
    codes = [None if r is None else r.code for r in records]
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
                path[-1] in {_key(f) for f in r.newer} for r in relations):
            # Direct pair records the start as removed/split/merged away from the chain's end.
            status = 'contradicted'
    chain_id = domain_id('series-chain', 1, {'series_id': sid,
                                             'nodes': [[x.ordinal, x.address, x.name] for x in nodes]})
    return Chain(chain_id=chain_id, nodes=tuple(nodes), edges=tuple(edges), hops=len(edges),
                 weakest_match_type=_weakest(edges), status=status, gaps=tuple(gaps), events=tuple(events))
