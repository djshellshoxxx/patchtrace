"""The pass table P01-P15 of the L1 ladder (SPEC-31 04 s4): key functions, gates, tiers, families, evidence classes.

Portions derived from google/bindiff v8 (Apache-2.0), Copyright 2011-2023 Google LLC (step order, strongest-first
uniqueness and drill-down semantics of differ.cc / match/call_graph.cc / bindiff.json, call-graph MD of
graph_util.h); algorithms re-expressed in Python and modified for PatchTrace (2026-10-14). The Apache-2.0 licence
text is shipped under third_party/notices/bindiff-v8-*/ (slice S1, 09-licensing s3). Header years are the ones
research note R02 s12 reports for tag v8 and must be re-checked against the pinned files by the notice owner.
Ghidra-VT-style ideas (implied matches, reference vectors) are clean-room from the VT help text (09 s2).
Nothing from Diaphora (AGPL), PatchDiff2, Turbodiff or Ghidriff (GPL) is used.

A pass is data (`passspec.PassSpec`, re-exported here): `keys(side, limits)` returns one hashable key (or None) per
function; a function whose key is None is not eligible. Static gates (size, tiny, thunk, hub, ICF suspect) are folded
into the key (None). The engine owns uniqueness: a pair needs a key that is unique on both sides among the unmatched
functions of the pool the key was evaluated in. A `guard` may veto a unique pair or cap its tier (P03, P12-P14); a
`run` hook replaces the key mechanics for passes that are not "bucket by key" (P15, and the residual passes of slice
S5).
"""
from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence

from ...enrichment.identity import domain_id
from ..limits import UnifiedLimits
from .passspec import PassSpec, Verdict
from .side import K_EXTERNAL, SideData
from .state import State
from .types import FAMILY_BYTES, TIER_RANK

LADDER_VERSION = 'ladder/1'
FAMILY_STRUCT = 'F-PT-STRUCT'
P15_MAX_WAVES = 8
_SQ = (math.sqrt(2), math.sqrt(3), math.sqrt(5), math.sqrt(7), math.sqrt(11), math.sqrt(13))


# ---- helpers -----------------------------------------------------------------------------------------------------------------

def ratio_ok(size_a: int, size_b: int, limits: UnifiedLimits) -> bool:
    """L-21 size-ratio guard 0.5 .. 2.0 (milli integers, symmetric in its arguments)."""
    return (size_a > 0 and size_b > 0
            and limits.l21_size_ratio_min_milli * size_a <= 1000 * size_b <= limits.l21_size_ratio_max_milli * size_a)


def classify_pair(spec: PassSpec, chain: Sequence[PassSpec], both_pdata: bool) -> tuple[str, str]:
    """(family, evidence class) of a pair accepted by `spec` after drilling down `chain` (05 s1.1). F-PT-BYTES only
    when every key involved reads bytes and both extents are confirmed by .pdata; mixed chains fall back to the
    structural family (the one that shares D_ghidra / D_callgraph with Ghidriff and therefore never corroborates it)."""
    specs = [*chain, spec]
    if all(s.bytes_family for s in specs):
        return (FAMILY_BYTES if both_pdata else FAMILY_STRUCT), spec.cls
    families = {s.family for s in specs}
    return (spec.family if len(families) == 1 else FAMILY_STRUCT), spec.cls


def _columns(side: SideData, column: list, gate: list) -> list:
    return [h if ok else None for h, ok in zip(column, gate, strict=True)]


# ---- key builders ------------------------------------------------------------------------------------------------------------

def _keys_import(side: SideData, limits: UnifiedLimits) -> list:
    return [side.import_key[f] or None if side.kind[f] == K_EXTERNAL else None for f in range(side.n)]


def _keys_export(side: SideData, limits: UnifiedLimits) -> list:
    return list(side.export_key)


def _keys_name(side: SideData, limits: UnifiedLimits) -> list:
    return [side.names[f] or None if side.kind[f] != K_EXTERNAL else None for f in range(side.n)]


def _keys_h0(side: SideData, limits: UnifiedLimits) -> list:
    return _columns(side, side.h0, side.content_ok)


def _keys_h1(side: SideData, limits: UnifiedLimits) -> list:
    return _columns(side, side.h1, side.content_ok)


def _keys_h2(side: SideData, limits: UnifiedLimits) -> list:
    return _columns(side, side.h2, side.multiset_ok)


def _keys_h3(side: SideData, limits: UnifiedLimits) -> list:
    return _columns(side, side.h3, side.multiset_ok)


def _keys_hm(side: SideData, limits: UnifiedLimits) -> list:
    return _columns(side, side.hm, side.multiset_ok)


def _keys_hms(side: SideData, limits: UnifiedLimits) -> list:
    return _columns(side, side.hms, side.multiset_ok)


def _keys_md_flow(side: SideData, limits: UnifiedLimits) -> list:
    out: list = [None] * side.n
    for f in range(side.n):
        if side.content_ok[f] and side.n_bb[f] >= limits.l11_md_min_blocks:
            td, bu = side.md_td[f], side.md_bu[f]
            if td is not None and bu is not None:
                out[f] = (td, bu, side.n_bb[f], side.n_edge[f])
    return out


def _call_graph_md(side: SideData) -> tuple[list, list]:
    """BinDiff-style call-graph vertex MD, top-down and bottom-up (sum of the MD of the incident call edges,
    terms sorted before the plain left-to-right sum, then `round(x * 10**12)`). Multi edges and self edges count
    as BinDiff counts them. Internal key of the ladder: parity with BinDiff is claimed for flow graphs only (G-U3)."""
    def build() -> tuple[list, list]:
        src: list[int] = []
        dst: list[int] = []
        for f in range(side.n):
            for callee, _ikey, _jump in side.sites[f]:
                if callee >= 0:
                    src.append(f)
                    dst.append(callee)
        return _vertex_md(side.n, src, dst), _vertex_md(side.n, dst, src)
    return side.cached('call_graph_md', build)


def _vertex_md(n: int, src: list[int], dst: list[int]) -> list:
    indeg = [0] * n
    outdeg = [0] * n
    adj: list[list[int]] = [[] for _ in range(n)]
    for s, t in zip(src, dst, strict=True):
        outdeg[s] += 1
        indeg[t] += 1
        adj[s].append(t)
    level = [0] * n
    seen = bytearray(n)
    queue = [v for v in range(n) if indeg[v] == 0]
    for v in queue:
        seen[v] = 1
    head = 0
    while head < len(queue):
        v = queue[head]
        head += 1
        for w in adj[v]:
            if not seen[w]:
                seen[w] = 1
                level[w] = level[v] + 1
                queue.append(w)
    p = [_SQ[0] * indeg[v] + _SQ[1] * outdeg[v] + _SQ[4] * level[v] for v in range(n)]    # as edge source
    q = [_SQ[2] * indeg[v] + _SQ[3] * outdeg[v] + _SQ[5] * level[v] for v in range(n)]    # as edge target
    terms: list[list[float]] = [[] for _ in range(n)]
    for s, t in zip(src, dst, strict=True):
        term = 1.0 / (p[s] + q[t])
        terms[s].append(term)
        terms[t].append(term)
    out: list = [None] * n
    for v in range(n):
        if terms[v]:
            total = 0.0
            for term in sorted(terms[v]):
                total += term
            out[v] = (round(total * 10 ** 12), len(terms[v]))
    return out


def _keys_md_call(side: SideData, limits: UnifiedLimits) -> list:
    td, bu = _call_graph_md(side)
    out: list = [None] * side.n
    for f in range(side.n):
        if side.content_ok[f] and td[f] is not None and td[f][1] >= 2 and bu[f] is not None:
            out[f] = (td[f][0], bu[f][0])
    return out


def _rare(side: SideData, attr: str, max_functions: int) -> list[tuple[int, ...]]:
    def build() -> list[tuple[int, ...]]:
        counts: Counter[int] = Counter()
        column = getattr(side, attr)
        for items in column:
            counts.update(items)
        return [tuple(v for v in items if counts[v] <= max_functions) for items in column]
    return side.cached(f'rare:{attr}:{max_functions}', build)


def _set_keys(side: SideData, sets: Sequence[tuple]) -> list:
    return [s if s and side.content_ok[f] else None for f, s in enumerate(sets)]


def _keys_strings(side: SideData, limits: UnifiedLimits) -> list:
    return _set_keys(side, _rare(side, 'strs', limits.l14_string_rare_functions))


def _import_sets(side: SideData) -> list[tuple[str, ...]]:
    return side.cached('import_sets', lambda: [tuple(sorted({ikey for _c, ikey, _j in sites if ikey}))
                                               for sites in side.sites])


def _keys_imports(side: SideData, limits: UnifiedLimits) -> list:
    return _set_keys(side, _import_sets(side))


def _keys_consts(side: SideData, limits: UnifiedLimits) -> list:
    return _set_keys(side, _rare(side, 'consts', limits.l15_const_rare_functions))


# ---- guards ----------------------------------------------------------------------------------------------------------------------

def _shared_mapped_callee(st: State, a: int, b: int) -> bool:
    """A callee of `a` was paired (before the current pass began) with a callee of `b`."""
    newer_callees = set(st.b.callees[b])
    for x in st.a.callees[a]:
        y = st.mate_a[x]
        if y >= 0 and y in newer_callees and st.pairs[st.pair_a[x]].seq < st.pass_start_seq:
            return True
    return False


def _guard_name(st: State, a: int, b: int, key: object) -> Verdict | None:
    """P03 (R05 F13): equal unique name AND (sizes within L-21 OR a shared mapped callee), else a tier-C candidate
    with hint `name-body-mismatch` (evaluated against the state at the start of the pass: order independent)."""
    if ratio_ok(st.a.size[a], st.b.size[b], st.limits) or _shared_mapped_callee(st, a, b):
        return Verdict('A')
    return Verdict('C', ('name-body-mismatch',))


def _guard_set(st: State, a: int, b: int, key: object) -> Verdict | None:
    """L-16: a set key needs >= 2 elements, or one rare element plus the size-ratio guard."""
    if len(key) >= st.limits.l16_set_min_elements:  # type: ignore[arg-type]
        return Verdict('B')
    return Verdict('B') if ratio_ok(st.a.size[a], st.b.size[b], st.limits) else None


# ---- P15 rehash-exact ----------------------------------------------------------------------------------------------------

def _rehash_keys(st: State, side_letter: str):
    """{key: [fid]} plus {fid: weakest tier rank of the substituted pairs} over unmatched eligible functions."""
    side = st.a if side_letter == 'a' else st.b
    mate = st.mate_a if side_letter == 'a' else st.mate_b
    pair_idx = st.pair_a if side_letter == 'a' else st.pair_b
    icf = st.icf_a if side_letter == 'a' else st.icf_b
    buckets: dict[tuple, list[int]] = {}
    floors: dict[int, int] = {}
    for f in range(side.n):
        if mate[f] >= 0 or not side.content_ok[f] or side.hub[f] or icf[f] or side.h1[f] is None:
            continue
        sites = side.sites[f]
        if not sites:
            continue
        tokens = []
        floor = TIER_RANK['M']
        for callee, ikey, jump in sites:
            if ikey:
                tokens.append(('I', ikey, jump))
            elif callee < 0:
                tokens.append(('?', jump))
            elif callee == f:
                tokens.append(('S', jump))
            elif mate[callee] >= 0:
                other = mate[callee]
                tokens.append(('P', callee, other, jump) if side_letter == 'a' else ('P', other, callee, jump))
                floor = min(floor, TIER_RANK[st.pairs[pair_idx[callee]].tier])
            else:
                tokens = None
                break
        if tokens is None:
            continue
        buckets.setdefault((side.h1[f], tuple(tokens)), []).append(f)
        floors[f] = floor
    return buckets, floors


def rehash_exact(st: State, rnd: int) -> None:
    """P15 (R04 s4.14): `h1` re-keyed with the matched pair id (or import key) of every call target, so shape-identical
    wrappers that differ only in WHICH matched callee they call become unique. A needs every substituted pair to be
    tier A/M, otherwise B. Iterates (a newly matched callee enables its callers) up to P15_MAX_WAVES waves."""
    spec = PASS_BY_ID['P15']
    for _wave in range(P15_MAX_WAVES):
        st.budget.tick()
        a_by, floors_a = _rehash_keys(st, 'a')
        b_by, floors_b = _rehash_keys(st, 'b')
        accepted = 0
        for key in sorted(a_by.keys() & b_by.keys(), key=repr):
            st.budget.tick()
            if len(a_by[key]) != 1 or len(b_by[key]) != 1:
                st.bump('ambiguous:P15')
                continue
            x, y = a_by[key][0], b_by[key][0]
            floor = min(floors_a[x], floors_b[y])
            tier = 'A' if floor >= TIER_RANK['A'] else 'B'
            family, cls = classify_pair(spec, (), False)
            st.accept(x, y, pass_id=spec.id, step=spec.step, tier=tier, family=family, cls=cls, rnd=rnd)
            accepted += 1
        if not accepted:
            break
    else:
        st.limit_hit('rehash-wave-cap')


# ---- the table ----------------------------------------------------------------------------------------------------------------

P00 = PassSpec('P00', 'manual', 0, 'M', 'F-MANUAL', 'E-MANUAL')
PASSES: tuple[PassSpec, ...] = (
    PassSpec('P01', 'import-key', 0, 'A', 'F-PT-PE', 'E-NAME', _keys_import, hubs=True),
    PassSpec('P02', 'export-key', 0, 'A', 'F-PT-PE', 'E-NAME', _keys_export, hubs=True),
    PassSpec('P03', 'name-exact', 0, 'A', 'F-PT-NAMES', 'E-NAME', _keys_name, _guard_name, hubs=True),
    PassSpec('P04', 'bytes-exact', 1, 'A', FAMILY_STRUCT, 'E-BODY', _keys_h0, hubs=True, neighbour=True,
             bytes_family=True),
    PassSpec('P05', 'masked-exact', 1, 'A', FAMILY_STRUCT, 'E-BODY', _keys_h1, hubs=True, neighbour=True,
             bytes_family=True),
    PassSpec('P06', 'operand-class', 2, 'B', FAMILY_STRUCT, 'E-BODY', _keys_h2, neighbour=True, bytes_family=True),
    PassSpec('P07', 'register-agnostic', 2, 'B', FAMILY_STRUCT, 'E-BODY', _keys_h3, neighbour=True,
             bytes_family=True),
    PassSpec('P08', 'mnemonic-seq', 2, 'B', FAMILY_STRUCT, 'E-BODY', _keys_hm, neighbour=True, bytes_family=True),
    PassSpec('P09', 'mnemonic-multiset', 2, 'B', FAMILY_STRUCT, 'E-BODY', _keys_hms, neighbour=True,
             bytes_family=True),
    PassSpec('P10', 'md-flowgraph', 2, 'B', FAMILY_STRUCT, 'E-CFG', _keys_md_flow, neighbour=True),
    PassSpec('P11', 'md-callgraph', 2, 'B', FAMILY_STRUCT, 'E-CALL', _keys_md_call, neighbour=True),
    PassSpec('P12', 'string-set', 3, 'B', FAMILY_STRUCT, 'E-DATA', _keys_strings, _guard_set, neighbour=True),
    PassSpec('P13', 'import-callee-set', 3, 'B', FAMILY_STRUCT, 'E-CALL', _keys_imports, _guard_set,
             neighbour=True),
    PassSpec('P14', 'const-set', 3, 'B', FAMILY_STRUCT, 'E-DATA', _keys_consts, _guard_set, neighbour=True,
             bytes_family=True),
    PassSpec('P15', 'rehash-exact', 4, 'B', FAMILY_STRUCT, 'E-CALL', run=rehash_exact),
)
PASS_BY_ID: dict[str, PassSpec] = {p.id: p for p in (P00, *PASSES)}
NEIGHBOUR_PASSES: tuple[PassSpec, ...] = tuple(p for p in PASSES if p.neighbour)
assert all(PASS_BY_ID[p.id] is p for p in PASSES)


def pass_table_digest(passes: Sequence[PassSpec] = PASSES) -> str:
    """Identity of the table for `keys.config_digest(pass_table_digest=...)`: any rule change changes it."""
    rows = [[p.id, p.name, p.stage, p.tier, p.family, p.cls, p.hubs, p.neighbour, p.bytes_family,
             p.guard is not None, p.run is not None, p.keys is not None] for p in passes]
    return domain_id('unified-pass-table', 1, {'version': LADDER_VERSION, 'passes': rows,
                                               'p15_max_waves': P15_MAX_WAVES})


PASS_TABLE_DIGEST = pass_table_digest()
__all__ = ['FAMILY_STRUCT', 'LADDER_VERSION', 'NEIGHBOUR_PASSES', 'P00', 'PASSES', 'PASS_BY_ID', 'PASS_TABLE_DIGEST',
           'PassSpec', 'Verdict', 'classify_pair', 'pass_table_digest', 'ratio_ok', 'rehash_exact']
