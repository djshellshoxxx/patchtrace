"""Feature schema `features/1` and extraction from stored Ghidriff + reconciliation data (spec §6).

One module used by training (tools/calibration) and by the app, so there is no train/serve skew.
Engine-native values stay raw and separate; nothing is averaged or pre-combined. Contested and
non-comparable rows produce no vector: they are routed by policy, never given to a model.
"""
from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from ..models import FunctionMatch
from ..secondary.reconcile import Reconciliation, ReconciliationReport

FEATURE_SCHEMA = 'features/1'
Family = Literal['G', 'B', 'R', 'S', 'P', 'X']
Kind = Literal['num', 'cat', 'flag']
PROFILES = ('G', 'G+B', 'G+R', 'G+B+R')
ENGINE_FAMILY = {'bindiff': 'B', 'rz-diff': 'R'}

# Ghidriff correlator names (provisional level set, to be confirmed against real exports; others -> 'other').
G_MATCH_TYPES = ('SymbolsHash', 'ExactBytesFunctionHasher', 'ExactInstructionsFunctionHasher',
                 'ExactMnemonicsFunctionHasher', 'StructuralGraphExactHash', 'StructuralGraphHash',
                 'BulkBasicBlockMnemonicHash', 'SigCallingCalledHasher', 'StringsRefsHasher', 'Implied Match')
# BinDiff function-algorithm buckets: (bucket, lowercase substring). First hit wins; else 'other'.
B_ALGORITHMS = (('name-hash', 'name hash'), ('hash', 'hash matching'), ('prime', 'prime signature'),
                ('md-index', 'md index'), ('call-sequence', 'call sequence'), ('call-reference', 'call reference'),
                ('strings', 'string references'), ('instruction-count', 'instruction count'),
                ('address-sequence', 'address sequence'))
B_FLAGS = ('G', 'I', 'O', 'J', 'E', 'L', 'C')
CATEGORIES = {'P.symbols': ('none', 'public', 'private'), 'P.arch': ('x64', 'x86', 'arm64', 'other'),
              'P.toolchain': ('msvc', 'clang', 'gcc', 'unknown'), 'P.binexport_producer': ('none', 'ghidra', 'ida')}

D_GHIDRA, D_IDA, D_SYMBOLS, D_COMPILER, D_CALLGRAPH, D_BYTES = (
    'D_ghidra', 'D_ida', 'D_symbols', 'D_compiler', 'D_callgraph', 'D_bytes')


def family_dependencies(binexport_producer: str = 'ghidra') -> dict[str, frozenset[str]]:
    """Spec §6.4 circular-dependency table. X carries the union of the engines it compares."""
    b_tool = D_IDA if binexport_producer == 'ida' else D_GHIDRA
    deps = {'G': frozenset({D_GHIDRA, D_SYMBOLS, D_CALLGRAPH, D_COMPILER}),
            'B': frozenset({b_tool, D_SYMBOLS, D_CALLGRAPH}), 'R': frozenset({D_BYTES}),
            'S': frozenset({D_GHIDRA}), 'P': frozenset()}
    deps['X'] = deps['G'] | deps['B'] | deps['R']
    return deps


def independence_index(profile: str, binexport_producer: str = 'ghidra') -> int:
    """Number of engines beyond the first whose dependency sets are disjoint from all others (components - 1)."""
    deps = family_dependencies(binexport_producer)
    engines = profile.split('+')
    parent = {e: e for e in engines}

    def find(e):
        while parent[e] != e:
            e = parent[e]
        return e
    for i, a in enumerate(engines):
        for b in engines[i + 1:]:
            if deps[a] & deps[b]:
                parent[find(b)] = find(a)
    return len({find(e) for e in engines}) - 1


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    family: Family
    kind: Kind
    missing_ok: bool = False

    @property
    def depends_on(self) -> frozenset[str]:
        return family_dependencies()[self.family]


def _specs() -> tuple[FeatureSpec, ...]:
    out: list[FeatureSpec] = []

    def num(name, family, missing_ok=False):
        out.append(FeatureSpec(name, family, 'num', missing_ok))
        if missing_ok:
            out.append(FeatureSpec(name + '.missing', family, 'flag'))
    num('G.ratio', 'G', True)
    out.append(FeatureSpec('G.unchanged', 'G', 'flag'))
    out += [FeatureSpec(f'G.mt.{t}', 'G', 'flag') for t in G_MATCH_TYPES + ('other',)]
    num('G.n_match_types', 'G')
    num('B.similarity', 'B')
    num('B.confidence', 'B')
    out += [FeatureSpec(f'B.alg.{b}', 'B', 'flag') for b, _ in B_ALGORITHMS] + [FeatureSpec('B.alg.other', 'B', 'flag')]
    out += [FeatureSpec(f'B.flag.{f}', 'B', 'flag') for f in B_FLAGS]
    num('R.similarity', 'R')
    for side in ('older', 'newer'):
        num(f'S.log_size_{side}', 'S', True)
    num('S.size_ratio', 'S', True)
    for side in ('older', 'newer'):
        num(f'S.log_callees_{side}', 'S')
    out.append(FeatureSpec('S.thunk', 'S', 'flag'))
    for cat, levels in CATEGORIES.items():
        out += [FeatureSpec(f'{cat}={level}', 'P', 'cat') for level in levels]
    out += [FeatureSpec(f'X.{k}', 'X', 'flag') for k in ('agree_B', 'agree_R', 'absent_B', 'absent_R')]
    num('X.log_alternatives', 'X')
    return tuple(out)


FEATURES: tuple[FeatureSpec, ...] = _specs()
SPEC_BY_NAME: Mapping[str, FeatureSpec] = {s.name: s for s in FEATURES}


def profile_families(profile: str) -> tuple[str, ...]:
    if profile not in PROFILES:
        raise ValueError(f'unknown profile {profile!r}')
    engines = profile.split('+')
    return tuple(f for f in ('G', 'B', 'R', 'S', 'P', 'X') if f in engines or f in ('G', 'S', 'P', 'X'))


def feature_names(profile: str) -> tuple[str, ...]:
    fams = profile_families(profile)
    return tuple(s.name for s in FEATURES if s.family in fams)


@dataclass(frozen=True)
class ExtractionContext:
    symbol_provenance: Literal['none', 'public', 'private'] = 'none'
    arch: str = 'other'
    toolchain: str = 'unknown'
    binexport_producer: Literal['none', 'ghidra', 'ida'] = 'none'


DEFAULT_CONTEXT = ExtractionContext()
RowStatus = Literal['ok', 'not-comparable', 'one-sided', 'contested']


@dataclass(frozen=True)
class FeatureRow:
    match_id: str
    status: RowStatus
    profile: str | None
    values: tuple[tuple[str, float | None], ...]
    categories: tuple[tuple[str, str], ...]
    engine_versions: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, float | None]:
        return dict(self.values)


def _num(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _length(record) -> float | None:
    value = _num(record.metadata.get('length'))
    return value if value is not None and value > 0 else None


def _bucket_algorithm(algorithm: str) -> str:
    low = algorithm.lower()
    return next((bucket for bucket, needle in B_ALGORITHMS if needle in low), 'other')


def extract(match: FunctionMatch, reports: Iterable[ReconciliationReport],
            context: ExtractionContext = DEFAULT_CONTEXT) -> FeatureRow:
    reports = tuple(reports)
    versions = tuple(sorted(f'{r.engine} {r.engine_version}' for r in reports))
    if len({r.engine for r in reports}) != len(reports):
        raise ValueError('one reconciliation report per engine required')
    rows: dict[str, Reconciliation] = {}
    for report in reports:
        found = [row for row in report.rows if row.match_id == match.id]
        if len(found) != 1:
            raise ValueError(f'{report.engine} report does not contain match {match.id} exactly once')
        rows[report.engine] = found[0]

    def abstain(status: RowStatus, reason: str) -> FeatureRow:
        return FeatureRow(match.id, status, None, (), (), versions, reason)
    if len(match.older) > 1 or len(match.newer) > 1 or any(r.status == 'not-comparable' for r in rows.values()):
        return abstain('not-comparable', 'many-to-many or unparsable endpoints')
    if any(r.status == 'disagreement' for r in rows.values()):
        return abstain('contested', 'an engine pairs an endpoint differently; manual review')
    if not match.older or not match.newer:
        return abstain('one-sided', 'added/removed function has no counterpart to judge')
    engines = sorted(e for e, r in rows.items() if r.status == 'agreement' and e in ENGINE_FAMILY)
    profile = '+'.join(['G'] + sorted(ENGINE_FAMILY[e] for e in engines))
    profile = {'G+R+B': 'G+B+R'}.get(profile, profile)
    old, new = match.older[0], match.newer[0]
    v: dict[str, float | None] = {}
    ratio = _num(old.metadata.get('upstream_similarity'))
    v['G.ratio'], v['G.ratio.missing'] = ratio, float(ratio is None)
    v['G.unchanged'] = float(match.category == 'unchanged')
    types = set(match.match_types)
    for t in G_MATCH_TYPES:
        v[f'G.mt.{t}'] = float(t in types)
    v['G.mt.other'] = float(bool(types - set(G_MATCH_TYPES)))
    v['G.n_match_types'] = float(len(types))
    if 'bindiff' in engines:
        sm = rows['bindiff'].secondary[0]
        v['B.similarity'] = sm.similarity_milli / 1000
        v['B.confidence'] = (sm.confidence_milli or 0) / 1000
        bucket = _bucket_algorithm(sm.algorithm)
        for b, _ in B_ALGORITHMS:
            v[f'B.alg.{b}'] = float(bucket == b)
        v['B.alg.other'] = float(bucket == 'other')
        for f in B_FLAGS:
            v[f'B.flag.{f}'] = float(f in sm.flags)
    if 'rz-diff' in engines:
        v['R.similarity'] = rows['rz-diff'].secondary[0].similarity_milli / 1000
    sizes = {'older': _length(old), 'newer': _length(new)}
    for side, size in sizes.items():
        v[f'S.log_size_{side}'] = math.log(size) if size else None
        v[f'S.log_size_{side}.missing'] = float(size is None)
        record = old if side == 'older' else new
        v[f'S.log_callees_{side}'] = math.log1p(len(record.callees))
    both = sizes['older'] and sizes['newer']
    v['S.size_ratio'] = min(sizes.values()) / max(sizes.values()) if both else None
    v['S.size_ratio.missing'] = float(not both)
    v['S.thunk'] = float(any(r.name.startswith('thunk_') or r.metadata.get('thunk') is True for r in (old, new)))
    cats = {'P.symbols': context.symbol_provenance, 'P.arch': context.arch, 'P.toolchain': context.toolchain,
            'P.binexport_producer': context.binexport_producer if 'bindiff' in engines else 'none'}
    for cat, levels in CATEGORIES.items():
        for level in levels:
            v[f'{cat}={level}'] = float(cats[cat] == level)
    for engine, fam in ENGINE_FAMILY.items():
        status = rows[engine].status if engine in rows else None
        v[f'X.agree_{fam}'] = float(status == 'agreement')
        v[f'X.absent_{fam}'] = float(status == 'absent')
    v['X.log_alternatives'] = math.log1p(sum(len(r.alternatives) for r in rows.values()))
    names = feature_names(profile)
    return FeatureRow(match.id, 'ok', profile, tuple((n, v[n]) for n in names),
                      tuple(sorted(cats.items())), versions, '')


def extract_all(matches: Iterable[FunctionMatch], reports: Iterable[ReconciliationReport],
                context: ExtractionContext = DEFAULT_CONTEXT) -> tuple[FeatureRow, ...]:
    reports = tuple(reports)
    return tuple(extract(m, reports, context) for m in sorted(matches, key=lambda m: m.id))
