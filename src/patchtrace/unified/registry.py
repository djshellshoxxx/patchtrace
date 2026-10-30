"""SPEC-31 registry (01 s2, 04 s4, 05 s1, 06 s1): evidence families with joining D-tags, evidence classes, tier maps,
source specs, the pass table and the versions that feed `config_digest`. Pure plain data plus small lookups.

S0a deferred this module and S0b needs it for fusion (02 s10 item 1). `Registry` is a frozen dataclass, so a new
source is one extra row (`dataclasses.replace(REGISTRY, sources=...)`), and every fusion function takes `registry=`.
S2 extends `PASSES` (key functions stay in `ladder/passes.py`); it never recreates this file.
Nothing here reads a score: tiers and classes are fixed by the step names alone.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..enrichment.identity import domain_id
from .contracts import EvidenceClass, Tier

TIER_RANK: dict[str, int] = {'M': 5, 'A': 4, 'B': 3, 'C': 2, 'W': 1}
DTAGS: tuple[str, ...] = ('D_analyst', 'D_bytes', 'D_callgraph', 'D_compiler', 'D_ghidra', 'D_ghidra_decode',
                          'D_hexrays', 'D_ida', 'D_pe_tables', 'D_rizin', 'D_symbols')
STEP_MAX = 64


@dataclass(frozen=True)
class Family:
    """An evidence family (05 s1.1): `tags` are all its dependencies, `joining` the subset that joins families
    into one independence component (D_ghidra_decode of F-PT-BYTES is recorded but does not join)."""
    name: str
    tags: tuple[str, ...]
    joining: tuple[str, ...]


@dataclass(frozen=True)
class SourceSpec:
    """Registry row of a source (D-08, 06 s1). `family` is None when the step decides (pt-ladder)."""
    id: str
    family: str | None
    display: str
    unit_caption: str
    native_labels: tuple[str, ...]
    tooltip_id: str
    licence_note: str


@dataclass(frozen=True)
class PassSpec:
    """Data of one ladder pass (04 s4): allowed tiers (first = nominal), class, family kind, stage."""
    id: str
    name: str
    tiers: tuple[Tier, ...]
    cls: EvidenceClass
    family_kind: str   # manual | pe | names | bytes-or-struct | struct
    stage: str


def _family(name: str, tags: tuple[str, ...], joining: tuple[str, ...] | None = None) -> Family:
    return Family(name, tuple(sorted(tags)), tuple(sorted(tags if joining is None else joining)))


FAMILIES: tuple[Family, ...] = (
    # BinDiff: D_ghidra for a Ghidra BinExport, D_ida for an IDA one; D_symbols and D_callgraph join it to the
    # same component either way, so the table lists the Ghidra variant (calibration.features does the same).
    _family('F-BINDIFF', ('D_ghidra', 'D_symbols', 'D_callgraph')),
    _family('F-DIAPHORA', ('D_ida', 'D_hexrays', 'D_symbols', 'D_callgraph')),
    _family('F-GHIDRIFF', ('D_ghidra', 'D_symbols', 'D_callgraph', 'D_compiler')),
    _family('F-MANUAL', ('D_analyst',)),
    _family('F-PT-BYTES', ('D_bytes', 'D_ghidra_decode'), ('D_bytes',)),
    _family('F-PT-NAMES', ('D_symbols',)),
    _family('F-PT-PE', ('D_pe_tables', 'D_symbols')),
    _family('F-PT-STRUCT', ('D_ghidra', 'D_ghidra_decode', 'D_callgraph'), ('D_ghidra', 'D_callgraph')),
    _family('F-RZDIFF', ('D_rizin', 'D_bytes')),
)

SOURCES: tuple[SourceSpec, ...] = (
    SourceSpec('ghidriff', 'F-GHIDRIFF', 'Ghidriff', 'match type (raw)', ('ratio', 'match types'),
               'unified.source.ghidriff', 'external process, GPL-3.0; JSON consumed as data'),
    SourceSpec('bindiff', 'F-BINDIFF', 'BinDiff', 'similarity / algorithm', ('similarity', 'confidence', 'algorithm'),
               'unified.source.bindiff', 'external process, Apache-2.0; never bundled'),
    SourceSpec('rz-diff', 'F-RZDIFF', 'rz-diff', 'byte similarity', ('similarity', 'type'),
               'unified.source.rz-diff', 'external process, LGPL-3.0-only'),
    SourceSpec('diaphora', 'F-DIAPHORA', 'Diaphora', 'category / ratio', ('ratio', 'category'),
               'unified.source.diaphora', 'external process, AGPL-3.0; ideas only, no code'),
    SourceSpec('pt-ladder', None, 'PatchTrace ladder', 'pass / tier', ('pass',),
               'unified.source.pt-ladder', 'in-house matcher'),
    SourceSpec('pt-bytes', 'F-PT-BYTES', 'PatchTrace bytes', 'pass / tier', ('pass',),
               'unified.source.pt-bytes', 'in-house masked-byte comparator'),
    SourceSpec('manual', 'F-MANUAL', 'Analyst', 'correction', (),
               'unified.source.manual', 'analyst correction in this project'),
)

# Ghidriff correlator names, strongest first inside a tier (05 s1.2); unknown names are tier C, class E-UNKNOWN.
GHIDRIFF_TYPES: tuple[tuple[str, Tier, EvidenceClass], ...] = (
    ('SymbolsHash', 'A', 'E-NAME'), ('ExternalsName', 'A', 'E-NAME'),
    ('ExactBytesFunctionHasher', 'A', 'E-BODY'), ('ExactInstructionsFunctionHasher', 'A', 'E-BODY'),
    ('ExactMnemonicsFunctionHasher', 'B', 'E-BODY'), ('BulkInstructionHash', 'B', 'E-BODY'),
    ('StringsRefsHasher', 'B', 'E-DATA'), ('StrUniqueFuncRefsHasher', 'B', 'E-DATA'),
    ('BSIM', 'B', 'E-DECOMP'), ('Decomp Match', 'B', 'E-DECOMP'),
    ('StructuralGraphExactHash', 'C', 'E-CFG'), ('StructuralGraphHash', 'C', 'E-CFG'),
    ('BulkBasicBlockMnemonicHash', 'C', 'E-CFG'), ('SwitchSigHasher', 'C', 'E-CFG'),
    ('SigCallingCalledHasher', 'C', 'E-CALL'), ('Implied Match', 'C', 'E-CALL'),
)

# BinDiff function steps after normalisation (lower case, no `function:` prefix); ordered, first hit wins, so
# `name hash` is tried before `hash matching`. The confidence of a step is never read (R02 s7).
BINDIFF_STEPS: tuple[tuple[str, Tier, EvidenceClass], ...] = (
    (r'^name hash', 'A', 'E-NAME'),
    (r'^hash matching', 'A', 'E-BODY'),
    (r'^edges flow', 'A', 'E-CFG'),
    (r'^edges call', 'B', 'E-CALL'),
    (r'^md index matching \(flow', 'B', 'E-CFG'),
    (r'^md index matching \(call', 'B', 'E-CALL'),
    (r'^prime signature', 'B', 'E-BODY'),
    (r'^relaxed md index', 'C', 'E-CFG'),
    (r'^instruction count', 'C', 'E-BODY'),
    (r'^address sequence', 'C', 'E-LAYOUT'),
    (r'^string references', 'C', 'E-DATA'),
    (r'^loop count', 'C', 'E-CFG'),
    (r'^call reference', 'C', 'E-CALL'),
    (r'^call sequence', 'C', 'E-CALL'),
)

PASSES: tuple[PassSpec, ...] = (
    PassSpec('P00', 'manual', ('M',), 'E-MANUAL', 'manual', 'T0'),
    PassSpec('P01', 'import-key', ('A',), 'E-NAME', 'pe', 'T0'),
    PassSpec('P02', 'export-key', ('A',), 'E-NAME', 'pe', 'T0'),
    PassSpec('P03', 'name-exact', ('A', 'C'), 'E-NAME', 'names', 'T0'),
    PassSpec('P04', 'bytes-exact', ('A',), 'E-BODY', 'bytes-or-struct', 'T1'),
    PassSpec('P05', 'masked-exact', ('A',), 'E-BODY', 'bytes-or-struct', 'T1'),
    PassSpec('P06', 'operand-class', ('B',), 'E-BODY', 'bytes-or-struct', 'T2'),
    PassSpec('P07', 'register-agnostic', ('B',), 'E-BODY', 'bytes-or-struct', 'T2'),
    PassSpec('P08', 'mnemonic-seq', ('B',), 'E-BODY', 'bytes-or-struct', 'T2'),
    PassSpec('P09', 'mnemonic-multiset', ('B',), 'E-BODY', 'bytes-or-struct', 'T2'),
    PassSpec('P10', 'md-flowgraph', ('B',), 'E-CFG', 'struct', 'T2'),
    PassSpec('P11', 'md-callgraph', ('B',), 'E-CALL', 'struct', 'T2'),
    PassSpec('P12', 'string-set', ('B',), 'E-DATA', 'struct', 'T3'),
    PassSpec('P13', 'import-callee-set', ('B',), 'E-CALL', 'struct', 'T3'),
    PassSpec('P14', 'const-set', ('B',), 'E-DATA', 'bytes-or-struct', 'T3'),
    PassSpec('P15', 'rehash-exact', ('A', 'B'), 'E-CALL', 'struct', 'T3+'),
    PassSpec('P16', 'ref-vector', ('B', 'C'), 'E-RESID', 'struct', 'T4-T5'),
    PassSpec('P17', 'bb-vote', ('C',), 'E-RESID', 'struct', 'T4-T5'),
    PassSpec('P18', 'layout-gap', ('C',), 'E-LAYOUT', 'struct', 'T4-T5'),
    PassSpec('P19', 'assignment', ('C',), 'E-RESID', 'struct', 'T4-T5'),
)

# Versions of implemented rules; they change `config_digest` (02 s5). S3 added the IR channels C0-C5, DATA-MAP/1,
# the alignment, EH-EQ and the structural proofs.
CHANNEL_VERSIONS: tuple[tuple[str, int], ...] = (
    ('C0', 1), ('C1', 1), ('C2', 1), ('C3', 1), ('C4', 1), ('C4n', 1), ('C5', 1), ('C5t', 1), ('C6', 1), ('C8', 1),
    ('align', 1), ('canon', 1), ('datamap', 1), ('eh-eq', 1))
PROOF_VERSIONS: tuple[tuple[str, int], ...] = (
    ('COS-ADDR/1', 1), ('COS-LAYOUT/1', 1), ('COS-PSEUDO/1', 2), ('UNCH/1', 1))
RZDIFF_META: tuple[str, Tier, EvidenceClass] = ('levenshtein-bytes', 'W', 'E-BODY')

_FAMILY_BY_KIND = {'manual': 'F-MANUAL', 'pe': 'F-PT-PE', 'names': 'F-PT-NAMES'}
_FUNCTION_PREFIX = re.compile(r'^function:\s*')
_SPACES = re.compile(r'\s+')


def normalise_algorithm(text: str) -> str:
    return _SPACES.sub(' ', _FUNCTION_PREFIX.sub('', str(text).strip().lower())).strip()[:STEP_MAX]


@dataclass(frozen=True)
class Registry:
    families: tuple[Family, ...] = FAMILIES
    sources: tuple[SourceSpec, ...] = SOURCES
    ghidriff_types: tuple[tuple[str, Tier, EvidenceClass], ...] = GHIDRIFF_TYPES
    bindiff_steps: tuple[tuple[str, Tier, EvidenceClass], ...] = BINDIFF_STEPS
    rzdiff_meta: tuple[str, Tier, EvidenceClass] = RZDIFF_META
    passes: tuple[PassSpec, ...] = PASSES
    channel_versions: tuple[tuple[str, int], ...] = CHANNEL_VERSIONS
    proof_versions: tuple[tuple[str, int], ...] = PROOF_VERSIONS

    def source(self, source_id: str) -> SourceSpec | None:
        return next((s for s in self.sources if s.id == source_id), None)

    def pass_spec(self, pass_id: str) -> PassSpec | None:
        return next((p for p in self.passes if p.id == pass_id), None)

    def family_of(self, source: str, step: str) -> str | None:
        """Family of an atom by its source and step; None for a source the registry does not know."""
        spec = self.source(source)
        if spec is None:
            return None
        if spec.family is not None:
            return spec.family
        spec_pass = self.pass_spec(str(step).split('-', 1)[0])
        return _FAMILY_BY_KIND.get(spec_pass.family_kind if spec_pass else '', 'F-PT-STRUCT')

    def ghidriff_meta(self, name: str) -> tuple[Tier, EvidenceClass]:
        for known, tier, cls in self.ghidriff_types:
            if known == name:
                return tier, cls
        return 'C', 'E-UNKNOWN'

    def ghidriff_strongest(self, names) -> tuple[str, Tier, EvidenceClass]:
        """The strongest `match_types` entry: highest tier, then registry order; unknown names sort last and the
        smallest one is taken, so the list order of the input never matters."""
        order = {known: i for i, (known, _t, _c) in enumerate(self.ghidriff_types)}
        known = sorted((n for n in set(names) if n in order), key=lambda n: (-TIER_RANK[self.ghidriff_meta(n)[0]],
                                                                            order[n]))
        if known:
            name = known[0]
            return (name, *self.ghidriff_meta(name))
        unknown = sorted(set(names))
        return (str(unknown[0])[:STEP_MAX] if unknown else 'unknown', 'C', 'E-UNKNOWN')

    def bindiff_meta(self, algorithm: str) -> tuple[str, Tier, EvidenceClass]:
        step = normalise_algorithm(algorithm)
        for pattern, tier, cls in self.bindiff_steps:
            if re.search(pattern, step):
                return step, tier, cls
        return step or 'unknown', 'C', 'E-UNKNOWN'

    def digest(self) -> str:
        """`registry_digest` of config_digest: every row that can change a decision."""
        return domain_id('unified-registry', 1, {
            'families': [[f.name, list(f.tags), list(f.joining)] for f in self.families],
            'sources': [[s.id, s.family, s.display, s.unit_caption, list(s.native_labels), s.tooltip_id,
                         s.licence_note] for s in self.sources],
            'ghidriff': [list(row) for row in self.ghidriff_types],
            'bindiff': [list(row) for row in self.bindiff_steps], 'rzdiff': list(self.rzdiff_meta),
            'channels': [list(row) for row in self.channel_versions],
            'proofs': [list(row) for row in self.proof_versions]})

    def pass_table_digest(self) -> str:
        return domain_id('unified-pass-table', 1, [[p.id, p.name, list(p.tiers), p.cls, p.family_kind, p.stage]
                                                   for p in self.passes])


REGISTRY = Registry()
