"""SPEC-31 registry (S0b delivers it; S0a deferred it): families, evidence classes, tier maps, pass table, digests.
Pure data tests; nothing here is live evidence."""
from __future__ import annotations

import dataclasses
import re

import pytest

from patchtrace.calibration.features import family_dependencies
from patchtrace.unified import registry as reg
from patchtrace.unified.contracts import EvidenceClass, SourceId
from patchtrace.unified.registry import REGISTRY, TIER_RANK

CLASSES = {'E-NAME', 'E-BODY', 'E-CFG', 'E-CALL', 'E-DATA', 'E-DECOMP', 'E-LAYOUT', 'E-RESID', 'E-MANUAL', 'E-UNKNOWN'}


def test_family_tags_extend_the_calibration_dependency_table():
    """05 s1.1: the table reproduces calibration.features.family_dependencies for G/B/R and only adds families."""
    deps = family_dependencies('ghidra')
    by_name = {f.name: f for f in REGISTRY.families}
    assert set(deps['G']) == set(by_name['F-GHIDRIFF'].tags)
    assert set(deps['B']) <= set(by_name['F-BINDIFF'].tags)
    assert set(deps['R']) <= set(by_name['F-RZDIFF'].tags) and 'D_rizin' in by_name['F-RZDIFF'].tags
    for family in REGISTRY.families:
        assert set(family.joining) <= set(family.tags) and set(family.tags) <= set(reg.DTAGS)
    assert [f.name for f in REGISTRY.families] == sorted(f.name for f in REGISTRY.families)


def test_family_of_follows_the_source_and_the_pass():
    family_of = REGISTRY.family_of
    assert family_of('ghidriff', 'SymbolsHash') == 'F-GHIDRIFF'
    assert family_of('bindiff', 'name hash matching') == 'F-BINDIFF'
    assert family_of('rz-diff', 'levenshtein-bytes') == 'F-RZDIFF'
    assert family_of('manual', 'manual-correction') == 'F-MANUAL'
    assert family_of('pt-bytes', 'P08-mnemonic-seq') == 'F-PT-BYTES'
    assert family_of('pt-ladder', 'P03-name-exact') == 'F-PT-NAMES'
    assert family_of('pt-ladder', 'P01-import-key') == family_of('pt-ladder', 'P02-export-key') == 'F-PT-PE'
    assert family_of('pt-ladder', 'P08-mnemonic-seq') == family_of('pt-ladder', 'P10-md-flowgraph') == 'F-PT-STRUCT'
    assert family_of('pt-ladder', 'invented-step') == 'F-PT-STRUCT'
    assert family_of('no-such-source', 'x') is None


def test_ghidriff_type_map_follows_05_s12():
    meta = REGISTRY.ghidriff_meta
    assert meta('SymbolsHash') == ('A', 'E-NAME') and meta('ExternalsName') == ('A', 'E-NAME')
    assert meta('ExactBytesFunctionHasher') == ('A', 'E-BODY')
    assert meta('ExactInstructionsFunctionHasher') == ('A', 'E-BODY')
    assert meta('ExactMnemonicsFunctionHasher') == ('B', 'E-BODY') and meta('BulkInstructionHash') == ('B', 'E-BODY')
    assert meta('StringsRefsHasher') == ('B', 'E-DATA') and meta('StrUniqueFuncRefsHasher') == ('B', 'E-DATA')
    assert meta('BSIM') == ('B', 'E-DECOMP') and meta('Decomp Match') == ('B', 'E-DECOMP')
    assert meta('StructuralGraphExactHash') == ('C', 'E-CFG') and meta('SwitchSigHasher') == ('C', 'E-CFG')
    assert meta('SigCallingCalledHasher') == ('C', 'E-CALL') and meta('Implied Match') == ('C', 'E-CALL')
    assert meta('Symbols') == ('C', 'E-UNKNOWN') and meta('') == ('C', 'E-UNKNOWN')  # unknown names never corroborate


def test_ghidriff_strongest_entry_wins_with_registry_order_for_ties():
    strongest = REGISTRY.ghidriff_strongest
    assert strongest(['StructuralGraphHash', 'SymbolsHash', 'BSIM']) == ('SymbolsHash', 'A', 'E-NAME')
    assert strongest(['BSIM', 'ExactMnemonicsFunctionHasher'])[0] == 'ExactMnemonicsFunctionHasher'
    assert strongest(['Nope', 'AlsoNope']) == strongest(['AlsoNope', 'Nope']) == ('AlsoNope', 'C', 'E-UNKNOWN')
    assert strongest([]) == ('unknown', 'C', 'E-UNKNOWN')
    assert strongest(['StrUniqueFuncRefsHasher', 'StringsRefsHasher'])[0] == 'StringsRefsHasher'  # table order


@pytest.mark.parametrize('algorithm, step, tier, cls', [
    ('function: name hash matching', 'name hash matching', 'A', 'E-NAME'),
    ('function: hash matching', 'hash matching', 'A', 'E-BODY'),
    ('function: edges flowgraph MD index', 'edges flowgraph md index', 'A', 'E-CFG'),
    ('function: edges callgraph MD index', 'edges callgraph md index', 'B', 'E-CALL'),
    ('function: MD index matching (flowgraph MD index, top down)',
     'md index matching (flowgraph md index, top down)', 'B', 'E-CFG'),
    ('function: MD index matching (callflowgraph MD index, bottom up)',
     'md index matching (callflowgraph md index, bottom up)', 'B', 'E-CALL'),
    ('function: prime signature matching', 'prime signature matching', 'B', 'E-BODY'),
    ('function: relaxed MD index matching', 'relaxed md index matching', 'C', 'E-CFG'),
    ('function: instruction count matching', 'instruction count matching', 'C', 'E-BODY'),
    ('function: address sequence matching', 'address sequence matching', 'C', 'E-LAYOUT'),
    ('function: string references matching', 'string references matching', 'C', 'E-DATA'),
    ('function: loop count matching', 'loop count matching', 'C', 'E-CFG'),
    ('function: call sequence matching(exact)', 'call sequence matching(exact)', 'C', 'E-CALL'),
    ('function: call reference matching', 'call reference matching', 'C', 'E-CALL'),
    ('function: manual', 'manual', 'C', 'E-UNKNOWN'),
    ('Some Future Step', 'some future step', 'C', 'E-UNKNOWN'),
], ids=[f'b{i}' for i in range(16)])
def test_bindiff_algorithm_tier_map(algorithm, step, tier, cls):
    assert REGISTRY.bindiff_meta(algorithm) == (step, tier, cls)


def test_bindiff_name_hash_is_not_mistaken_for_hash_matching():
    """`hash matching` is a substring of `name hash matching`: the ordered patterns keep them apart (05 s1.2)."""
    assert REGISTRY.bindiff_meta('function: name hash matching')[2] == 'E-NAME'
    assert REGISTRY.bindiff_meta('function:   NAME  Hash   Matching ')[0] == 'name hash matching'


def test_rzdiff_is_tier_w_body_evidence():
    assert REGISTRY.rzdiff_meta == ('levenshtein-bytes', 'W', 'E-BODY')


def test_pass_table_matches_04_s4_and_05_classes():
    passes = {p.id: p for p in REGISTRY.passes}
    assert [p.id for p in REGISTRY.passes] == [f'P{i:02d}' for i in range(20)]
    assert {i: passes[i].tiers[0] for i in ('P00', 'P01', 'P02', 'P03', 'P04', 'P05')} == {
        'P00': 'M', 'P01': 'A', 'P02': 'A', 'P03': 'A', 'P04': 'A', 'P05': 'A'}
    assert {passes[f'P{i:02d}'].tiers for i in range(6, 15)} == {('B',)}
    assert passes['P15'].tiers == ('A', 'B') and passes['P16'].tiers == ('B', 'C')
    assert {passes[i].tiers for i in ('P17', 'P18', 'P19')} == {('C',)}
    classes = {i: passes[i].cls for i in passes}
    assert all(classes[f'P{n:02d}'] == 'E-NAME' for n in (1, 2, 3))
    assert all(classes[f'P{n:02d}'] == 'E-BODY' for n in range(4, 10))
    assert classes['P10'] == 'E-CFG' and {classes[i] for i in ('P11', 'P13', 'P15')} == {'E-CALL'}
    assert {classes[i] for i in ('P12', 'P14')} == {'E-DATA'} and classes['P18'] == 'E-LAYOUT'
    assert {classes[i] for i in ('P16', 'P17', 'P19')} == {'E-RESID'} and classes['P00'] == 'E-MANUAL'
    assert set(classes.values()) <= CLASSES


def test_export_and_name_passes_never_share_a_family_with_each_other_incorrectly():
    """R-17: P02 export names are symbols in Ghidra's table; P02/P03 never corroborate each other (same component)."""
    assert REGISTRY.family_of('pt-ladder', 'P02-export-key') != REGISTRY.family_of('pt-ladder', 'P03-name-exact')
    by_name = {f.name: f for f in REGISTRY.families}
    assert 'D_symbols' in by_name['F-PT-PE'].joining and 'D_symbols' in by_name['F-PT-NAMES'].joining


def test_sources_are_unique_valid_ids_with_tooltip_ids():
    pattern = re.compile(r'^[a-z][a-z0-9-]{1,31}$')
    ids = [s.id for s in REGISTRY.sources]
    assert len(ids) == len(set(ids)) and all(pattern.match(i) for i in ids)
    assert {'ghidriff', 'bindiff', 'rz-diff', 'diaphora', 'manual', 'pt-ladder', 'pt-bytes'} == set(ids)
    for spec in REGISTRY.sources:
        assert spec.tooltip_id == f'unified.source.{spec.id}' and len(spec.native_labels) <= 4
        assert spec.display and spec.unit_caption and spec.licence_note
        assert spec.family is None or spec.family in {f.name for f in REGISTRY.families}
    assert REGISTRY.source('pt-ladder').family is None and REGISTRY.source('nope') is None


def test_registry_text_never_uses_banned_words():
    from patchtrace.secondary.evidence_view import BANNED
    texts = []
    for spec in REGISTRY.sources:
        texts += [spec.display, spec.unit_caption, spec.licence_note, *spec.native_labels]
    for word in BANNED:
        assert not any(word in t.lower() for t in texts), word


def test_digests_are_stable_and_follow_every_row():
    first = REGISTRY.digest()
    assert first == REGISTRY.digest() and re.fullmatch(r'[0-9a-f]{64}', first)
    assert REGISTRY.pass_table_digest() == reg.REGISTRY.pass_table_digest()
    other_source = dataclasses.replace(REGISTRY, sources=REGISTRY.sources[:-1])
    other_pass = dataclasses.replace(REGISTRY, passes=tuple(
        dataclasses.replace(p, tiers=('C',)) if p.id == 'P05' else p for p in REGISTRY.passes))
    other_type = dataclasses.replace(REGISTRY, ghidriff_types=tuple(
        (n, 'C' if n == 'SymbolsHash' else t, c) for n, t, c in REGISTRY.ghidriff_types))
    assert len({first, other_source.digest(), other_type.digest()}) == 3
    assert other_pass.digest() == first  # config_digest (02 s5) carries pass_table_digest separately
    assert other_pass.pass_table_digest() != REGISTRY.pass_table_digest()
    assert other_source.pass_table_digest() == REGISTRY.pass_table_digest()  # sources do not change the pass table


def test_versions_feed_config_digest_inputs():
    assert dict(REGISTRY.channel_versions)['C6'] >= 1 and dict(REGISTRY.proof_versions)['COS-PSEUDO/1'] >= 1
    assert set(dict(REGISTRY.proof_versions)) <= {'UNCH/1', 'COS-ADDR/1', 'COS-LAYOUT/1', 'COS-PSEUDO/1'}


def test_tier_rank_orders_m_a_b_c_w():
    assert sorted(TIER_RANK, key=TIER_RANK.get, reverse=True) == ['M', 'A', 'B', 'C', 'W']


def test_contract_literals_cover_the_registry_vocabulary():
    from typing import get_args
    assert set(get_args(EvidenceClass)) == CLASSES
    assert SourceId is not None
