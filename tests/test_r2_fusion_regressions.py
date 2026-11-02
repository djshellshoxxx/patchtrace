"""R2 synthetic fusion regressions: provenance ordering and accepted-match witnesses.

These are manufactured evidence records, not native engine accuracy measurements.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from itertools import combinations
from pathlib import Path

import pytest

from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion.arbiter import decide, to_match
from patchtrace.unified.fusion.components import components_for
from patchtrace.unified.read_text import reason_text
from patchtrace.unified.registry import REGISTRY
from patchtrace.unified.sources import SourceGroup


def _atom(source='ghidriff', step='ExactMnemonicsFunctionHasher', cls='E-BODY', *, ref=None, native=()):
    return Atom(source=source, step=step, tier='B', cardinality='1:1', cls=cls,
                older_rva=0x1000, newer_rva=0x1800, ref=ref, native=native)


def _corroborates(atoms):
    components = components_for(REGISTRY)
    return any(components.of(REGISTRY, a.source, a.step) != components.of(REGISTRY, b.source, b.step)
               and a.cls != b.cls and 'E-UNKNOWN' not in (a.cls, b.cls)
               and a.tier in ('A', 'B') and b.tier in ('A', 'B')
               for a, b in combinations(atoms, 2))


def _accepted_with_many_correlated_observations():
    return [*(_atom(ref=f'body-{i:03}') for i in range(70)),
            _atom(step='StringsRefsHasher', cls='E-DATA', ref='data-witness'),
            _atom('pt-bytes', 'P08-mnemonic-seq', ref='body-witness')]


def test_native_display_ties_have_identical_serialization_across_hash_seeds():
    """Equal semantic sort keys must not expose randomized set ordering in persisted atoms."""
    code = '''
import json
from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion.arbiter import decide
atoms = [Atom(source='ghidriff', step='SymbolsHash', tier='A', cardinality='1:1',
              cls='E-NAME', older_rva=0x1000, newer_rva=0x1800, ref='same',
              native=(('ratio', str(i)),)) for i in range(8)]
row = decide(atoms, [])[0]
print(json.dumps([a.model_dump(mode='json') for a in row.atoms], sort_keys=True))
'''
    outputs = [subprocess.check_output([sys.executable, '-c', code], text=True,
                                      env={**os.environ, 'PYTHONHASHSEED': str(seed),
                                           'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')})
               for seed in range(4)]
    assert len(set(outputs)) == 1


def test_atom_cap_retains_the_cross_class_witness_of_an_accepted_match():
    [row] = decide(_accepted_with_many_correlated_observations(), [])
    assert row.decision == 'matched'
    assert len(row.atoms) == 64
    assert 'atoms-omitted:8' in row.hints
    assert _corroborates(row.atoms), 'persisted matched row lost the evidence class that justified acceptance'


def test_support_indexes_identify_the_actual_corroborating_classes():
    [row] = decide(_accepted_with_many_correlated_observations(), [])
    assert row.decision == 'matched'
    assert _corroborates([row.atoms[s.atom_index] for s in row.support])


def test_cap_preserves_acceptance_witness_and_strong_contest_together():
    opposing = _atom('bindiff', 'prime signature matching', ref='opposition').model_copy(
        update={'newer_rva': 0x1900})
    rows = decide([*_accepted_with_many_correlated_observations(), opposing], [])
    row = next(r for r in rows if r.older == (0x1000,))
    assert row.decision == 'contested' and row.contest.strength == 'strong'
    assert 'uncontested:matched' in row.hints
    assert opposing in [row.atoms[i] for i in row.contest.against]
    assert _corroborates([row.atoms[s.atom_index] for s in row.support])


def test_insufficient_atom_cap_rejects_instead_of_erasing_the_contest():
    from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError

    evidence = [_atom(step='StringsRefsHasher', cls='E-DATA'), _atom('pt-bytes', 'P08-mnemonic-seq'),
                _atom('bindiff', 'prime signature matching').model_copy(update={'newer_rva': 0x1900})]
    with pytest.raises(UnifiedError) as error:
        decide(evidence, [], limits=replace(DEFAULT_LIMITS, l39_atoms_per_row=2))
    assert error.value.code == 'PT-UNIFIED-LIMIT' and error.value.reason == 'atoms-cap'


@pytest.mark.parametrize('kind,decision', [('split', 'matched'), ('merged', 'matched'), ('ambiguous', 'ambiguous')])
def test_manual_group_explanation_identifies_the_analyst_decision(kind, decision):
    older, newer = ((0x1000,), (0x1800, 0x1900)) if kind != 'merged' else ((0x1000, 0x1100), (0x1800,))
    atoms = tuple(_atom('manual', 'manual-correction', 'E-MANUAL').model_copy(
        update={'tier': 'M', 'older_rva': o, 'newer_rva': n, 'cardinality': 'N:M'})
        for o in older for n in newer)
    group = SourceGroup(kind=f'manual-{kind}', source='manual', older=older, newer=newer,
                        decision=decision, reason=f'manual-{kind}', atoms=atoms)
    [row] = decide([], [group])
    match = to_match(row, {}, 'a' * 64, 'b' * 64)
    assert row.support == ()
    assert row.decision == decision
    reason = reason_text(match)
    assert 'analyst correction' in reason.lower() and kind in reason
    assert 'tier B' not in reason


def test_inferred_ambiguous_group_does_not_claim_an_analyst_decision():
    group = SourceGroup(kind='ghidriff-1n', source='ghidriff', older=(0x1000,), newer=(0x1800, 0x1900),
                        decision='ambiguous', reason='one-to-many', atoms=(_atom(),))
    [row] = decide([], [group])
    reason = reason_text(to_match(row, {}, 'a' * 64, 'b' * 64))
    assert 'analyst correction' not in reason.lower()


@pytest.fixture
def leftover_readers(tmp_path):
    from unified_facts_builder import NEW_SHA, OLD_SHA, build_reader, function

    older = build_reader(tmp_path, 'leftover-old', [function(0x1000, [('ret',)], name='only_old')], sha=OLD_SHA)
    newer = build_reader(tmp_path, 'leftover-new', [function(0x1800, [('int3',)], name='only_new')], sha=NEW_SHA)
    try:
        yield older, newer
    finally:
        older.close()
        newer.close()


def _leftover_corr(older, newer, *, partial=False):
    from patchtrace.unified.ladder.types import Correspondence, Leftover

    reason = 'unfinished' if partial else 'no-unique-evidence'
    return Correspondence(pairs=(), groups=(), older_only=(Leftover(0, reason, ('fixture-hint',)),),
                          newer_only=(Leftover(0, reason),), status='partial' if partial else 'complete',
                          stop_reason='deadline' if partial else None, passes_completed=(), limits_hit=(), stats=(),
                          older_rva=tuple(older.functions.rva), newer_rva=tuple(newer.functions.rva))


@pytest.mark.parametrize('partial', [False, True])
def test_ladder_leftovers_are_source_specific_unknown_observations(leftover_readers, partial):
    from patchtrace.unified.sources.ladder import ladder_output

    older, newer = leftover_readers
    output = ladder_output(_leftover_corr(older, newer, partial=partial), older, newer)
    assert {(a.older_rva, a.newer_rva) for a in output.atoms} == {(0x1000, None), (None, 0x1800)}
    assert {(n.side, n.rva, n.name) for n in output.nodes} == {
        ('older', 0x1000, 'only_old'), ('newer', 0x1800, 'only_new')}
    assert all(a.source == 'pt-ladder' and a.tier == 'W' and a.cls == 'E-UNKNOWN' for a in output.atoms)
    assert all(REGISTRY.family_of(a.source, a.step) == 'F-PT-STRUCT' for a in output.atoms)
    assert any('fixture-hint' in text for a in output.atoms for _label, text in a.native)
    if partial:
        assert 'ladder-partial:deadline' in output.limitations
        assert all('unfinished' in a.step for a in output.atoms)
    rows = decide(output.atoms, [])
    assert {r.decision for r in rows} == {'older-only', 'newer-only'}
    assert all(r.support == () and r.contest is None for r in rows)


def test_ladder_leftover_observation_does_not_oppose_another_sources_pair(leftover_readers):
    from patchtrace.unified.sources.ladder import ladder_output

    older, newer = leftover_readers
    output = ladder_output(_leftover_corr(older, newer), older, newer)
    pair = _atom().model_copy(update={'tier': 'A'})
    [row] = decide([pair, *output.atoms], [])
    assert row.decision == 'matched' and row.contest is None
    assert 'one-sided-by:pt-ladder' in row.hints
    assert all(a in row.atoms for a in output.atoms)


@pytest.mark.parametrize('fid', [-1, 1])
def test_ladder_leftover_fid_outside_verified_reader_is_rejected(leftover_readers, fid):
    from patchtrace.unified.ladder.types import Leftover
    from patchtrace.unified.limits import UnifiedError
    from patchtrace.unified.sources.ladder import ladder_output

    older, newer = leftover_readers
    corr = replace(_leftover_corr(older, newer), older_only=(Leftover(fid, 'no-unique-evidence'),))
    with pytest.raises(UnifiedError):
        ladder_output(corr, older, newer)


def test_ladder_leftover_foreign_rva_is_rejected(leftover_readers):
    from patchtrace.unified.limits import UnifiedError
    from patchtrace.unified.sources.ladder import ladder_output

    older, newer = leftover_readers
    corr = replace(_leftover_corr(older, newer), older_rva=(0x1900,))
    with pytest.raises(UnifiedError):
        ladder_output(corr, older, newer)


def test_ir_only_unmatched_functions_survive_compute_and_verified_persistence(tmp_path, leftover_readers):
    from unified_facts_builder import NEW_SHA, OLD_SHA

    from patchtrace.unified import keys, store
    from patchtrace.unified.addressing import AddressMap, PeLayout
    from patchtrace.unified.compute import IrInputs, compute_result
    from patchtrace.unified.sources import GhidriffRun, RawGhidriff, SourceInputs

    older, newer = leftover_readers
    inputs = SourceInputs(older_sha256=OLD_SHA, newer_sha256=NEW_SHA,
                          run=GhidriffRun('leftover-run', '1', RawGhidriff('ok', {}, 'c' * 64)), matches=())
    addr = AddressMap(PeLayout(older.manifest.image_base, older.manifest.size_of_image),
                      PeLayout(newer.manifest.image_base, newer.manifest.size_of_image))
    directory = tmp_path / 'persisted-leftovers'
    directory.mkdir()
    manifest = compute_result(inputs, addr, result_dir=directory, sources=('pt-ladder',),
                              ir=IrInputs(older, newer, (), ()), residual=False,
                              created_utc='2026-10-30T00:00:00+00:00')
    store.verify_result_dir(directory)
    rows = list(store.read_rows(directory, manifest))
    assert len(rows) == 2
    assert {(r.decision, tuple(s.rva for s in r.older), tuple(s.rva for s in r.newer)) for r in rows} == {
        ('older-only', (0x1000,), ()), ('newer-only', (), (0x1800,))}
    assert all(r.materiality == 'not-applicable' and r.support == () and r.contest is None for r in rows)
    assert all(r.row_id == keys.row_id(OLD_SHA, NEW_SHA, [s.rva for s in r.older], [s.rva for s in r.newer])
               for r in rows)
    assert all(a.source == 'pt-ladder' and a.cls == 'E-UNKNOWN' and a.tier == 'W' for r in rows for a in r.atoms)
    assert manifest.ghidriff_run_id == 'leftover-run'
    assert list(store.read_facts(directory, manifest)) == []
