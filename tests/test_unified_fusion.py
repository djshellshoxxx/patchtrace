"""SPEC-31 S0b fusion (05 s1): independence components AND evidence classes, no averaging, conflicts preserved,
missing is unknown. Synthetic atoms only; nothing here is live evidence."""
from __future__ import annotations

import dataclasses
import json
import random

import pytest
from unified_s0_fixtures import NEW_SHA, OLD_SHA

from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion import arbiter
from patchtrace.unified.fusion.components import build_components, components_for
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.registry import FAMILIES, REGISTRY, Family, SourceSpec
from patchtrace.unified.sources import NodeRecord, SourceGroup


def atom(source, step, tier, cls, o, n, card='1:1', ref=None, native=()):
    return Atom(source=source, step=step, tier=tier, cardinality=card, cls=cls, older_rva=o, newer_rva=n, ref=ref,
                native=native)


def ghid(o, n, step='SymbolsHash', tier='A', cls='E-NAME', ref='m1'):
    return atom('ghidriff', step, tier, cls, o, n, ref=ref)


def bindiff(o, n, step='name hash matching', tier='A', cls='E-NAME'):
    return atom('bindiff', step, tier, cls, o, n, ref='bd')


def rzdiff(o, n, card='non-exclusive'):
    return atom('rz-diff', 'levenshtein-bytes', 'W', 'E-BODY', o, n, card=card, ref='rz')


def ptbytes(o, n, step='P08-mnemonic-seq', tier='B', cls='E-BODY'):
    return atom('pt-bytes', step, tier, cls, o, n)


def manual(o, n):
    return atom('manual', 'manual-correction', 'M', 'E-MANUAL', o, n, ref='mm')


def decide(atoms, groups=(), **kw):
    return arbiter.decide(list(atoms), list(groups), {}, **kw)


def only(rows, older=None, newer=None):
    found = [r for r in rows if (older is None or older in r.older) and (newer is None or newer in r.newer)]
    assert len(found) == 1, found
    return found[0]


# --- components ---------------------------------------------------------------------------------------------------

def test_components_reproduce_the_documented_table():
    comps = components_for(REGISTRY)
    assert comps.members == {'K0': ('F-MANUAL',),
                             'K1': ('F-BINDIFF', 'F-DIAPHORA', 'F-GHIDRIFF', 'F-PT-NAMES', 'F-PT-PE', 'F-PT-STRUCT'),
                             'K2': ('F-PT-BYTES', 'F-RZDIFF')}
    assert comps.of(REGISTRY, 'ghidriff', 'SymbolsHash') == comps.of(REGISTRY, 'bindiff', 'x') == 'K1'
    assert comps.of(REGISTRY, 'pt-bytes', 'P05-masked-exact') == comps.of(REGISTRY, 'rz-diff', 'y') == 'K2'
    assert comps.of(REGISTRY, 'manual', 'manual-correction') == 'K0'
    with pytest.raises(UnifiedError) as info:
        comps.of(REGISTRY, 'mystery', 'step')
    assert info.value.code == 'PT-UNIFIED-INTERNAL' and info.value.reason == 'unknown-source'


def test_components_are_deterministic_for_any_family_order():
    shuffled = tuple(random.Random(3).sample(FAMILIES, len(FAMILIES)))
    assert build_components(shuffled) == build_components(FAMILIES)


# --- decisions ------------------------------------------------------------------------------------------------------

def test_a_tier_a_atom_alone_makes_a_matched_row_with_its_support():
    [row] = decide([ghid(0x1000, 0x1080)])
    assert row.decision == 'matched' and (row.older, row.newer) == ((0x1000,), (0x1080,))
    assert [(s.component, s.tier) for s in row.support] == [('K1', 'A')] and row.contest is None
    assert row.atoms[row.support[0].atom_index].source == 'ghidriff' and row.ghidriff_match_id == 'm1'


def test_two_ghidra_derived_sources_are_one_component():
    """Ghidriff and BinDiff share D_symbols/D_callgraph: two tier-B atoms of different classes are ONE opinion."""
    rows = decide([ghid(0x1000, 0x1080, 'StringsRefsHasher', 'B', 'E-DATA'),
                   bindiff(0x1000, 0x1080, 'prime signature matching', 'B', 'E-BODY')])
    assert only(rows).decision == 'tentative'


def test_same_class_never_corroborates_across_components():
    """R-05: Ghidriff ExactMnemonics (K1) and pt-bytes P08 (K2) are the same key over the same decoding."""
    same = decide([ghid(0x1000, 0x1080, 'ExactMnemonicsFunctionHasher', 'B', 'E-BODY'), ptbytes(0x1000, 0x1080)])
    assert only(same).decision == 'tentative'
    different = decide([ghid(0x1000, 0x1080, 'StringsRefsHasher', 'B', 'E-DATA'), ptbytes(0x1000, 0x1080)])
    row = only(different)
    assert row.decision == 'matched' and {s.component for s in row.support} == {'K1', 'K2'}


def test_unknown_class_never_corroborates():
    rows = decide([ghid(0x1000, 0x1080, 'Weird', 'B', 'E-UNKNOWN'), ptbytes(0x1000, 0x1080)])
    assert only(rows).decision == 'tentative'


@pytest.mark.parametrize('atoms, expected', [
    ([rzdiff(0x1000, 0x1080)], 'candidate'),
    ([ghid(0x1000, 0x1080, 'StructuralGraphHash', 'C', 'E-CFG')], 'candidate'),
    ([ghid(0x1000, 0x1080, 'ExactMnemonicsFunctionHasher', 'B', 'E-BODY')], 'tentative'),
    ([ghid(0x1000, 0x1080, 'SymbolsHash', 'A', 'E-NAME')], 'matched'),
    ([manual(0x1000, 0x1080)], 'matched'),
], ids=['w', 'c', 'b', 'a', 'm'])
def test_base_decisions_follow_the_best_evidence(atoms, expected):
    assert only(decide(atoms)).decision == expected


def test_absent_source_is_not_a_vote():
    alone = only(decide([ghid(0x1000, 0x1080)]))
    with_unrelated = decide([ghid(0x1000, 0x1080), bindiff(0x1100, 0x1180)])
    same = only(with_unrelated, older=0x1000)
    assert (same.decision, same.support, same.contest, same.hints) == (alone.decision, alone.support, None, ())
    assert only(with_unrelated, older=0x1100).support[0].component == 'K1'  # nothing is borrowed across rows


def test_weak_contest_still_contested():
    rows = decide([ghid(0x1000, 0x1080), rzdiff(0x1010, 0x1080)])
    row = only(rows, older=0x1000)
    assert row.decision == 'contested' and row.contest.strength == 'weak'
    assert 'uncontested:matched' in row.hints
    assert [row.atoms[i].source for i in row.contest.against] == ['rz-diff']
    loser = only(rows, older=0x1010)
    assert loser.decision == 'older-only' and loser.newer == () and 'partner-taken' in loser.hints


def test_strong_contest_when_an_opposing_atom_is_tier_a_b_or_m():
    rows = decide([ghid(0x1000, 0x1080), bindiff(0x1000, 0x1100)])
    row = only(rows, older=0x1000)
    assert (row.decision, row.contest.strength) == ('contested', 'strong') and row.newer == (0x1080,)
    assert only(rows, newer=0x1100).decision == 'newer-only'


def test_manual_row_accepted_with_contest_shown():
    rows = decide([manual(0x1000, 0x1100), ghid(0x1000, 0x1080)])
    row = only(rows, older=0x1000)
    assert row.decision == 'matched' and row.newer == (0x1100,) and row.contest.strength == 'strong'
    assert [row.atoms[i].source for i in row.contest.against] == ['ghidriff']
    assert row.hints == () and row.support[0].tier == 'M'
    assert only(rows, newer=0x1080).decision == 'newer-only'


def test_greedy_matching_keeps_every_against_atom():
    # A1-B1 (tier A, chosen), A1-B2 (weak), A2-B2 (tier B, chosen): the weak edge touches BOTH chosen rows
    rows = decide([ghid(0x1000, 0x1080), rzdiff(0x1000, 0x1100),
                   ghid(0x1010, 0x1100, 'ExactMnemonicsFunctionHasher', 'B', 'E-BODY', ref='m2')])
    first, second = only(rows, older=0x1000), only(rows, older=0x1010)
    assert first.decision == second.decision == 'contested'
    assert [first.atoms[i].source for i in first.contest.against] == ['rz-diff']
    assert [second.atoms[i].source for i in second.contest.against] == ['rz-diff']
    assert first.contest.strength == second.contest.strength == 'weak'


def test_one_sided_observation_never_contests():
    rows = decide([ghid(0x1000, 0x1080), atom('rz-diff', 'levenshtein-bytes', 'W', 'E-BODY', 0x1000, None, ref='rz')])
    [row] = rows
    assert row.decision == 'matched' and row.contest is None and 'one-sided-by:rz-diff' in row.hints
    assert any(a.newer_rva is None for a in row.atoms)  # the observation stays in the audit trail


def test_one_sided_rows_for_unpaired_nodes():
    rows = decide([atom('ghidriff', 'added', 'W', 'E-UNKNOWN', None, 0x1200),
                   atom('ghidriff', 'deleted', 'W', 'E-UNKNOWN', 0x1400, None)])
    assert sorted((r.decision, r.older, r.newer) for r in rows) == [
        ('newer-only', (), (0x1200,)), ('older-only', (0x1400,), ())]


def test_fusion_never_emits_numbers():
    rows = decide([ghid(0x1000, 0x1080), rzdiff(0x1010, 0x1080), bindiff(0x1100, 0x1180),
                   ghid(0x1200, 0x1280, 'ExactMnemonicsFunctionHasher', 'B', 'E-BODY')])
    matches = [arbiter.to_match(r, {}, OLD_SHA, NEW_SHA) for r in rows]
    for match in matches:
        text = json.dumps(match.model_dump(mode='json'))
        assert not any(isinstance(v, float) for v in _walk(json.loads(text)))


def _walk(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v)
    else:
        yield value


def test_rzdiff_similarity_never_read_by_rules():
    """Changing every upstream display text changes no decision, support or contest."""
    base = [ghid(0x1000, 0x1080), rzdiff(0x1010, 0x1080), bindiff(0x1100, 0x1180)]
    mutated = [a.model_copy(update={'native': (('similarity', '0.999'), ('confidence', '0.001'))}) for a in base]

    def shape(rows):
        return [(r.older, r.newer, r.decision, r.support, r.contest, r.hints) for r in rows]
    assert shape(decide(base)) == shape(decide(mutated))


def test_fusion_output_does_not_depend_on_input_order():
    rng = random.Random(11)
    atoms = [ghid(0x1000 + 16 * i, 0x1800 + 16 * i, ref=f'm{i}') for i in range(10)]
    atoms += [rzdiff(0x1000 + 16 * i, 0x1810 + 16 * i) for i in range(10)]
    atoms += [bindiff(0x1000, 0x1ff0), atom('ghidriff', 'added', 'W', 'E-UNKNOWN', None, 0x1ffe)]
    reference = decide(atoms)
    for _ in range(5):
        shuffled = atoms[:]
        rng.shuffle(shuffled)
        assert decide(shuffled) == reference


def test_rows_are_ordered_by_older_then_newer_rva_then_row_id():
    rows = decide([ghid(0x1100, 0x1180), ghid(0x1000, 0x1080), atom('ghidriff', 'added', 'W', 'E-UNKNOWN', None, 0x1010),
                   atom('ghidriff', 'deleted', 'W', 'E-UNKNOWN', 0x1050, None)])
    assert [(min(r.older, default=None), min(r.newer, default=None)) for r in rows] == [
        (0x1000, 0x1080), (0x1050, None), (0x1100, 0x1180), (None, 0x1010)]


# --- groups and manual claims -----------------------------------------------------------------------------------------

def group(kind='ghidriff-1n', older=(0x1000,), newer=(0x1080, 0x1100), decision='ambiguous', source='ghidriff'):
    atoms = tuple(atom(source, 'SymbolsHash' if source == 'ghidriff' else 'manual-correction',
                       'A' if source == 'ghidriff' else 'M', 'E-NAME' if source == 'ghidriff' else 'E-MANUAL',
                       o, n, card='1:N') for o in older for n in newer)
    return SourceGroup(kind=kind, source=source, older=older, newer=newer, decision=decision, reason='r', atoms=atoms)


def test_a_group_is_one_ambiguous_row_and_absorbs_other_sources_edges():
    rows = decide([bindiff(0x1000, 0x1080), bindiff(0x1200, 0x1100)], [group()])
    row = only(rows, older=0x1000)
    assert row.decision == 'ambiguous' and row.older == (0x1000,) and row.newer == (0x1080, 0x1100)
    assert row.support == () and row.contest is None
    assert {a.source for a in row.atoms} == {'ghidriff', 'bindiff'} and len(row.atoms) == 4
    orphan = only(rows, older=0x1200)  # its partner 0x1100 sits in the group: it keeps a row of its own
    assert orphan.decision == 'older-only' and 'lost-to-group' in orphan.hints and 'proposal-lost:1' in orphan.hints


def test_overlapping_groups_of_different_sources_are_merged():
    rows = decide([], [group(older=(0x1000,), newer=(0x1080, 0x1100)),
                       group(kind='other', older=(0x1010,), newer=(0x1100,), source='ghidriff')])
    [row] = rows
    assert row.older == (0x1000, 0x1010) and row.newer == (0x1080, 0x1100) and row.decision == 'ambiguous'


def test_manual_group_is_matched_and_beats_engine_groups():
    manual_group = group('manual-split', (0x1000,), (0x1080, 0x1100), 'matched', 'manual')
    engine = group('ghidriff-1n', (0x1000, 0x1010), (0x1100, 0x1200))
    rows = decide([], [engine, manual_group])
    claimed = only(rows, older=0x1000)
    assert claimed.decision == 'matched' and claimed.newer == (0x1080, 0x1100) and 'manual-group:split' in claimed.hints
    rest = [r for r in rows if r is not claimed]
    assert all(r.decision != 'ambiguous' or 0x1000 not in r.older for r in rest)


def test_two_manual_claims_on_one_function_are_an_input_error():
    with pytest.raises(UnifiedError) as info:
        decide([manual(0x1000, 0x1080), manual(0x1000, 0x1100)])
    assert info.value.code == 'PT-UNIFIED-INPUT' and info.value.reason == 'manual-overlap'


def test_manual_one_sided_declaration_claims_the_function():
    declared = atom('manual', 'manual-correction', 'M', 'E-MANUAL', 0x1000, None, ref='mm')
    rows = decide([declared, ghid(0x1000, 0x1080)])
    row = only(rows, older=0x1000)
    assert row.decision == 'older-only' and 'manual-one-sided' in row.hints
    assert {a.source for a in row.atoms} == {'manual', 'ghidriff'}
    assert only(rows, newer=0x1080).decision == 'newer-only'


# --- caps and registry extension ----------------------------------------------------------------------------------------

def test_atom_cap_keeps_chosen_atoms_and_one_against_atom():
    many = [atom('ghidriff', 'SymbolsHash', 'A', 'E-NAME', 0x1000, 0x1080, ref=f'm{i}') for i in range(70)]
    rows = decide([*many, rzdiff(0x1010, 0x1080)])
    row = only(rows, older=0x1000)
    assert len(row.atoms) == 64 and row.contest is not None and any(h.startswith('atoms-omitted:') for h in row.hints)
    assert row.atoms[row.contest.against[0]].source == 'rz-diff'
    assert row.atoms[row.support[0].atom_index].source == 'ghidriff'


def test_new_source_needs_only_adapter_and_registry_entry():
    registry = dataclasses.replace(
        REGISTRY, families=(*FAMILIES, Family('F-NEWTOOL', ('D_new',), ('D_new',))),
        sources=(*REGISTRY.sources, SourceSpec('newtool', 'F-NEWTOOL', 'New tool', 'score text', (),
                                               'unified.source.newtool', 'external process')))
    extra = atom('newtool', 'rule-1', 'B', 'E-BODY', 0x1000, 0x1080)
    with_new = decide([ghid(0x1000, 0x1080, 'StringsRefsHasher', 'B', 'E-DATA'), extra], registry=registry)
    row = only(with_new)
    assert row.decision == 'matched' and {s.component for s in row.support} == {'K1', 'K2'}
    with pytest.raises(UnifiedError):  # the default registry does not know the source
        decide([extra])


def test_to_match_builds_validated_rows_for_every_shape():
    atoms = [ghid(0x1000, 0x1080), rzdiff(0x1010, 0x1080), manual(0x1100, 0x1180), ghid(0x1100, 0x1200),
             bindiff(0x1300, 0x1380), atom('ghidriff', 'added', 'W', 'E-UNKNOWN', None, 0x1400)]
    rows = decide(atoms, [group(older=(0x1500,), newer=(0x1580, 0x1600))])
    nodes = {('older', 0x1000): arbiter.NodeInfo('f', 'function')}
    matches = [arbiter.to_match(r, nodes, OLD_SHA, NEW_SHA) for r in rows]
    assert {m.decision for m in matches} >= {'contested', 'matched', 'newer-only', 'older-only', 'ambiguous'}
    assert next(m for m in matches if m.older and m.older[0].rva == 0x1000).older[0].name == 'f'
    assert all(m.materiality == 'unknown' or m.materiality == 'not-applicable' for m in matches)


def test_node_records_merge_with_the_first_source_winning():
    merged = arbiter.merge_nodes([[NodeRecord('older', 1, 'from-ghidriff'), NodeRecord('newer', 2, None)],
                                  [NodeRecord('older', 1, 'from-bindiff'), NodeRecord('newer', 2, 'only-here')]])
    assert merged[('older', 1)].name == 'from-ghidriff' and merged[('newer', 2)].name == 'only-here'


# --- U7-05: BinDiff stub rows (basicblocks = 0) ---------------------------------------------------------------------

def _bindiff_atoms(rows):
    from unified_s0_fixtures import addr_map, bindiff_set, inputs, loaded

    from patchtrace.unified.limits import Budget
    from patchtrace.unified.sources.secondary import SecondaryAdapter
    out = SecondaryAdapter().atoms(inputs([], secondary=[loaded(bindiff_set(rows), 'bd-entry')]), addr_map(), Budget())
    return list(out.atoms), out


def _stub_and_real():
    from unified_s0_fixtures import bd
    stub, real = bd(0x1000, 0x1080), bd(0x1100, 0x1180)
    return stub.model_copy(update={'basicblocks': 0}), real.model_copy(update={'basicblocks': 7})


@pytest.mark.parametrize('blocks', [0, None, 7], ids=['stub', 'unknown', 'real'])
def test_bindiff_stub_row_alone_is_never_matched(blocks):
    from unified_s0_fixtures import bd
    atoms, out = _bindiff_atoms([bd(0x1000, 0x1080).model_copy(update={'basicblocks': blocks})])
    row = only(decide(atoms), 0x1000, 0x1080)
    assert row.decision == ('candidate' if blocks == 0 else 'matched')
    if blocks == 0:
        assert dict(atoms[0].native)['demoted'] == 'stub-basicblocks-0'
        assert atoms[0].source == 'bindiff' and atoms[0].ref == 'bd-entry' and atoms[0].tier == 'C'
        assert 'bindiff-stub-rows-demoted:1' in out.limitations


def test_bindiff_non_stub_rows_keep_their_tier_and_old_rows_still_parse():
    from patchtrace.secondary.contracts import SecondaryMatch
    stub, real = _stub_and_real()
    atoms, out = _bindiff_atoms([stub, real])
    assert [(a.older_rva, a.tier) for a in atoms] == [(0x1000, 'C'), (0x1100, 'A')]
    assert 'bindiff-stub-rows-not-identified' not in out.limitations
    legacy = json.loads(real.model_dump_json())
    del legacy['basicblocks']
    assert SecondaryMatch.model_validate_json(json.dumps(legacy)).basicblocks is None


def test_stub_row_with_an_independent_agreeing_source_follows_the_corroboration_rules():
    stub, _ = _stub_and_real()
    atoms, _ = _bindiff_atoms([stub])
    # a stub (tier C) adds no usable class, so one agreeing tier-B source stays tentative
    assert only(decide([*atoms, ptbytes(0x1000, 0x1080)]), 0x1000, 0x1080).decision == 'tentative'
    # an independent tier-A source decides alone, exactly as without the stub
    assert only(decide([*atoms, ghid(0x1000, 0x1080)]), 0x1000, 0x1080).decision == 'matched'
