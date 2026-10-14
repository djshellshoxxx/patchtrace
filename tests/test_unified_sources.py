"""SPEC-31 S0b sources (06 s9, s10): Ghidriff, BinDiff/rz-diff and manual adapters over loaded, synthetic inputs."""
from __future__ import annotations

import random

import pytest
from unified_s0_fixtures import (
    BASE,
    NEW_SHA,
    OLD_SHA,
    RAW_SHA,
    addr_map,
    alternative,
    bd,
    bindiff_set,
    func,
    inputs,
    loaded,
    match,
    raw_ok,
    rz,
    rzdiff_set,
    va,
)

from patchtrace.unified import keys
from patchtrace.unified.contracts import SourceRef
from patchtrace.unified.limits import Budget
from patchtrace.unified.sources import RawGhidriff, SourceAdapter
from patchtrace.unified.sources.ghidriff import GhidriffAdapter
from patchtrace.unified.sources.manual import ManualAdapter, manual_digest_of
from patchtrace.unified.sources.secondary import SecondaryAdapter


def run(adapter, data):
    return adapter.atoms(data, addr_map(), Budget())


def pairs(out):
    return {(a.older_rva, a.newer_rva): a for a in out.atoms if a.older_rva is not None and a.newer_rva is not None}


def one_sided(out):
    return sorted(((a.step, a.older_rva, a.newer_rva) for a in out.atoms if None in (a.older_rva, a.newer_rva)),
                  key=lambda t: (t[0], -1 if t[1] is None else t[1], -1 if t[2] is None else t[2]))


# --- Ghidriff -----------------------------------------------------------------------------------------------------

def test_adapters_follow_the_source_protocol():
    for adapter in (GhidriffAdapter(), SecondaryAdapter(), ManualAdapter()):
        assert isinstance(adapter, SourceAdapter) and adapter.available(inputs()).state in ('ok', 'missing', 'stale')


def test_ghidriff_adapter_maps_modified_unchanged_added_deleted():
    modified = match('m1', 'modified', [func('read_item', 0x1000, ratio='0.58')], [func('read_item', 0x1080)],
                     types=['SymbolsHash', 'StructuralGraphHash'])
    added = match('m2', 'added', newer=[func('new_fn', 0x1200)])
    removed = match('m3', 'removed', older=[func('old_fn', 0x1400)])
    table = {va(0x1000): [[va(0x1080), ['SymbolsHash']]], va(0x1600): [[va(0x1700), ['ExactBytesFunctionHasher']]]}
    out = run(GhidriffAdapter(), inputs([modified, added, removed], raw_ok(table)))
    found = pairs(out)
    assert set(found) == {(0x1000, 0x1080), (0x1600, 0x1700)}
    a = found[(0x1000, 0x1080)]
    assert (a.source, a.step, a.tier, a.cls, a.cardinality, a.ref) == ('ghidriff', 'SymbolsHash', 'A', 'E-NAME',
                                                                       '1:1', 'm1')
    assert dict(a.native) == {'ratio': '0.58', 'match types': 'StructuralGraphHash, SymbolsHash'}
    b = found[(0x1600, 0x1700)]
    assert (b.step, b.tier, b.cls, b.ref) == ('ExactBytesFunctionHasher', 'A', 'E-BODY', 'raw:1600')
    assert one_sided(out) == [('added', None, 0x1200), ('deleted', 0x1400, None)]
    assert {a.tier for a in out.atoms if None in (a.older_rva, a.newer_rva)} == {'W'}
    assert out.groups == () and out.limitations == ()
    assert out.source_refs == (SourceRef(source='ghidriff', entry_id='run-1', file_sha256=RAW_SHA, version='1'),)
    names = {(n.side, n.rva): n.name for n in out.nodes}
    assert names[('older', 0x1000)] == 'read_item' and names[('newer', 0x1200)] == 'new_fn'


def test_ghidriff_one_to_many_becomes_group_not_cross_product():
    table = {va(0x1000): [[va(0x1080), ['SymbolsHash']], [va(0x1100), ['StructuralGraphHash']]],
             va(0x1010): [[va(0x1100), ['SymbolsHash']]], va(0x1600): [[va(0x1700), ['SymbolsHash']]]}
    out = run(GhidriffAdapter(), inputs([], raw_ok(table)))
    assert set(pairs(out)) == {(0x1600, 0x1700)}  # only the clean 1:1 relation is an edge atom
    [group] = out.groups
    assert (group.kind, group.source, group.decision) == ('ghidriff-1n', 'ghidriff', 'ambiguous')
    assert group.older == (0x1000, 0x1010) and group.newer == (0x1080, 0x1100)
    cards = {(a.older_rva, a.newer_rva): a.cardinality for a in group.atoms}
    assert cards == {(0x1000, 0x1080): '1:N', (0x1000, 0x1100): 'N:M', (0x1010, 0x1100): 'N:1'}
    assert not {(a.older_rva, a.newer_rva) for a in out.atoms} & set(cards)  # members are not also loose atoms


def test_external_keys_skipped_and_counted():
    table = {'EXTERNAL:00000012': [['EXTERNAL:00000013', ['ExternalsName']]],
             va(0x1000): [['EXTERNAL:00000014', ['ExternalsName']], [va(0x1080), ['SymbolsHash']]],
             va(0x1100): [[va(0x1180), ['SymbolsHash']]]}
    out = run(GhidriffAdapter(), inputs([], raw_ok(table)))
    assert set(pairs(out)) == {(0x1100, 0x1180)} and out.groups == ()
    assert out.limitations == ('externals-skipped:2',)  # a relation with ANY external target is skipped whole


@pytest.mark.parametrize('status, limitation', [('hash-mismatch', 'raw-hash-mismatch'), ('missing', 'raw-missing'),
                                                ('unparsable', 'raw-unparsable')],
                         ids=['mismatch', 'missing', 'unparsable'])
def test_raw_hash_mismatch_drops_raw_with_limitation(status, limitation):
    modified = match('m1', 'modified', [func('f', 0x1000)], [func('f', 0x1080)], types=['SymbolsHash'])
    table = {va(0x1600): [[va(0x1700), ['SymbolsHash']]]}
    out = run(GhidriffAdapter(), inputs([modified], RawGhidriff(status=status, address_matches=table, sha256=RAW_SHA)))
    assert set(pairs(out)) == {(0x1000, 0x1080)}  # normalized rows survive, the untrusted raw table is ignored
    assert out.limitations == (limitation,)
    assert [r.file_sha256 for r in out.source_refs] == [None]
    assert out.source_refs[0].version == f'1 [raw-{status}]'  # the failure kind is part of the input's identity


def test_every_raw_failure_kind_has_its_own_source_ref():
    """Three failure kinds give three different limitations, so they must not share one result id."""
    refs = {status: GhidriffAdapter().source_ref(inputs([], RawGhidriff(status=status, sha256=RAW_SHA)))
            for status in ('ok', 'missing', 'hash-mismatch', 'unparsable')}
    assert len(set(refs.values())) == 4 and refs['ok'].file_sha256 == RAW_SHA and refs['ok'].version == '1'
    assert all(ref.file_sha256 is None for status, ref in refs.items() if status != 'ok')
    long = GhidriffAdapter().source_ref(inputs([], RawGhidriff(status='hash-mismatch', sha256=RAW_SHA),
                                               version='v' * 100))
    assert len(long.version) == 64 and long.version.endswith(' [raw-hash-mismatch]')


def test_ghidriff_unknown_match_types_are_tier_c_and_never_corroborate():
    modified = match('m1', 'modified', [func('f', 0x1000)], [func('f', 0x1080)], types=['Symbols', 'StructuralGraph'])
    [atom] = pairs(run(GhidriffAdapter(), inputs([modified]))).values()
    assert (atom.step, atom.tier, atom.cls) == ('StructuralGraph', 'C', 'E-UNKNOWN')
    empty = match('m2', 'modified', [func('g', 0x1100)], [func('g', 0x1180)])
    assert pairs(run(GhidriffAdapter(), inputs([empty])))[(0x1100, 0x1180)].step == 'unknown'


def test_ghidriff_address_outside_the_image_makes_the_set_not_comparable():
    modified = match('m1', 'modified', [func('f', 0x1000)], [func('f', 0x9000)], types=['SymbolsHash'])
    out = run(GhidriffAdapter(), inputs([modified]))
    assert out.atoms == () and out.limitations == ('ghidriff-address-basis-not-comparable',)


def test_ghidriff_functions_without_an_address_are_counted_not_guessed():
    modified = match('m1', 'modified', [func('f', None)], [func('f', 0x1080)], types=['SymbolsHash'])
    added = match('m2', 'added', newer=[func('g', 0x1100)])
    out = run(GhidriffAdapter(), inputs([modified, added]))
    assert set(pairs(out)) == set() and one_sided(out) == [('added', None, 0x1100)]
    assert out.limitations == ('no-address:1',)


def test_ghidriff_manual_matches_are_left_to_the_manual_adapter():
    manual = match('m1', 'modified', [func('f', 0x1000)], [func('g', 0x1100)], types=['manual'], manual=True)
    assert run(GhidriffAdapter(), inputs([manual])).atoms == ()


def test_ghidriff_raw_pairs_touching_a_manual_correction_stay_as_atoms():
    """The manual row must show the engine's original pairing as its contest (02 s10 item 6)."""
    manual = match('m1', 'modified', [func('f', 0x1000)], [func('g', 0x1100)], types=['manual'], manual=True)
    table = {va(0x1000): [[va(0x1080), ['SymbolsHash']]]}
    out = run(GhidriffAdapter(), inputs([manual], raw_ok(table)))
    assert set(pairs(out)) == {(0x1000, 0x1080)}


def test_ghidriff_output_does_not_depend_on_input_order():
    rng = random.Random(7)
    items = [match(f'm{i}', 'modified', [func(f'f{i}', 0x1000 + 16 * i)], [func(f'f{i}', 0x1800 + 16 * i)],
                   types=['SymbolsHash', 'BSIM']) for i in range(8)]
    items += [match('a1', 'added', newer=[func('n', 0x1f00)]), match('r1', 'removed', older=[func('o', 0x1f80)])]
    table = {va(0x1400 + 16 * i): [[va(0x1500 + 16 * i), ['ExactBytesFunctionHasher']]] for i in range(8)}
    table[va(0x1ff0)] = [[va(0x1fe0), ['SymbolsHash']], [va(0x1fd0), ['SymbolsHash']]]
    reference = run(GhidriffAdapter(), inputs(items, raw_ok(table)))
    for _ in range(5):
        shuffled = items[:]
        rng.shuffle(shuffled)
        keys_ = list(table)
        rng.shuffle(keys_)
        assert run(GhidriffAdapter(), inputs(shuffled, raw_ok({k: table[k] for k in keys_}))) == reference


def test_ghidriff_conflicting_modified_and_raw_relation_is_a_group():
    modified = match('m1', 'modified', [func('f', 0x1000)], [func('f', 0x1080)], types=['SymbolsHash'])
    table = {va(0x1000): [[va(0x1100), ['SymbolsHash']]]}
    out = run(GhidriffAdapter(), inputs([modified], raw_ok(table)))
    [group] = out.groups
    assert group.older == (0x1000,) and group.newer == (0x1080, 0x1100) and pairs(out) == {}


# --- manual -------------------------------------------------------------------------------------------------------

def test_manual_pair_is_a_tier_m_atom():
    manual = match('mm1', 'modified', [func('f', 0x1000)], [func('g', 0x1100)], types=['manual'], manual=True)
    out = run(ManualAdapter(), inputs([manual]))
    [atom] = out.atoms
    assert (atom.source, atom.step, atom.tier, atom.cls, atom.cardinality, atom.ref) == (
        'manual', 'manual-correction', 'M', 'E-MANUAL', '1:1', 'mm1')
    assert (atom.older_rva, atom.newer_rva) == (0x1000, 0x1100) and out.groups == ()
    [ref] = out.source_refs
    assert ref.source == 'manual' and ref.entry_id == manual_digest_of(inputs([manual]), addr_map())


def test_manual_one_sided_declarations_and_groups():
    removed = match('mm1', 'removed', older=[func('f', 0x1000)], manual=True)
    added = match('mm2', 'added', newer=[func('g', 0x1100)], manual=True)
    split = match('mm3', 'split', older=[func('s', 0x1200)], newer=[func('s1', 0x1300), func('s2', 0x1400)],
                  manual=True)
    ambiguous = match('mm4', 'ambiguous', older=[func('x', 0x1500), func('y', 0x1510)], newer=[func('z', 0x1600)],
                      manual=True)
    out = run(ManualAdapter(), inputs([removed, added, split, ambiguous]))
    assert one_sided(out) == [('manual-correction', None, 0x1100), ('manual-correction', 0x1000, None)]
    assert {a.tier for a in out.atoms if None in (a.older_rva, a.newer_rva)} == {'M'}
    groups = {g.kind: g for g in out.groups}
    assert set(groups) == {'manual-split', 'manual-ambiguous'}
    assert groups['manual-split'].decision == 'matched' and groups['manual-ambiguous'].decision == 'ambiguous'
    assert groups['manual-split'].older == (0x1200,) and groups['manual-split'].newer == (0x1300, 0x1400)
    assert {a.cardinality for a in groups['manual-split'].atoms} == {'1:N'}
    assert {a.cardinality for a in groups['manual-ambiguous'].atoms} == {'N:1'}


def test_manual_correction_changes_result_key():
    base = [match('mm1', 'modified', [func('f', 0x1000)], [func('g', 0x1100)], manual=True)]
    other = [match('mm1', 'modified', [func('f', 0x1000)], [func('g', 0x1180)], manual=True)]
    d0, d1 = manual_digest_of(inputs(base), addr_map()), manual_digest_of(inputs(other), addr_map())
    assert d0 != d1 and manual_digest_of(inputs([]), addr_map()) == keys.manual_digest([])
    assert manual_digest_of(inputs(base[::-1]), addr_map()) == d0

    def result_id(digest):
        return keys.result_key(keys.ResultKeyInputs(older_sha256=OLD_SHA, newer_sha256=NEW_SHA,
                                                    ghidriff_raw_sha256=RAW_SHA, ir_older_digest=None,
                                                    ir_newer_digest=None, manual_digest=digest,
                                                    config_digest='f' * 64))
    assert result_id(d0) != result_id(d1)


def test_manual_adapter_ignores_engine_matches():
    modified = match('m1', 'modified', [func('f', 0x1000)], [func('f', 0x1080)], types=['SymbolsHash'])
    out = run(ManualAdapter(), inputs([modified]))
    assert out.atoms == () and out.source_refs == ()


# --- BinDiff and rz-diff --------------------------------------------------------------------------------------------

def test_bindiff_algorithm_tier_map_and_stub_rows_are_a_recorded_limitation():
    rows = [bd(0x1000, 0x1080, 'function: name hash matching', sim=970, conf=990),
            bd(0x1100, 0x1180, 'function: edges callgraph MD index'),
            bd(0x1200, 0x1280, 'function: relaxed MD index matching'), bd(0x1300, 0x1380, 'function: manual')]
    out = run(SecondaryAdapter(), inputs([], secondary=[loaded(bindiff_set(rows), 'bd-entry')]))
    found = pairs(out)
    assert [(a.step, a.tier, a.cls) for _, a in sorted(found.items())] == [
        ('name hash matching', 'A', 'E-NAME'), ('edges callgraph md index', 'B', 'E-CALL'),
        ('relaxed md index matching', 'C', 'E-CFG'), ('manual', 'C', 'E-UNKNOWN')]
    first = found[(0x1000, 0x1080)]
    assert first.source == 'bindiff' and first.cardinality == '1:1' and first.ref == 'bd-entry'
    assert dict(first.native) == {'similarity': '0.97', 'confidence': '0.99',
                                  'algorithm': 'function: name hash matching'}
    assert out.limitations == ('bindiff-stub-rows-not-identified',)
    assert out.source_refs == (SourceRef(source='bindiff', entry_id='bd-entry', file_sha256='d' * 64, version='8.0'),)


def test_bindiff_alternatives_become_rank_atoms():
    candidate = bd(0x1000, 0x1100, 'function: hash matching')
    other = bd(0x1000, 0x1180, 'function: hash matching')
    rows = [bd(0x1000, 0x1080)]
    alts = [alternative('older', 0x1000, candidate, rank=2), alternative('older', 0x1000, other, rank=3),
            alternative('older', 0x1000, bd(0x1000, 0x1200), rank=2, source='rz-diff')]
    out = run(SecondaryAdapter(), inputs([], secondary=[loaded(bindiff_set(rows, alternatives=alts))]))
    ranked = {(a.older_rva, a.newer_rva): a for a in out.atoms if 'alt-rank' in a.step}
    assert set(ranked) == {(0x1000, 0x1100), (0x1000, 0x1180)}
    assert (ranked[(0x1000, 0x1100)].step, ranked[(0x1000, 0x1100)].tier, ranked[(0x1000, 0x1100)].cls) == (
        'hash matching alt-rank-2', 'C', 'E-BODY')
    assert ranked[(0x1000, 0x1180)].step == 'hash matching alt-rank-3'
    assert len(out.atoms) == 3  # the primary row plus two bindiff alternatives; the rz-diff-sourced one is not used


def test_rzdiff_shared_newer_endpoint_is_non_exclusive():
    rows = [rz(0x1000, 0x1080), rz(0x1010, 0x1080), rz(0x1100, 0x1180), rz(0x1200, None), rz(None, 0x1300)]
    out = run(SecondaryAdapter(), inputs([], secondary=[loaded(rzdiff_set(rows))]))
    found = pairs(out)
    assert found[(0x1000, 0x1080)].cardinality == found[(0x1010, 0x1080)].cardinality == 'non-exclusive'
    assert found[(0x1100, 0x1180)].cardinality == '1:1'
    assert {(a.source, a.step, a.tier, a.cls) for a in out.atoms} == {('rz-diff', 'levenshtein-bytes', 'W', 'E-BODY')}
    assert one_sided(out) == [('levenshtein-bytes', None, 0x1300), ('levenshtein-bytes', 0x1200, None)]
    assert out.limitations == ()


def test_rzdiff_similarity_text_is_native_only():
    a = run(SecondaryAdapter(), inputs([], secondary=[loaded(rzdiff_set([rz(0x1000, 0x1080, sim=100)]))]))
    b = run(SecondaryAdapter(), inputs([], secondary=[loaded(rzdiff_set([rz(0x1000, 0x1080, sim=999)]))]))
    strip = [[(x.source, x.step, x.tier, x.cls, x.cardinality, x.older_rva, x.newer_rva) for x in o.atoms]
             for o in (a, b)]
    assert strip[0] == strip[1] and a.atoms != b.atoms  # only the display text differs


def test_rzdiff_untested_version_is_noted():
    out = run(SecondaryAdapter(), inputs([], secondary=[loaded(rzdiff_set([rz(0x1000, 0x1080, version='0.10.0')],
                                                                          version='0.10.0'))]))
    assert out.limitations == ('rz-diff-untested-version:0.10.0',) and len(out.atoms) == 1


def test_secondary_set_of_another_pair_is_refused_with_a_limitation_but_stays_an_input():
    foreign = bindiff_set([bd(0x1000, 0x1080)], older=NEW_SHA, newer=OLD_SHA)
    out = run(SecondaryAdapter(), inputs([], secondary=[loaded(foreign, 'bd-entry')]))
    assert out.atoms == () and out.limitations == ('bindiff-pair-mismatch',)
    # the refusal changes the result (it is degrading), so the set is part of its identity: same id, same content
    assert out.source_refs == (SourceRef(source='bindiff', entry_id='bd-entry', file_sha256='d' * 64, version='8.0'),)


def test_secondary_set_with_mixed_address_basis_is_not_comparable():
    wrong = bindiff_set([bd(0x1000, 0x1080), bd(0x1100, 0x1180, base=0)])  # one row in VA form, one in RVA form
    out = run(SecondaryAdapter(), inputs([], secondary=[loaded(wrong)]))
    assert out.atoms == () and out.limitations == ('bindiff-address-basis-not-comparable',)


def test_secondary_rva_sets_are_accepted():
    rows = [bd(0x1000, 0x1080, base=0), bd(0x1100, 0x1180, base=0)]
    out = run(SecondaryAdapter(), inputs([], secondary=[loaded(bindiff_set(rows))]))
    assert set(pairs(out)) == {(0x1000, 0x1080), (0x1100, 0x1180)}


def test_secondary_adapter_orders_sets_and_atoms_deterministically():
    rows = [bd(0x1000 + 0x10 * i, 0x1800 + 0x10 * i) for i in range(6)]
    one = run(SecondaryAdapter(), inputs([], secondary=[loaded(bindiff_set(rows)),
                                                         loaded(rzdiff_set([rz(0x1000, 0x1080)]))]))
    two = run(SecondaryAdapter(), inputs([], secondary=[loaded(rzdiff_set([rz(0x1000, 0x1080)])),
                                                         loaded(bindiff_set(rows[::-1]))]))
    assert one == two


def test_address_values_in_atoms_are_rvas_not_vas():
    out = run(SecondaryAdapter(), inputs([], secondary=[loaded(bindiff_set([bd(0x1000, 0x1080)]))]))
    [atom] = out.atoms
    assert (atom.older_rva, atom.newer_rva) == (0x1000, 0x1080) and BASE + 0x1000 not in (atom.older_rva,)
