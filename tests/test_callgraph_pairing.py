"""WB2 G2: A1 resolution ladder and A2 pair map."""
from __future__ import annotations

import pytest
from callgraph_graph_support import graph_input, project_and_raw, reader_for

from patchtrace.callgraph.pairing import ExtraOpinion, PairMap
from patchtrace.callgraph.project_input import read_project_input
from patchtrace.callgraph.resolver import Resolver
from patchtrace.models import FunctionMatch


def resolve(name, side, label, mutate=None, with_raw=True, **kwargs):
    return Resolver(graph_input(name, mutate, with_raw), side, **kwargs).resolve(label)


@pytest.mark.parametrize('side,label,kind,via,tier', [
    ('older', 'DriverEntry', 'function', 'emitted-record', 'record'),
    ('older', 'FUN_140001500', 'function', 'emitted-record', 'record'),
    ('older', 'FUN_140001200', 'paired-unchanged', 'name-match', 'pairing'),
    ('newer', 'FUN_140001340', 'paired-unchanged', 'name-match', 'pairing'),
    ('older', 'ntoskrnl.exe::EtwWrite', 'external', 'external', 'label'),
    ('newer', 'ntoskrnl.exe::ProbeForRead', 'external', 'external', 'record'),
    ('newer', 'FUN_140001f00', 'function', 'emitted-record', 'record'),
    ('newer', 'FUN_1400099ff', 'label-only', 'unresolved', 'label'),
], ids=['named', 'default-record', 'older-unchanged', 'newer-unchanged', 'label-import', 'record-import',
        'added-function', 'unknown'])
def test_ladder_rungs_on_svc(side, label, kind, via, tier):
    node = resolve('svc_pair', side, label)
    assert (node.kind, node.via, node.tier) == (kind, via, tier)
    assert (node.kind == 'external') == ('import' in node.flags)


def test_label_only_names_its_reason_and_has_no_record():
    node = resolve('svc_pair', 'newer', 'FUN_1400099ff')
    assert node.reason == 'not-in-emitted-or-matched-sets' and node.function_id is None


def test_address_rung_resolves_default_names_when_names_are_not_paired():
    def drop_names(raw):
        raw['matches']['name_matches'] = {}
    node = resolve('svc_pair', 'older', 'FUN_140001200', drop_names)
    assert (node.kind, node.via, node.address) == ('paired-unchanged', 'address-match', 0x140001200)
    assert resolve('svc_pair', 'newer', 'FUN_140001340', drop_names).via == 'address-match'


def test_addresses_are_never_compared_across_sides():
    def drop_names(raw):
        raw['matches']['name_matches'] = {}
    # 140001200 is an older address only: on the newer side it must stay unresolved.
    assert resolve('svc_pair', 'newer', 'FUN_140001200', drop_names).kind == 'label-only'


def test_one_to_many_name_match_is_ambiguous_with_candidates():
    def split(raw):
        raw['matches']['name_matches']['FUN_140001200'] = [['A1', ['T']], ['A2', ['T']]]
    node = resolve('svc_pair', 'older', 'FUN_140001200', split)
    assert (node.kind, node.candidates) == ('ambiguous', ('A1', 'A2'))


def test_duplicate_record_names_are_ambiguous_never_first_wins():
    node = resolve('ambiguous_pair', 'newer', 'parser.dll::Parse')
    assert node.kind == 'ambiguous' and len(node.candidates) == 2 and node.function_id is None
    assert resolve('ambiguous_pair', 'older', 'parser.dll::Parse').kind == 'function'


@pytest.mark.parametrize('label,kind,via,flags', [
    ('ReadBuffer-2', 'function', 'emitted-record', ()),
    ('ReadBuffer-3', 'function', 'count-suffix', ('inferred-count-suffix',)),
    ('Write-2', 'label-only', 'unresolved', ()),
    ('Write', 'ambiguous', 'emitted-record', ()),
], ids=['exact-first', 'unique-stem', 'ambiguous-stem', 'duplicate-stem'])
def test_count_suffix_is_inferred_only_for_a_unique_stem(label, kind, via, flags):
    node = resolve('count_suffix', 'newer', label)
    assert (node.kind, node.via, node.flags) == (kind, via, flags)


def test_thunk_rung_is_off_by_default_and_flags_when_on():
    def add(raw):
        raw['functions']['modified'][0]['old']['called'].append('thunk_FUN_140001500')
    assert resolve('svc_pair', 'older', 'thunk_FUN_140001500', add).kind == 'label-only'
    node = resolve('svc_pair', 'older', 'thunk_FUN_140001500', add, resolve_thunks=True)
    assert (node.kind, node.via, node.flags) == ('function', 'thunk', ('thunk-suspect',))
    assert node.id != resolve('svc_pair', 'older', 'FUN_140001500').id


def test_namespace_qualified_name_is_not_an_import():
    assert resolve('svc_pair', 'older', 'std::vector::push', None).kind == 'label-only'


def test_hostile_labels_are_sanitized_bounded_and_hashable():
    data = graph_input('hostile_names')
    resolver = Resolver(data, 'newer')
    for label in ['Long' + 'x' * 600, 'Nul\x00Byte', 'Line\nBreak', 'lone\ud800surrogate', '‮evil']:
        node = resolver.resolve(label)
        assert len(node.label) <= 512 and '\n' not in node.label and '\x00' not in node.label
        assert '‮' not in node.label
    assert resolver.resolve('Long' + 'x' * 600).label.endswith('...')


def test_node_ids_are_per_side_and_per_build():
    data = graph_input('svc_pair')
    assert Resolver(data, 'older').resolve('DriverEntry').id != Resolver(data, 'newer').resolve('DriverEntry').id


# ---- A2 pair map --------------------------------------------------------------------------------------

def pairs(name='svc_pair', with_raw=True, mutate=None, **kwargs) -> PairMap:
    data = graph_input(name, mutate, with_raw)
    return PairMap(data, **kwargs)


@pytest.mark.parametrize('side,label,kind,partners,via', [
    ('older', 'FUN_140001500', 'one', ('FUN_140001640',), 'ghidriff:Symbols'),
    ('newer', 'FUN_1400018c0', 'one', ('FUN_140001800',), 'ghidriff:Symbols'),
    ('older', 'FUN_140001200', 'one', ('FUN_140001340',), 'ghidriff:ExactBytesFunctionHasher'),
    ('newer', 'FUN_140001340', 'one', ('FUN_140001200',), 'ghidriff:ExactBytesFunctionHasher'),
    ('newer', 'FUN_140001f00', 'added', (), 'ghidriff:added'),
    ('older', 'FUN_999', 'unknown', (), ''),
], ids=['emitted-older', 'emitted-newer', 'raw-older', 'raw-newer', 'added', 'unknown'])
def test_partner_precedence_emitted_then_raw(side, label, kind, partners, via):
    pairing = pairs().partner(side, label)
    assert (pairing.kind, pairing.partners, pairing.via) == (kind, partners, via)


def test_removed_function_has_kind_removed():
    pairing = pairs('no_matches', with_raw=False).partner('older', 'debug_dump')
    assert (pairing.kind, pairing.partners) == ('removed', ())


def test_equality_of_non_default_labels_is_inferred_only_without_raw_matches():
    labels = {'older': {'ntoskrnl.exe::EtwWrite', 'FUN_140001200'}, 'newer': {'ntoskrnl.exe::EtwWrite'}}
    absent = PairMap(graph_input('svc_pair', with_raw=False), labels)
    inferred = absent.partner('older', 'ntoskrnl.exe::EtwWrite')
    assert (inferred.kind, inferred.via, inferred.inferred) == ('one', 'inferred', True)
    assert absent.partner('older', 'FUN_140001200').kind == 'unknown'  # default names never infer
    present = PairMap(graph_input('svc_pair'), labels)
    assert not present.partner('older', 'ntoskrnl.exe::EtwWrite').inferred


def test_manual_correction_beats_emitted_and_raw_and_is_never_contested():
    project, raw = project_and_raw('svc_pair')
    modified = {m.older[0].name: m for m in project.matches if m.category == 'modified'}
    manual = FunctionMatch(run_id=project.runs[0].id, older=modified['FUN_140001600'].older,
                           newer=modified['FUN_140001800'].newer, category='modified', manual=True)
    project.matches = [*project.matches, manual]
    data = read_project_input(project, None, reader_for(raw))
    extra = [ExtraOpinion('older', 'FUN_140001600', 'secondary:other', ('FUN_zzz',))]
    pairing = PairMap(data, extra=extra).partner('older', 'FUN_140001600')
    assert (pairing.kind, pairing.partners, pairing.via) == ('one', ('FUN_1400018c0',), 'manual')


def test_disagreeing_engines_are_contested_and_keep_every_opinion():
    extra = [ExtraOpinion('older', 'FUN_140001500', 'secondary:other', ('FUN_140001740',))]
    pairing = pairs(extra=extra).partner('older', 'FUN_140001500')
    assert pairing.kind == 'contested' and pairing.partners == ()
    assert {o.via for o in pairing.engines} == {'ghidriff:Symbols', 'secondary:other'}


def test_agreeing_engine_is_kept_next_to_ghidriff():
    extra = [ExtraOpinion('older', 'FUN_140001500', 'secondary:other', ('FUN_140001640',))]
    pairing = pairs(extra=extra).partner('older', 'FUN_140001500')
    assert pairing.kind == 'one' and len(pairing.engines) == 2


def test_secondary_opinion_fills_an_unknown_pairing():
    extra = [ExtraOpinion('older', 'FUN_999', 'secondary:other', ('FUN_998',))]
    pairing = pairs(extra=extra).partner('older', 'FUN_999')
    assert (pairing.kind, pairing.via) == ('one', 'secondary:other')


def test_label_held_by_two_emitted_records_has_no_pairing():
    assert pairs('ambiguous_pair').partner('newer', 'parser.dll::Parse').kind == 'unknown'


def test_one_to_many_raw_pairing_is_many():
    def split(raw):
        raw['matches']['name_matches']['FUN_140001200'] = [['A1', ['T']], ['A2', ['T']]]
    pairing = pairs(mutate=split).partner('older', 'FUN_140001200')
    assert (pairing.kind, pairing.partners) == ('many', ('A1', 'A2'))
