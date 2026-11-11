"""SPEC-09 §5 synthetic acceptance for pure chain extraction (in-memory pair projects)."""
import pytest
from test_nway_support import HASHES, PairBuilder, fn

from patchtrace.nway.contracts import Chain, NwayError
from patchtrace.nway.graph import extract_chains, parse_address, series_id

H = HASHES


def pairs(n=3):
    return [PairBuilder(H[i], H[i + 1]) for i in range(n - 1)]


def straight(n=3):
    ps = pairs(n)
    for i, p in enumerate(ps):
        p.one(fn('f', 0x1000 + i, f'v{i}'), fn('f', 0x1000 + i + 1, f'v{i + 1}'),
              match_types=('SymbolsHash', 'BSIM') if i else ('ExactBytesFunctionHasher',), ratio=0.5 + i / 10)
    return ps


def test_straight_one_to_one_chain():
    chains, nodes = extract_chains(H[:3], [p.build() for p in straight()])
    assert nodes == 3
    [chain] = chains
    assert [(n.ordinal, n.address, n.name) for n in chain.nodes] == [(0, 0x1000, 'f'), (1, 0x1001, 'f'),
                                                                    (2, 0x1002, 'f')]
    assert chain.hops == 2 and chain.status == 'inferred' and not chain.gaps and not chain.events
    assert [e.ratio_text for e in chain.edges] == ['0.5', '0.6']
    assert chain.edges[1].match_types == ('SymbolsHash', 'BSIM')
    # weakest by first (strongest-recorded) type per hop: ExactBytes is weaker than SymbolsHash
    assert chain.weakest_match_type == 'ExactBytesFunctionHasher'


def test_split_in_middle_ends_chain_as_event():
    ps = pairs(4)
    ps[0].one(fn('f', 1, 'a'), fn('f', 2, 'b'))
    ps[1].one(fn('f', 2, 'b'), fn('f', 3, 'c'))
    ps[2].rel('split', [fn('f', 3, 'c')], [fn('f', 4, 'd'), fn('f_part', 5, 'e')], manual=True,
              match_types=('manual',))
    [chain] = extract_chains(H[:4], [p.build() for p in ps])[0]
    assert len(chain.nodes) == 3
    assert [(e.kind, e.ordinal) for e in chain.events] == [('split', 3)]
    assert not chain.gaps


def test_split_before_three_builds_yields_no_chain():
    ps = pairs(3)
    ps[0].rel('split', [fn('f', 1)], [fn('f', 2), fn('g', 3)], manual=True)
    ps[1].one(fn('f', 2), fn('f', 4))
    assert extract_chains(H[:3], [p.build() for p in ps])[0] == []


def test_manual_correction_wins_over_engine_edge():
    ps = pairs(3)
    ps[0].one(fn('f', 1), fn('f', 2))
    ps[1].one(fn('f', 2), fn('wrong', 9), match_types=('NameParamHash',))
    ps[1].one(fn('f', 2), fn('right', 7), match_types=('manual',), manual=True)
    [chain] = extract_chains(H[:3], [p.build() for p in ps])[0]
    assert chain.nodes[-1].name == 'right' and chain.edges[-1].manual
    assert chain.weakest_match_type == 'SymbolsHash'


def test_two_engine_edges_without_manual_are_ambiguous():
    ps = pairs(3)
    ps[0].one(fn('f', 1), fn('f', 2))
    ps[1].one(fn('f', 2), fn('a', 9))
    ps[1].one(fn('f', 2), fn('b', 7))
    assert extract_chains(H[:3], [p.build() for p in ps])[0] == []
    ps = pairs(4)
    ps[0].one(fn('f', 1), fn('f', 2))
    ps[1].one(fn('f', 2), fn('f', 3))
    ps[2].one(fn('f', 3), fn('a', 9))
    ps[2].one(fn('f', 3), fn('b', 7))
    [chain] = extract_chains(H[:4], [p.build() for p in ps])[0]
    assert [(e.kind, e.ordinal) for e in chain.events] == [('ambiguous', 3)]


def test_revert_detection_by_code_text():
    ps = pairs(4)
    codes = ['orig', 'patched', 'other', 'orig']
    for i, p in enumerate(ps):
        p.one(fn('f', 1, codes[i]), fn('f', 1, codes[i + 1]))
    [chain] = extract_chains(H[:4], [p.build() for p in ps])[0]
    assert [(e.kind, e.ordinal, e.detail) for e in chain.events] == [('reverted', 3, 'code text equals build 0')]


def test_no_revert_without_intervening_change_or_code():
    ps = pairs(3)
    ps[0].one(fn('f', 1, 'a'), fn('f', 1, 'b'))
    ps[1].one(fn('f', 1, 'b'), fn('f', 1, None))
    assert not extract_chains(H[:3], [p.build() for p in ps])[0][0].events


def test_gap_and_boundary_events():
    ps = pairs(5)
    # f: added in B1, then 1:1 to B3, then no record in pair 3→4 (a gap)
    ps[0].rel('added', newer=[fn('f', 1)], match_types=())
    ps[1].one(fn('f', 1), fn('f', 2))
    ps[2].one(fn('f', 2), fn('f', 3))
    # g: no record in pair 0→1 (gap), 1:1 through B3, removed in B4
    ps[1].one(fn('g', 10), fn('g', 11))
    ps[2].one(fn('g', 11), fn('g', 12))
    ps[3].rel('removed', older=[fn('g', 12)], match_types=())
    chains = extract_chains(H[:5], [p.build() for p in ps])[0]
    by = {c.nodes[0].name: c for c in chains}
    assert by['f'].gaps == (4,) and [(e.kind, e.ordinal) for e in by['f'].events] == [('added', 1)]
    assert by['g'].gaps == (0,) and [(e.kind, e.ordinal) for e in by['g'].events] == [('removed', 4)]


def direct_pair(target, category='modified'):
    d = PairBuilder(H[0], H[2])
    if category == 'removed':
        d.rel('removed', older=[fn('f', 0x1000)], match_types=())
    else:
        d.one(fn('f', 0x1000), fn(*target))
    return d.build()


def test_confirmed_and_contradicted_with_direct_pair():
    built = [p.build() for p in straight()]
    assert extract_chains(H[:3], built, direct_pair(('f', 0x1002)))[0][0].status == 'confirmed'
    assert extract_chains(H[:3], built, direct_pair(('g', 0x5000)))[0][0].status == 'contradicted'
    assert extract_chains(H[:3], built, direct_pair(None, 'removed'))[0][0].status == 'contradicted'
    unrelated = PairBuilder(H[0], H[2]).one(fn('x', 1), fn('x', 2)).build()
    assert extract_chains(H[:3], built, unrelated)[0][0].status == 'inferred'
    assert extract_chains(H[:3], built)[0][0].status == 'inferred'


def test_direct_pair_must_hold_first_and_last():
    with pytest.raises(NwayError, match='PT-NWAY-PAIR'):
        extract_chains(H[:3], [p.build() for p in straight()], PairBuilder(H[0], H[1]).build())


def test_pair_projects_validated_for_exact_ordered_pair():
    ps = straight()
    swapped = [PairBuilder(H[2], H[1]).build(), ps[0].build()]
    with pytest.raises(NwayError, match='ordered pair'):
        extract_chains(H[:3], [ps[0].build(), swapped[0]])
    with pytest.raises(NwayError, match='expected 2'):
        extract_chains(H[:3], [ps[0].build()])


@pytest.mark.parametrize('hashes', [H[:2], H[:1] * 3, [*H, H[0]]])
def test_build_bounds_and_uniqueness(hashes):
    with pytest.raises(NwayError, match='PT-NWAY-INPUT'):
        extract_chains(hashes, [])


def test_deterministic_ids_and_order():
    ps = pairs(3)
    for name, addr in [('z', 5), ('a', 9), ('m', 1)]:
        ps[0].one(fn(name, addr), fn(name, addr))
        ps[1].one(fn(name, addr), fn(name, addr))
    built = [p.build() for p in ps]
    first = extract_chains(H[:3], built)[0]
    ps[0].matches.reverse()
    ps[1].matches.reverse()
    second = extract_chains(H[:3], [p.build() for p in ps])[0]
    assert [c.chain_id for c in first] == [c.chain_id for c in second]
    assert [c.nodes[0].address for c in first] == [1, 5, 9]
    assert series_id(H[:3]) == series_id(list(H[:3])) != series_id([H[1], H[0], H[2]])


def test_node_limit(monkeypatch):
    import patchtrace.nway.graph as graph
    monkeypatch.setattr(graph, 'MAX_NODES', 3)
    ps = straight()
    ps[0].one(fn('x', 7), fn('x', 7))
    with pytest.raises(NwayError, match='PT-NWAY-LIMIT'):
        graph.extract_chains(H[:3], [p.build() for p in ps])


def test_parse_address():
    assert parse_address('180001000') == 0x180001000 and parse_address('0x10') == 16
    assert parse_address('ram:1000') is None and parse_address(None) is None and parse_address('1' * 17) is None


def test_chain_contract_rejects_inconsistent_edges():
    chain = extract_chains(H[:3], [p.build() for p in straight()])[0][0]
    with pytest.raises(ValueError):
        Chain.model_validate(chain.model_copy(update={'hops': 3}).model_dump(), strict=False)
    assert Chain.model_validate_json(chain.model_dump_json()) == chain


def raw(table):
    return {'address_matches': {f'{k:x}': [[f'{t:x}', types] for t, types in v] for k, v in table.items()}}


def test_raw_unchanged_hop_joins_by_address():
    ps = pairs(3)
    ps[1].one(fn('f', 0x20, 'b'), fn('f', 0x30, 'c'))
    [chain] = extract_chains(H[:3], [p.build() for p in ps],
                             raw_matches=[raw({0x10: [(0x20, ['SymbolsHash'])]}), None])[0]
    assert [(n.address, n.name) for n in chain.nodes] == [(0x10, None), (0x20, 'f'), (0x30, 'f')]
    assert chain.edges[0].category == 'unchanged' and chain.edges[0].match_id.startswith('raw:')


@pytest.mark.parametrize('table', [
    {0x10: [(0x20, ['A']), (0x21, ['B'])]},           # two targets
    {0x10: [(0x20, ['A'])], 0x11: [(0x20, ['B'])]},  # shared target
])
def test_ambiguous_address_matches_create_no_hop(table):
    ps = pairs(4)
    ps[0].one(fn('f', 0x1, 'a'), fn('f', 0x2, 'b'))
    ps[1].one(fn('f', 0x2, 'b'), fn('f', 0x10, 'c'))
    ps[2].matches = []
    [chain] = extract_chains(H[:4], [p.build() for p in ps], raw_matches=[None, None, raw(table)])[0]
    assert chain.nodes[-1].address == 0x10
    assert [(e.kind, e.ordinal) for e in chain.events] == [('ambiguous', 3)]


def test_normalized_and_manual_relations_override_raw():
    ps = pairs(3)
    ps[0].one(fn('f', 0x1), fn('f', 0x10))
    ps[1].one(fn('f', 0x10), fn('right', 0x40), match_types=('manual',), manual=True)
    raws = [None, raw({0x10: [(0x30, ['ExactBytesFunctionHasher'])], 0x11: [(0x40, ['BSIM'])]})]
    [chain] = extract_chains(H[:3], [p.build() for p in ps], raw_matches=raws)[0]
    assert chain.nodes[-1].name == 'right' and chain.edges[-1].manual


def test_raw_ghidra_external_locations_are_skipped_not_fatal():
    """Real Ghidriff output keys imports as `EXTERNAL:<hex>` (research note 03 s2); they are no image functions."""
    ps = pairs(3)
    ps[1].one(fn('f', 0x20, 'b'), fn('f', 0x30, 'c'))
    table = {'10': [['20', ['SymbolsHash']]],
             'EXTERNAL:0000000c': [['EXTERNAL:0000000d', ['SymbolsHash']]],   # external -> external
             '11': [['EXTERNAL:0000000e', ['SymbolsHash']], ['21', ['X']]]}  # a source touching an external target
    [chain] = extract_chains(H[:3], [p.build() for p in ps], raw_matches=[{'address_matches': table}, None])[0]
    assert [(n.address, n.name) for n in chain.nodes] == [(0x10, None), (0x20, 'f'), (0x30, 'f')]


def test_nway_external_skips_are_counted():
    """Each raw entry skipped as an EXTERNAL:<hex> location is counted in the limitation; zero adds no text."""
    from patchtrace.nway.graph import external_limitations
    table = {'10': [['20', ['SymbolsHash']]],  # ordinary entry, not counted
             'EXTERNAL:0000000c': [['21', ['SymbolsHash']]],  # external source
             '11': [['EXTERNAL:0000000e', ['SymbolsHash']], ['22', ['X']]],  # external target among others
             '12': [['EXTERNAL:00000010', ['SymbolsHash']]]}  # external-only target
    assert external_limitations({'address_matches': table}) == (
        '3 raw address_matches entries at EXTERNAL:<hex> import locations skipped: '
        'not functions of either build, so no edges',)
    assert external_limitations({'address_matches': {'10': [['20', ['SymbolsHash']]]}}) == ()
    assert external_limitations({'address_matches': {}}) == ()


def test_other_unparsable_raw_addresses_are_still_rejected():
    for bad in ('EXTERNAL:', 'EXTERNALISH:0c', 'EXTERNAL:0c garbage', 'zz'):
        with pytest.raises(NwayError, match='invalid address'):
            extract_chains(H[:3], [p.build() for p in straight()],
                           raw_matches=[{'address_matches': {bad: [['20', []]]}}, None])


def test_malformed_raw_matches_rejected():
    with pytest.raises(NwayError, match='address_matches'):
        extract_chains(H[:3], [p.build() for p in straight()], raw_matches=[{'address_matches': []}, None])
    with pytest.raises(NwayError, match='target'):
        extract_chains(H[:3], [p.build() for p in straight()],
                       raw_matches=[{'address_matches': {'10': [['zz', []]]}}, None])


def test_overridden_engine_edge_does_not_create_a_second_chain_through_the_node():
    from patchtrace.nway.graph import extract_chains
    from tests.test_nway_support import HASHES as H
    from tests.test_nway_support import PairBuilder, fn
    pairs = [PairBuilder(H[0], H[1]), PairBuilder(H[1], H[2])]
    pairs[0].one(fn('a', 0x10), fn('n', 0x20), match_types=('NameParamHash',))
    pairs[0].one(fn('b', 0x11), fn('n', 0x20), match_types=('manual',), manual=True)
    pairs[1].one(fn('n', 0x20), fn('z', 0x30))
    chains, _ = extract_chains(H[:3], [p.build() for p in pairs])
    through_n = [c for c in chains if any(n.name == 'n' for n in c.nodes)]
    assert len(through_n) == 1 and all(e.manual for e in through_n[0].edges[:1])


def test_ser2_over_long_name_is_an_nway_error_not_a_contract_error():
    ps = pairs(3)
    ps[0].one(fn('x' * 5000, 0x1000), fn('f', 0x1001))
    ps[1].one(fn('f', 0x1001), fn('f', 0x1002))
    with pytest.raises(NwayError, match='PT-NWAY-INPUT'):
        extract_chains(H[:3], [p.build() for p in ps])


def test_ser2_empty_name_with_an_address_becomes_an_address_only_node():
    ps = pairs(3)
    ps[0].one(fn('', 0x1000), fn('', 0x1001))
    ps[1].one(fn('', 0x1001), fn('', 0x1002))
    chain = extract_chains(H[:3], [p.build() for p in ps])[0][0]
    assert [(n.address, n.name) for n in chain.nodes] == [(0x1000, None), (0x1001, None), (0x1002, None)]


def test_ser2_empty_name_without_an_address_is_an_nway_error():
    ps = pairs(3)
    ps[0].one(fn('', None), fn('f', 0x1001))
    ps[1].one(fn('f', 0x1001), fn('f', 0x1002))
    with pytest.raises(NwayError, match='PT-NWAY-INPUT'):
        extract_chains(H[:3], [p.build() for p in ps])


def test_ser3_split_that_includes_the_chain_end_is_inferred_not_contradicted():
    built = [p.build() for p in straight(3)]
    d = PairBuilder(H[0], H[2])
    d.rel('split', older=[fn('f', 0x1000)], newer=[fn('f', 0x1002), fn('g', 0x5000)], match_types=())
    assert extract_chains(H[:3], built, d.build())[0][0].status == 'inferred'
