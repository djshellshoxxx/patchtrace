"""FAB-0 origin tags, `components` and the registry (docs/specs/program-e/FAB-integration-plan.md s6, s7).

Covers: the shared-origin calculus (permutation invariant, idempotent, transitive, refuses an empty origin set, equal to an
independent reference), the default table and registry, its digest, and the guard that a witness must carry exactly the
registry's tags of its source. PIL uses this table and calculus since FAB-3; that adoption is `test_fabric_adopt.py`.
Synthetic data only.
"""
from __future__ import annotations

import hashlib
import json

import fabric_support as fs
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.fabric import ids, origins
from patchtrace.fabric.limits import FabricError

PROPS = settings(deadline=None, max_examples=80, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])
TAG_SETS = st.lists(st.frozensets(st.sampled_from(origins.TAGS + ('D_extra1', 'D_extra2')), min_size=1, max_size=4),
                    max_size=7)


def oracle(domain: str, payload) -> str:
    head = b'patchtrace\x00' + domain.encode('ascii') + b'\x00' + b'1' + b'\x00'
    body = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(head + body).hexdigest()


def reference_components(sets) -> tuple[tuple[str, ...], ...]:
    """A quadratic reference, written differently from the union-find: merge any two groups that share a tag."""
    groups = [set(tags) for tags in sets]
    merged = True
    while merged:
        merged = False
        for i, first in enumerate(groups):
            for j in range(i + 1, len(groups)):
                if first & groups[j]:
                    first |= groups.pop(j)
                    merged = True
                    break
            if merged:
                break
    return tuple(sorted(tuple(sorted(group)) for group in groups))


# --- the calculus -------------------------------------------------------------------------------------------------

def test_components_join_sets_that_share_a_tag_transitively():
    result = origins.components([{'D_a'}, {'D_a', 'D_b'}, {'D_b', 'D_c'}, {'D_x'}, {'D_y', 'D_x'}])
    assert result == (('D_a', 'D_b', 'D_c'), ('D_x', 'D_y'))
    assert origins.components([]) == ()
    assert origins.independent_count([{'D_a'}, {'D_b'}, {'D_a', 'D_b'}]) == 1
    assert origins.independent_count([{'D_a'}, {'D_b'}]) == 2


def test_components_refuse_what_would_add_independence_without_provenance():
    with pytest.raises(ValueError):
        origins.components([set()])
    with pytest.raises(TypeError):
        origins.components(['D_ghidra'])
    for bad in ('ghidra', 'D_', 'D_UPPER', 'D_' + 'x' * 33, 7):
        with pytest.raises(ValueError):
            origins.components([[bad]])


@PROPS
@given(TAG_SETS)
def test_components_partition_the_tags_and_contain_every_input_set(sets):
    comps = origins.components(sets)
    flat = [t for c in comps for t in c]
    assert len(flat) == len(set(flat)) == len(frozenset().union(*sets)) if sets else not comps
    assert list(comps) == sorted(comps) and all(list(c) == sorted(c) for c in comps)
    for tag_set in sets:
        assert sum(1 for c in comps if tag_set <= set(c)) == 1


@PROPS
@given(TAG_SETS, st.randoms(use_true_random=False))
def test_components_ignore_order_and_duplicates_and_are_idempotent(sets, rnd):
    shuffled = list(sets) + list(sets)
    rnd.shuffle(shuffled)
    assert origins.components(shuffled) == origins.components(sets)
    again = origins.components([set(c) for c in origins.components(sets)])
    assert again == origins.components(sets)


@PROPS
@given(TAG_SETS)
def test_components_equal_an_independent_reference(sets):
    assert origins.components(sets) == reference_components(sets)


# --- the registry -------------------------------------------------------------------------------------------------

def test_default_table_is_sorted_and_uses_known_tags():
    for tags in origins.SOURCE_TAGS.values():
        assert list(tags) == sorted(set(tags)) and set(tags) <= set(origins.TAGS)


@pytest.mark.parametrize('source, tags', [('kev-catalog', ('D_kev',)), ('pe-self-report', ('D_pe_self_report',)),
                                          ('emulation', ('D_emulation',)), ('ir', ('D_ghidra',))],
                         ids=['kev-catalog', 'pe-self-report', 'wb3-emulation', 'wb3-ir'])
def test_the_fab2_rows_name_their_origin(source, tags):
    assert origins.DefaultOriginRegistry().tags_for(source) == tags
    assert set(tags) <= set(origins.TAGS)


def test_registry_answers_tags_and_fails_closed_on_an_unknown_source():
    registry = origins.DefaultOriginRegistry()
    assert registry.version == origins.ORIGINS_VERSION == 1
    assert registry.tags_for('capa') == ('D_vivisect',) and registry.tags_for('capa-ghidra') == ('D_ghidra',)
    err = pytest.raises(FabricError, registry.tags_for, 'mystery').value
    assert (err.code, err.reason) == ('PT-FAB-ORIGIN', 'unknown-origin-source')
    assert registry.components([{'D_a'}, {'D_a', 'D_b'}]) == (('D_a', 'D_b'),)


def test_registry_digest_is_the_planned_formula_and_tracks_table_and_version():
    registry = origins.DefaultOriginRegistry()
    sources = {name: list(tags) for name, tags in sorted(origins.SOURCE_TAGS.items())}
    assert registry.digest() == origins.digest() == oracle('fabric-origins', {'version': 1, 'sources': sources})
    assert origins.DefaultOriginRegistry(version=2).digest() != registry.digest()
    table = dict(origins.SOURCE_TAGS)
    table['floss'] = ('D_bytes', 'D_vivisect')
    assert origins.DefaultOriginRegistry(table).digest() != registry.digest()


def test_registry_payload_is_the_hashed_table_in_sorted_order_and_hands_out_copies():
    registry = origins.DefaultOriginRegistry()
    payload = registry.payload()
    assert payload == {'version': 1, 'sources': {name: list(tags) for name, tags in origins.SOURCE_TAGS.items()}}
    assert list(payload['sources']) == sorted(origins.SOURCE_TAGS)
    assert registry.digest() == oracle('fabric-origins', payload)
    payload['sources']['b1'].append('D_other')
    assert registry.tags_for('b1') == ('D_ghidra',) and registry.payload() != payload


def test_registry_digest_golden():
    """A data addition to `SOURCE_TAGS` changes this value on purpose: update it in the same change (plan s10)."""
    assert origins.digest() == 'a48c53ab4e44d99a2ef8dc4d3f36fa81e33b5c42dc20cfa2ff453ce30c1a3f10'


@pytest.mark.parametrize('table,version', [({'x': ()}, 1), ({'x': ('ghidra',)}, 1), ({'x': ('D_BAD',)}, 1),
                                           ({'x': ('D_ok',)}, 0), ({'x': ('D_ok',)}, True)],
                         ids=['no-tags', 'bad-tag', 'upper-tag', 'zero-version', 'bool-version'])
def test_registry_rejects_a_malformed_table_or_version(table, version):
    with pytest.raises(ValueError):
        origins.DefaultOriginRegistry(table, version)


# --- independent witnesses ----------------------------------------------------------------------------------------

def _anchor_with(*pairs):
    """One cwe anchor holding a witness per (producer, source)."""
    witnesses = tuple(fs.wit(producer, source, batch=f'b{i}') for i, (producer, source) in enumerate(pairs))
    return ids.make_anchor(kind='cwe', key='CWE-190', side='none', role='stated', witnesses=witnesses)


def test_repeated_advisory_claims_count_once():
    anchor = _anchor_with(('kb', 'advisory-text'), ('kb', 'nvd-cwe'), ('kb', 'msrc-cwe'), ('kev', 'kev-cwe'))
    assert len(anchor.witnesses) == 4
    assert origins.anchor_components(anchor) == (('D_vendor_text',),)
    assert origins.independent_count(w.origins for w in anchor.witnesses) == 1


def test_the_capa_backend_decides_whether_it_is_independent_of_ghidra():
    vivisect = _anchor_with(('cap', 'capa'), ('ue', 'call-label'))
    ghidra = _anchor_with(('cap', 'capa-ghidra'), ('ue', 'call-label'))
    assert len(origins.anchor_components(vivisect)) == 2
    assert origins.anchor_components(ghidra) == (('D_ghidra',),)


def test_a_third_independent_channel_adds_a_component():
    anchor = _anchor_with(('cap', 'capa'), ('ue', 'call-label'), ('wbq', 'pe-import'))
    assert len(origins.anchor_components(anchor)) == 3


# --- the publish-time guard ---------------------------------------------------------------------------------------

def test_check_origins_requires_exactly_the_registry_tags_of_the_source():
    registry = origins.DefaultOriginRegistry()
    origins.check_origins(fs.import_anchor('Foo'), registry)
    forged = fs.import_anchor('Foo', origin=('D_ghidra',))  # capa claims a Ghidra lineage: not what the table says
    err = pytest.raises(FabricError, origins.check_origins, forged, registry).value
    assert (err.code, err.reason) == ('PT-FAB-ORIGIN', 'origin-mismatch')
    padded = fs.import_anchor('Foo', origin=('D_bytes', 'D_vivisect'))
    assert pytest.raises(FabricError, origins.check_origins, padded, registry).value.reason == 'origin-mismatch'
    unknown = fs.import_anchor('Foo', source='capa', origin=('D_vivisect',))
    unknown = unknown.model_copy(update={'witnesses': (unknown.witnesses[0].model_copy(update={'source': 'mystery'}),)})
    assert pytest.raises(FabricError, origins.check_origins, unknown, registry).value.reason == 'unknown-origin-source'
