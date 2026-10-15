"""FAB-3 adoption: PIL's origin table, shared-origin calculus and anchor seams are the fabric's (plan s9, s10).

Covers: `pilot.origins` and `pilot.ports` re-export the fabric objects instead of keeping copies; PIL's default registry
is the fabric registry under PIL's error type and identity domain; the digest formula did not change (the table PIL
shipped before the adoption still hashes to the old golden), so the new golden moves only because the shared table gained
rows; the shared table still holds every pre-adoption row with equal tags; PIL offers flow through the rebound sink.
Synthetic data only.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from patchtrace.fabric import convert
from patchtrace.fabric import origins as fabric_origins
from patchtrace.fabric import ports as fabric_ports
from patchtrace.fabric.contracts import AnchorQuery, PublishReport
from patchtrace.fabric.limits import FabricError
from patchtrace.fabric.memory import MemoryAnchorStore, NullAnchorSink
from patchtrace.pilot import origins as pilot_origins
from patchtrace.pilot import ports as pilot_ports
from patchtrace.pilot.contracts import PilotAnchor
from patchtrace.pilot.limits import PilotError

# The table `pilot/origins.py` held before FAB-3 (plan s9): 15 sources, the golden it hashed to, and the tags it used.
PIL_ERA_SOURCE_TAGS = {
    'advisory-text': ('D_vendor_text',), 'nvd-cwe': ('D_vendor_text',), 'msrc-cwe': ('D_vendor_text',),
    'kev-cwe': ('D_vendor_text',),
    'b1': ('D_ghidra',), 'change-facts': ('D_ghidra',), 'call-label': ('D_ghidra',),
    'pe-import': ('D_pe_tables',),
    'capa': ('D_vivisect',), 'capa-ghidra': ('D_ghidra',),
    'floss': ('D_bytes',), 'die': ('D_compiler',),
    'names': ('D_symbols',), 'pairing': ('D_ghidra',), 'analyst': ('D_analyst',)}
PIL_ERA_TAGS = ('D_analyst', 'D_bytes', 'D_callgraph', 'D_compiler', 'D_ghidra', 'D_ghidra_decode', 'D_hexrays', 'D_ida',
                'D_pe_tables', 'D_rizin', 'D_symbols', 'D_vendor_text', 'D_vivisect')
PIL_ERA_ORIGINS_DIGEST = 'affccb01cfc3893d0eab9ae54a594a20b19e1a9eeade8179082bec3e3721c12f'
PILOT_ORIGINS_DIGEST = '3370b2c85687a46f50bf7231e765d199a0c4c9a1e0e73f0ec992619adde6bc18'


def oracle(domain: str, payload) -> str:
    head = b'patchtrace\x00' + domain.encode('ascii') + b'\x00' + b'1' + b'\x00'
    body = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(head + body).hexdigest()


def payload_of(table) -> dict:
    return {'version': 1, 'sources': {name: list(tags) for name, tags in sorted(table.items())}}


# --- one source of truth ------------------------------------------------------------------------------------------

@pytest.mark.parametrize('name', ['components', 'TAGS', 'SOURCE_TAGS'], ids=['calculus', 'tags', 'table'])
def test_pilot_origins_hold_no_copy_of_the_fabric_table_or_calculus(name):
    assert getattr(pilot_origins, name) is getattr(fabric_origins, name)
    assert pilot_origins.ORIGINS_VERSION == fabric_origins.ORIGINS_VERSION == 1


@pytest.mark.parametrize('name', ['OriginRegistry', 'AnchorSink'], ids=['registry', 'sink'])
def test_pilot_ports_rebind_the_fabric_seams(name):
    assert getattr(pilot_ports, name) is getattr(fabric_ports, name)


def test_the_shared_table_holds_every_pre_adoption_source_with_equal_tags():
    for source, tags in PIL_ERA_SOURCE_TAGS.items():
        assert fabric_origins.SOURCE_TAGS[source] == tags, source
    assert set(PIL_ERA_TAGS) <= set(fabric_origins.TAGS)


def test_fab2_added_exactly_the_planned_rows_to_the_pre_adoption_table_and_left_capa_alone():
    added = set(fabric_origins.SOURCE_TAGS) - set(PIL_ERA_SOURCE_TAGS)
    assert added == {'kev-catalog', 'pe-self-report', 'emulation', 'ir'}
    assert fabric_origins.SOURCE_TAGS['capa'] == PIL_ERA_SOURCE_TAGS['capa'] == ('D_vivisect',)


# --- the PIL registry ---------------------------------------------------------------------------------------------

def test_the_pilot_registry_answers_like_the_fabric_registry():
    registry = pilot_origins.DefaultOriginRegistry()
    assert isinstance(registry, fabric_origins.DefaultOriginRegistry) and isinstance(registry, pilot_ports.OriginRegistry)
    assert registry.version == fabric_origins.ORIGINS_VERSION
    assert {source: registry.tags_for(source) for source in fabric_origins.SOURCE_TAGS} == dict(
        fabric_origins.SOURCE_TAGS)
    sets = [registry.tags_for(source) for source in ('advisory-text', 'b1', 'capa-ghidra', 'pe-import')]
    expected = (('D_ghidra',), ('D_pe_tables',), ('D_vendor_text',))  # b1 and capa on Ghidra are one origin
    assert registry.components(sets) == fabric_origins.components(sets) == expected


def test_an_unknown_source_fails_closed_with_pilots_error_and_the_fabric_keeps_its_own():
    with pytest.raises(PilotError) as info:
        pilot_origins.DefaultOriginRegistry().tags_for('mystery-engine')
    error = info.value
    assert (error.code, error.reason, error.exit_code) == ('PT-PILOT-INPUT', 'unknown-origin-source', 2)
    assert not isinstance(error, FabricError) and error.__cause__ is None and error.__suppress_context__
    with pytest.raises(FabricError) as fabric:
        fabric_origins.DefaultOriginRegistry().tags_for('mystery-engine')
    assert (fabric.value.code, fabric.value.reason) == ('PT-FAB-ORIGIN', 'unknown-origin-source')


def test_a_custom_table_and_version_reach_the_shared_constructor():
    registry = pilot_origins.DefaultOriginRegistry({'elsewhere': ('D_elsewhere',)}, version=3)
    assert registry.tags_for('elsewhere') == ('D_elsewhere',) and registry.version == 3
    with pytest.raises(PilotError):
        registry.tags_for('b1')
    with pytest.raises(ValueError):
        pilot_origins.DefaultOriginRegistry({'x': ('ghidra',)})


# --- the PIL identity ---------------------------------------------------------------------------------------------

def test_the_pilot_digest_keeps_pilots_domain_and_the_shared_payload():
    expected = oracle('pilot-origins', payload_of(fabric_origins.SOURCE_TAGS))
    assert pilot_origins.digest() == pilot_origins.DefaultOriginRegistry().digest() == expected
    assert pilot_origins.digest() != fabric_origins.digest()  # one table, two identity domains: ids never collide


def test_the_table_pil_shipped_before_the_adoption_still_hashes_to_the_old_golden():
    """The formula did not change with the adoption; only the table did."""
    registry = pilot_origins.DefaultOriginRegistry(PIL_ERA_SOURCE_TAGS)
    assert registry.digest() == PIL_ERA_ORIGINS_DIGEST == oracle('pilot-origins', payload_of(PIL_ERA_SOURCE_TAGS))


def test_the_pilot_digest_golden():
    """Moves when a row is added to `fabric.origins.SOURCE_TAGS`: re-pin it with `tests/test_fabric_origins.py` and
    regenerate the PIL examples (`python tools/generate_pilot_schemas.py`) in the same change."""
    assert pilot_origins.digest() == PILOT_ORIGINS_DIGEST


# --- the rebound sink ---------------------------------------------------------------------------------------------

def test_pilot_offers_flow_through_the_rebound_sink_with_pilots_registry():
    registry = pilot_origins.DefaultOriginRegistry()
    offers = [PilotAnchor(anchor_id='cwe:CWE-190', kind='cwe', label='CWE-190 integer overflow'),
              PilotAnchor(anchor_id='api:RtlSizeTAdd', kind='api', label='RtlSizeTAdd')]
    converted = [convert.from_pilot_anchor(offer, batch='pil1', registry=registry) for offer in offers]
    assert converted == [convert.from_pilot_anchor(offer, batch='pil1') for offer in offers]  # same tags, same anchors
    sink: pilot_ports.AnchorSink = MemoryAnchorStore(registry=registry)
    assert sink.publish('synthetic-fab3', converted) == PublishReport(added=2)
    page = sink.find('synthetic-fab3', AnchorQuery())
    assert page.total == 2 and {w.origins for a in page.items for w in a.witnesses} == {('D_vendor_text',)}
    assert sink.retract('synthetic-fab3', 'pil', 'pil1') == PublishReport(removed=2)


def test_a_no_op_sink_still_satisfies_the_rebound_port():
    sink = NullAnchorSink()
    assert isinstance(sink, pilot_ports.AnchorSink)
    assert sink.publish('synthetic-fab3', []) == PublishReport()
