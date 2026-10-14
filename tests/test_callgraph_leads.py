"""WB2 G3: groups, blast radius, entry distance, observed paths and graph leads."""
from __future__ import annotations

import re

import pytest
from callgraph_delta_support import Entries, analysis, by_label, modified
from callgraph_fixtures import FIXTURE_NAMES

from patchtrace.callgraph.blast import blast, entry_distance
from patchtrace.callgraph.groups import build_groups
from patchtrace.callgraph.leads import build_leads, signals_for
from patchtrace.callgraph.limits import GraphError
from patchtrace.callgraph.paths import find_paths
from patchtrace.callgraph.query import find_node
from patchtrace.callgraph.text import UNSAFE

BANNED = re.compile(r'vulnerab|exploit|confiden|score|probab|likely|malicious|risk|danger|bug', re.IGNORECASE)
ENTRY = Entries('DriverEntry')


def _share_new_function(raw):
    modified(raw, 'FUN_140001600')['new']['called'].append('FUN_140001f00')


def _share_hub_import(raw):
    modified(raw, 'FUN_140001800')['new']['called'].append('ntoskrnl.exe::EtwWriteTransfer')


def test_group_of_two_pairs_sharing_a_new_callee():
    snap, deltas = analysis('svc_pair', _share_new_function)
    groups = build_groups(deltas)
    assert [(g.label, g.cls, len(g.members), g.hub) for g in groups] == [
        ('FUN_140001f00', 'call-to-new-function', 2, False)]
    assert set(groups[0].members) == {by_label(deltas, 'FUN_140001600').match_id,
                                      by_label(deltas, 'FUN_140001800').match_id}
    assert snap.newer.nodes[snap.newer.index[groups[0].callee]].label == 'FUN_140001f00'


def test_single_pair_makes_no_group_and_hub_groups_sort_last():
    assert build_groups(analysis('svc_pair')[1]) == ()

    def both(raw):
        _share_new_function(raw)
        _share_hub_import(raw)

    groups = build_groups(analysis('svc_pair', both)[1])
    assert [g.hub for g in groups] == [False, True]


def test_blast_and_entry_distance_for_the_changed_parser():
    snap, deltas = analysis('svc_pair')
    node = find_node(snap, 'newer', 'FUN_1400018c0')
    assert blast(snap, 'newer', node.id).model_dump() == {'direct_callers': 1, 'observed_callers': 2,
                                                          'unknown_frontier': 0}
    entry = entry_distance(snap, 'newer', node.id, ENTRY)
    assert (entry.state, entry.hops, entry.via) == ('reached', 2, 'DriverEntry')


def test_entry_unknown_and_not_reached():
    snap, _ = analysis('svc_pair')
    node = find_node(snap, 'newer', 'FUN_1400018c0')
    assert entry_distance(snap, 'newer', node.id, None).state == 'unknown'
    assert entry_distance(snap, 'newer', node.id, Entries('Missing')).state == 'unknown'
    leaf = find_node(snap, 'newer', 'FUN_140001340')
    assert entry_distance(snap, 'newer', leaf.id, Entries('FUN_140001f00')).state == 'not-reached'


def test_blast_counts_the_hub_callers_and_unknown_frontier():
    snap, _ = analysis('cycle_hub')
    hub = find_node(snap, 'newer', 'TraceMessageHub')
    result = blast(snap, 'newer', hub.id)
    assert result.direct_callers == 66 and result.observed_callers == 66 and result.unknown_frontier == 0


def test_unknown_node_id_is_an_input_error():
    snap, _ = analysis('svc_pair')
    with pytest.raises(GraphError) as caught:
        blast(snap, 'newer', 'nope')
    assert caught.value.code == 'PT-GRAPH-INPUT'


def test_paths_found_with_an_upper_bound_note():
    snap, _ = analysis('svc_pair')
    src, dst = (find_node(snap, 'newer', label) for label in ('DriverEntry', 'FUN_1400018c0'))
    result = find_paths(snap, 'newer', src.id, dst.id)
    assert [[result.labels[n] for n in path] for path in result.paths] == [
        ['DriverEntry', 'FUN_140001640', 'FUN_1400018c0']]
    assert 'at most 2 calls' in result.note and result.completeness == 'changed-set-lists'


def test_no_path_is_not_found_among_listed_functions_never_absent():
    snap, _ = analysis('svc_pair')
    src, dst = (find_node(snap, 'newer', label) for label in ('FUN_140001f00', 'DriverEntry'))
    result = find_paths(snap, 'newer', src.id, dst.id)
    assert result.paths == () and 'Not found among the' in result.note and 'not proof' in result.note


def test_paths_do_not_cross_functions_without_stored_lists():
    snap, _ = analysis('svc_pair')
    src, dst = (find_node(snap, 'newer', label) for label in ('FUN_140001640', 'FUN_140001340'))
    # D calls H directly; H has no list of its own but is the destination, so the direct edge is observed.
    assert find_paths(snap, 'newer', src.id, dst.id).paths
    via = find_node(snap, 'newer', 'FUN_140001340')
    other = find_node(snap, 'newer', 'ntoskrnl.exe::ExAllocatePool2')
    assert find_paths(snap, 'newer', via.id, other.id).paths == ()


def test_leads_order_and_origin():
    snap, deltas = analysis('svc_pair')
    leads = build_leads(snap, deltas, ENTRY)
    assert [by_label(deltas, name).match_id for name in ('FUN_140001800', 'FUN_140001c00')] == [x.match_id for x in leads]
    assert [s.id for s in leads[0].signals] == ['new-function-called', 'api-hint-called']
    assert [s.id for s in leads[1].signals] == ['hub-only']
    assert {(lead.origin.engine, lead.origin.run_id, lead.origin.group) for lead in leads} == {
        ('ghidriff-lists', snap.data.run_id, 'calls')}


def test_signal_ranks_never_leak_into_the_text_and_evidence_names_a_record():
    snap, deltas = analysis('svc_pair', _share_new_function)
    for delta in deltas:
        for signal in signals_for(delta):
            assert not re.search(r'\brank\b', signal.meaning + signal.next_step)
            assert signal.evidence.record_id and signal.evidence.field in {'callees', 'callers'}


def test_dropped_call_signal_names_the_older_record():
    snap, deltas = analysis('svc_pair', lambda raw: modified(raw, 'FUN_140001800')['new']['called'].remove(
        'FUN_140001340'))
    delta = by_label(deltas, 'FUN_140001800')
    dropped = next(s for s in signals_for(delta) if s.id == 'call-dropped')
    assert dropped.evidence.record_id == delta.older_function_id
    assert 'FUN_140001200' in dropped.meaning


def test_fan_in_context_only_when_the_listed_callers_differ():
    def add_caller(raw):
        modified(raw, 'FUN_140001800')['new']['calling'].append('FUN_140001600')

    delta = by_label(analysis('svc_pair', add_caller)[1], 'FUN_140001800')
    fan_in = next(s for s in signals_for(delta) if s.id == 'fan-in-context')
    assert fan_in.meaning == 'Listed as called from 2 functions' and fan_in.evidence.field == 'callers'


@pytest.mark.parametrize('name', FIXTURE_NAMES)
def test_banned_string_and_unsafe_text_sweep_over_all_signal_text(name):
    snap, deltas = analysis(name)
    for lead in build_leads(snap, deltas, ENTRY):
        for signal in lead.signals:
            text = f'{signal.meaning} {signal.next_step}'
            assert not BANNED.search(text), text
            assert not UNSAFE.search(text) and '\n' not in text and len(signal.meaning) <= 400
    for delta in deltas:
        for change in delta.changes:
            assert not UNSAFE.search(f'{change.older_label} {change.newer_label} {change.reason}')
