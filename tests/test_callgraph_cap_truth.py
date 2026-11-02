"""Issue #105 CG-3: capped exploration stays partial across actual graph, CLI and panel export paths."""
from __future__ import annotations

import json

import pytest
from callgraph_cli_support import make_project, match_id, run
from callgraph_fixtures import build_fixture
from callgraph_graph_support import snapshot

from patchtrace.callgraph.dot import render_dot
from patchtrace.callgraph.export_json import build_export, to_json
from patchtrace.callgraph.query import find_node, neighbourhood


def test_actual_cycle_hub_is_partial_in_view_paired_json_and_dot():
    snap = snapshot('cycle_hub')
    hub = find_node(snap, 'newer', 'TraceMessageHub')
    view = neighbourhood(snap, 'newer', [hub.id], direction='in', max_nodes=500, max_edges=500)
    assert len(view.nodes) == 65 and len(view.edges) == 64
    assert [(marker.node, marker.count) for marker in view.more] == [(hub.id, 2)]
    assert view.truncated
    assert any('capped' in note for note in view.limitations)
    exported = build_export(snap, hub.match_id)
    assert exported.truncated and exported.older.truncated and exported.newer.truncated
    assert any('capped' in note for note in exported.limitations)
    document = json.loads(to_json(exported))
    assert document['truncated'] and any('capped' in note for note in document['limitations'])
    text = render_dot(exported)
    assert any(line.startswith('//') and 'capped' in line for line in text.splitlines())
    assert '  label="The view is capped; some nodes or edges may be omitted.";' in text


def _merged_snapshot(unique, repeats=1):
    def mutate(raw):
        leaves = [f'Leaf{index:02d}' for index in range(unique)] * repeats
        raw['functions'] = {'added': [
            {'name': root, 'fullname': root, 'address': address, 'called': leaves, 'calling': []}
            for root, address in (('RootA', '1000'), ('RootB', '2000'))], 'modified': [], 'deleted': []}
        raw['matches'] = {'name_matches': {}, 'address_matches': {}}
    return snapshot('no_matches', mutate)


def test_duplicate_focus_ids_do_not_hide_a_distinct_root_or_claim_truncation():
    snap = _merged_snapshot(0)
    a, b = (find_node(snap, 'newer', name).id for name in ('RootA', 'RootB'))
    view = neighbourhood(snap, 'newer', [a, a, b, b], depth=0, max_nodes=2)
    assert {node.id for node in view.nodes} == {a, b}
    assert not view.truncated and not view.more


def test_overlapping_capped_frontiers_keep_per_origin_counts_without_inventing_unique_totals():
    snap = _merged_snapshot(65, repeats=2)
    roots = [find_node(snap, 'newer', name).id for name in ('RootA', 'RootB')]
    view = neighbourhood(snap, 'newer', roots, direction='out', max_nodes=100, max_edges=500)
    assert len(view.nodes) == 66 and len(view.edges) == 128
    assert {marker.node: marker.count for marker in view.more} == {root: 1 for root in roots}
    assert {node.label for node in snap.newer.nodes} - {node.label for node in view.nodes} == {'Leaf64'}
    assert view.truncated and any('capped' in note for note in view.limitations)
    assert all('2 nodes' not in note for note in view.limitations)


def test_duplicate_claims_and_shared_neighbours_below_cap_remain_complete():
    snap = _merged_snapshot(64, repeats=3)
    roots = [find_node(snap, 'newer', name).id for name in ('RootA', 'RootB')]
    view = neighbourhood(snap, 'newer', roots, direction='out', max_nodes=100, max_edges=500)
    assert len(view.nodes) == 66 and len(view.edges) == 128
    assert not view.truncated and not view.more
    assert not any('capped' in note for note in view.limitations)


@pytest.mark.parametrize('format_', ['dot', 'json'])
def test_actual_cli_export_and_neighbours_return_partial_for_cycle_hub(tmp_path, format_):
    root = make_project(tmp_path / 'project', build_fixture('cycle_hub'))
    neighbours = run('neighbours', str(root), '--name', 'TraceMessageHub', '--side', 'newer', '--json')
    assert neighbours.code == 3 and neighbours.document['status'] == 'partial'
    assert neighbours.document['result']['views'][0]['truncated']
    target = tmp_path / f'graph.{format_}'
    exported = run('export', str(root), '--match', match_id(root, 'TraceMessageHub'), '--format', format_,
                   '--output', str(target), '--json')
    assert exported.code == 3 and exported.document['status'] == 'partial'
    assert exported.document['result']['truncated']
    assert 'capped' in target.read_text()
