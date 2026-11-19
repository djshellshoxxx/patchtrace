"""Capped export reasons reach each public format independently of neighbours."""
from __future__ import annotations

import json

import pytest
from callgraph_cli_support import make_project, match_id, run
from callgraph_fixtures import build_fixture
from callgraph_graph_support import snapshot
from test_callgraph_cap_truth import _merged_snapshot

from patchtrace.callgraph.dot import render_dot
from patchtrace.callgraph.export_json import build_export, to_json
from patchtrace.callgraph.query import find_node, neighbourhood

CAP_NOTE = 'The view is capped; some nodes or edges may be omitted.'


def test_paired_export_retains_the_cap_reason_once_even_when_both_sides_are_capped():
    snap = snapshot('cycle_hub')
    hub = find_node(snap, 'newer', 'TraceMessageHub')
    exported = build_export(snap, hub.match_id)
    assert exported.truncated  # Already true before the repair; test the omitted reason independently.
    assert exported.limitations.count(CAP_NOTE) == 1
    document = json.loads(to_json(exported))
    assert document['limitations'].count(CAP_NOTE) == 1
    for side in ('older', 'newer'):
        assert document[side]['truncated']
        assert CAP_NOTE in document[side]['limitations']


@pytest.mark.parametrize('format_', ['dot', 'json'])
def test_cli_export_includes_partial_reason_without_first_running_neighbours(tmp_path, format_):
    root = make_project(tmp_path / 'project', build_fixture('cycle_hub'))
    target = tmp_path / f'partial.{format_}'
    exported = run('export', str(root), '--match', match_id(root, 'TraceMessageHub'), '--format', format_,
                   '--output', str(target), '--json')
    assert exported.code == 3 and exported.document['status'] == 'partial'
    assert exported.document['result']['truncated']
    text = target.read_text()
    if format_ == 'json':
        data = json.loads(text)
        assert data['limitations'].count(CAP_NOTE) == 1
        assert data['older']['truncated'] and data['newer']['truncated']
    else:
        assert '// Partial graph: ' + CAP_NOTE in text
        assert f'  label="{CAP_NOTE}";' in text


def test_uncapped_export_and_neighbours_keep_complete_flags_and_original_coverage():
    snap = snapshot('svc_pair')
    focus = find_node(snap, 'newer', 'DriverEntry')
    view = neighbourhood(snap, 'newer', [focus.id])
    exported = build_export(snap, focus.match_id)
    assert not view.truncated and not exported.truncated
    assert view.completeness == snap.completeness
    assert CAP_NOTE not in view.limitations and CAP_NOTE not in exported.limitations
    assert CAP_NOTE not in render_dot(exported)


def test_distinct_roots_over_budget_still_report_truncation():
    snap = _merged_snapshot(0)
    a, b = (find_node(snap, 'newer', name).id for name in ('RootA', 'RootB'))
    view = neighbourhood(snap, 'newer', [a, a, b, b], depth=0, max_nodes=1)
    assert tuple(node.id for node in view.nodes) == (a,)
    assert view.truncated and not view.more
    assert CAP_NOTE in view.limitations
