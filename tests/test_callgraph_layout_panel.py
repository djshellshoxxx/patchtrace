"""The existing query owns layout; diagram limits cannot change graph evidence."""
from __future__ import annotations

from test_callgraph_inspection import loaded, neighbourhood

from patchtrace.callgraph import layout as lay
from patchtrace.callgraph import panel_data as pd
from patchtrace.callgraph.contracts import MoreMarker
from patchtrace.callgraph.limits import GraphError


def test_query_returns_completed_geometry_and_cached_position_helpers():
    _, data = loaded()
    found = neighbourhood(data)
    assert isinstance(found.diagram, lay.Layout)
    assert found.diagram == lay.layout_view(found.view, found.focus_id)
    assert pd.layers(found) == {n.id: n.layer for n in found.diagram.nodes}
    assert pd.positions(found) == {n.id: (n.x + n.w / 2, n.y + n.h / 2) for n in found.diagram.nodes}
    assert pd.diagram_notice(found) == ''


def test_diagram_timeout_preserves_rows_graph_and_export(monkeypatch):
    _, data = loaded()
    before = neighbourhood(data)

    def timeout(*_args, **_kwargs):
        raise GraphError('PT-GRAPH-LAYOUT-LIMIT', 'the diagram layout reached its time limit')

    monkeypatch.setattr(pd, 'layout_view', timeout)
    after = neighbourhood(data)
    assert isinstance(after.diagram, pd.Failure)
    assert (after.view, after.rows, after.total) == (before.view, before.rows, before.total)
    assert pd.dot_text(data, after) == pd.dot_text(data, before)
    assert 'time limit' in pd.diagram_notice(after) and 'Neighbours' in pd.diagram_notice(after)
    assert pd.positions(after) == {} and pd.layers(after) == {}


def test_layout_node_omissions_do_not_remove_nodes_from_table_or_dot(monkeypatch):
    _, data = loaded()
    before = neighbourhood(data)
    monkeypatch.setattr(pd, 'layout_view', lambda view, seed, **kw: lay.layout_view(view, seed, max_nodes=1, **kw))
    after = neighbourhood(data)
    assert len(after.diagram.nodes) == 1 and after.diagram.nodes[0].id == after.focus_id
    assert (after.view, after.rows, after.total) == (before.view, before.rows, before.total)
    assert pd.dot_text(data, before) == pd.dot_text(data, after)
    assert 'nodes' in pd.diagram_notice(after) and 'Diagram omits' in pd.diagram_notice(after)


def test_layout_failure_preserves_truncation_and_more_markers(monkeypatch):
    _, data = loaded()
    original = pd.neighbourhood

    def capped(*args, **kwargs):
        view = original(*args, **kwargs)
        return view.model_copy(update={'truncated': True, 'more': (MoreMarker(node=view.nodes[0].id, count=27),)})

    def timeout(*args, **kwargs):
        raise GraphError('PT-GRAPH-LAYOUT-LIMIT', 'the diagram layout reached its time limit')

    monkeypatch.setattr(pd, 'neighbourhood', capped)
    monkeypatch.setattr(pd, 'layout_view', timeout)
    found = neighbourhood(data)
    assert found.view.truncated and found.view.more[0].count == 27
    exported = pd.dot_export(data, found)
    assert exported.truncated and exported.newer.more == found.view.more


def test_layout_cancellation_is_query_cancellation_not_a_diagram_only_failure(monkeypatch):
    _, data = loaded()
    before = neighbourhood(data)

    def cancelled(*args, **kwargs):
        raise GraphError('PT-GRAPH-CANCEL', 'cancelled')

    monkeypatch.setattr(pd, 'layout_view', cancelled)
    result = pd.query(data, before.spec, lambda: False)
    assert result == pd.Failure('PT-GRAPH-CANCEL', 'cancelled')
