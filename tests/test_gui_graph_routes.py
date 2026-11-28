"""Optional bounded route values leave the existing graph canvas port compatible."""
from __future__ import annotations

import pytest

from patchtrace.gui.graph_view import GraphEdgeView, GraphNodeView, validate_graph


def test_straight_edge_default_and_immutable_route_endpoints():
    assert GraphEdgeView('a', 'b', 'call').points == ()
    points = ((1.0, 2), (3, 4), (5, 6.0))
    edge = GraphEdgeView('a', 'b', 'back', points)
    assert edge.points == points and edge.source == 'a' and edge.target == 'b'
    validate_graph([GraphNodeView('a', 'a', 0, 0), GraphNodeView('b', 'b', 10, 10)], [edge])
    with pytest.raises(AttributeError):
        edge.points = ()


@pytest.mark.parametrize('points', [
    [(0, 0), (1, 1)], ((0, 0), [1, 1]), ((0, 0),), ((0, 0),) * 17,
    ((0, 0), (1,)), ((0, 0), (1, 2, 3)), ((0, 0), ('1', 2)), ((0, 0), (True, 1)),
    ((0, 0), (float('nan'), 1)), ((0, 0), (1, float('inf'))), ((0, 0), (1, -float('inf'))),
    ((0, 0), (10**1_000, 1)), None,
])
def test_mutable_malformed_nonfinite_and_oversized_routes_are_rejected(points):
    with pytest.raises(ValueError):
        GraphEdgeView('a', 'b', points=points)


def test_route_at_the_point_limit_is_accepted():
    edge = GraphEdgeView('a', 'b', points=tuple((i, i) for i in range(16)))
    assert len(edge.points) == 16
