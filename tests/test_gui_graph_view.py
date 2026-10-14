"""GUI slice F6b: the pure graph values (GUI plan 8.4). No Qt; the isolation test also covers this module."""
from __future__ import annotations

import pytest

from patchtrace.gui import graph_view as gv
from patchtrace.gui.graph_view import GraphEdgeView, GraphNodeView, GraphTooLargeError


def grid(columns: int, rows: int) -> list[GraphNodeView]:
    return [GraphNodeView(f'n{r}_{c}', f'node {r} {c}', c * 100.0, r * 60.0) for r in range(rows) for c in range(columns)]


@pytest.mark.parametrize('nodes,edges,ok', [(500, 2000, True), (501, 0, False), (1, 2001, False)],
                         ids=['at', 'nodes', 'edges'])
def test_default_ceilings(nodes, edges, ok):
    views = [GraphNodeView(f'n{i}', 'x', 0, 0) for i in range(nodes)]
    links = [GraphEdgeView('n0', 'n0')] * edges
    if ok:
        gv.validate_graph(views, links)
        return
    with pytest.raises(GraphTooLargeError) as caught:
        gv.validate_graph(views, links)
    assert caught.value.code == 'PT-GUI-GRAPH-TOO-LARGE' and 'PT-GUI-GRAPH-TOO-LARGE' in str(caught.value)


@pytest.mark.parametrize('limits', [(0, 10), (2_001, 10), (10, 8_001), (10, 0)], ids=['n0', 'nmax', 'emax', 'e0'])
def test_ceilings_stay_within_the_framework_maximum(limits):
    with pytest.raises(ValueError):
        gv.check_ceilings(*limits)
    gv.check_ceilings(2_000, 8_000)


def test_duplicate_keys_and_dangling_edges_are_rejected():
    with pytest.raises(ValueError, match='duplicate'):
        gv.validate_graph([GraphNodeView('a', 'a', 0, 0), GraphNodeView('a', 'b', 1, 1)], [])
    with pytest.raises(ValueError, match='missing'):
        gv.validate_graph([GraphNodeView('a', 'a', 0, 0)], [GraphEdgeView('a', 'z')])


def test_node_text_is_sanitized_and_tokens_checked():
    node = GraphNodeView('k', 'a\x00b‮rev', 0, 0, description='x\x1b[31m')
    assert '\x00' not in node.label and '‮' not in node.label and '\x1b' not in node.description
    with pytest.raises(ValueError):
        GraphNodeView('k', 'x', 0, 0, chip='nope')
    with pytest.raises(ValueError):
        GraphNodeView('', 'x', 0, 0)


@pytest.mark.parametrize('zoom,level', [(0.05, 'mark'), (0.1499, 'mark'), (0.15, 'box'), (0.4999, 'box'),
                                        (0.5, 'label'), (8, 'label')],
                         ids=['min', 'markmax', 'box', 'boxmax', 'label', 'max'])
def test_detail_level(zoom, level):
    assert gv.detail_level(zoom) == level


@pytest.mark.parametrize('zoom,clamped', [(0, 0.05), (1, 1), (99, 8)], ids=['low', 'mid', 'high'])
def test_zoom_clamp(zoom, clamped):
    assert gv.clamp_zoom(zoom) == clamped


def test_antialiasing_is_off_above_200_items():
    assert gv.antialias(200) and not gv.antialias(201)


@pytest.mark.parametrize('current,direction,expected', [
    ('n1_1', 'left', 'n1_0'), ('n1_1', 'right', 'n1_2'), ('n1_1', 'up', 'n0_1'), ('n1_1', 'down', 'n2_1'),
    ('n0_0', 'up', None), ('n0_0', 'left', None), ('n2_2', 'down', None)],
    ids=['left', 'right', 'up', 'down', 'top', 'edge', 'bottom'])
def test_arrows_follow_rows_and_columns(current, direction, expected):
    points = {n.key: (n.x, n.y) for n in grid(3, 3)}
    assert gv.nearest_in_direction(points, current, direction) == expected


def test_nearest_prefers_alignment_and_breaks_ties_by_key():
    points = {'a': (0, 0), 'near_off': (50, 90), 'far_on': (150, 0), 'b': (100, 0), 'c': (100, 0)}
    assert gv.nearest_in_direction(points, 'a', 'right') == 'b'
    with pytest.raises(ValueError):
        gv.nearest_in_direction(points, 'a', 'sideways')


def test_first_node_is_top_left_and_adjacency_counts_both_ends():
    assert gv.first_node({'b': (5, 0), 'a': (9, 0), 'c': (0, 5)}) == 'b'
    assert gv.first_node({}) is None
    counts = gv.adjacency([GraphEdgeView('a', 'b'), GraphEdgeView('b', 'c')])
    assert counts == {'a': 1, 'b': 2, 'c': 1}
