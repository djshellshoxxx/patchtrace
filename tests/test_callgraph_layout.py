"""Call-graph layout: determinism, no overlap, budgets, cycles, minimap and keyboard order (WB2 G6)."""
from __future__ import annotations

import random

import pytest

from patchtrace.callgraph import layout as lay
from patchtrace.callgraph.contracts import GraphEdge, GraphNode, GraphView, SourceInfo
from patchtrace.callgraph.limits import GraphError

HOSTILE = ['a"b', 'c\\d', '\\N', 'x\ny', '‮evil', 'z\x00z', '<b>x</b>', '{0}', '%s']


def _star():
    # callers p1 p2 -> seed -> c1 c2 c3, c1 -> leaf, p1 -> c3 (a long edge)
    edges = [('p1', 'seed'), ('p2', 'seed'), ('seed', 'c1'), ('seed', 'c2'), ('seed', 'c3'), ('c1', 'leaf'),
             ('p1', 'c3')]
    ids = sorted({x for e in edges for x in e})
    return ids, edges


def _random_graph(rng: random.Random, n: int = 30):
    ids = [f'n{i:02d}' for i in range(n)]
    edges = [(rng.choice(ids), rng.choice(ids)) for _ in range(2 * n)]
    return ids, edges


def _assert_no_overlap(layout: lay.Layout) -> None:
    by_layer: dict[int, list[lay.LayoutNode]] = {}
    for node in layout.nodes:
        by_layer.setdefault(node.layer, []).append(node)
    for nodes in by_layer.values():
        assert len({n.x for n in nodes}) == 1
        nodes.sort(key=lambda n: n.y)
        for upper, lower in zip(nodes, nodes[1:], strict=False):
            assert lower.y >= upper.y + upper.h + lay.ROW_GAP


def test_layers_are_signed_hops_from_the_seed():
    ids, edges = _star()
    result = lay.layout_graph(ids, edges, 'seed')
    layer = {n.id: n.layer for n in result.nodes}
    assert layer == {'seed': 0, 'p1': -1, 'p2': -1, 'c1': 1, 'c2': 1, 'c3': 1, 'leaf': 2}
    x = {n.id: n.x for n in result.nodes}
    assert x['p1'] < x['seed'] < x['c1'] < x['leaf']
    assert not result.truncated and result.notes == ()
    _assert_no_overlap(result)


def test_long_edge_gets_a_polyline_through_the_skipped_layer():
    ids, edges = _star()
    edge = next(e for e in lay.layout_graph(ids, edges, 'seed').edges if (e.src, e.dst) == ('p1', 'c3'))
    assert edge.kind == 'forward' and len(edge.points) == 3  # one dummy for layer 0
    xs = [p[0] for p in edge.points]
    assert xs == sorted(xs)


def test_output_is_independent_of_input_order():
    rng = random.Random(7)
    ids, edges = _random_graph(rng)
    first = lay.layout_graph(ids, edges, 'n00')
    shuffled_ids, shuffled_edges = ids[:], edges[:]
    rng.shuffle(shuffled_ids)
    rng.shuffle(shuffled_edges)
    again = lay.layout_graph(iter(shuffled_ids), iter(shuffled_edges + shuffled_edges), 'n00')
    assert first == again


@pytest.mark.parametrize('seed', range(8), ids=[f's{i}' for i in range(8)])
def test_random_graphs_never_overlap_and_stay_in_bounds(seed):
    ids, edges = _random_graph(random.Random(seed))
    result = lay.layout_graph(ids, edges, 'n00')
    _assert_no_overlap(result)
    for node in result.nodes:
        assert node.x >= 0 and node.y >= 0
        assert node.x + node.w <= result.width and node.y + node.h <= result.height
    ids_out = {n.id for n in result.nodes}
    assert all(e.src in ids_out and e.dst in ids_out for e in result.edges)


def test_cycles_self_loops_and_same_layer_calls_are_kept_and_typed():
    edges = [('a', 'b'), ('b', 'c'), ('c', 'a'), ('b', 'b'), ('b', 'd'), ('b', 'e'), ('d', 'e'), ('e', 'd')]
    result = lay.layout_graph('abcde', edges, 'a')
    kinds = {(e.src, e.dst): e.kind for e in result.edges}
    assert {n.id: n.layer for n in result.nodes} == {'a': 0, 'b': 1, 'c': -1, 'd': 2, 'e': 2}
    assert kinds[('b', 'c')] == 'back' and kinds[('c', 'a')] == 'forward'
    assert kinds[('b', 'b')] == 'self'
    assert {kinds[('d', 'e')], kinds[('e', 'd')]} == {'same-layer'}
    assert len(result.edges) == len(set(edges))
    back = next(e for e in result.edges if (e.src, e.dst) == ('b', 'c'))
    assert back.points[0][0] > back.points[-1][0]  # drawn from the callee side back to the caller
    _assert_no_overlap(result)


def test_propagated_layers_for_nodes_reached_through_a_shared_caller():
    edges = [('top', 'seed'), ('top', 'sibling')]
    layer = {n.id: n.layer for n in lay.layout_graph(['seed', 'sibling', 'top'], edges, 'seed').nodes}
    assert layer == {'seed': 0, 'top': -1, 'sibling': 0}


def test_node_budget_truncates_by_distance_and_reports_it():
    edges = [('s', f'c{i:02d}') for i in range(10)] + [('c00', 'deep')]
    ids = ['s', 'deep', *(f'c{i:02d}' for i in range(10))]
    result = lay.layout_graph(ids, edges, 's', max_nodes=5)
    assert [n.id for n in result.nodes] == ['c00', 'c01', 'c02', 'c03', 's']
    assert result.notes == (lay.LayoutNote('nodes', 7, 5),)
    assert result.truncated


def test_hard_node_cap_cannot_be_raised():
    ids = ['s', *(f'c{i:04d}' for i in range(2_100))]
    result = lay.layout_graph(ids, [('s', i) for i in ids[1:]], 's', max_nodes=10**6)
    assert len(result.nodes) == lay.LAYOUT_NODES_HARD
    assert result.notes[0].dropped == 2_101 - lay.LAYOUT_NODES_HARD


def test_depth_and_disconnected_nodes_are_reported():
    chain = [(f'n{i}', f'n{i + 1}') for i in range(8)]
    result = lay.layout_graph([*(f'n{i}' for i in range(9)), 'island'], chain, 'n0', half_depth=3)
    assert [n.layer for n in result.nodes] == [0, 1, 2, 3]
    assert result.notes == (lay.LayoutNote('disconnected', 1, 0), lay.LayoutNote('depth', 5, 3))


def test_dummy_budget_drops_the_longest_edges_and_says_so():
    edges = [('s', 'a'), ('a', 'b'), ('b', 'c'), ('p', 's'), ('p', 'c'), ('p', 'b')]
    ids = ['s', 'a', 'b', 'c', 'p']
    full = lay.layout_graph(ids, edges, 's')
    assert full.notes == () and len(full.edges) == 6
    result = lay.layout_graph(ids, edges, 's', max_dummies=2)
    kept = {(e.src, e.dst) for e in result.edges}
    assert ('p', 'c') not in kept and ('p', 'b') in kept
    assert result.notes == (lay.LayoutNote('long-edges', 1, 2),)


def test_seed_must_exist_and_cancel_is_honoured():
    with pytest.raises(GraphError) as bad:
        lay.layout_graph(['a'], [], 'missing')
    assert bad.value.code == 'PT-GRAPH-INPUT'
    ids, edges = _star()
    with pytest.raises(GraphError) as cancelled:
        lay.layout_graph(ids, edges, 'seed', cancel=lambda: True)
    assert cancelled.value.code == 'PT-GRAPH-CANCEL'


def test_barycentre_sweeps_untangle_a_crossed_pair():
    edges = [('s', 'a'), ('s', 'b'), ('a', 'y'), ('b', 'x')]  # ids sort x before y: the first order crosses
    result = lay.layout_graph(['s', 'a', 'b', 'x', 'y'], edges, 's')
    y = {n.id: n.y for n in result.nodes}
    assert (y['a'] < y['b']) == (y['y'] < y['x'])


def test_hostile_ids_pass_through_untouched_and_layout_reads_no_text():
    edges = [('seed', h) for h in HOSTILE]
    result = lay.layout_graph(['seed', *HOSTILE], edges, 'seed')
    assert sorted(n.id for n in result.nodes) == sorted(['seed', *HOSTILE])
    assert sorted(e.dst for e in result.edges) == sorted(HOSTILE)
    _assert_no_overlap(result)


def test_minimap_fits_and_round_trips_clicks():
    ids, edges = _star()
    result = lay.layout_graph(ids, edges, 'seed')
    mini = lay.minimap_for(result)
    x1, y1 = mini.to_map(result.width, result.height)
    x0, y0 = mini.to_map(0, 0)
    assert 0 <= x0 < x1 <= lay.MINIMAP_SIZE[0] and 0 <= y0 < y1 <= lay.MINIMAP_SIZE[1]
    sx, sy = mini.to_scene(*mini.to_map(100, 40))
    assert (round(sx), round(sy)) == (100, 40)
    assert mini.to_scene(-50, -50) == (0.0, 0.0)
    assert mini.to_scene(10_000, 10_000) == (float(result.width), float(result.height))
    rect = mini.viewport_rect(0, 0, 200, 100)
    assert rect[2] == pytest.approx(200 * mini.scale)


def test_minimap_of_an_empty_extent_does_not_divide_by_zero():
    empty = lay.Layout('s', (), (), 0, 0, ())
    assert lay.minimap_for(empty).scale > 0


def test_keyboard_neighbours_follow_arrows_and_break_ties_by_id():
    ids, edges = _star()
    result = lay.layout_graph(ids, edges, 'seed')
    assert lay.neighbour_in_direction(result, 'seed', 'left') in {'p1', 'p2'}
    assert lay.neighbour_in_direction(result, 'p1', 'right') == 'seed'
    assert lay.neighbour_in_direction(result, 'c1', 'right') == 'leaf'
    assert lay.neighbour_in_direction(result, 'leaf', 'right') is None
    assert lay.neighbour_in_direction(result, 'nope', 'up') is None
    c = {'c1', 'c2', 'c3'}
    seen, node = [], 'c1'
    for _ in range(3):
        nxt = lay.neighbour_in_direction(result, node, 'down')
        if nxt is None or nxt not in c:
            break
        seen.append(nxt)
        node = nxt
    assert len(set(seen)) == len(seen)


def test_layout_view_uses_graph_view_nodes_and_edges():
    nodes = tuple(GraphNode(id=f'n{i}', side='newer', kind='function', label=f'<b>{i}</b>', via='emitted-record',
                            tier='record') for i in range(3))
    edges = (GraphEdge(id='e0', src='n0', dst='n1', side='newer', support=('called',)),
             GraphEdge(id='e1', src='n1', dst='n2', side='newer', support=('called',)),
             GraphEdge(id='e2', src='n2', dst='ghost', side='newer', support=('called',)))
    view = GraphView(project_id='p', run_id='r', older_sha256='a', newer_sha256='b', side='newer', nodes=nodes,
                     edges=edges, completeness='changed-set-lists',
                     source=SourceInfo(source_id='t', version='1', tier='labels'))
    result = lay.layout_view(view, 'n1')
    assert {n.id: n.layer for n in result.nodes} == {'n0': -1, 'n1': 0, 'n2': 1}
    assert len(result.edges) == 2
