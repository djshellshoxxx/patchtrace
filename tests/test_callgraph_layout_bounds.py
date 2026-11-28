"""Bounded work and deterministic completion for the pure Calls layout (WB2 G6)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace.callgraph import layout as lay
from patchtrace.callgraph.limits import GraphError


class Repeating:
    def __init__(self, value):
        self.value, self.reads = value, 0

    def __iter__(self):
        while True:
            self.reads += 1
            yield self.value


def test_pre_cancel_does_not_consume_even_one_input():
    source = Repeating('seed')
    with pytest.raises(GraphError) as caught:
        lay.layout_graph(source, (), 'seed', cancel=lambda: True)
    assert caught.value.code == 'PT-GRAPH-CANCEL' and source.reads == 0


@pytest.mark.parametrize('kind,limit', [('nodes', 2_000), ('edges', 8_000)])
def test_unbounded_iterables_stop_at_raw_input_ceiling(kind, limit):
    source = Repeating('seed' if kind == 'nodes' else ('unknown', 'unknown'))
    with pytest.raises(GraphError) as caught:
        lay.layout_graph(source if kind == 'nodes' else ['seed'], source if kind == 'edges' else (), 'seed')
    assert caught.value.code == 'PT-GRAPH-LAYOUT-LIMIT'
    assert source.reads == limit + 1  # duplicates and dangling endpoints still cost admission work


def test_cancel_during_input_stops_before_the_input_limit():
    source = Repeating('seed')
    with pytest.raises(GraphError) as caught:
        lay.layout_graph(source, (), 'seed', cancel=lambda: source.reads >= 100)
    assert caught.value.code == 'PT-GRAPH-CANCEL' and source.reads < 200


@pytest.mark.parametrize('name,value', [
    ('max_nodes', False), ('max_nodes', 0), ('max_nodes', 1.5),
    ('max_dummies', True), ('max_dummies', -1), ('sweeps', False), ('sweeps', -1),
    ('half_depth', -1), ('half_depth', 2.5), ('budget_ms', 0), ('budget_ms', float('inf')),
])
def test_budget_arguments_reject_invalid_values(name, value):
    with pytest.raises(GraphError) as caught:
        lay.layout_graph(['s'], [], 's', **{name: value})
    assert caught.value.code == 'PT-GRAPH-INPUT'


def test_budget_requests_cannot_raise_hard_caps():
    ids = ['s', 'a', 'b', 'x', 'y']
    edges = [('s', 'a'), ('s', 'b'), ('a', 'y'), ('b', 'x')]
    assert lay.layout_graph(ids, edges, 's') == lay.layout_graph(
        ids, edges, 's', max_nodes=10**9, max_dummies=10**9, sweeps=10**9, half_depth=10**9, budget_ms=10**9)


def test_deadline_is_checked_during_input_without_a_partial_result(monkeypatch):
    source = Repeating('s')
    monkeypatch.setattr(lay, 'monotonic', lambda: source.reads / 100)
    with pytest.raises(GraphError) as caught:
        lay.layout_graph(source, (), 's', budget_ms=100)
    assert caught.value.code == 'PT-GRAPH-LAYOUT-LIMIT' and source.reads < 100


@pytest.mark.parametrize('phase', ['_assign_layers', '_build', '_order', '_coordinates', '_emit'])
@pytest.mark.parametrize('reason', ['cancel', 'deadline'])
def test_later_phases_honour_abort_without_emitting_partial_geometry(monkeypatch, phase, reason):
    entered = False
    original = getattr(lay, phase)

    def enter(*args, **kwargs):
        nonlocal entered
        entered = True
        return original(*args, **kwargs)

    monkeypatch.setattr(lay, phase, enter)
    monkeypatch.setattr(lay, 'monotonic', lambda: 1.0 if entered and reason == 'deadline' else 0.0)
    with pytest.raises(GraphError) as caught:
        lay.layout_graph(['s', 'a', 'b'], [('s', 'a'), ('a', 'b')], 's',
                         cancel=lambda: entered and reason == 'cancel')
    assert entered
    assert caught.value.code == ('PT-GRAPH-CANCEL' if reason == 'cancel' else 'PT-GRAPH-LAYOUT-LIMIT')


def test_zero_dummy_budget_drops_only_spanning_routes():
    ids = ['s', 'a', 'b', 'p']
    edges = [('p', 's'), ('s', 'a'), ('a', 'b'), ('p', 'b')]
    result = lay.layout_graph(ids, edges, 's', max_dummies=0)
    assert {(e.src, e.dst) for e in result.edges} == set(edges) - {('p', 'b')}
    assert result.notes == (lay.LayoutNote('long-edges', 1, 0),)


def test_small_node_cap_keeps_seed_before_an_earlier_same_layer_sibling():
    result = lay.layout_graph(['seed', 'a-sibling', 'caller'],
                              [('caller', 'seed'), ('caller', 'a-sibling')], 'seed', max_nodes=1)
    assert [node.id for node in result.nodes] == ['seed']
    assert result.notes == (lay.LayoutNote('nodes', 2, 1),)


@pytest.mark.parametrize('nodes,edges', [([1], []), ([''], []), (['s'], [('s',)]),
                                      (['s'], [('s', 1)]), (['s'], ['ss'])])
def test_malformed_input_has_a_typed_failure(nodes, edges):
    with pytest.raises(GraphError) as caught:
        lay.layout_graph(nodes, edges, 's')
    assert caught.value.code == 'PT-GRAPH-INPUT'


def test_routes_are_inside_reported_bounds_even_for_self_and_same_layer():
    ids = ['s', 'a', 'b', 'c']
    result = lay.layout_graph(ids, [('s', 'a'), ('s', 'b'), ('a', 'b'), ('b', 'a'),
                                    ('a', 'c'), ('c', 's'), ('s', 's')], 's')
    assert {'same-layer', 'self'} <= {e.kind for e in result.edges}
    assert all(0 <= x <= result.width and 0 <= y <= result.height for e in result.edges for x, y in e.points)


def test_hash_order_does_not_change_geometry(tmp_path):
    source = Path(__file__).resolve().parents[1] / 'src'
    script = """from dataclasses import asdict
import json
from patchtrace.callgraph.layout import layout_graph
nodes = {'s', 'a', 'b', 'x', 'y'}
edges = {('s', 'a'), ('s', 'b'), ('a', 'y'), ('b', 'x'), ('y', 's')}
print(json.dumps(asdict(layout_graph(nodes, edges, 's')), sort_keys=True))
"""
    outputs = []
    for seed in ('0', '17'):
        env = dict(os.environ, PYTHONPATH=str(source), PYTHONHASHSEED=seed)
        result = subprocess.run([sys.executable, '-c', script], env=env, cwd=tmp_path, capture_output=True,
                                text=True, check=True, timeout=10)
        outputs.append(json.loads(result.stdout))
    assert outputs[0] == outputs[1]
