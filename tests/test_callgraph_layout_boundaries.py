"""Hostile graph work bounds and cancellation, independent of rendered labels."""
from __future__ import annotations

import pytest

from patchtrace.callgraph import layout as lay
from patchtrace.callgraph.limits import GraphError


@pytest.mark.parametrize('name', ['max_nodes', 'max_dummies', 'sweeps', 'half_depth'])
@pytest.mark.parametrize('value', [-1, True, False, 1.5, '2', None])
def test_invalid_budgets_fail_before_consuming_input(name, value):
    def untouched():
        raise AssertionError('invalid budgets must not consume input')
        yield 'seed'
    with pytest.raises(GraphError, match='PT-GRAPH-INPUT'):
        lay.layout_graph(untouched(), (), 'seed', **{name: value})


def test_zero_node_budget_is_invalid_but_other_zero_budgets_keep_the_seed():
    with pytest.raises(GraphError, match='PT-GRAPH-INPUT'):
        lay.layout_graph(['seed'], (), 'seed', max_nodes=0)
    result = lay.layout_graph(['seed', 'callee'], [('seed', 'callee')], 'seed',
                              max_dummies=0, sweeps=0, half_depth=0)
    assert [node.id for node in result.nodes] == ['seed']
    assert result.notes == (lay.LayoutNote('depth', 1, 0),)


def test_depth_and_sweep_budgets_cannot_raise_hard_limits():
    nodes = [f'n{i}' for i in range(9)]
    edges = list(zip(nodes, nodes[1:], strict=False))
    assert lay.layout_graph(nodes, edges, 'n0', half_depth=10**100, sweeps=10**100) == (
        lay.layout_graph(nodes, edges, 'n0', half_depth=lay.LAYOUT_HALF_DEPTH, sweeps=lay.LAYOUT_SWEEPS))


def test_the_seed_survives_a_tiny_node_budget_with_shared_caller_peers():
    result = lay.layout_graph(['a', 'parent', 'seed'], [('parent', 'seed'), ('parent', 'a')],
                              'seed', max_nodes=1)
    assert [node.id for node in result.nodes] == ['seed']
    assert result.notes == (lay.LayoutNote('nodes', 2, 1),)


def test_duplicate_node_items_count_towards_the_input_limit(monkeypatch):
    monkeypatch.setattr(lay, 'LAYOUT_INPUT_NODES', 5)
    seen = []

    def duplicates():
        for i in range(6):
            seen.append(i)
            yield 'seed'
        raise AssertionError('consumed past the rejecting item')

    with pytest.raises(GraphError, match='PT-GRAPH-LIMIT'):
        lay.layout_graph(duplicates(), (), 'seed')
    assert len(seen) == 6


@pytest.mark.parametrize('edge', [('seed', 'seed'), ('outside', 'missing')])
def test_duplicate_and_dangling_edges_count_towards_the_input_limit(monkeypatch, edge):
    monkeypatch.setattr(lay, 'LAYOUT_INPUT_EDGES', 5)
    seen = []

    def duplicates():
        for i in range(6):
            seen.append(i)
            yield edge
        raise AssertionError('consumed past the rejecting item')

    with pytest.raises(GraphError, match='PT-GRAPH-LIMIT'):
        lay.layout_graph(['seed'], duplicates(), 'seed')
    assert len(seen) == 6


@pytest.mark.parametrize('node', ['', None, 7, ['seed'], 'n' * 513])
def test_invalid_node_identity_is_rejected(node):
    with pytest.raises(GraphError, match='PT-GRAPH-INPUT'):
        lay.layout_graph(['seed', node], (), 'seed')


@pytest.mark.parametrize('edge', ['ab', ('seed',), ('seed', 'seed', 'seed'), (None, 'seed'), (3, 'seed')])
def test_malformed_edges_have_a_controlled_failure(edge):
    with pytest.raises(GraphError, match='PT-GRAPH-INPUT'):
        lay.layout_graph(['seed'], [edge], 'seed')


def test_cancelled_layout_never_starts_input_iteration():
    def untouched():
        raise AssertionError('already cancelled input was consumed')
        yield 'seed'

    with pytest.raises(GraphError, match='PT-GRAPH-CANCEL'):
        lay.layout_graph(untouched(), (), 'seed', cancel=lambda: True)


@pytest.mark.parametrize('which', ['nodes', 'edges'])
def test_cancellation_stops_a_duplicate_stream_within_one_check_interval(which):
    seen = []

    def stream():
        for i in range(1000):
            seen.append(i)
            yield 'seed' if which == 'nodes' else ('seed', 'seed')
        raise AssertionError('cancellation did not stop iteration')

    inputs = (stream(), ()) if which == 'nodes' else (['seed'], stream())
    with pytest.raises(GraphError, match='PT-GRAPH-CANCEL'):
        lay.layout_graph(*inputs, 'seed', cancel=lambda: len(seen) >= 20)
    assert 20 <= len(seen) <= 20 + lay.CANCEL_CLAIM_INTERVAL
