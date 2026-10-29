"""WB2 G8: whole-program call sources (program-ir/1 reader, BinExport2 call graph) on synthetic graphs."""
from __future__ import annotations

import random
from types import SimpleNamespace as NS

import pytest
from binexport_builder import cls, valid
from callgraph_graph_support import graph_input

from patchtrace.callgraph.csr import build_csr
from patchtrace.callgraph.limits import GraphError
from patchtrace.callgraph.snapshot import build_snapshot
from patchtrace.callgraph.source_binexport import BinExportCallSource
from patchtrace.callgraph.source_ir import IrCallSource
from patchtrace.unified.ir.reader import CallRow

BASE = 0x140000000


class FakeIr:
    """Duck-typed `IrReader`: functions with names, rvas and per-function call rows."""

    def __init__(self, rvas, names, calls):
        self.functions = NS(n=len(rvas), name=list(names), rva=list(rvas))
        self._calls = calls

    def calls(self, fid):
        return [CallRow(site, callee, key, kind) for site, callee, key, kind in self._calls.get(fid, ())]


def _ir():
    # 0 named root, 1 unnamed, 2 named, 3 unnamed (never called)
    return FakeIr([0x1000, 0x1100, 0x1200, 0x1300], ['root', None, 'leaf', None],
                  {0: [(1, 1, None, 'call'), (2, 2, None, 'jump'), (3, None, 'kernel32.dll!CreateFileW', 'call')],
                   1: [(5, 2, None, 'call'), (6, 2, None, 'call')], 2: [(7, 0, None, 'call')]})


def _ir_source(**kwargs):
    return IrCallSource({'older': _ir(), 'newer': _ir()}, {'older': BASE, 'newer': BASE}, **kwargs)


def test_ir_claims_use_names_and_default_addresses():
    source = _ir_source()
    pairs = {(c.caller, c.callee, c.support) for c in source.claims('newer', None)}
    assert pairs >= {('root', 'FUN_140001100', 'called'), ('FUN_140001100', 'leaf', 'called'),
                     ('root', 'kernel32.dll::CreateFileW', 'called'), ('leaf', 'root', 'called')}
    assert (source.source_id, source.tier, source.completeness) == ('program-ir', 'addresses', 'whole-program')


def test_ir_listed_covers_every_function_but_no_import():
    assert sorted(_ir_source().listed('newer')) == ['FUN_140001100', 'FUN_140001300', 'leaf', 'root']


def test_ir_keeps_call_and_jump_kinds_and_records_the_jump_limitation():
    source = _ir_source()
    list(source.claims('newer', None))
    kinds = source.edge_kinds('newer')
    assert kinds[('root', 'leaf')] == frozenset({'jump'})
    assert kinds[('root', 'FUN_140001100')] == frozenset({'call'})
    assert any('tail-call jump' in note for note in source.limitations)


def test_ir_can_exclude_jumps():
    source = _ir_source(include_jumps=False)
    assert ('root', 'leaf') not in {(c.caller, c.callee) for c in source.claims('newer', None)}
    assert not source.limitations


def _ring():
    return FakeIr(list(range(0, 400, 4)), [None] * 100, {i: [(1, (i + 1) % 100, None, 'call')] for i in range(100)})


def test_ir_edge_cap_is_recorded():
    source = IrCallSource({'older': _ring(), 'newer': _ring()}, {'older': 0, 'newer': 0}, max_edges=10)
    assert len(list(source.claims('newer', None))) == 10
    assert any('capped' in note for note in source.limitations)


def test_ir_cancel_is_honoured(monkeypatch):
    import patchtrace.callgraph.source_ir as module
    monkeypatch.setattr(module, 'CANCEL_CLAIM_INTERVAL', 5)
    source = IrCallSource({'older': _ring(), 'newer': _ring()}, {'older': 0, 'newer': 0})
    with pytest.raises(GraphError) as err:
        list(source.claims('newer', lambda: True))
    assert err.value.code == 'PT-GRAPH-CANCEL'


def _binexport(edges, names=None, extra=None):
    msg = valid(functions=4)
    del msg.call_graph.edge[:]
    for src, dst in edges:
        msg.call_graph.edge.add(source_vertex_index=src, target_vertex_index=dst)
    for index, name in (names or {}).items():
        msg.call_graph.vertex[index].mangled_name = name
    if extra:
        extra(msg)
    return msg


def _bx_source(msg):
    return BinExportCallSource({'older': msg, 'newer': msg})


def test_binexport_claims_use_names_and_addresses_and_record_jump_as_call():
    source = _bx_source(_binexport([(0, 1), (1, 2), (3, 0)], {0: 'main', 1: ''}))
    pairs = {(c.caller, c.callee) for c in source.claims('newer', None)}
    assert pairs == {('main', 'FUN_140001100'), ('FUN_140001100', 'f2'), ('f3', 'main')}
    assert (source.source_id, source.tier, source.completeness) == ('binexport', 'addresses', 'whole-program')
    assert any('jump' in note and 'call' in note for note in source.limitations)
    assert sorted(source.listed('newer')) == ['FUN_140001100', 'f2', 'f3', 'main']


def test_binexport_imported_vertex_becomes_a_library_label():
    def add(msg):
        msg.call_graph.vertex.add(address=0, type=2, mangled_name='CreateFileW', library_index=0)
        msg.library[0].name = 'kernel32.dll'
    source = _bx_source(_binexport([(0, 4)], extra=add))
    assert [(c.caller, c.callee) for c in source.claims('newer', None)] == [('f0', 'kernel32.dll::CreateFileW')]
    assert 'kernel32.dll::CreateFileW' not in set(source.listed('newer'))


def test_binexport_rejects_an_edge_index_out_of_range():
    msg = _binexport([(0, 1)])
    msg.call_graph.edge[0].target_vertex_index = 99
    with pytest.raises(GraphError) as err:
        list(_bx_source(msg).claims('newer', None))
    assert err.value.code == 'PT-GRAPH-SOURCE'


def test_binexport_labels_are_sanitized():
    source = _bx_source(_binexport([(0, 1)], {0: 'bad\nname‮'}))
    assert {c.caller for c in source.claims('newer', None)} == {'bad name'}


@pytest.mark.parametrize('seed', [1, 2, 3], ids=['s1', 's2', 's3'])
def test_binexport_graph_matches_networkx_oracle(seed):
    nx = pytest.importorskip('networkx')
    rng = random.Random(seed)
    n = 30
    edges = sorted({(rng.randrange(n), rng.randrange(n)) for _ in range(120)})
    msg = cls()()
    for i in range(n):
        msg.call_graph.vertex.add(address=BASE + 0x10 * i, type=0, mangled_name=f'n{i}')
    for src, dst in edges:
        msg.call_graph.edge.add(source_vertex_index=src, target_vertex_index=dst)
    claims = list(_bx_source(msg).claims('newer', None))
    graph = build_csr(n, {(int(c.caller[1:]), int(c.callee[1:])) for c in claims})
    oracle = nx.DiGraph(edges)
    oracle.add_nodes_from(range(n))
    for node in range(n):
        assert set(graph.successors(node)) == set(oracle.successors(node))
        assert set(graph.predecessors(node)) == set(oracle.predecessors(node))


def test_snapshot_over_a_whole_program_source_reports_the_source_and_completeness():
    snap = build_snapshot(graph_input('svc_pair'), _bx_source(_binexport([(0, 1), (1, 2)], {0: 'main'})))
    assert (snap.source.source_id, snap.source.tier, snap.completeness) == ('binexport', 'addresses',
                                                                            'whole-program')
    assert snap.newer.graph.edge_count == 2 and len(snap.newer.listed) == 4
