"""Issue #105 findings whose code is outside the audit-2 worker's files: tests recorded for their owners.
Only the NEW test is marked xfail(strict); no existing test is touched."""
from __future__ import annotations

import pytest
from callgraph_graph_support import snapshot

from patchtrace.callgraph.dot import render_dot
from patchtrace.callgraph.export_json import GraphExport
from patchtrace.callgraph.query import find_node, neighbourhood


def test_a105_cg3_dot_export_states_that_neighbours_were_left_out():
    snap = snapshot('cycle_hub')
    hub = find_node(snap, 'newer', 'TraceMessageHub')
    view = neighbourhood(snap, 'newer', [hub.id], direction='in', max_nodes=500, max_edges=500)
    assert view.more  # the 64-neighbour cap fired
    data = snap.data
    export = GraphExport(project_id=data.project_id, run_id=data.run_id, match_id='m' * 64,
                         older_sha256=data.older_sha256, newer_sha256=data.newer_sha256, older=None, newer=view,
                         correspondence=(), truncated=view.truncated, limitations=view.limitations)
    text = render_dot(export).lower()
    assert 'more' in text or 'capped' in text or 'truncated' in text


def test_a105_rule2_same_second_decisions_keep_their_insertion_order(tmp_path):
    import rules_fixtures as rf
    from rules_store_support import candidate_of, rule_store

    from patchtrace.rules import store
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    bench = rf.Bench(tmp_path)
    try:
        candidate = candidate_of(bench)
        for n, order in enumerate((('accept', 'reject'), ('reject', 'accept'))):  # the hash order wins in one of them
            rules = rule_store(tmp_path / f'store{n}')
            for action in order:
                rules.add_decision(store.decision_for(candidate, action, '2026-10-14T09:00:00+00:00',
                                                      label='Terminate removed' if action == 'accept' else None),
                                   candidate.source)
            assert [d.action for d in rules.decisions(candidate.candidate_id)] == list(order)
    finally:
        bench.close()


def test_a105_rule7_a_large_all_unique_middle_is_not_handed_to_difflib(monkeypatch):
    from patchtrace.rules import window
    from patchtrace.rules.masks import MaskedFunction, MaskedInstruction

    def body(keys):
        return MaskedFunction(0, tuple(MaskedInstruction(i, 1, (k,), (), 'seq', None, ())
                                       for i, k in enumerate(keys)))
    n = 8000
    older = [f'{i:04x}' for i in range(n)]
    newer = [older[i ^ 1] for i in range(n)]  # swapped neighbours: every key unique, difflib's worst shape

    class Spy:
        def __init__(self, *args, **kwargs):
            raise AssertionError('difflib was asked to weigh an 8000 x 8000 middle')
    monkeypatch.setattr(window.difflib, 'SequenceMatcher', Spy)
    ops = window.diff_opcodes(body(older), body(newer))
    assert ops and ops[0][0] == 'replace'
