"""WB2 G2: snapshot construction, bounded queries, goldens, determinism and the import boundary."""
from __future__ import annotations

import dataclasses
import os
import subprocess
import sys

import pytest
from callgraph_graph_support import edge_labels, graph_input, labels, snapshot

import patchtrace.callgraph.snapshot as snapshot_module
from patchtrace.callgraph.limits import GraphError
from patchtrace.callgraph.query import find_node, neighbourhood, partner
from patchtrace.callgraph.snapshot import SnapshotOptions, build_snapshot, snapshot_key

SVC_P_NEWER_EDGES = [
    ('FUN_140001640', 'FUN_1400018c0'),
    ('FUN_1400018c0', 'FUN_140001340'),
    ('FUN_1400018c0', 'FUN_140001f00'),
    ('FUN_1400018c0', 'ntoskrnl.exe::ExAllocatePool2'),
    ('FUN_1400018c0', 'ntoskrnl.exe::ProbeForRead'),
]


def view_of(snap, side, label, **kwargs):
    return neighbourhood(snap, side, [find_node(snap, side, label).id], **kwargs)


# ---- snapshot -----------------------------------------------------------------------------------------

def test_svc_edges_merge_called_and_calling_support():
    snap = snapshot('svc_pair')
    view = view_of(snap, 'newer', 'FUN_1400018c0')
    support = {(s, d): e.support for (s, d), e in zip(edge_labels(view), view.edges, strict=True)}
    assert support[('FUN_140001640', 'FUN_1400018c0')] == ('called', 'calling')  # listed by both ends
    assert support[('FUN_1400018c0', 'FUN_140001340')] == ('called',)
    assert (snap.older.graph.n, snap.newer.graph.n) == (8, 11)


def test_only_changed_set_functions_have_lists():
    snap = snapshot('svc_pair')
    listed = {snap.newer.nodes[p].label for p in snap.newer.listed}
    assert 'FUN_1400018c0' in listed and 'FUN_140001340' not in listed
    assert not any(snap.newer.nodes[p].kind == 'external' for p in snap.newer.listed)


def test_source_info_completeness_and_limitations():
    snap = snapshot('svc_pair')
    assert (snap.source.source_id, snap.source.tier, snap.source.version) == ('ghidriff-lists', 'labels', 'unknown')
    assert snap.completeness == 'changed-set-lists' and snap.claims > 0 and not snap.truncated
    text = ' '.join(snap.limitations)
    assert 'Direct calls only' in text and 'unknown, not removed' in text and 'Raw Ghidriff' not in text


def test_missing_raw_adds_the_degraded_limitation_and_keeps_emitted_pairs():
    snap = snapshot('svc_pair', with_raw=False)
    assert any('Raw Ghidriff matches are not available' in n for n in snap.limitations)
    node = find_node(snap, 'older', 'FUN_140001500')
    assert partner(snap, 'older', node.id).partners == ('FUN_140001640',)
    assert find_node(snap, 'older', 'FUN_140001200').kind == 'label-only'


def test_claim_cap_truncates_deterministically(monkeypatch):
    monkeypatch.setattr(snapshot_module, 'MAX_CLAIMS', 7)
    first, second = snapshot('svc_pair'), snapshot('svc_pair')
    assert first.truncated and first.claims == 7
    assert any('capped at 7' in n for n in first.limitations)
    assert first.older.graph.edge_count == second.older.graph.edge_count
    assert neighbourhood(first, 'older', [first.older.nodes[0].id]).truncated


def test_cancel_is_honoured_between_claims(monkeypatch):
    monkeypatch.setattr(snapshot_module, 'CANCEL_CLAIM_INTERVAL', 2)
    with pytest.raises(GraphError) as excinfo:
        snapshot('svc_pair', cancel=lambda: True)
    assert excinfo.value.code == 'PT-GRAPH-CANCEL'


def test_claims_from_an_ambiguous_caller_are_not_attributed():
    def give_calls(raw):
        raw['functions']['added'][0]['called'] = ['FUN_140001340']
    snap = snapshot('ambiguous_pair', give_calls)
    assert any('not attributed' in n for n in snap.limitations)
    duplicate = find_node(snap, 'newer', 'parser.dll::Parse')
    assert duplicate.kind == 'ambiguous'
    assert all(snap.newer.nodes[s].kind != 'ambiguous' for s, _ in snap.newer.graph.edges())
    assert not snap.newer.listed & {snap.newer.index[duplicate.id]}


def test_key_is_stable_and_sensitive_to_every_input():
    data = graph_input('svc_pair')
    base = snapshot_key(data)
    assert base == snapshot_key(graph_input('svc_pair'))
    variants = [
        dataclasses.replace(data, revision=data.revision + 1), dataclasses.replace(data, run_id='other'),
        dataclasses.replace(data, manual_digest='x'), dataclasses.replace(data, raw_sha256='f' * 64),
        dataclasses.replace(data, older_sha256='1' * 64),
    ]
    assert len({snapshot_key(v) for v in variants} | {base}) == 6
    options = [SnapshotOptions(resolve_thunks=True), SnapshotOptions(hub_registry_version='2'),
               SnapshotOptions(patch_rules=('1', 'abc')), SnapshotOptions(secondary_set_digest='d'),
               SnapshotOptions(unified_result_id='u')]
    assert len({snapshot_key(data, o) for o in options} | {base}) == 6


def test_swapping_sides_in_the_input_changes_the_key():
    data = graph_input('svc_pair')
    swapped = dataclasses.replace(data, older_sha256=data.newer_sha256, newer_sha256=data.older_sha256)
    assert snapshot_key(swapped) != snapshot_key(data)


# ---- queries ------------------------------------------------------------------------------------------

def test_golden_view_of_the_changed_function_in_the_newer_build():
    view = view_of(snapshot('svc_pair'), 'newer', 'FUN_1400018c0')
    assert labels(view) == ['FUN_140001340', 'FUN_140001640', 'FUN_1400018c0', 'FUN_140001f00',
                            'ntoskrnl.exe::ExAllocatePool2', 'ntoskrnl.exe::ProbeForRead']
    assert sorted(edge_labels(view)) == SVC_P_NEWER_EDGES
    assert (view.side, view.orientation, view.truncated, view.completeness) == (
        'newer', 'older->newer', False, 'changed-set-lists')
    assert [n.kind for n in view.nodes] == ['paired-unchanged', 'function', 'function', 'function',
                                            'external', 'external']


def test_older_build_view_uses_older_labels_only():
    view = view_of(snapshot('svc_pair'), 'older', 'FUN_140001800')
    assert 'FUN_1400018c0' not in labels(view) and 'FUN_140001500' in labels(view)


def test_depth_zero_is_the_focus_alone_and_depth_two_reaches_further():
    snap = snapshot('svc_pair')
    assert labels(view_of(snap, 'newer', 'FUN_1400018c0', depth=0)) == ['FUN_1400018c0']
    deeper = view_of(snap, 'newer', 'DriverEntry', direction='out', depth=3)
    assert 'FUN_140001f00' in labels(deeper)
    assert 'FUN_140001f00' not in labels(view_of(snap, 'newer', 'DriverEntry', direction='out', depth=2))


def test_direction_in_lists_callers_only():
    view = view_of(snapshot('svc_pair'), 'newer', 'FUN_1400018c0', direction='in')
    assert labels(view) == ['FUN_140001640', 'FUN_1400018c0']


@pytest.mark.parametrize('kwargs', [{'depth': 5}, {'depth': -1}, {'max_nodes': 501}, {'max_nodes': 0},
                                    {'max_edges': 2001}], ids=['deep', 'negative', 'many', 'none', 'edges'])
def test_limits_are_input_errors(kwargs):
    snap = snapshot('svc_pair')
    with pytest.raises(GraphError) as excinfo:
        view_of(snap, 'newer', 'DriverEntry', **kwargs)
    assert excinfo.value.code == 'PT-GRAPH-INPUT'


def test_unknown_node_empty_focus_and_missing_label_are_input_errors():
    snap = snapshot('svc_pair')
    for call in (lambda: neighbourhood(snap, 'newer', ['nope']), lambda: neighbourhood(snap, 'newer', []),
                 lambda: find_node(snap, 'newer', 'FUN_140001500')):  # an older-build label
        with pytest.raises(GraphError) as excinfo:
            call()
        assert excinfo.value.code == 'PT-GRAPH-INPUT'


def test_node_cap_marks_the_view_truncated():
    snap = snapshot('cycle_hub')
    view = view_of(snap, 'newer', 'TraceMessageHub', direction='in', max_nodes=10)
    assert len(view.nodes) == 10 and view.truncated
    assert any('capped' in n for n in view.limitations)


def test_edge_cap_marks_the_view_truncated():
    view = view_of(snapshot('svc_pair'), 'newer', 'FUN_1400018c0', max_edges=2)
    assert len(view.edges) == 2 and view.truncated


def test_hub_neighbours_stop_at_64_then_plus_n_more():
    snap = snapshot('cycle_hub')
    hub = find_node(snap, 'newer', 'TraceMessageHub')
    view = neighbourhood(snap, 'newer', [hub.id], direction='in', max_nodes=500, max_edges=500)
    assert len(view.nodes) == 65  # the hub plus 64 callers
    [marker] = view.more
    assert (marker.node, marker.count) == (hub.id, 2)
    assert not view.truncated


def test_cycle_does_not_loop():
    view = view_of(snapshot('cycle_hub'), 'newer', 'CycleA', direction='out', depth=4)
    assert {'CycleA', 'CycleB', 'TraceMessageHub'} == set(labels(view))


def test_query_cancel_raises_cancel_error():
    snap = snapshot('svc_pair')
    with pytest.raises(GraphError) as excinfo:
        neighbourhood(snap, 'newer', [find_node(snap, 'newer', 'DriverEntry').id], cancel=lambda: True)
    assert excinfo.value.code == 'PT-GRAPH-CANCEL'


def test_hostile_labels_are_plain_text_in_the_view():
    snap = snapshot('hostile_names')
    view = view_of(snap, 'newer', 'Dispatch', direction='out', max_nodes=50, max_edges=100)
    assert len(view.nodes) == 12 and not view.truncated  # Dispatch, ten hostile callees, one import
    for node in view.nodes:
        assert len(node.label) <= 512 and not any(c in node.label for c in '\x00\n\r\x7f‮')


def test_view_is_independent_of_entry_order():
    data = graph_input('svc_pair')
    flipped = dataclasses.replace(data, entries=tuple(reversed(data.entries)))
    views = []
    for item in (data, flipped):
        snap = build_snapshot(item)
        views.append(view_of(snap, 'newer', 'FUN_1400018c0').model_dump_json())
    assert views[0] == views[1]


def test_partner_of_a_node_comes_from_the_pair_map():
    snap = snapshot('svc_pair')
    node = find_node(snap, 'newer', 'FUN_1400018c0')
    assert partner(snap, 'newer', node.id).partners == ('FUN_140001800',)
    ambiguous = find_node(snapshot('ambiguous_pair'), 'newer', 'parser.dll::Parse')
    assert ambiguous.kind == 'ambiguous'


# ---- determinism and boundaries -----------------------------------------------------------------------

_DUMP = (
    "import sys; sys.path[:0] = ['tests']\n"
    "from callgraph_graph_support import snapshot\n"
    "from patchtrace.callgraph.query import find_node, neighbourhood\n"
    "snap = snapshot('svc_pair')\n"
    "node = find_node(snap, 'newer', 'FUN_1400018c0')\n"
    "print(snap.key)\n"
    "view = neighbourhood(snap, 'newer', [node.id])\n"
    # record ids are random uuids, so they are left out of the byte comparison
    "print(view.model_dump_json(exclude={'nodes': {'__all__': {'function_id', 'match_id'}}}))\n")


def _run(code: str, seed: str | None = None) -> str:
    env = {**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path), 'QT_QPA_PLATFORM': 'offscreen'}
    if seed is not None:
        env['PYTHONHASHSEED'] = seed
    return subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, text=True, check=True,
                          timeout=120).stdout


def test_output_is_byte_identical_under_different_hash_seeds():
    assert _run(_DUMP, '0') == _run(_DUMP, '1')


def test_graph_modules_import_no_qt_nway_or_intelligence():
    code = ("import sys\n"
            "import patchtrace.callgraph.snapshot, patchtrace.callgraph.query, patchtrace.callgraph.pairing\n"
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in {'PySide6', 'PyQt5', 'PyQt6'}\n"
            "             or m.startswith(('patchtrace.nway', 'patchtrace.intelligence', 'patchtrace.ui')))\n"
            "print(bad)\n")
    assert _run(code).strip() == '[]'
