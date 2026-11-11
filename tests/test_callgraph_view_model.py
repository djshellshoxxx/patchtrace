"""WB2 G5 (pure part): Changes, Neighbours and Tree view models, copy and the local tooltip table."""
from __future__ import annotations

import re

import pytest
from callgraph_delta_support import Entries, analysis, by_label
from callgraph_fixtures import FIXTURE_NAMES

from patchtrace.callgraph import view_model as vm
from patchtrace.callgraph.contracts import GraphEdge, GraphNode, GraphView, Pairing, SourceInfo
from patchtrace.callgraph.contracts_delta import EntryDistance
from patchtrace.callgraph.leads import build_leads
from patchtrace.callgraph.query import find_node, neighbourhood
from patchtrace.callgraph.text import UNSAFE

BANNED = ('probab', 'likelihood', 'vulnerab', 'exploit', 'safe', 'secure', 'fixed', 'verified', 'proven',
          'certain', 'confiden', 'score', 'malicious', 'risk', 'danger')
HOSTILE = ['<b>x</b>', '{0}', '%s', 'file:///etc/passwd', 'a‮b', 'nul\x00name', 'x' * 10_000]


def _setup(name='svc_pair'):
    snap, deltas = analysis(name)
    return snap, deltas, build_leads(snap, deltas, Entries('DriverEntry'))


def _view(labels_, edges):
    nodes = tuple(GraphNode(id=f'n{i}', side='newer', kind='function', label=label, via='emitted-record',
                            tier='record') for i, label in enumerate(labels_))
    return GraphView(project_id='p', run_id='r', older_sha256='a', newer_sha256='b', side='newer', nodes=nodes,
                     edges=tuple(GraphEdge(id=f'e{i}', src=f'n{s}', dst=f'n{d}', side='newer',
                                           support=('called',)) for i, (s, d) in enumerate(edges)),
                     completeness='changed-set-lists', source=SourceInfo(source_id='t', version='1', tier='labels'))


def test_changes_rows_have_one_row_per_pair_and_exact_cells():
    _, deltas, leads = _setup()
    view = vm.changes_view(deltas, leads)
    assert view.total == len(deltas) == len(view.rows) and not view.capped
    row = next(r for r in view.rows if r.match_id == by_label(deltas, 'FUN_140001600').match_id)
    assert vm.changes_cell(row, 0) == row.name and row.state in vm.DELTA_STATE_TEXT.values()
    assert row.accessible.startswith(row.name) and f'added {row.added}' in row.accessible


def test_changes_sort_filter_and_cap_are_model_owned():
    _, deltas, leads = _setup()
    names = [r.name for r in vm.changes_view(deltas, leads).rows]
    assert names == sorted(names)
    assert [r.name for r in vm.changes_view(deltas, leads, descending=True).rows] == names[::-1]
    only = vm.changes_view(deltas, leads, changed_only=True)
    assert all(r.added or r.removed for r in only.rows)
    assert vm.changes_view(deltas, leads, text=names[0][:6].upper()).rows[0].name == names[0]
    capped = vm.changes_view(deltas, leads, cap=1)
    assert capped.capped and capped.total == len(names) and len(capped.rows) == 1
    for column in vm.CHANGES_COLUMNS:
        vm.changes_view(deltas, leads, sort=column)


def test_changes_row_for_noise_downgrade_is_hidden_by_filter():
    _, deltas, leads = _setup()
    noisy = deltas[0].model_copy(update={'downgrade': 'hub-only'})
    assert vm.changes_view([noisy], leads, hide_noise=True).rows == ()
    assert vm.changes_view([noisy], leads).rows[0].noise


def test_neighbour_rows_relation_hops_and_change():
    snap, deltas, _ = _setup()
    delta = by_label(deltas, 'FUN_140001600')
    node = find_node(snap, 'newer', delta.newer_label)
    graph = neighbourhood(snap, 'newer', [node.id], 'both', depth=2)
    rows, total = vm.neighbour_rows(graph, node.id, delta=delta)
    assert total == len(rows) == len(graph.nodes) - 1
    assert [r.hops for r in rows] == sorted(r.hops for r in rows)
    assert {r.relation for r in rows} <= {'Caller', 'Callee', 'Caller and callee', 'Related'}
    assert all(r.pairing == 'No pairing data' for r in rows)
    assert all(r.name in r.accessible and 'calls away' in r.accessible for r in rows)
    assert vm.neighbour_cell(rows[0], 1) == rows[0].relation


def test_neighbour_rows_direction_and_cap():
    g = _view(['seed', 'up', 'down', 'both'], [(1, 0), (0, 2), (0, 3), (3, 0)])
    rows, total = vm.neighbour_rows(g, 'n0')
    assert {r.name: r.relation for r in rows} == {'up': 'Caller', 'down': 'Callee', 'both': 'Caller and callee'}
    capped, total = vm.neighbour_rows(g, 'n0', cap=2)
    assert len(capped) == 2 and total == 3


def test_neighbour_change_cell_names_the_callee_change():
    g = _view(['seed', 'NewCallee'], [(0, 1)])
    _, deltas, _ = _setup()
    change = deltas[0].changes[0].model_copy(update={'cls': 'added-call', 'newer_label': 'NewCallee', 'flags': ()})
    delta = deltas[0].model_copy(update={'changes': (change,)})
    rows, _ = vm.neighbour_rows(g, 'n0', delta=delta)
    assert rows[0].change == '+ Added' and 'call change Added' in rows[0].accessible


@pytest.mark.parametrize('kind, partners, text', [
    ('one', ('x',), 'Paired'), ('added', (), 'New in newer build'), ('removed', (), 'Deleted from older build'),
    ('unknown', (), 'No pairing data'), ('many', ('a', 'b', 'c'), 'Ambiguous (3)'),
    ('contested', ('a',), 'Ambiguous (2)')], ids=['one', 'added', 'removed', 'unknown', 'many', 'contested'])
def test_pairing_text(kind, partners, text):
    assert vm.pairing_text(Pairing(kind=kind, partners=partners)) == text
    assert vm.pairing_text(None) == 'No pairing data'


def test_tree_children_are_lazy_bounded_and_cycle_safe():
    big = _view(['root'] + [f'c{i:03d}' for i in range(70)], [(0, i) for i in range(1, 71)])
    kids = vm.TreeIndex(big).children('n0')
    assert len(kids.children) == 64 and kids.more == 6 and kids.more_text == '+6 more'
    assert [c.name for c in kids.children] == sorted(c.name for c in kids.children)
    cyc = vm.TreeIndex(_view(['a', 'b'], [(0, 1), (1, 0)]))
    assert [(c.name, c.repeat, c.expandable) for c in cyc.children('n0').children] == [('b', False, True)]
    assert [(c.name, c.repeat, c.expandable) for c in cyc.children('n1', ('n0', 'n1')).children] == [
        ('a', True, False)]
    assert cyc.children('n0', ('a',) * 5) == vm.TreeChildren((), 0)
    callers = vm.TreeIndex(_view(['a', 'b'], [(1, 0)]), 'callers')
    assert [c.name for c in callers.children('n0').children] == ['b']


@pytest.mark.parametrize('flag, key', [
    ('no-project', 'E0'), ('no-comparison', 'E1'), ('loading', 'E2'), ('cancelled', 'E8'),
    ('failed', 'E9'), ('stale', 'E10'), ('not-in-set', 'E4'), ('no-lists', 'E5'),
    ('too-large', 'E11'), ('capped', 'E7')],
    ids=['E0', 'E1', 'E2', 'E8', 'E9', 'E10', 'E4', 'E5', 'E11', 'E7'])
def test_every_headline_state_has_its_text(flag, key):
    state = vm.PanelState(frozenset({flag}), shown=3, total=9, code='PT-GRAPH-X', message='boom',
                          reason='run changed', nodes=2501)
    expected = vm.STATE_TEXT[key].format(n='2,501' if key == 'E11' else '3', m='9', code='PT-GRAPH-X',
                                         message='boom', reason='run changed')
    assert vm.status_lines(state) == (expected,)


def test_notes_follow_the_headline_and_headline_precedence():
    state = vm.PanelState(frozenset({'raw-missing', 'no-instruction-data', 'loading', 'failed'}))
    assert vm.status_lines(state) == (vm.STATE_TEXT['E2'], vm.STATE_TEXT['E6'], vm.STATE_TEXT['E12'])
    assert vm.status_lines(vm.PanelState()) == ()


def test_status_keeps_hostile_error_text_plain_and_bounded():
    state = vm.PanelState(frozenset({'failed'}), code='{0}', message='<b>x</b>%s' + 'y' * 5000)
    (line,) = vm.status_lines(state)
    assert line.startswith('Calls could not be read: {0}: <b>x</b>%s') and len(line) < 500


def test_footer_and_state_copy_exact():
    assert vm.STATE_TEXT['E0'] == 'Open a project to explore calls.'
    assert vm.FOOTER.endswith('Missing is unknown, not removed.')
    assert set(vm.STATE_TEXT) == {f'E{i}' for i in range(13)} - {'E3'}  # the card defines no E3 text


def test_entry_and_call_site_text():
    assert vm.entry_text(EntryDistance(state='reached', hops=3, via='DriverEntry')) == (
        'Reachable from export DriverEntry in at most 3 calls (observed path)')
    assert vm.entry_text(EntryDistance(state='not-reached')) == vm.NO_ENTRY_PATH
    assert vm.entry_text(EntryDistance(state='unknown')) == vm.entry_text(None) == ''
    code = 'void f() {\n  xFoo(1);\n  Foo (2);\n}'
    assert vm.find_call_site(code, 'Foo') == 3
    assert vm.find_call_site(code, 'ntoskrnl.exe::Foo') == 3
    assert vm.find_call_site(code, 'Fo') is None and vm.find_call_site(code, '') is None
    assert vm.callsite_text(None) == vm.CALLSITE_MISSING
    assert vm.callsite_text(3) == 'text match in decompiled code, line 3'


def test_change_detail_and_copy_have_fixed_sections_and_are_capped():
    _, deltas, leads = _setup()
    delta = by_label(deltas, 'FUN_140001600')
    lead = next((x for x in leads if x.match_id == delta.match_id), None)
    detail = vm.change_detail(delta, lead)
    assert tuple(detail) == vm.SECTIONS
    text = vm.copy_text(detail)
    assert text.startswith('Identity\n') and 'Limits\n' in text and vm.FOOTER in text
    assert len(vm.copy_text({'Identity': ['x' * 40_000]})) == vm.CLIPBOARD_CAP
    assert vm.copy_text({name: [] for name in vm.SECTIONS}) == ''


def test_node_detail_names_provenance():
    g = _view(['a'], [])
    text = vm.copy_text(vm.node_detail(g.nodes[0], Pairing(kind='one', partners=('a2',)), g))
    assert 'Name: a' in text and 'Partners: a2' in text and 'Source t 1, run r' in text


@pytest.mark.parametrize('label', HOSTILE, ids=['markup', 'braces', 'percent', 'url', 'bidi', 'nul', 'long'])
def test_hostile_names_stay_plain_in_every_view(label):
    g = _view(['seed', label[:512]], [(0, 1)])
    rows, _ = vm.neighbour_rows(g, 'n0')
    kids = vm.TreeIndex(g).children('n0').children
    texts = [rows[0].name, rows[0].accessible, kids[0].name, vm.copy_text(vm.node_detail(g.nodes[1], None, g))]
    for text in texts:
        assert not UNSAFE.search(text) and len(text) < 1_000
    assert rows[0].name.startswith(label[:20].replace('\x00', '').replace('‮', ''))
    delta = analysis('svc_pair')[1][0].model_copy(update={'newer_label': label})
    row = vm.changes_view([delta]).rows[0]
    assert not UNSAFE.search(row.name) and len(row.name) <= 120


def test_tooltip_table_is_complete_plain_and_audited():
    ids = ('dock action tabs side direction depth show_unresolved changed_only hide_noise follow changes_table '
           'table tree diagram minimap detail open callsite focus back copy export_dot status edges callsites').split()
    assert set(vm.GRAPH_TIPS) == {f'graph.{i}' for i in ids}
    assert set(vm.GRAPH_TIP_TEMPLATES) == {'graph.row', 'graph.cell', 'graph.node'}
    for entry in (*vm.GRAPH_TIPS.values(), *vm.GRAPH_TIP_TEMPLATES.values()):
        assert len(entry) == 3 and all(entry)
        assert not any(c in text for text in entry for c in '<>%')
    assert vm.ACCESSIBLE_NAMES['diagram'] == ('Call diagram (visual only; the Neighbours table has the same '
                                              'information)')


def test_copy_has_no_banned_words_and_no_percent():
    for text in vm.all_copy():
        lowered = text.lower()
        for word in BANNED:  # stems match as prefixes, the rest as whole words ('provenance' is fine)
            tail = '' if word in ('probab', 'vulnerab', 'exploit', 'likelihood', 'confiden') else r'\b'
            assert not re.search(r'\b' + re.escape(word) + tail, lowered), (word, text)
        assert '%' not in text


@pytest.mark.parametrize('rows', [10_000, 100_000], ids=['10k', '100k'])
def test_changes_view_caps_rows_at_scale(rows):
    _, deltas, _ = _setup()
    many = [deltas[0].model_copy(update={'match_id': f'm{i:06d}'}) for i in range(rows)]
    view = vm.changes_view(many, cap=1_000)
    assert view.total == rows and len(view.rows) == 1_000 and view.capped
    assert vm.changes_cell(view.rows[0], 0) == view.rows[0].name


def test_fixture_sweep_builds_views_without_error():
    for name in FIXTURE_NAMES:
        snap, deltas = analysis(name)
        view = vm.changes_view(deltas, build_leads(snap, deltas))
        assert view.total == len(deltas)
