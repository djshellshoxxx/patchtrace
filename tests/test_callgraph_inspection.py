"""Calls panel inspection slice, Qt-free: edge rows, call-site reveal, the DOT export of what is shown and the
minimap geometry (docs/specs/panels/graph-inspection.md). Data are the synthetic call-graph fixtures."""
from __future__ import annotations

import pytest
from callgraph_graph_support import project_and_raw, reader_for

from patchtrace.callgraph import panel_data as pd
from patchtrace.callgraph.call_sites import (
    CALLSITE_ROW_CAP,
    NO_CODE_TEXT,
    ROW_TEXT_LIMIT,
    address_text,
    call_site_view,
    edge_rows,
    function_code,
)
from patchtrace.callgraph.limits import GraphError
from patchtrace.callgraph.minimap import KEY_STEP, build_minimap, pan_target, to_scene
from patchtrace.callgraph.project_input import read_project_input
from patchtrace.callgraph.view_model import CALLSITE_MISSING

CANCEL = lambda: False  # noqa: E731


def loaded(fixture: str = 'svc_pair'):
    project, raw = project_and_raw(fixture)
    data = pd.load_from_input(read_project_input(project, None, reader_for(raw)), project, CANCEL)
    assert isinstance(data, pd.GraphData)
    return project, data


def neighbourhood(data, label: str = 'DriverEntry', depth: int = 2, direction: str = 'both',
                  unresolved: bool = True) -> pd.Neighbourhood:
    match = next(d.match_id for d in data.deltas if label in (d.newer_label, d.older_label))
    found = pd.query(data, pd.QuerySpec(match, 'newer', direction, depth, unresolved), CANCEL)
    assert isinstance(found, pd.Neighbourhood)
    return found


# ---- edges -----------------------------------------------------------------------------------------------------

def test_edge_rows_list_every_edge_touching_the_node_with_addresses():
    _project, data = loaded()
    found = neighbourhood(data)
    rows, total = edge_rows(found.view, found.focus_id)
    assert total == len(rows) >= 1
    assert all(found.focus_id in (r.caller_id, r.callee_id) for r in rows)
    row = next(r for r in rows if r.caller == 'DriverEntry')
    assert row.caller_address == '0x140001000' and row.basis
    assert [(r.caller, r.callee, r.edge_id) for r in rows] == sorted((r.caller, r.callee, r.edge_id) for r in rows)


def test_unknown_address_reads_unknown_never_zero():
    assert address_text(None) == 'Unknown' and address_text(0x1400) == '0x1400'
    _project, data = loaded()
    found = neighbourhood(data)
    rows, _ = edge_rows(found.view, found.focus_id)
    assert all(r.callee_address == 'Unknown' or r.callee_address.startswith('0x') for r in rows)
    assert all(r.callee_address != '0x0' for r in rows)


def test_edge_rows_are_capped_and_report_the_total():
    _project, data = loaded()
    found = neighbourhood(data, 'FUN_140001640', depth=1)
    rows, total = edge_rows(found.view, found.focus_id, cap=1)
    assert len(rows) == 1 and total > 1


def test_hostile_labels_in_edge_rows_are_one_bounded_line():
    _project, data = loaded('hostile_names')
    found = neighbourhood(data, 'Dispatch')
    rows, _ = edge_rows(found.view, found.focus_id)
    for r in rows:
        for text in (r.caller, r.callee, r.accessible):
            assert '\n' not in text and '\x00' not in text and '‮' not in text and len(text) <= 400


# ---- call sites ------------------------------------------------------------------------------------------------

CODE = 'void f() {\n  FUN_140001640(1);\n  x = FUN_1400016400;\n  // FUN_140001640 again\n  FUN_140001640 (2);\n}'


def test_call_site_rows_are_every_exact_token_match_with_line_numbers():
    view = call_site_view(CODE, 'FUN_140001640')
    assert [r.line for r in view.rows] == [2, 4, 5] and view.message == ''
    assert view.rows[0].text == 'FUN_140001640(1);' and 'text match' in view.rows[0].accessible
    assert view.total == 3


def test_call_site_namespace_is_stripped_like_the_single_match_rule():
    view = call_site_view('call ntoskrnl.exe_ExAlloc(a);\nExAllocatePool2(x);', 'ntoskrnl.exe::ExAllocatePool2')
    assert [r.line for r in view.rows] == [2]


def test_call_site_missing_and_no_text_have_exact_copy():
    assert call_site_view(CODE, 'Nope').message == CALLSITE_MISSING
    assert call_site_view('', 'FUN_140001640').message == NO_CODE_TEXT
    assert call_site_view(None, 'FUN_140001640').message == NO_CODE_TEXT


def test_call_site_rows_are_capped_and_text_is_bounded_and_sanitised():
    code = '\n'.join(f'call(); \x1b[31m{"x" * 400}; target(); ‮' for _ in range(CALLSITE_ROW_CAP + 20))
    view = call_site_view(code, 'target')
    assert len(view.rows) == CALLSITE_ROW_CAP and view.total == CALLSITE_ROW_CAP + 20
    assert all(len(r.text) <= ROW_TEXT_LIMIT and '\x1b' not in r.text and '‮' not in r.text for r in view.rows)


def test_function_code_reads_the_record_of_the_current_run_by_id():
    project, data = loaded()
    match = next(m for m in project.matches if any(r.name == 'DriverEntry' for r in m.newer))
    record = next(r for r in match.newer if r.name == 'DriverEntry')
    record.code = 'void DriverEntry() {\n  FUN_140001640();\n}'
    assert function_code(project, record.id) == record.code
    assert function_code(project, 'no-such-id') is None
    view = call_site_view(function_code(project, record.id), 'FUN_140001640')
    assert [r.line for r in view.rows] == [2]


# ---- DOT -------------------------------------------------------------------------------------------------------

def test_dot_text_is_the_visible_graph_only():
    _project, data = loaded()
    found = neighbourhood(data, depth=1)
    text = pd.dot_text(data, found)
    assert text.startswith('// patchtrace call graph export') and text.endswith('}\n') and '\r' not in text
    for node in found.view.nodes:
        assert node.label in text
    export = pd.dot_export(data, found)
    assert export.newer is not None and export.older is None and export.match_id == found.spec.match_id


def test_dot_labels_cannot_inject_graphviz_syntax():
    _project, data = loaded('hostile_names')
    found = neighbourhood(data, 'Dispatch')
    text = pd.dot_text(data, found)
    assert '\x00' not in text and '‮' not in text
    assert text.count('digraph') == 1 and '\n}\n' in text


def test_dot_over_the_size_cap_raises_before_anything_is_written(monkeypatch):
    _project, data = loaded()
    found = neighbourhood(data)
    from patchtrace.callgraph import export_json
    monkeypatch.setattr(export_json, 'MAX_EXPORT_BYTES', 50)
    with pytest.raises(GraphError) as caught:
        pd.dot_text(data, found)
    assert caught.value.code == 'PT-GRAPH-EXPORT'


def test_suggested_name_is_content_derived_not_label_derived():
    name = pd.dot_name('digraph x {}\n')
    assert name.startswith('callgraph-') and name.endswith('.dot') and 'DriverEntry' not in name


# ---- minimap ---------------------------------------------------------------------------------------------------

POINTS = {'a': (0.0, 0.0), 'b': (1000.0, 500.0), 'c': (500.0, 250.0)}
SCENE = (-100.0, -50.0, 1300.0, 700.0)


def test_minimap_scales_all_nodes_into_the_widget_and_keeps_the_aspect_ratio():
    model = build_minimap(POINTS, SCENE, (200.0, 100.0, 400.0, 300.0), (130, 70), focus='b')
    assert model.size == (130, 70) and len(model.dots) == 3 and model.focus_index is not None
    for x, y in model.dots:
        assert 0 <= x <= 130 and 0 <= y <= 70
    px, py, pw, ph = model.viewport
    assert 0 <= px and 0 <= py and px + pw <= 130 + 1e-6 and py + ph <= 70 + 1e-6
    assert model.coverage_percent == round(100 * (400 * 300) / (1300 * 700))


def test_minimap_viewport_larger_than_the_scene_is_clamped_to_all():
    model = build_minimap(POINTS, SCENE, (-500.0, -500.0, 5000.0, 5000.0), (100, 100))
    assert model.coverage_percent == 100 and model.viewport[2] <= 100 and model.viewport[3] <= 100


def test_minimap_click_maps_back_to_the_scene_and_round_trips():
    model = build_minimap(POINTS, SCENE, (0.0, 0.0, 400.0, 300.0), (130, 70))
    x, y = to_scene(model, 65.0, 35.0)
    assert SCENE[0] <= x <= SCENE[0] + SCENE[2] and SCENE[1] <= y <= SCENE[1] + SCENE[3]
    cx, cy = to_scene(model, *model.dots[1])
    assert (round(cx), round(cy)) == (1000, 500)


def test_minimap_with_no_nodes_or_an_empty_scene_is_empty_and_safe():
    assert build_minimap({}, (0.0, 0.0, 0.0, 0.0), (0.0, 0.0, 0.0, 0.0), (100, 50)).dots == ()
    model = build_minimap({}, SCENE, (0.0, 0.0, 10.0, 10.0), (100, 50))
    assert model.dots == () and to_scene(model, 5, 5) is not None


def test_keyboard_pan_moves_the_viewport_centre_by_a_tenth_of_the_scene_and_stays_inside():
    viewport = (200.0, 100.0, 400.0, 300.0)
    cx, cy = 400.0, 250.0
    assert pan_target(SCENE, viewport, 'right') == (cx + SCENE[2] * KEY_STEP, cy)
    assert pan_target(SCENE, viewport, 'up') == (cx, cy - SCENE[3] * KEY_STEP)
    far = (1200.0, 600.0, 100.0, 100.0)
    x, y = pan_target(SCENE, far, 'right')
    assert x <= SCENE[0] + SCENE[2] and y <= SCENE[1] + SCENE[3]
    with pytest.raises(ValueError):
        pan_target(SCENE, viewport, 'sideways')


def test_minimap_description_is_plain_text_with_coverage_and_position():
    model = build_minimap(POINTS, SCENE, (0.0, 0.0, 650.0, 350.0), (130, 70))
    assert model.description == ('Viewport covers 25 percent of the diagram, centred at column 4 of 10, row 4 of 10.')
