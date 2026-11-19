"""Actual query bounds and Changes delivery remain independent in the Calls UI."""
from __future__ import annotations

from test_ui_graph_panel import names, select_change, settle, start, status

from patchtrace.callgraph import panel_data as pd
from patchtrace.callgraph import panel_qt


def test_existing_node_cap_does_not_claim_the_displayed_count_is_the_global_total(qtbot, monkeypatch):
    monkeypatch.setattr(pd, 'NEIGHBOUR_NODES', 4)
    controller, *_ = start(qtbot, fixture='cycle_hub')
    select_change(qtbot, controller, 'TraceMessageHub')
    assert controller.found.view.truncated
    assert controller.panel.state.kind == 'partial'
    assert 'some nodes or edges may be omitted' in status(controller)
    assert '3 of 3' not in status(controller)
    assert 'capped' in pd.dot_text(controller.data, controller.found)
    controller._refresh_rows()
    settle(qtbot, controller)
    assert 'capped' in controller.flags and 'capped' in status(controller)


def test_uncapped_query_does_not_clear_an_independent_changes_limit(qtbot, monkeypatch):
    original = panel_qt.changes_view
    limit = [1]

    def limited(*args, **kwargs):
        return original(*args, **kwargs, cap=limit[0])

    monkeypatch.setattr(panel_qt, 'changes_view', limited)
    controller, *_ = start(qtbot)
    assert controller.rows.capped
    select_change(qtbot, controller, names(controller.panel.changes)[0])
    assert not controller.found.view.truncated
    assert 'capped' in controller.flags
    limit[0] = 100_000
    controller._refresh_rows()
    settle(qtbot, controller)
    assert not controller.rows.capped and 'capped' not in controller.flags
