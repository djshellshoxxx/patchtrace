"""Offscreen integration of actual capped cycle-hub data with the Calls controller."""
from __future__ import annotations

from test_ui_graph_panel import select_change, settle, start, status

from patchtrace.callgraph import panel_data as pd


def test_query_cap_is_visible_survives_rows_delivery_and_clears_after_narrowing(qtbot):
    controller, *_ = start(qtbot, fixture='cycle_hub')
    select_change(qtbot, controller, 'TraceMessageHub')
    assert controller.found.view.truncated
    assert 'capped' in status(controller)
    assert '64 of 64' not in status(controller)
    assert 'capped' in pd.dot_text(controller.data, controller.found)
    controller._refresh_rows()  # an independent real Changes task may finish after the neighbourhood
    settle(qtbot, controller)
    assert 'capped' in controller.flags and 'capped' in status(controller)
    select_change(qtbot, controller, 'Caller000')
    assert not controller.found.view.truncated
    assert 'capped' not in controller.flags and 'capped' not in status(controller)
    assert 'capped' not in pd.dot_text(controller.data, controller.found)
