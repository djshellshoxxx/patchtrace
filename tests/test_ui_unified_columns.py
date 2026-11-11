"""SPEC-31 U5: the Unified table remembers the widths the analyst sets (`unified/columns`), validated on every read.
Pure helpers first, then the panel and the controller (offscreen Qt; results made up in code)."""
from __future__ import annotations

# ruff: noqa: F811  (fixtures imported from a sibling test module are redefined as parameters)
import pytest
from qt_support import main_window, settings  # noqa: F401  (the fixtures are used by name)
from test_ui_unified import loaded_controller, panel, ready, unified  # noqa: F401  (fixtures and helper by name)

from patchtrace.gui.tips import register_tips
from patchtrace.unified import read_model
from patchtrace.unified.panel import TEMPLATES, TIPS


@pytest.fixture(autouse=True)
def tips():
    register_tips(TIPS, TEMPLATES)


# ---- pure ----------------------------------------------------------------------------------------------------


def test_widths_parse_only_column_keys_and_sane_numbers():
    items = ('decision:150', 'function:300', 'bogus:100', 'change:5', 'change:99999', 'source:ghidriff:x', 'decision:151',
             'nocolon', 'source:ghidriff:210', ':10', 'function:0x20', 'source:Bad Key:100', 'source:rz-diff:90')
    assert read_model.parse_column_widths(items) == {'function': 300, 'decision': 150, 'source:ghidriff': 210,
                                                     'source:rz-diff': 90}
    assert read_model.parse_column_widths(()) == {}


def test_widths_format_sorted_valid_and_within_the_settings_limits():
    text = read_model.format_column_widths({'decision': 150, 'function': 300, 'unknown': 90})
    assert text == ('decision:150', 'function:300')
    many = {f'source:s{i}': 100 + i for i in range(40)}
    assert len(read_model.format_column_widths(many)) == 32
    assert read_model.parse_column_widths(read_model.format_column_widths(many)) == dict(sorted(many.items())[:32])


# ---- panel ----------------------------------------------------------------------------------------------------


def test_default_widths_come_from_the_column_spec_and_saved_widths_win(panel, tmp_path):
    vm = ready(tmp_path)
    panel.set_view_model(vm)
    header = panel.table.horizontalHeader()
    spec = read_model.columns(vm)
    defaults = [header.sectionSize(i) for i in range(len(spec))]
    assert defaults[0] > defaults[1] > 0 and defaults[0] >= panel.table.fontMetrics().averageCharWidth() * spec[0].width_em
    panel.set_column_widths({'decision': 222})
    panel.set_view_model(vm)
    assert header.sectionSize(1) == 222 and header.sectionSize(0) == defaults[0]


def test_only_a_user_resize_is_reported_and_remembered(panel, tmp_path, qtbot):
    vm = ready(tmp_path)
    panel.set_view_model(vm)
    with qtbot.assertNotEmitted(panel.columns_changed):
        panel.set_view_model(vm)
        panel.set_column_widths({'decision': 180})
    with qtbot.waitSignal(panel.columns_changed, timeout=2000):
        panel.table.horizontalHeader().resizeSection(0, 333)
    assert panel.user_widths()['function'] == 333


# ---- controller -----------------------------------------------------------------------------------------------


def test_a_resize_is_written_to_the_unified_columns_setting(unified, qtbot):  # noqa: F811
    _, controller = loaded_controller(unified)
    with qtbot.waitSignal(controller.panel.columns_changed, timeout=2000):
        controller.panel.table.horizontalHeader().resizeSection(1, 177)
    assert 'decision:177' in controller.settings.get_list('columns')


def test_saved_widths_are_restored_and_corrupt_values_are_ignored(unified):  # noqa: F811
    _, controller = loaded_controller(unified)
    controller.settings.set('columns', ['decision:140', 'decision:abc', 'zzz:100', 'change:3'])
    controller._restore_columns()
    controller._show(controller.vm)
    header = controller.panel.table.horizontalHeader()
    assert header.sectionSize(1) == 140 and header.sectionSize(2) > 3
    controller.settings.set('columns', 'not-a-list-but-one-bad-item')
    controller._restore_columns()
    controller._show(controller.vm)
    assert header.sectionSize(1) != 140
