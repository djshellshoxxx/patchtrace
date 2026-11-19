# ruff: noqa: F811
"""SPEC-45 R-N1, R-N7 and GUI plan 8.7 R1 and R9 for the whole main window: with every built panel shown, every
enabled interactive control has an accessible name, every accessible identifier (the UIA AutomationId) is unique in
the window, and names are unique among siblings. Names are read from the widget, not from
`QAccessible.queryAccessibleInterface`: on Linux Qt reports a combo box's current text as its name, on Windows the
explicit name, and Windows is the gate."""
from __future__ import annotations

import re
from collections import Counter

from PySide6.QtWidgets import QAbstractButton, QComboBox, QLabel, QLineEdit, QToolButton, QWidget
from qt_support import a11y_audit, join_gui_threads, main_window, settings  # noqa: F401

from patchtrace import tooltips
from patchtrace.gui import tips
from patchtrace.gui.access_names import NAMES, popup_name
from patchtrace.gui.registry import NAME_LIMIT

ROLE_WORDS = re.compile(r'\b(button|edit box|text box|combo ?box|check ?box|list ?box|spin ?box|drop-?down)\b', re.I)


def shown(window) -> list[QWidget]:
    """Show every built panel, then return the window and every widget under it."""
    for panel_id in window.panels.build_all_for_test():
        window.panels.show_panel(panel_id)
    return [window, *window.findChildren(QWidget)]


def qt_clear_buttons(widgets: list[QWidget]) -> list[str]:
    """The audit labels of Qt's own QLineEdit clear buttons (`setClearButtonEnabled`): a private QToolButton subclass
    that Qt creates, owns and recreates, so no PatchTrace code can name it. It is the one exemption."""
    return [f'QToolButton#{w.objectName() or "?"}: no accessible name' for w in widgets
            if isinstance(w, QToolButton) and isinstance(w.parent(), QLineEdit)
            and w.metaObject().className() == 'QLineEditIconButton' and not w.accessibleName()]


def test_every_interactive_control_of_the_window_has_a_name(main_window):
    widgets = shown(main_window)
    unnamed = Counter(problem for problem in a11y_audit(main_window) if problem.endswith('no accessible name'))
    exempt = qt_clear_buttons(widgets)
    assert exempt, 'the navigator and findings search fields have Qt clear buttons'
    assert not unnamed - Counter(exempt), sorted(unnamed - Counter(exempt))


def test_accessible_identifiers_are_unique_in_the_window(main_window):
    ids = Counter(widget.accessibleIdentifier() for widget in shown(main_window) if widget.accessibleIdentifier())
    assert len(ids) > 100
    assert not {identifier: count for identifier, count in ids.items() if count > 1}


def _name(widget: QWidget) -> str:
    """The UIA Name: the explicit name, else a button's own text."""
    return widget.accessibleName() or (widget.text() if isinstance(widget, QAbstractButton) else '')


def test_names_are_unique_among_siblings(main_window):
    clashes = []
    for parent in shown(main_window):
        names = Counter(_name(child) for child in parent.children()
                        if isinstance(child, QWidget) and not child.isWindow() and _name(child).strip())
        clashes += [f'{parent.objectName() or type(parent).__name__}: {name!r} x{count}'
                    for name, count in names.items() if count > 1]
    assert not clashes, clashes


def test_every_name_has_a_registered_tip_and_follows_the_naming_rules():
    assert NAMES and len(set(NAMES.values())) == len(NAMES)
    for tip_id, name in NAMES.items():
        assert tip_id in tooltips.REGISTRY, tip_id
        assert name == ' '.join(name.split()) and 0 < len(name) <= NAME_LIMIT, name
        assert name[0].isupper() and not name.endswith('.') and not ROLE_WORDS.search(name), name
        assert len(popup_name(name)) <= NAME_LIMIT


def test_popup_names_stay_within_the_limit():
    assert popup_name('Raw byte scope') == 'Raw byte scope options'
    long = popup_name('word ' * 30)
    assert len(long) <= NAME_LIMIT and long.endswith(' options') and '  ' not in long


def test_apply_tip_keeps_a_preset_name_and_names_the_popup(qtbot):
    combo = QComboBox()
    qtbot.addWidget(combo)
    combo.setAccessibleName('Preset name')
    tips.apply_tip(combo, 'findings.review_filter')
    assert combo.accessibleName() == 'Preset name'
    assert combo.view().accessibleName() == 'Preset name options'


def test_apply_tip_names_an_unnamed_control_its_popup_and_its_line_edit(qtbot):
    combo = QComboBox()
    combo.setEditable(True)
    qtbot.addWidget(combo)
    tips.apply_tip(combo, 'findings.note_target')
    name = NAMES['findings.note_target']
    assert combo.accessibleName() == name and combo.view().accessibleName() == popup_name(name)
    assert combo.lineEdit().accessibleName() == name


def test_apply_tip_names_nothing_outside_the_table_and_never_a_label(qtbot):
    edit, label = QLineEdit(), QLabel('Analysis log')
    for widget in (edit, label):
        qtbot.addWidget(widget)
    assert 'nav.search' not in NAMES
    tips.apply_tip(edit, 'nav.search')
    tips.apply_tip(label, 'job.log')
    assert edit.accessibleName() == '' and label.accessibleName() == ''  # R-N4: a label keeps an empty name
    assert label.accessibleIdentifier() == 'job.log'
