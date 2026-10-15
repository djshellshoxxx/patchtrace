"""GUI plan 8.10 step M4: every extra selection of the code panes goes through `compose_selections` layers."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QTextEdit

from patchtrace.gui.qt.codediff import compose_selections
from patchtrace.gui.qt.theme import DARK
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow

UI = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace' / 'ui.py'


@pytest.fixture
def window(qtbot, tmp_path):
    view = MainWindow(ProjectService.sample(tmp_path / 'sample'),
                      QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat), tmp_path / 'profiles')
    qtbot.addWidget(view)
    view.show()
    yield view
    view._stop_inspection()
    view.close()


def test_ui_never_calls_set_extra_selections_directly():
    assert not re.search(r'\.setExtraSelections\(', UI.read_text(encoding='utf-8'))


def test_hunk_tints_are_the_theme_tokens_and_survive_another_layer(window):
    view = window.views['older']
    tints = {item.format.background().color().name() for item in view.extraSelections()}
    assert tints and tints <= {QColor(DARK.hunk_replace).name(), QColor(DARK.hunk_other).name()}
    before = len(view.extraSelections())
    compose_selections(view, 'search', [QTextEdit.ExtraSelection()])
    assert len(view.extraSelections()) == before + 1


def test_a_new_render_replaces_the_diff_layer_but_keeps_the_others(window):
    view = window.views['older']
    compose_selections(view, 'search', [QTextEdit.ExtraSelection()])
    window.render_match()
    assert len(view.extraSelections()) == len(window._hunks) + 1
