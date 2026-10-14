# ruff: noqa: F811
"""The ui.py seam: line budget, call sites, forbidden APIs, one main window, legacy dock coexistence (GUI plan 8.8,
8.9, 8.10)."""
from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from host_support import Window, make_host, private_tooltip_registry, spec  # noqa: F401
from PySide6.QtCore import QSettings
from qt_support import a11y_audit, join_gui_threads, main_window, settings, top_level_windows  # noqa: F401

from patchtrace.gui.qt.host import PanelHost
from patchtrace.panel_manifest import MANIFEST
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow

SRC = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace'
# ui.py was 3,142 lines when F5 started (3,119 at d972125 plus the zero-download bundle work). F5 alone kept the
# evidence hooks (+25); F8 removed them (M1, M2). The plan's final seam is +15 over d972125 (3,134 = 3,142 - 8);
# F9 removed the series and files code (M3: -50 lines net), which closed the gap and went below it; the ceiling
# only goes down from here.
UI_LINES_BEFORE_F5 = 3142
UI_TRANSITIONAL_CEILING = -50


def test_ui_seam_budget():
    lines = (SRC / 'ui.py').read_text(encoding='utf-8').count('\n')
    assert lines <= UI_LINES_BEFORE_F5 + UI_TRANSITIONAL_CEILING, lines


def test_ui_seam_is_a_handful_of_host_calls_and_names_no_feature():
    text = (SRC / 'ui.py').read_text(encoding='utf-8')
    assert len(re.findall(r'self\.panels\.', text)) <= 8
    assert text.count('PanelHost') == 2  # the import and the one construction
    packages = {entry.module.split('.')[1] for entry in MANIFEST}
    assert not [name for name in packages if re.search(rf'(?:from|import) \.{name}\b|patchtrace\.{name}\b', text)]


# ---- forbidden APIs (8.9) ----------------------------------------------------------------------------------------

FORBIDDEN = {
    'proxy sort': r'QSortFilterProxyModel|\blessThan\b',
    'content-sized columns': r'ResizeToContents|resize\w*ToContents',
    'rich text': r'\.setHtml\(|\.setMarkdown\(|TextFormat\.RichText',
    'thread kill': r'\.terminate\(',
    'event pumping': r'processEvents\(',
    'parented thread': r'QThread\([^)]',
    'pool threads': r'QRunnable|QThreadPool',
    'dynamic import': r'importlib|__import__',
    'item widgets': r'QTableWidget\(|QStandardItemModel',
}
# Where the API is the framework's own business.
ALLOWED_IN = {'updateAccessibility': 'announce.py', 'setswitchinterval': 'runtime.py'}
# Legacy files may only shrink: counted occurrences at F5 (the two content-sized column calls and three QTableWidget
# constructors of ui.py, one content-sized call of ui_inspection.py). F9 moved the two overview tables to models.
LEGACY_BASELINE = {('ui.py', 'content-sized columns'): 1, ('ui.py', 'item widgets'): 1}
NEW_CODE = [*(SRC / 'gui').rglob('*.py'), SRC / 'panel_manifest.py']
LEGACY = [path for path in SRC.glob('ui*.py')]


@pytest.mark.parametrize('rule', FORBIDDEN, ids=[name.replace(' ', '-') for name in FORBIDDEN])
def test_new_code_uses_no_forbidden_api(rule):
    hits = [f'{path.name}:{number}' for path in NEW_CODE for number, line in enumerate(
        path.read_text(encoding='utf-8').splitlines(), 1) if re.search(FORBIDDEN[rule], line)]
    assert not hits


@pytest.mark.parametrize('api, owner', ALLOWED_IN.items(), ids=list(ALLOWED_IN))
def test_framework_only_apis_stay_in_their_module(api, owner):
    users = {path.name for path in [*NEW_CODE, *LEGACY] if api in path.read_text(encoding='utf-8')}
    assert users <= {owner}


def test_thread_signals_never_take_lambdas_in_the_gui_layer():
    pattern = re.compile(r'(?:finished|started|progress|result_ready|failed|event_ready)\s*\.connect\(\s*lambda')
    assert not [path.name for path in NEW_CODE if pattern.search(path.read_text(encoding='utf-8'))]


@pytest.mark.parametrize('rule', sorted({rule for _, rule in LEGACY_BASELINE}), ids=lambda rule: rule.replace(' ', '-'))
def test_legacy_counts_may_only_shrink(rule):
    for path in LEGACY:
        found = len(re.findall(FORBIDDEN[rule], path.read_text(encoding='utf-8')))
        assert found <= LEGACY_BASELINE.get((path.name, rule), 0), path.name


# ---- one main window ------------------------------------------------------------------------------------------


def test_no_new_top_level_window(main_window, qtbot):
    window = main_window
    window.show()
    qtbot.waitExposed(window)
    window.panels.open_palette()
    assert top_level_windows() == [window]


def test_host_owned_widgets_pass_the_accessibility_audit(qtbot, settings):
    window, host = make_host(qtbot, settings, spec('alpha'))
    window.show()
    host.restore_layout()
    host.show_panel('alpha')
    host.open_palette()
    assert a11y_audit(host.palette) == [] and a11y_audit(host.strip) == []
    assert a11y_audit(host.panels['alpha'].dock.view) == []


# ---- the real manifest and the legacy evidence dock ---------------------------------------------------------------


def test_the_shipped_manifest_builds_only_the_migrated_panels_and_has_no_problem(main_window):
    host = main_window.panels
    built = {'evidence', 'series', 'files'}
    assert set(host.panels) == built and host.problems == []
    assert set(host.not_built) == {entry.id for entry in MANIFEST} - built
    assert host.self_check() == [] and set(host.build_all_for_test()) == built


def test_building_the_host_is_cheap(qtbot, settings):
    window = Window(settings)
    qtbot.addWidget(window)
    start = time.perf_counter()
    PanelHost(window)
    assert time.perf_counter() - start < 0.5  # 14 absent modules; the budget is 25 ms, this is 5x slack and then some


def test_the_legacy_evidence_dock_survives_the_saved_layout(qtbot, tmp_path):
    ini = str(tmp_path / 'ui.ini')

    def open_window(name):
        view = MainWindow(ProjectService.sample(tmp_path / name), QSettings(ini, QSettings.Format.IniFormat),
                          tmp_path / 'profiles')
        qtbot.addWidget(view)
        return view

    first = open_window('one')
    first.show()
    first.panels.controller('evidence').dock.show()
    first.close()
    first.service = None
    second = open_window('two')
    second.show()
    assert second.panels.controller('evidence').dock.objectName() == 'evidence.dock' and not second.panels.controller('evidence').dock.isHidden()
    second.close()
    second.service = None


def test_closing_the_window_saves_the_layout_and_joins_the_workers(main_window):
    window = main_window
    host = window.panels
    window.close()
    assert host.closed and window.settings.contains('layout/state')
    with pytest.raises(RuntimeError):
        host.tasks.submit('late', lambda token, report: None)
