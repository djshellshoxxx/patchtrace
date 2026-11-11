# ruff: noqa: F811
"""Build environment panel (DIE D5): state matrix, hostile text, names and keys, anchors, late results and shutdown
(offscreen Qt). The controller is driven through fake ports; reads are injected, so no file or tool is touched."""
from __future__ import annotations

import dataclasses
import threading
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication
from qt_support import a11y_audit, join_gui_threads, top_level_windows  # noqa: F401
from test_buildenv_support import pair_fingerprints

from patchtrace import tooltips
from patchtrace.buildenv import qt_panel
from patchtrace.buildenv.anchors import anchors_for
from patchtrace.buildenv.panel import PANEL
from patchtrace.buildenv.panel_model import Outcome, ReadRequest
from patchtrace.buildenv.view_model import BannerView, BuildEnvViewModel, FactRow
from patchtrace.gui import registry
from patchtrace.gui.anchors import AnchorRef
from patchtrace.gui.projection import ProjectKey
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.panel_manifest import MANIFEST

SHA = 'a' * 64
HOSTILE = '<b>bold</b>\x1b[31m\u202e&amp; ' + 'x' * 600


def key_of(project_id: str = 'p', revision: int = 1) -> ProjectKey:
    return ProjectKey('root', project_id, revision, 'run-1', SHA, SHA)


class FakeProject:
    def __init__(self, *, is_open: bool = True, project_id: str = 'p') -> None:
        self.service = SimpleNamespace(root='root', store=None)
        self.is_open, self.project_id = is_open, project_id

    def project(self):
        return SimpleNamespace(id=self.project_id, revision=1, artifacts=[]) if self.is_open else None

    def key(self):
        return key_of(self.project_id) if self.is_open else None

    def busy(self) -> bool:
        return False


class FakeShell:
    def __init__(self) -> None:
        self.tasks = TaskRunner(reraise=True)
        self.settings = self.theme = None
        self.announced: list[tuple[str, bool]] = []
        self.copied: list[str] = []
        self.notices: dict = {}
        self.statuses: list[str] = []

    def announce(self, text: str, *, assertive: bool = False) -> None:
        self.announced.append((text, assertive))

    def copy_text(self, text: str) -> bool:
        self.copied.append(text)
        return True

    def status(self, text: str) -> None:
        self.statuses.append(text)

    def notice(self, key: str, model) -> None:
        self.notices[key] = model


@pytest.fixture(scope='module')
def pairs(tmp_path_factory):
    root = tmp_path_factory.mktemp('pairs')
    return {
        'differs': pair_fingerprints(root, 'diec-toolchain', 'toolchain'),
        'same': pair_fingerprints(root, 'diec-same', 'same'),
        'unknown': pair_fingerprints(root, 'diec-unknown', 'unknown'),
        'plain': pair_fingerprints(root, 'diec-unknown')}


def taker(_service, _project, key) -> ReadRequest:
    return ReadRequest(key, None, (), {})


def reading(outcome: Outcome):
    return lambda _request, _token, _report: outcome


def start(qtbot, reader, *, project=None, show=True):
    project = project or FakeProject()
    shell = FakeShell()
    ctx = registry.PanelContext(PANEL, project, SimpleNamespace(), SimpleNamespace(), shell)
    controller = qt_panel.BuildEnvController(ctx, taker=taker, reader=reader)
    qtbot.addWidget(controller.widget())
    controller.widget().resize(900, 600)
    if show:
        controller.widget().show()
    controller.project_changed(project.key())
    return controller, shell, project


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy() and controller.progress is None, timeout=5000)
    QApplication.processEvents()


def status(controller) -> tuple[str, str]:
    return controller.view.kind, controller.view.status_label().full_text()


def audit(widget) -> list[str]:
    return [p for p in a11y_audit(widget) if p != 'QHeaderView#?: not keyboard focusable']


# ---- states ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('name,kind,start_of_text', [
    ('differs', 'ready', 'Toolchain differs between OLDER and NEWER:'),
    ('same', 'ready', 'No toolchain change detected between OLDER and NEWER.'),
    ('unknown', 'partial', 'The toolchain could not be compared:'),
    ('plain', 'partial', 'Detect It Easy is not set up.')], ids=['b4', 'b3', 'b5', 'b2'])
def test_result_states_use_the_view_model_copy(qtbot, pairs, name, kind, start_of_text):
    older, newer = pairs[name]
    controller, shell, _ = start(qtbot, reading(Outcome(older, newer)))
    settle(qtbot, controller)
    got_kind, text = status(controller)
    assert got_kind == kind and text.startswith(start_of_text)
    assert controller.table.table_model.rowCount() == len(controller.good.rows) > 0
    assert (text, False) in shell.announced


def test_b0_without_a_project_says_to_open_one(qtbot):
    controller, shell, _ = start(qtbot, reading(Outcome(None, None)), project=FakeProject(is_open=False))
    assert status(controller) == ('no-project', 'Open a project to see the build environment.')
    assert not controller.table.isVisibleTo(controller.widget())
    assert shell.notices['build_env.preflight'] is None


def test_b1_loading_shows_progress_and_cancel(qtbot):
    gate = threading.Event()

    def slow(_request, token, report):
        report('newer', 1, 2)
        gate.wait(5)
        return Outcome(None, None, cancelled=token.is_set())
    controller, *_ = start(qtbot, slow)
    qtbot.waitUntil(lambda: status(controller)[1].startswith('Reading build environment: NEWER'), timeout=5000)
    assert status(controller)[0] == 'loading' and controller.buttons['cancel'].isVisibleTo(controller.widget())
    assert not controller.buttons['reread'].isEnabled()
    controller.cancel()
    gate.set()
    settle(qtbot, controller)
    assert status(controller) == ('cancelled', 'Cancelled. Earlier results are unchanged.')
    assert not controller.buttons['cancel'].isVisibleTo(controller.widget())


def test_b6_one_unreadable_side_keeps_the_other(qtbot, pairs):
    older, _ = pairs['differs']
    controller, *_ = start(qtbot, reading(Outcome(older, None)))
    settle(qtbot, controller)
    kind, text = status(controller)
    assert kind == 'partial' and text.startswith('Build environment is incomplete for NEWER')


def test_b7_stale_evidence_is_for_reference_and_offers_refresh(qtbot, pairs):
    controller, *_ = start(qtbot, reading(Outcome(*pairs['differs'], stale=True)))
    settle(qtbot, controller)
    assert status(controller)[0] == 'stale'
    assert controller.view.action_button('refresh').isVisibleTo(controller.widget())
    assert controller.table.table_model.rowCount() > 0


def test_b8_error_keeps_earlier_results_and_offers_retry_and_copy(qtbot, pairs):
    results = iter([Outcome(*pairs['differs']), Outcome(None, None, error='PT-BUILD-INPUT')])
    controller, shell, _ = start(qtbot, lambda *_: next(results))
    settle(qtbot, controller)
    rows = controller.table.table_model.rowCount()
    controller.read()
    settle(qtbot, controller)
    kind, text = status(controller)
    assert kind == 'error' and text == ('Build environment could not be read (PT-BUILD-INPUT). '
                                        'Earlier results are unchanged.')
    assert shell.announced[-1] == (text, True)
    assert controller.table.table_model.rowCount() == rows
    for action in ('retry', 'copy'):
        assert controller.view.action_button(action).isVisibleTo(controller.widget())
    controller.view.action_button('copy').click()
    assert shell.copied[-1] == text


def test_a_failing_worker_shows_an_error_by_class_only(qtbot):
    def boom(*_):
        raise RuntimeError('secret C:/path')
    controller, shell, _ = start(qtbot, boom)
    settle(qtbot, controller)
    assert status(controller)[0] == 'error' and 'secret' not in status(controller)[1]


def test_setup_says_how_without_downloading(qtbot, pairs):
    controller, shell, _ = start(qtbot, reading(Outcome(*pairs['plain'])))
    settle(qtbot, controller)
    controller.view.action_button('setup').click()
    assert shell.statuses and 'Nothing is downloaded' in shell.statuses[-1]


def test_preflight_cautions_go_to_one_notice_and_stay_in_the_detail(qtbot, pairs):
    controller, shell, _ = start(qtbot, reading(Outcome(*pairs['plain'])))
    settle(qtbot, controller)
    notice = shell.notices['build_env.preflight']
    assert notice is None or notice.text.startswith(('[!]', '[i]'))
    for banner in controller.good.banners:
        assert banner.text in controller.detail.toPlainText()


# ---- hostile text ----------------------------------------------------------------------------------------------

def test_hostile_text_is_bounded_and_never_rich(qtbot, pairs, monkeypatch):
    row = FactRow('compiler', HOSTILE, HOSTILE, HOSTILE, HOSTILE, HOSTILE)
    banner = BannerView('packed', 'older', 'caution', '[!]', HOSTILE, None)
    view = BuildEnvViewModel('B4', HOSTILE, (banner,), (row,), '', HOSTILE, (HOSTILE,))
    monkeypatch.setattr(qt_panel, 'build_view', lambda *a, **k: view)
    controller, shell, _ = start(qtbot, reading(Outcome(*pairs['differs'])))
    settle(qtbot, controller)
    shown = [status(controller)[1], *controller.table.table_model.texts_at(0), controller.detail.toPlainText(),
             shell.notices['build_env.preflight'].text]
    for text in shown:
        assert '\x1b' not in text and '\u202e' not in text and len(text) < 20_000
    assert all(len(t) <= 600 for t in (shown[0], *shown[1:6]))
    assert controller.table.table_model.texts_at(0)[0].startswith('<b>bold</b>')  # shown literally, not as markup
    assert not controller.view.status_label().textFormat().name == 'RichText'


# ---- names, keys, tooltips -------------------------------------------------------------------------------------

def test_panel_is_accessible_and_every_control_has_a_tip(qtbot, pairs):
    controller, *_ = start(qtbot, reading(Outcome(*pairs['differs'])))
    settle(qtbot, controller)
    assert audit(controller.widget()) == []
    for button in controller.buttons.values():
        assert button.objectName() in tooltips.REGISTRY
    assert set(top_level_windows()) <= {controller.widget()}  # no window of its own


def test_keyboard_focus_lands_on_the_table(qtbot, pairs):
    controller, *_ = start(qtbot, reading(Outcome(*pairs['differs'])))
    settle(qtbot, controller)
    assert controller.widget().focusProxy() is controller.table


def test_technical_details_are_off_until_asked(qtbot, pairs):
    controller, *_ = start(qtbot, reading(Outcome(*pairs['differs'])))
    settle(qtbot, controller)
    assert not controller.good.technical
    controller.technical_box.setChecked(True)
    assert controller.good.technical and controller.good.technical[0] in controller.detail.toPlainText()


def test_copy_puts_the_card_on_the_clipboard_within_the_limit(qtbot, pairs):
    controller, shell, _ = start(qtbot, reading(Outcome(*pairs['differs'])))
    settle(qtbot, controller)
    controller.buttons['copy'].click()
    assert shell.copied and 'Compiler' in shell.copied[-1] and len(shell.copied[-1]) <= 16_384


# ---- anchors ---------------------------------------------------------------------------------------------------

def test_a_build_fact_anchor_selects_its_row_and_a_miss_changes_nothing(qtbot, pairs):
    older, newer = pairs['differs']
    controller, *_ = start(qtbot, reading(Outcome(older, newer)))
    settle(qtbot, controller)
    anchor = next(a for a in anchors_for(older) if a.key in {r.key for r in controller.good.rows})
    result = controller.show_anchor(AnchorRef('build_fact', anchor.anchor_id, 'older', 'run-1'))
    assert result.status == 'shown' and controller.table.current_key() == anchor.key
    before = controller.table.current_key()
    wrong_side = controller.show_anchor(AnchorRef('build_fact', anchor.anchor_id, 'newer', 'run-1', label='fact'))
    unknown = controller.show_anchor(AnchorRef('build_fact', 'f' * 64, 'older', 'run-1', label='fact'))
    assert wrong_side.status == unknown.status == 'not-found' and controller.table.current_key() == before
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2024-0001')).status == 'blocked'


def test_an_anchor_before_anything_is_loaded_is_blocked(qtbot):
    controller, *_ = start(qtbot, reading(Outcome(None, None)), project=FakeProject(is_open=False))
    assert controller.show_anchor(AnchorRef('build_fact', 'a' * 64, 'older')).status == 'blocked'


# ---- threads ---------------------------------------------------------------------------------------------------

def test_a_late_result_after_a_project_switch_is_dropped(qtbot, pairs):
    gate, entered, calls = threading.Event(), threading.Event(), []

    def reader(request, _token, _report):
        calls.append(request.key.project_id)
        if len(calls) == 1:
            entered.set()
            gate.wait(5)  # ignores the token on purpose: the guard must hold even for a worker that does not stop
            return Outcome(*pairs['differs'])
        return Outcome(*pairs['same'])
    project = FakeProject(project_id='one')
    controller, shell, _ = start(qtbot, reader, project=project)
    assert entered.wait(5)
    project.project_id = 'two'
    controller.project_changed(project.key())
    gate.set()
    settle(qtbot, controller)
    assert status(controller)[1].startswith('No toolchain change detected')
    assert controller.key.project_id == 'two' and calls == ['one', 'two']


def test_a_stale_epoch_is_rejected_even_if_the_runner_delivers_it(qtbot, pairs):
    controller, *_ = start(qtbot, reading(Outcome(*pairs['same'])))
    settle(qtbot, controller)
    before = status(controller)
    request = ReadRequest(controller.key, None, (), {})
    controller._done(controller.epoch - 1, request, Outcome(*pairs['differs']))
    controller._done(controller.epoch, dataclasses.replace(request, key=key_of('other')), Outcome(*pairs['differs']))
    assert status(controller) == before


def test_shutdown_cancels_the_read_drops_its_result_and_is_idempotent(qtbot, pairs, join_gui_threads):
    gate, entered = threading.Event(), threading.Event()

    def reader(_request, token, _report):
        entered.set()
        gate.wait(5)
        return Outcome(*pairs['differs'])
    controller, shell, _ = start(qtbot, reader)
    assert entered.wait(5)
    controller.shutdown()
    controller.shutdown()
    gate.set()
    settle(qtbot, controller)
    QApplication.processEvents()
    assert controller.good is None and shell.notices['build_env.preflight'] is None
    controller.read()  # a closed panel starts nothing
    assert not controller.tasks.busy()


# ---- declaration -----------------------------------------------------------------------------------------------

def test_the_spec_matches_its_manifest_slot_and_lints_clean():
    entry = next(e for e in MANIFEST if e.id == 'build_env')
    assert entry.load() is PANEL
    assert (PANEL.area, PANEL.tabify_with, PANEL.shortcut) == (entry.area, entry.tabify_with, entry.shortcut)
    loaded = registry.load_manifest([entry])
    assert not loaded.errors and not loaded.forbidden and list(loaded.specs) == ['build_env']
    report = registry.lint(MANIFEST, loaded)
    assert [f for f in report.findings if f.panel == 'build_env'] == []
