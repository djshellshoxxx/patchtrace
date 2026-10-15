# ruff: noqa: F811
"""PanelHost: shells, lazy construction, lifecycle hooks, blocked and failed panels, ports, anchors (GUI plan 8.2)."""
from __future__ import annotations

import pytest
from host_support import (  # noqa: F401 - the autouse fixture must be imported
    Provider,
    Recorder,
    absent,
    make_host,
    private_tooltip_registry,
    spec,
)
from PySide6.QtCore import Qt
from qt_support import join_gui_threads, main_window, settings  # noqa: F401

from patchtrace.gui.anchors import AnchorRef
from patchtrace.gui.capabilities import CapabilityState
from patchtrace.gui.ports import MutationPort, NavigationPort, ProjectPort, ShellPort, WindowPort
from patchtrace.gui.projection import ProjectKey
from patchtrace.gui.registry import CLIPBOARD_BYTES
from patchtrace.gui.state import NoticeModel


def built(host, panel_id):
    return host.panels[panel_id].controller


# ---- shells -------------------------------------------------------------------------------------------------


def test_shells_are_hidden_named_and_grouped(qtbot, settings):
    window, host = make_host(qtbot, settings, spec('alpha', 'bottom'), spec('beta', 'bottom', tabify_with='alpha'),
                             spec('gamma', 'left'), spec('card', 'none'))
    window.show()
    docks = {panel_id: panel.dock for panel_id, panel in host.panels.items()}
    assert docks['card'] is None
    for panel_id in ('alpha', 'beta', 'gamma'):
        assert docks[panel_id].objectName() == f'{panel_id}.dock' and docks[panel_id].isHidden()
        assert docks[panel_id].accessibleName().endswith(' panel')
    docks['alpha'].show()
    docks['beta'].show()  # Qt lists only visible docks as tab siblings
    assert docks['beta'] in window.tabifiedDockWidgets(docks['alpha'])
    assert window.dockWidgetArea(docks['gamma']) == Qt.DockWidgetArea.LeftDockWidgetArea
    assert all(panel.controller is None for panel in host.panels.values())  # nothing is built before it is shown


def test_unbuilt_and_rejected_manifest_entries_are_skipped(qtbot, settings):
    clash = spec('clash', 'right', shortcut='Ctrl+Shift+Q')
    bad = spec('worse', 'right', shortcut='Ctrl+Shift+Q')  # the same shortcut twice: PT-GUI-MANIFEST
    window, host = make_host(qtbot, settings, clash, bad, extra=(absent('later'),))
    assert 'later' in host.not_built and 'later' not in host.panels
    assert 'clash' in host.panels and 'worse' not in host.panels  # the first claim of a shortcut wins
    assert any('PT-GUI-MANIFEST' in problem for problem in host.problems)


def test_a_panel_without_a_dock_has_tips_and_no_shell(qtbot, settings):
    window, host = make_host(qtbot, settings, spec('card', 'none', eager=True))
    host.restore_layout()
    assert host.panels['card'].dock is None and isinstance(built(host, 'card'), Recorder)
    assert 'card.card' in __import__('patchtrace.tooltips', fromlist=['REGISTRY']).REGISTRY


# ---- lazy construction and lifecycle hooks --------------------------------------------------------------------


def test_a_panel_is_built_once_on_first_show_and_replayed_the_current_state(qtbot, settings):
    window, host = make_host(qtbot, settings, spec('alpha'))
    window.show()
    host.selection_changed(type('M', (), {'id': 'm1'})())
    qtbot.waitUntil(lambda: host._selected == 'm1')
    action = host.toggle_action('alpha')
    action.trigger()
    qtbot.waitUntil(lambda: built(host, 'alpha') is not None)
    recorder = built(host, 'alpha')
    qtbot.waitUntil(lambda: ('selection', 'm1') in recorder.calls)
    assert recorder.names()[0] == 'theme'
    assert recorder.names().count('project') == 1 and ('busy', False) in recorder.calls
    action.trigger()
    action.trigger()
    qtbot.wait(50)
    assert built(host, 'alpha') is recorder and recorder.names().count('theme') == 1


def test_a_hidden_panel_is_marked_dirty_and_catches_up_when_shown(qtbot, settings):
    window, host = make_host(qtbot, settings, spec('alpha'))
    window.show()
    host.show_panel('alpha')
    recorder = built(host, 'alpha')
    host.panels['alpha'].dock.hide()
    qtbot.waitUntil(lambda: not host.panels['alpha'].active)
    recorder.calls.clear()
    host.project_changed()
    host.update_controls()
    assert 'project' not in recorder.names()  # hidden: nothing is applied
    host.show_panel('alpha')
    assert recorder.names().count('project') == 1


def test_selection_is_debounced_and_busy_is_reported_on_change_only(qtbot, settings):
    window, host = make_host(qtbot, settings, spec('alpha'))
    window.show()
    host.show_panel('alpha')
    recorder = built(host, 'alpha')
    recorder.calls.clear()
    for number in range(5):
        host.selection_changed(type('M', (), {'id': f'm{number}'})())
    assert not recorder.calls
    qtbot.waitUntil(lambda: recorder.calls == [('selection', 'm4')], timeout=2000)
    window.worker = object()
    host.update_controls()
    host.update_controls()
    assert recorder.names().count('busy') == 1 and ('busy', True) in recorder.calls
    window.worker = None
    host.update_controls()


def test_a_hook_that_raises_costs_a_status_line_not_the_window(qtbot, settings):
    class Broken(Recorder):
        def project_changed(self, key) -> None:
            raise RuntimeError('boom with a secret path C:\\private')

    window, host = make_host(qtbot, settings, spec('alpha', factory=Broken))
    window.show()
    host.show_panel('alpha')
    assert 'Alpha panel error: RuntimeError.' in window.statusBar().currentMessage()
    assert 'private' not in window.statusBar().currentMessage()


# ---- failed and blocked panels ----------------------------------------------------------------------------------


def test_a_failing_factory_shows_the_class_only_and_retry_rebuilds(qtbot, settings):
    attempts = []

    def factory(ctx):
        attempts.append(1)
        if len(attempts) == 1:
            raise ValueError('secret C:\\Users\\x\\key')
        return Recorder(ctx)

    window, host = make_host(qtbot, settings, spec('alpha', factory=factory), spec('beta'))
    window.show()
    assert host.show_panel('alpha') is not None and built(host, 'alpha') is None
    view = host.panels['alpha'].dock.view
    assert view.kind == 'error' and 'ValueError' in view.model.text
    assert 'secret' not in view.model.text + view.model.detail
    assert host.show_panel('beta') is not None and built(host, 'beta') is not None  # others are unaffected
    view.action_button('retry').click()
    assert built(host, 'alpha') is not None and view.kind == 'ready'


def test_unmet_requirements_open_the_panel_blocked_with_reason_and_remedy(qtbot, settings):
    provider = Provider(**{'tool:capa': CapabilityState('missing', 'capa is not installed.', 'patchtrace setup')})
    window, host = make_host(qtbot, settings, spec('alpha', requires=('tool:capa',)), capabilities=provider)
    window.show()
    host.update_controls()
    host.show_panel('alpha')
    view = host.panels['alpha'].dock.view
    assert view.kind == 'blocked' and 'capa is not installed.' in view.model.text
    assert 'patchtrace setup' in view.model.text and view.action_button('setup').isVisibleTo(view)
    assert host.panels['alpha'].dock.isVisible()  # never hidden
    recorder = built(host, 'alpha')
    recorder.calls.clear()
    provider.states.clear()
    host.update_controls()
    host.project_changed()
    assert view.kind == 'ready' and ('capabilities',) in recorder.calls


def test_headless_build_all_for_test_builds_everything_even_when_blocked(qtbot, settings):
    provider = Provider(project=CapabilityState('missing', 'Open a project first.'))
    window, host = make_host(qtbot, settings, spec('alpha', requires=('project',)), spec('card', 'none'),
                             capabilities=provider)
    host.update_controls()
    controllers = host.build_all_for_test()
    assert set(controllers) == {'alpha', 'card'} and host.self_check() == []


def test_self_check_reports_a_failing_factory(qtbot, settings):
    def factory(ctx):
        raise KeyError('x')

    window, host = make_host(qtbot, settings, spec('alpha', factory=factory))
    assert host.self_check() == ['alpha: PT-GUI-FACTORY KeyError']


# ---- ports ------------------------------------------------------------------------------------------------------


def test_the_context_ports_satisfy_the_protocols_and_settings_are_scoped(qtbot, settings):
    window, host = make_host(qtbot, settings, spec('alpha'))
    window.show()
    host.show_panel('alpha')
    ctx = built(host, 'alpha').ctx
    for protocol, port in ((ProjectPort, ctx.project), (MutationPort, ctx.mutate), (NavigationPort, ctx.nav),
                           (ShellPort, ctx.shell), (WindowPort, ctx.shell)):
        assert isinstance(port, protocol)
    ctx.settings.set('width', 7)
    assert settings.value('alpha/width') == '7' or settings.value('alpha/width') == 7
    assert ctx.tasks is host.tasks and ctx.theme is host.tokens


def test_copy_text_refuses_more_than_16_kib(qtbot, settings):
    window, host = make_host(qtbot, settings)
    assert host.port.copy_text('x' * CLIPBOARD_BYTES) is True
    assert host.port.copy_text('x' * (CLIPBOARD_BYTES + 1)) is False
    assert host.port.copy_text('é' * (CLIPBOARD_BYTES // 2 + 1)) is False  # bytes, not characters


def test_announcements_go_to_the_status_bar_through_the_announcer(qtbot, settings, monkeypatch):
    window, host = make_host(qtbot, settings)
    sent = []
    monkeypatch.setattr(host.announcer, '_sender', lambda target, text, assertive: sent.append((target, text, assertive)))
    host.port.announce('Loaded 3 rows.')
    host.port.announce('Cannot continue.', assertive=True)
    assert sent == [(window.statusBar(), 'Loaded 3 rows.', False), (window.statusBar(), 'Cannot continue.', True)]


def test_notices_show_in_the_strip_above_the_workspace(qtbot, settings):
    window, host = make_host(qtbot, settings)
    host.restore_layout()
    window.show()
    assert window.centralWidget().objectName() == 'workspace.wrapper'
    host.port.notice('pre.flight', NoticeModel('pre.flight', 'caution', 'Hash mismatch.'))
    assert host.strip.current is not None and host.strip.isVisible()
    host.port.notice('pre.flight', None)
    assert host.strip.current is None


def test_the_task_runner_is_shut_down_with_the_host_and_controllers_once(qtbot, settings):
    window, host = make_host(qtbot, settings, spec('alpha'))
    window.show()
    host.show_panel('alpha')
    recorder = built(host, 'alpha')
    host.shutdown()
    host.shutdown()
    assert recorder.names().count('shutdown') == 1
    with pytest.raises(RuntimeError):
        host.tasks.submit('x', lambda token, report: None)


# ---- anchors ------------------------------------------------------------------------------------------------------


def key_of(host):
    return ProjectKey('root', 'p1', 1, 'run1', 'a' * 64, 'b' * 64)


def test_an_anchor_opens_the_panel_that_declares_its_kind(qtbot, settings, monkeypatch):
    window, host = make_host(qtbot, settings, spec('alpha', anchors_in=frozenset({'string'})))
    window.show()
    monkeypatch.setattr(host.port, 'key', lambda: key_of(host))
    result = host.router.navigate(AnchorRef('string', 'abc', run_id='run1', revision=1))
    assert result.status == 'shown' and host.panels['alpha'].dock.isVisible()
    assert built(host, 'alpha').calls[-1][0] == 'anchor'


@pytest.mark.parametrize('anchor, expected', [
    (AnchorRef('cve', 'CVE-2020-1', run_id='run1', revision=1), 'blocked'),
    (AnchorRef('string', 'abc', run_id='other', revision=1), 'stale'),
    (AnchorRef('string', 'abc', run_id='run1', revision=9), 'stale'),
], ids=['unhandled', 'other-run', 'old-revision'])
def test_unhandled_and_stale_anchors_navigate_nowhere(qtbot, settings, monkeypatch, anchor, expected):
    window, host = make_host(qtbot, settings, spec('alpha', anchors_in=frozenset({'string'})))
    window.show()
    monkeypatch.setattr(host.port, 'key', lambda: key_of(host))
    assert host.router.navigate(anchor).status == expected
    assert built(host, 'alpha') is None


def test_an_anchor_into_a_blocked_panel_says_why(qtbot, settings, monkeypatch):
    provider = Provider(project=CapabilityState('missing', 'Open a project first.'))
    window, host = make_host(qtbot, settings, spec('alpha', requires=('project',), anchors_in=frozenset({'string'})),
                             capabilities=provider)
    host.update_controls()
    monkeypatch.setattr(host.port, 'key', lambda: key_of(host))
    result = host.router.navigate(AnchorRef('string', 'abc', run_id='run1', revision=1))
    assert result.status == 'blocked' and result.message == 'Alpha is unavailable: Open a project first.'


def test_a_raising_anchor_handler_is_a_blocked_result(qtbot, settings, monkeypatch):
    class Broken(Recorder):
        def show_anchor(self, anchor):
            raise RuntimeError('private detail')

    window, host = make_host(qtbot, settings, spec('alpha', factory=Broken, anchors_in=frozenset({'string'})))
    window.show()
    monkeypatch.setattr(host.port, 'key', lambda: key_of(host))
    result = host.router.navigate(AnchorRef('string', 'abc', run_id='run1', revision=1))
    assert result.status == 'blocked' and 'private' not in result.message


# ---- the real window ------------------------------------------------------------------------------------------


def test_function_anchors_select_the_match_through_the_main_window(main_window):
    window = main_window
    window.show()
    key = window.panels.port.key()
    match = next(m for m in window.project.matches if m.newer and m.older)
    function = match.newer[0]
    result = window.panels.port.navigate(AnchorRef('function', function.id, 'newer', key.run_id, function.name))
    assert result.status == 'shown' and window.current_match().id == match.id
    missing = window.panels.port.navigate(AnchorRef('function', 'nope', 'newer', key.run_id, 'nope'))
    assert missing.status == 'not-found' and 'Not found in run' in missing.message
    stale = window.panels.port.navigate(AnchorRef('function', function.id, 'newer', 'old-run', function.name))
    assert stale.status == 'stale'
    other = next(m for m in window.project.matches if m.newer and m.id != match.id).newer[0]
    assert window.panels.port.navigate(AnchorRef('function', other.id, 'newer', key.run_id, other.name)).status == 'shown'
    assert window.panels.port.back().status == 'shown' and window.current_match().id == match.id
    assert window.panels.port.forward().status == 'shown' and window.current_match().id != match.id


def test_the_main_window_hooks_reach_the_host(main_window, qtbot):
    window = main_window
    seen = []
    window.panels.selection_changed = lambda match: seen.append(getattr(match, 'id', None))
    window.navigator.setCurrentRow(1)
    assert seen and seen[-1] == window.current_match().id
    key = window.panels.port.key()
    assert key.project_id == window.project.id and key.revision == window.project.revision
    assert isinstance(window.panels.port, WindowPort)


def test_reveal_lines_show_original_lines_and_report_a_miss(main_window):
    window = main_window
    window.show()
    window.navigator.setCurrentRow(next(row for row in range(window.navigator.count()) if all(
        (window.navigator.item(row).data(Qt.ItemDataRole.UserRole) == m.id and m.newer) for m in window.project.matches
        if m.id == window.navigator.item(row).data(Qt.ItemDataRole.UserRole))))
    function = window.current_match().newer[0]
    view = window.panels.port.reveal_lines(function.id, 1, 1)
    assert view is window.views['newer'] and view.textCursor().hasSelection()
    assert window.panels.port.reveal_lines('nope', 1, 1) is None
    assert window.panels.port.reveal_lines(function.id, 10_000, 10_001) is None


def test_show_pair_replaces_the_code_panes_and_clears_hunks(main_window):
    window = main_window
    window.show()
    window.panels.port.show_pair('old <b>text</b>', 'new text', 'Panel pair')
    assert window.views['older'].toPlainText() == 'old <b>text</b>' and window.views['newer'].toPlainText() == 'new text'
    assert window._function_offsets == {} and window._hunks == [] and window.hunk_list.count() == 0
    assert window.match_label.text() == 'Panel pair'
    window.panels.port.show_pair('x' * 300_000, '', 'big')
    assert window.views['older'].toPlainText().startswith('x' * 200_000 + '\n[View truncated')
