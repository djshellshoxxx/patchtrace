"""StateView and NoticeStrip: per-state copy, precedence, actions, announcements, hostile text (GUI plan 8.4, 8.7)."""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget
from qt_support import HOSTILE_PARAMS, RecordingAnnouncer, a11y_audit, join_gui_threads  # noqa: F401

from patchtrace import tooltips
from patchtrace.gui.qt.state_view import NoticeStrip, StateView
from patchtrace.gui.state import STATE_KINDS, NoticeModel, StateModel, factory_failure, state_model
from patchtrace.gui.tips import register_gui_tips


@pytest.fixture(autouse=True)
def gui_tips(monkeypatch):
    """The host registers the framework tips; a private copy keeps the tooltip tests' registry untouched."""
    monkeypatch.setattr(tooltips, 'REGISTRY', dict(tooltips.REGISTRY))
    register_gui_tips()


@pytest.fixture
def announcer():
    return RecordingAnnouncer()


@pytest.fixture
def view(qtbot, announcer):
    widget = StateView('search', 'Search', announcer)
    qtbot.addWidget(widget)
    widget.resize(500, 300)
    widget.show()
    return widget


def shown(view, name):
    return view.action_button(name).isVisibleTo(view)


# The copy of plan 8.4, written out here so that a change to the templates is a visible decision.
COPY = [
    ('no-project', {}, 'Open a project to use Search.', ()),
    ('idle', {'hint': 'Run a search.'}, 'Search has no results yet. Run a search.', ()),
    ('loading', {'noun': 'matches'}, 'Loading matches...', ()),
    ('refreshing', {'noun': 'matches'}, 'Refreshing matches...', ()),
    ('partial', {'reasons': 'two segments missing'},
     'Partial result: two segments missing. Missing evidence is unknown, not disagreement.', ()),
    ('stale', {'reason': 'the project changed'}, 'Search is stale: the project changed. It is shown for reference only.',
     ('refresh',)),
    ('blocked', {'reason': 'No index.', 'remedy': 'Build one.'}, 'Search is unavailable: No index. Build one.',
     ('setup',)),
    ('error', {'code': 'PT-X', 'message': 'disk full'},
     'Search could not be loaded: PT-X: disk full. Earlier results are unchanged.', ('retry', 'copy')),
    ('too-large', {'n': 150000}, 'Too many rows to display (150000). Narrow the filter.', ()),
    ('unsupported', {'reason': 'Needs Windows.'}, 'Search is not supported here: Needs Windows.', ()),
    ('cancelled', {}, 'Cancelled. Earlier results are unchanged.', ()),
]


@pytest.mark.parametrize('kind, fields, text, actions', COPY, ids=[row[0] for row in COPY])
def test_each_state_shows_its_copy_and_only_its_buttons(view, kind, fields, text, actions):
    view.show_conditions({kind: fields})
    assert view.kind == kind and view.status_label().full_text() == text
    assert [name for name in ('retry', 'copy', 'setup', 'refresh') if shown(view, name)] == sorted(
        actions, key=('retry', 'copy', 'setup', 'refresh').index)


def test_the_copy_table_covers_every_state_except_ready():
    assert {row[0] for row in COPY} == set(STATE_KINDS) - {'ready'}


def test_ready_hides_the_whole_strip(view):
    view.show_conditions({'ready': {}})
    assert not view.status_label().isVisibleTo(view) and view.status_label().full_text() == ''


def test_a_factory_failure_shows_only_the_class_name(view):
    view.set_state(factory_failure('Search', 'KeyError'))
    assert view.status_label().full_text() == (
        'Search could not be created: PT-GUI-FACTORY: KeyError. Other panels are unaffected.')


@pytest.mark.parametrize('conditions, expected', [
    ({'partial': {'reasons': 'x'}, 'error': {'code': 'C', 'message': 'm'}, 'stale': {'reason': 'r'}}, 'error'),
    ({'partial': {'reasons': 'x'}, 'stale': {'reason': 'r'}, 'ready': {}}, 'stale'),
    ({'partial': {'reasons': 'x'}, 'ready': {}}, 'partial'),
    ({'refreshing': {}, 'ready': {}}, 'refreshing'),
    ({'ready': {}, 'idle': {}}, 'ready'),
    ({}, 'idle'),
], ids=['error', 'stale', 'partial', 'refreshing', 'ready', 'none'])
def test_precedence_picks_the_dominant_state(view, conditions, expected):
    view.show_conditions(conditions, has_content=True)
    assert view.kind == expected


def test_an_unknown_kind_is_refused(view):
    with pytest.raises(ValueError):
        view.show_conditions({'confused': {}})


def test_buttons_are_named_per_panel_and_unique_across_panels(qtbot, announcer):
    first, second = StateView('search', 'Search'), StateView('graph', 'Graph')
    for widget in (first, second):
        qtbot.addWidget(widget)
    assert first.action_button('retry').accessibleName() == 'Retry loading Search'
    assert first.action_button('copy').accessibleName() == 'Copy Search details'
    assert first.action_button('setup').accessibleName() == 'Open setup for Search'
    assert first.action_button('refresh').accessibleName() == 'Refresh Search'
    names = {widget.action_button(a).accessibleName() for widget in (first, second)
             for a in ('retry', 'copy', 'setup', 'refresh')}
    assert len(names) == 8
    identifiers = {widget.action_button('retry').accessibleIdentifier() for widget in (first, second)}
    assert identifiers == {'search.state_retry', 'graph.state_retry'}


def test_the_buttons_have_tips_and_visible_labels(view):
    retry = view.action_button('retry')
    assert retry.text() == 'Retry' and retry.accessibleDescription() == 'Load this panel again.'
    assert 'Why' in retry.toolTip()
    assert view.action_button('copy').text() == 'Copy details' and view.action_button('setup').text() == 'Open setup'


def test_the_status_label_keeps_an_empty_accessible_name_and_is_plain(view):
    view.show_conditions({'error': {'code': 'C', 'message': 'm'}})
    label = view.status_label()
    assert label.accessibleName() == '' and label.textFormat() == Qt.TextFormat.PlainText


@pytest.mark.parametrize('action, signal', [('retry', 'retry_requested'), ('setup', 'setup_requested'),
                                            ('refresh', 'refresh_requested')])
def test_a_button_emits_its_signal(qtbot, view, action, signal):
    kind = {'retry': 'error', 'setup': 'blocked', 'refresh': 'stale'}[action]
    view.show_conditions({kind: {'code': 'C', 'message': 'm', 'reason': 'r', 'remedy': 'x'}})
    with qtbot.waitSignal(getattr(view, signal), timeout=1000):
        view.action_button(action).click()


def test_copy_details_sends_the_details_text(qtbot, view):
    view.set_state(state_model('error', 'Search', detail='Traceback class: KeyError', code='C', message='m'))
    with qtbot.waitSignal(view.copy_requested, timeout=1000) as blocker:
        view.action_button('copy').click()
    assert blocker.args == ['Traceback class: KeyError']


@pytest.mark.parametrize('kind, has_content, visible', [
    ('ready', False, True), ('partial', True, True), ('partial', False, False), ('stale', True, True),
    ('refreshing', True, True), ('error', True, True), ('error', False, False), ('cancelled', True, True),
    ('loading', True, False), ('blocked', True, False), ('no-project', True, False), ('too-large', True, False),
    ('unsupported', True, False), ('idle', True, False),
], ids=lambda value: str(value))
def test_content_is_shown_only_where_results_exist(qtbot, view, kind, has_content, visible):
    content = QLabel('results')
    view.set_content(content)
    view.show_conditions({kind: {'n': 3, 'reasons': 'r', 'reason': 'r', 'code': 'C', 'message': 'm'}},
                         has_content=has_content)
    assert content.isVisibleTo(view) is visible


def test_replacing_the_content_removes_the_old_one_from_the_layout(qtbot, view):
    first, second = QLabel('one'), QLabel('two')
    view.set_content(first)
    view.set_content(second)
    view.show_conditions({'ready': {}})
    assert view.layout().indexOf(first) == -1 and second.isVisibleTo(view)


def test_changes_are_announced_once_and_errors_assertively(view, announcer):
    view.show_conditions({'loading': {'noun': 'matches'}})
    view.show_conditions({'loading': {'noun': 'matches'}})
    view.show_conditions({'ready': {}})
    view.show_conditions({'error': {'code': 'C', 'message': 'm'}})
    assert announcer.messages == [
        ('Loading matches...', False),
        ('Search could not be loaded: C: m. Earlier results are unchanged.', True)]


def test_a_view_without_an_announcer_still_works(qtbot):
    widget = StateView('search', 'Search')
    qtbot.addWidget(widget)
    widget.show_conditions({'loading': {'noun': 'matches'}})
    assert widget.kind == 'loading'


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_reasons_are_data(view, announcer, text):
    view.show_conditions({'partial': {'reasons': text}})
    label = view.status_label()
    assert label.textFormat() == Qt.TextFormat.PlainText
    assert not any(char in label.full_text() for char in '\x00\x1b‮ \n')
    assert not any(char in announcer.texts[-1] for char in '\x00\x1b‮ ')


@pytest.mark.parametrize('kind, fields, text, actions', COPY, ids=[row[0] for row in COPY])
def test_the_accessibility_audit_is_clean_in_every_state(view, kind, fields, text, actions):
    view.show_conditions({kind: fields})
    assert a11y_audit(view) == []


# ---- NoticeStrip ----------------------------------------------------------------------------------------------

def notice(key='die.preflight', level='caution', text='The build environment was not checked.', **more):
    return NoticeModel(key, level, text, **more)


@pytest.fixture
def strip(qtbot, announcer):
    host = QWidget()  # the strip lives in the main window's layout; on its own, showing it would open a window
    QVBoxLayout(host)
    widget = NoticeStrip(announcer, host)
    host.layout().addWidget(widget)
    qtbot.addWidget(host)
    host.resize(600, 120)
    host.show()
    yield widget  # a yield keeps `host` alive for the test


def test_the_strip_is_hidden_until_there_is_a_notice(strip):
    assert strip.isHidden() and strip.current is None
    strip.set_notice('die.preflight', notice())
    assert not strip.isHidden() and strip.current.key == 'die.preflight'
    strip.set_notice('die.preflight', None)
    assert strip.isHidden()


def test_the_level_is_written_not_only_coloured(strip):
    strip.set_notice('a.one', notice('a.one', 'notice', 'Calibration scope is narrow.'))
    assert strip._label.full_text() == 'Note: Calibration scope is narrow.'
    strip.set_notice('die.preflight', notice())
    assert strip._label.full_text().startswith('Caution: ')


def test_a_caution_comes_first_and_the_rest_is_counted(strip):
    strip.set_notice('a.one', notice('a.one', 'notice', 'Calibration scope is narrow.'))
    strip.set_notice('die.preflight', notice())
    assert strip.current.key == 'die.preflight' and strip._label.full_text().endswith('(+1 more)')


def test_the_buttons_are_named_and_tipped(strip):
    strip.set_notice('die.preflight', notice(detail='Full explanation.'))
    assert strip.accessibleName() == 'Notices'
    assert strip._details_button.accessibleName() == 'Show notice details' and strip._details_button.text() == 'Details'
    assert strip._dismiss_button.accessibleName() == 'Dismiss notice' and strip._dismiss_button.text() == 'Dismiss'
    assert strip._dismiss_button.accessibleDescription() == 'Hide this notice.'


def test_details_toggle_a_plain_text_view_and_only_exist_with_detail(qtbot, strip):
    strip.set_notice('die.preflight', notice())
    assert not strip._details_button.isVisibleTo(strip)
    strip.set_notice('die.preflight', notice(detail='<b>Full</b>\nexplanation.'))
    assert strip._details_button.isVisibleTo(strip) and not strip._details.isVisibleTo(strip)
    strip._details_button.click()
    assert strip._details.isVisibleTo(strip) and strip._details.toPlainText() == '<b>Full</b>\nexplanation.'
    strip._details_button.click()
    assert not strip._details.isVisibleTo(strip)


def test_dismissing_hides_it_until_its_text_changes(qtbot, strip):
    strip.set_notice('die.preflight', notice())
    with qtbot.waitSignal(strip.dismissed, timeout=1000) as blocker:
        strip._dismiss_button.click()
    assert blocker.args == ['die.preflight'] and strip.isHidden()
    strip.set_notice('die.preflight', notice())
    assert strip.isHidden()
    strip.set_notice('die.preflight', None)
    strip.set_notice('die.preflight', notice())
    assert strip.isHidden()
    strip.set_notice('die.preflight', notice(text='The build environment changed.'))
    assert not strip.isHidden()


def test_dismissal_follows_the_scope(strip):
    strip.set_notice('a.project', notice('a.project', text='Project note.', scope='project'))
    strip.set_notice('a.session', notice('a.session', text='Session note.', scope='session'))
    strip._dismiss_button.click()
    strip._dismiss_button.click()
    assert strip.isHidden()
    strip.project_changed()
    assert strip.current.key == 'a.project'


def test_a_notice_that_cannot_be_dismissed_has_no_button(strip):
    strip.set_notice('die.preflight', notice(dismissible=False))
    assert not strip._dismiss_button.isVisibleTo(strip)
    strip._on_dismiss()
    assert not strip.isHidden()


def test_the_key_must_match_the_model(strip):
    with pytest.raises(ValueError):
        strip.set_notice('other.key', notice())


def test_a_notice_is_announced_when_it_appears_or_changes(strip, announcer):
    strip.set_notice('die.preflight', notice())
    strip.set_notice('die.preflight', notice())
    strip.set_notice('die.preflight', notice(text='Changed.'))
    assert announcer.texts == ['Caution: The build environment was not checked.', 'Caution: Changed.']


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_notice_text_is_data(strip, text):
    strip.set_notice('die.preflight', notice(text='x' + text, detail=text))
    assert strip._label.textFormat() == Qt.TextFormat.PlainText
    assert not any(char in strip._label.full_text() for char in '\x00\x1b‮ ')


def test_the_strip_passes_the_accessibility_audit(strip):
    strip.set_notice('die.preflight', notice(detail='Full explanation.'))
    strip._details_button.click()
    assert a11y_audit(strip) == []


def test_a_panel_may_ask_for_longer_multiline_state_copy(qtbot):
    long_text = 'first line ' + 'x' * 300 + '\nsecond line'
    default = StateView('search', 'Search')
    roomy = StateView('evidence', 'Evidence', text_limit=4_000, multiline=True)
    for widget in (default, roomy):
        qtbot.addWidget(widget)
        widget.set_state(StateModel('idle', long_text))
    assert len(default.status_label().text()) <= 200 and '\n' not in default.status_label().text()
    assert roomy.status_label().text() == long_text
