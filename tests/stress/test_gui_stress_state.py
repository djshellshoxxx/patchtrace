"""Stress: StateView state flips and a notice flood on NoticeStrip (GUI plan 8.2 lifecycle, 8.11 states).

A screen reader hears a state only when its text changes, so the announcer must receive exactly the changes and
nothing for a repeat. The notice strip shows one line, the most important notice first, with a count of the rest."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QPushButton
from qt_support import RecordingAnnouncer, join_gui_threads  # noqa: F401

from patchtrace import tooltips
from patchtrace.gui.qt.state_view import NoticeStrip, StateView
from patchtrace.gui.state import NoticeModel, state_model
from patchtrace.gui.tips import register_gui_tips

FLIPS = 300
NOTICES = 400


@pytest.fixture(autouse=True)
def gui_tips(monkeypatch):
    monkeypatch.setattr(tooltips, 'REGISTRY', dict(tooltips.REGISTRY))
    monkeypatch.setattr(tooltips, 'TEMPLATES', dict(tooltips.TEMPLATES))
    register_gui_tips()


def model_for(index: int):
    if index % 3 == 0:
        return state_model('blocked', 'Stress', reason=f'reason {index % 4}', remedy='Open setup.')
    if index % 3 == 1:
        return state_model('ready', 'Stress')
    return state_model('error', 'Stress')


def test_the_announcer_hears_exactly_the_state_text_changes_across_three_hundred_flips(qtbot):
    announcer = RecordingAnnouncer()
    view = StateView('stress', 'Stress', announcer)
    qtbot.addWidget(view)
    expected = 0
    previous = None
    for index in range(FLIPS):
        current = model_for(index // 2)  # every state is repeated once, so half of the flips change nothing
        view.set_state(current, has_content=False)
        if (current.kind, current.text) != previous and current.text:  # a ready state has no text to announce
            expected += 1
        previous = (current.kind, current.text)
    assert len(announcer.messages) == expected
    assert all(text for text, _ in announcer.messages)
    assert view.kind == model_for((FLIPS - 1) // 2).kind


def notice(index: int, level: str = 'notice') -> NoticeModel:
    return NoticeModel(f'stress-{index}', level, f'note number {index}', detail=f'detail {index}')


def test_a_flood_of_notices_shows_one_line_with_a_count_and_clears_to_nothing(qtbot):
    announcer = RecordingAnnouncer()
    strip = NoticeStrip(announcer)
    qtbot.addWidget(strip)
    strip.show()
    for index in range(NOTICES):
        strip.set_notice(f'stress-{index}', notice(index))
    assert strip.isVisible() and strip.current is not None
    assert strip.current.key == 'stress-0'
    assert len(announcer.messages) == 1  # one announcement for the first notice, not one per notice
    caution = NoticeModel('stress-caution', 'caution', 'the one that matters')
    strip.set_notice(caution.key, caution)
    assert strip.current.key == caution.key  # a caution outranks every notice
    for index in range(NOTICES):
        strip.set_notice(f'stress-{index}', None)
    strip.set_notice(caution.key, None)
    assert strip.current is None and not strip.isVisible()


def test_a_dismissed_notice_returns_only_when_its_text_changes(qtbot):
    strip = NoticeStrip()
    qtbot.addWidget(strip)
    strip.show()
    same = NoticeModel('stress-d', 'notice', 'the same text')
    strip.set_notice('stress-d', same)
    for _ in range(50):
        strip._dismiss_button.click()
        strip.set_notice('stress-d', same)  # the same text again: still dismissed
    assert strip.current is None
    strip.set_notice('stress-d', NoticeModel('stress-d', 'notice', 'a new text'))
    assert strip.current is not None and strip.current.text == 'a new text'


def test_a_project_change_brings_back_project_scope_dismissals_and_keeps_session_ones(qtbot):
    strip = NoticeStrip()
    qtbot.addWidget(strip)
    strip.show()
    strip.set_notice('stress-p', NoticeModel('stress-p', 'notice', 'project note'))
    strip._dismiss_button.click()
    strip.set_notice('stress-s', NoticeModel('stress-s', 'notice', 'session note', scope='session'))
    strip.set_notice('stress-s', NoticeModel('stress-s', 'notice', 'session note', scope='session'))
    strip._dismiss_button.click()
    assert strip.current is None
    strip.project_changed()
    assert strip.current is not None and strip.current.key == 'stress-p'
    assert strip.findChildren(QPushButton)  # the strip keeps its controls through the churn
