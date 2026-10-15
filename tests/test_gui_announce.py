"""StatusAnnouncer, Metrics and runtime install (GUI plan 8.6, 8.7, 8.5 rule 7; slice F2). Offscreen, hermetic."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from PySide6.QtGui import QAccessible, QAccessibleAnnouncementEvent, QFont
from PySide6.QtWidgets import QLabel, QStatusBar
from qt_support import HOSTILE_PARAMS, RecordingAnnouncer, join_gui_threads  # noqa: F401

from patchtrace.gui.qt import announce, runtime
from patchtrace.gui.qt.announce import StatusAnnouncer
from patchtrace.gui.qt.metrics import Metrics, MetricsWatcher


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def bar(qtbot):
    widget = QStatusBar()
    qtbot.addWidget(widget)
    return widget


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def sent():
    return []


@pytest.fixture
def announcer(bar, clock, sent):
    return StatusAnnouncer(bar, lambda target, text, assertive: sent.append((target, text, assertive)), clock)


def test_first_message_is_sent_at_once_to_the_status_bar(announcer, sent, bar):
    announcer.announce('Search finished: 12 results.')
    assert sent == [(bar, 'Search finished: 12 results.', False)]


def test_messages_inside_the_window_collapse_to_the_latest_sent_after_the_window(announcer, sent, clock, qtbot):
    announcer.announce('one')
    clock.now += 0.2
    announcer.announce('two')
    announcer.announce('three')
    assert [text for _, text, _ in sent] == ['one']
    clock.now += 1.5
    announcer.flush()
    assert [text for _, text, _ in sent] == ['one', 'three']


def test_pending_message_is_sent_by_its_own_timer(bar, sent, qtbot):
    announcer = StatusAnnouncer(bar, lambda target, text, assertive: sent.append(text), interval=0.05)
    announcer.announce('one')
    announcer.announce('two')
    qtbot.waitUntil(lambda: sent == ['one', 'two'], timeout=3000)


def test_an_unchanged_repeat_is_not_announced_again(announcer, sent, clock):
    announcer.announce('same')
    clock.now += 5
    announcer.announce('same')
    assert len(sent) == 1
    announcer.announce('other')
    assert len(sent) == 2


def test_assertive_goes_out_immediately_and_replaces_pending(announcer, sent, clock):
    announcer.announce('polite')
    clock.now += 0.1
    announcer.announce('queued')
    announcer.announce('Project could not be opened.', assertive=True)
    announcer.flush()
    assert [(text, loud) for _, text, loud in sent] == [('polite', False), ('Project could not be opened.', True)]


def test_nothing_is_announced_without_a_target_or_for_empty_text(bar, clock, sent):
    announcer = StatusAnnouncer(None, lambda target, text, assertive: sent.append(text), clock)
    announcer.announce('lost')
    announcer.set_target(bar)
    announcer.announce('   ')
    announcer.announce('\x00‮')
    assert sent == []
    announcer.announce('kept')
    assert sent == ['kept']


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_text_is_stripped_and_bounded(announcer, sent, text):
    announcer.announce(text + 'x' * 500)
    spoken = sent[0][1]
    assert len(spoken) <= announce.MAX_LENGTH
    assert not re.search('[\x00-\x1f\x7f-\x9f  ‮]', spoken)


def test_default_sender_builds_a_polite_and_an_assertive_event(bar, monkeypatch):
    events = []
    monkeypatch.setattr(QAccessible, 'updateAccessibility', events.append)
    announce.qt_sender(bar, 'hello', False)
    announce.qt_sender(bar, 'broken', True)
    assert all(isinstance(event, QAccessibleAnnouncementEvent) for event in events)
    assert [e.politeness() for e in events] == [QAccessible.AnnouncementPoliteness.Polite,
                                                QAccessible.AnnouncementPoliteness.Assertive]
    assert [e.message() for e in events] == ['hello', 'broken']


def test_recording_announcer_has_the_same_surface():
    recorder = RecordingAnnouncer()
    recorder.announce('a')
    recorder.announce('b', assertive=True)
    assert recorder.messages == [('a', False), ('b', True)] and recorder.texts == ['a', 'b']


def test_only_announce_py_sends_accessibility_updates():
    root = Path(announce.__file__).parent
    offenders = [p.name for p in root.glob('*.py') if p.name != 'announce.py'
                 and 'updateAccessibility' in p.read_text(encoding='utf-8')]
    assert offenders == []


# ---- metrics --------------------------------------------------------------------------------------


def test_metrics_follow_the_font_and_keep_the_row_height_floor(qtbot):
    label = QLabel('x')
    qtbot.addWidget(label)
    small = Metrics.of(label)
    assert small.row_height == max(2 * small.line + 6, 28) and small.gap == max(1, small.em // 2)
    font = QFont(label.font())
    font.setPointSize(font.pointSize() * 3)
    label.setFont(font)
    large = Metrics.of(label)
    assert large.em > small.em and large.row_height > small.row_height


def test_watcher_recomputes_on_font_change_and_emits_once(qtbot):
    label = QLabel('x')
    qtbot.addWidget(label)
    watcher = MetricsWatcher(label)
    before = watcher.metrics
    seen = []
    watcher.changed.connect(seen.append)
    font = QFont(label.font())
    font.setPointSize(font.pointSize() * 2)
    label.setFont(font)
    assert watcher.metrics != before and seen == [watcher.metrics]
    watcher.refresh()
    assert len(seen) == 1


# ---- runtime --------------------------------------------------------------------------------------


def test_runtime_install_sets_one_millisecond_once_and_uninstall_restores():
    original = sys.getswitchinterval()
    try:
        assert runtime.install() is True
        assert sys.getswitchinterval() == pytest.approx(runtime.SWITCH_INTERVAL)
        assert runtime.install() is False
    finally:
        runtime.uninstall()
    assert sys.getswitchinterval() == pytest.approx(original)
    runtime.uninstall()


def test_switch_interval_is_set_only_in_runtime_py():
    root = Path(runtime.__file__).parent
    offenders = [p.name for p in root.glob('*.py') if p.name != 'runtime.py'
                 and 'setswitchinterval' in p.read_text(encoding='utf-8')]
    assert offenders == []
