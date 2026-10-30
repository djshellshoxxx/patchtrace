"""The only sender of accessibility announcements (GUI plan 8.7; the forbidden-API grep enforces it).

Name changes of a label reach UI Automation only while it is focused, so every asynchronous message goes
through ``StatusAnnouncer`` as a ``QAccessibleAnnouncementEvent`` aimed at the status bar. Messages inside the
coalescing window collapse to the latest one; progress is never announced (there is no API for it); the sender
is injected in tests because PySide6 cannot install an accessibility update handler offscreen."""
from __future__ import annotations

import re
import time
from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer
from PySide6.QtGui import QAccessible, QAccessibleAnnouncementEvent

COALESCE_SECONDS = 1.5
MAX_LENGTH = 200
_UNSAFE = re.compile('[\x00-\x1f\x7f-\x9f\u2028\u2029\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]')

Sender = Callable[[QObject, str, bool], None]


def qt_sender(target: QObject, text: str, assertive: bool) -> None:
    event = QAccessibleAnnouncementEvent(target, text)
    event.setPoliteness(QAccessible.AnnouncementPoliteness.Assertive if assertive
                        else QAccessible.AnnouncementPoliteness.Polite)
    QAccessible.updateAccessibility(event)


class StatusAnnouncer(QObject):
    def __init__(self, target: QObject | None = None, sender: Sender = qt_sender,
                 clock: Callable[[], float] = time.monotonic, interval: float = COALESCE_SECONDS,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._sender = sender
        self._clock = clock
        self._interval = interval
        self._last_sent: float | None = None
        self._last_text = ''
        self._pending: str | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.flush)

    def set_target(self, target: QObject | None) -> None:
        """The status bar; nothing is announced before a target exists."""
        self._target = target

    def announce(self, text: str, assertive: bool = False) -> None:
        """Polite messages are coalesced (latest wins) and an unchanged repeat is dropped; assertive ones
        (blocking errors only) are sent at once and replace anything pending."""
        text = _UNSAFE.sub(' ', text).strip()[:MAX_LENGTH]
        if not text or self._target is None:
            return
        if assertive:
            self._pending = None
            self._timer.stop()
            self._send(text, True)
            return
        wait = self._wait()
        if wait <= 0:
            if text != self._last_text:
                self._send(text, False)
        else:
            self._pending = text
            self._timer.start(int(wait * 1000) + 1)

    def flush(self) -> None:
        """Send the pending message now (the window timer calls this)."""
        text, self._pending = self._pending, None
        if text and text != self._last_text and self._target is not None:
            self._send(text, False)

    def _wait(self) -> float:
        if self._last_sent is None:
            return 0.0
        return self._interval - (self._clock() - self._last_sent)

    def _send(self, text: str, assertive: bool) -> None:
        self._last_sent, self._last_text = self._clock(), text
        self._sender(self._target, text, assertive)
