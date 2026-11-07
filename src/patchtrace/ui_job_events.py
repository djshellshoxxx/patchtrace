"""Worker-scoped Qt event delivery for the desktop job status."""
from PySide6.QtCore import QObject, Slot


class JobEventRelay(QObject):
    """Main-thread receiver bound to one worker, including already queued signals."""

    def __init__(self, window, worker):
        super().__init__(worker)
        self.window = window
        self.worker = worker

    @Slot(object)
    def forward(self, event):
        if self.window.worker is self.worker:
            self.window.job_event(event)
