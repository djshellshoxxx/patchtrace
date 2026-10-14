"""Fakes for the panel host tests: a minimal host window, a recording controller and manifest slots that never
import a feature module (GUI plan 8.8). The host needs `settings`, `service`, `worker`, a status bar and a menu bar
with a Help menu named `menu.help`; the real MainWindow is used where the seam itself is under test."""
from __future__ import annotations

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QMainWindow, QPlainTextEdit

from patchtrace import tooltips
from patchtrace.gui.anchors import NavResult
from patchtrace.gui.capabilities import CapabilityState
from patchtrace.gui.qt.docks import ControllerBase
from patchtrace.gui.qt.host import PanelHost
from patchtrace.gui.qt.labels import PlainLabel
from patchtrace.gui.registry import ManifestEntry, PanelSpec
from patchtrace.tooltips import TooltipEntry


@pytest.fixture(autouse=True)
def private_tooltip_registry(monkeypatch):
    """Fake panels register tips; they must not leak into the tests that enumerate the registry."""
    monkeypatch.setattr(tooltips, 'REGISTRY', dict(tooltips.REGISTRY))
    monkeypatch.setattr(tooltips, 'TEMPLATES', dict(tooltips.TEMPLATES))


class Window(QMainWindow):
    def __init__(self, settings: QSettings) -> None:
        super().__init__()
        self.settings = settings
        self.service = None
        self.worker = None
        self.setCentralWidget(QPlainTextEdit())
        self.menuBar().addMenu('Project')
        self.menuBar().addMenu('Help').menuAction().setObjectName('menu.help')
        self.resize(900, 600)


class Recorder(ControllerBase):
    """Records every hook the host calls."""

    def __init__(self, ctx) -> None:
        super().__init__(PlainLabel(ctx.spec.id))
        self.ctx = ctx
        self.calls: list[tuple] = []

    def names(self) -> list[str]:
        return [call[0] for call in self.calls]

    def project_changed(self, key) -> None:
        self.calls.append(('project', key))

    def selection_changed(self, match_id) -> None:
        self.calls.append(('selection', match_id))

    def busy_changed(self, busy) -> None:
        self.calls.append(('busy', busy))

    def capabilities_changed(self) -> None:
        self.calls.append(('capabilities',))

    def theme_changed(self, tokens) -> None:
        self.calls.append(('theme', tokens))

    def show_anchor(self, anchor) -> NavResult:
        self.calls.append(('anchor', anchor))
        return NavResult.shown()

    def shutdown(self) -> None:
        self.calls.append(('shutdown',))


def tips_for(panel_id: str, docked: bool = True) -> dict:
    entry = lambda what: TooltipEntry(what, f'Fixture {panel_id}.', 'Nothing changes.')  # noqa: E731
    if not docked:
        return {f'{panel_id}.card': entry(f'Show the {panel_id} fixture card.')}
    return {f'{panel_id}.dock': entry(f'The {panel_id} fixture panel.'),
            f'{panel_id}.action': entry(f'Show or hide the {panel_id} fixture panel.')}


def spec(panel_id: str, area: str = 'right', *, tabify_with: str | None = None, shortcut: str | None = None,
         factory=Recorder, **kw) -> PanelSpec:
    return PanelSpec(id=panel_id, title=panel_id.replace('_', ' ').title(), factory=factory, area=area,
                     tabify_with=tabify_with, shortcut=shortcut, tips=tips_for(panel_id, area != 'none'), **kw)


def slot(panel: PanelSpec) -> ManifestEntry:
    return ManifestEntry(panel.id, f'patchtrace.fake.{panel.id}', lambda: panel, panel.area, panel.tabify_with,
                         panel.shortcut)


def absent(panel_id: str, area: str = 'right') -> ManifestEntry:
    """A slot whose module does not exist: "not built yet"."""
    def load():
        raise ModuleNotFoundError(name=f'patchtrace.fake.{panel_id}')
    return ManifestEntry(panel_id, f'patchtrace.fake.{panel_id}', load, area)


class Provider:
    """Capability answers a test can change."""

    def __init__(self, **states: CapabilityState) -> None:
        self.states = states

    def capability(self, capability_id: str) -> CapabilityState:
        return self.states.get(capability_id, CapabilityState())


def make_host(qtbot, settings: QSettings, *specs: PanelSpec, extra=(), **kw) -> tuple[Window, PanelHost]:
    window = Window(settings)
    qtbot.addWidget(window)
    host = PanelHost(window, tuple(slot(s) for s in specs) + tuple(extra), **kw)
    return window, host
