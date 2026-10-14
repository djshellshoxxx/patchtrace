"""PanelHost: the one object that turns the manifest into docks and connects the main window to its panels (GUI plan
8.2 lifecycle and ports, 8.3 behaviour, 8.10 seam).

`MainWindow` calls a handful of hooks (`project_changed`, `selection_changed`, `update_controls`, `restore_layout`,
`shutdown`) and knows nothing else about panels. The host creates a hidden dock shell per built panel before the
menus exist, builds a panel only when it is first shown (or at once for `eager` panels), shows a blocked or failed
panel in words, wires the anchor router, owns the `TaskRunner` and the screen-reader announcer, and joins every
worker at shutdown.
"""
from __future__ import annotations

import dataclasses
import logging
import sys
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow, QVBoxLayout, QWidget

from ...panel_manifest import MANIFEST
from ...secondary import evidence_panel_service as service_api
from ..anchors import CODE_KINDS, AnchorRef, AnchorRouter, NavResult, locate_match
from ..capabilities import Availability, CapabilityProvider, CapabilityState, check
from ..projection import MatchIndex, MatchIndexCache, ProjectKey
from ..registry import (
    CLIPBOARD_BYTES,
    SELECTION_DEBOUNCE_MS,
    ManifestEntry,
    PanelContext,
    PanelSpec,
    lint,
    load_manifest,
    toggle_name,
)
from ..state import NoticeModel, factory_failure, state_model
from ..text import sanitize_text
from ..tips import TipError, apply_tip, register_gui_tips, register_tips
from . import layout
from .announce import StatusAnnouncer
from .commands import action_entries, focus_region, host_entries, install_view_menu, next_region
from .docks import AREAS, PanelDock, name_tab_bars, place_default
from .palette import CommandPalette, PaletteEntry
from .settings import PanelSettings
from .state_view import NoticeStrip
from .tasks import TaskRunner
from .theme import DARK, ThemeTokens

log = logging.getLogger('patchtrace.gui')
CODE_TARGET = '@code'  # the pseudo panel that function and match anchors open: the main window's code panes
FILTER_RESET = (('search', 'clear'), ('category_filter', 'setCurrentIndex', 0), ('review_filter', 'setCurrentIndex', 0),
                ('manual_filter', 'setChecked', False), ('finding_match_filter', 'setChecked', False))
_PAIR_FOCUS = (('navigator', 'navigator'), ('code_split', 'code'), ('findings_list', 'findings'), ('logs', 'diagnostics'))


class Panel:
    """Runtime record of one built spec. `active` = its dock is visible (or it has no dock); a hidden panel keeps
    its results and is told about a project change when it is next shown."""

    __slots__ = ('spec', 'dock', 'controller', 'failure', 'active', 'dirty', 'availability', 'port')

    def __init__(self, spec: PanelSpec, dock: PanelDock | None) -> None:
        self.spec, self.dock = spec, dock
        self.controller: object | None = None
        self.failure: str | None = None
        self.active = dock is None
        self.dirty = True
        self.availability = Availability()
        self.port: MainWindowPort | None = None


class MainWindowPort:
    """The four ports (`ProjectPort`, `MutationPort`, `NavigationPort`, `ShellPort`) over the main window; one per
    panel so that `settings` is scoped to the panel's `<id>/` keys. GUI thread only."""

    def __init__(self, host: PanelHost, panel_id: str | None = None) -> None:
        self._host, self._panel_id = host, panel_id
        self.window = host.window

    # ---- ProjectPort -----------------------------------------------------------------------------

    @property
    def service(self):
        return getattr(self.window, 'service', None)

    def project(self):
        service = self.service
        return service.project if service else None

    def busy(self) -> bool:
        return getattr(self.window, 'worker', None) is not None

    def key(self) -> ProjectKey | None:
        project = self.project()
        if project is None:
            return None
        run = service_api.latest_run(project)
        sides = {a.side: a.sha256 for a in project.artifacts}
        return ProjectKey(str(self.service.root), project.id, project.revision, run.id if run else None,
                          sides.get('older'), sides.get('newer'))

    def artifact_paths(self) -> tuple[Path, Path, str, str]:
        sides = {a.side: a for a in self.project().artifacts}
        root = Path(self.service.root)
        return ((root / sides['older'].relative_path).resolve(), (root / sides['newer'].relative_path).resolve(),
                sides['older'].sha256, sides['newer'].sha256)

    def match_index(self) -> MatchIndex:
        project = self.project()
        return self._host.index_cache.get(self.key(), project.matches if project else ())

    # ---- MutationPort ----------------------------------------------------------------------------

    def annotate(self, target_id: str, text: str, kind: str = 'note') -> None:
        self.service.annotate(target_id, text, kind=kind)

    def review_match(self, match_id: str, status: str) -> None:
        self.service.review_match(match_id, status)

    # ---- NavigationPort --------------------------------------------------------------------------

    def select_match(self, match_id: str, clear_filters: bool = False) -> bool:
        navigator = getattr(self.window, 'navigator', None)
        if navigator is None:
            return False
        if clear_filters:  # a filter may hide the target; the analyst asked to go there
            for name, method, *args in FILTER_RESET:
                getattr(getattr(self.window, name), method)(*args)
        for row in range(navigator.count()):
            item = navigator.item(row)
            if item.data(Qt.ItemDataRole.UserRole) == match_id:
                navigator.setCurrentItem(item)
                navigator.scrollToItem(item)
                return True
        return False

    def reveal_lines(self, function_id: str, start: int, end: int) -> object | None:
        return self.window.reveal_lines(function_id, start, end)

    def show_raw_offset(self, side: str, offset: int) -> None:
        self.window.show_raw_offset(side, offset)

    def show_pair(self, older: str, newer: str, label: str) -> None:
        self.window.show_external_pair(older, newer, label)

    def navigate(self, anchor: AnchorRef) -> NavResult:
        return self._host.router.navigate(anchor.pinned(self.key()) if anchor.revision is None else anchor)

    def focus_panel(self, panel_id: str) -> None:
        self._host.focus_panel(panel_id)

    def back(self) -> NavResult | None:
        return self._host.router.back()

    def forward(self) -> NavResult | None:
        return self._host.router.forward()

    # ---- ShellPort -------------------------------------------------------------------------------

    @property
    def tasks(self) -> TaskRunner:
        return self._host.tasks

    @property
    def settings(self):
        base = self.window.settings
        return base if self._panel_id is None else PanelSettings(base, self._panel_id)

    @property
    def theme(self) -> ThemeTokens:
        return self._host.tokens

    def status(self, text: str) -> None:
        self.window.statusBar().showMessage(sanitize_text(text), 5000)

    def announce(self, text: str, *, assertive: bool = False) -> None:
        self._host.announcer.announce(text, assertive)

    def notice(self, key: str, model: NoticeModel | None) -> None:
        self._host.strip.set_notice(key, model)

    def copy_text(self, text: str) -> bool:
        if len(text.encode('utf-8', 'replace')) > CLIPBOARD_BYTES:
            return False
        QApplication.clipboard().setText(text)
        return True

    def choose_file(self, title: str, file_filter: str = '') -> Path | None:
        name, _ = QFileDialog.getOpenFileName(self.window, title, '', file_filter)
        return Path(name) if name else None

    def spotlight(self, tip_id: str) -> None:
        """Reserved for the guide (E-5); nothing is outlined yet."""


class WindowCapabilities:
    """Answers `requires` ids from the live window. Tools and engines are `unchecked`: probing runs a program, which
    only ever happens as an explicit user action."""

    def __init__(self, port: MainWindowPort) -> None:
        self._port = port

    def capability(self, capability_id: str) -> CapabilityState:
        port = self._port
        if capability_id == 'project':
            return CapabilityState() if port.project() is not None else CapabilityState('missing', 'Open a project first.')
        if capability_id == 'run':
            project = port.project()
            return (CapabilityState() if project is not None and service_api.latest_run(project) is not None
                    else CapabilityState('missing', 'Run a comparison first.'))
        if capability_id == 'idle':
            return CapabilityState('missing', 'A job is running; wait for it to finish.') if port.busy() \
                else CapabilityState()
        if capability_id == 'os:windows':
            return CapabilityState() if sys.platform == 'win32' else CapabilityState('unsupported', 'Windows only.')
        return CapabilityState('unchecked')


class PanelHost(QObject):
    def __init__(self, window: QMainWindow, entries: tuple[ManifestEntry, ...] = MANIFEST, *,
                 capabilities: CapabilityProvider | None = None) -> None:
        super().__init__(window)
        self.window = window
        self.entries = entries
        self.tokens = DARK
        self.index_cache = MatchIndexCache()
        self.closed = False
        register_gui_tips()
        self.announcer = StatusAnnouncer(window.statusBar(), parent=self)
        self.strip = NoticeStrip(self.announcer)
        self.port = MainWindowPort(self)
        self.tasks = TaskRunner(self, status=self.port.status)
        self.capabilities = capabilities or WindowCapabilities(self.port)
        self.router = AnchorRouter(self.port.key, self._handler_for, self._show_anchor)
        self.problems: list[str] = []
        self.not_built: tuple[str, ...] = ()
        self.panels: dict[str, Panel] = {}
        self.view_menu = None
        self.palette = CommandPalette(window, self.palette_entries, window.settings, self.announcer, self.port.status)
        self._toggles: set[QAction] = set()
        self._selected: str | None = None
        self._busy = False
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(SELECTION_DEBOUNCE_MS)
        self._debounce.timeout.connect(self._flush_selection)
        self._load_specs()
        self._build_shells()
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self.shutdown)

    # ---- specs and shells -------------------------------------------------------------------------

    @property
    def specs(self) -> dict[str, PanelSpec]:
        return {panel_id: panel.spec for panel_id, panel in self.panels.items()}

    def _load_specs(self) -> None:
        loaded = load_manifest(self.entries)
        report = lint(self.entries, loaded)
        self.not_built = loaded.not_built
        self.problems = [f'{panel_id}: PT-GUI-MANIFEST {cls}' for panel_id, cls in loaded.errors.items()]
        self.problems += [f'{item.panel}: {item.code} {item.rule}' for item in report.findings]
        rejected = {item.panel for item in report.findings} | set(loaded.errors)
        for panel_id, spec in loaded.specs.items():
            if panel_id in rejected:
                continue
            try:
                register_tips(spec.tips, spec.tip_templates)
            except TipError:
                self.problems.append(f'{panel_id}: PT-GUI-TIPS conflicting registration')
                continue
            self.panels[panel_id] = Panel(spec, None)
        for problem in self.problems:
            log.warning('panel skipped: %s', problem)

    def _build_shells(self) -> None:
        docks: dict[str, PanelDock] = {}
        for panel in self.panels.values():
            spec = panel.spec
            if spec.area == 'none':
                continue
            dock = panel.dock = PanelDock(spec, self.announcer, self.window)
            panel.active = False
            docks[spec.id] = dock
            place_default(self.window, dock, docks)
            action = dock.toggleViewAction()
            action.setText(spec.title)
            if spec.shortcut:
                action.setShortcut(spec.shortcut)
            apply_tip(action, toggle_name(spec.id))
            dock.view.retry_requested.connect(self._retry)
            dock.view.setup_requested.connect(self._open_setup)
            dock.view.copy_requested.connect(self.port.copy_text)
            dock.visibilityChanged.connect(self._reconcile, Qt.ConnectionType.QueuedConnection)
        self.window.tabifiedDockWidgetActivated.connect(lambda _dock: name_tab_bars(self.window))

    # ---- lifecycle hooks called by MainWindow ----------------------------------------------------

    def restore_layout(self) -> None:
        """End of `MainWindow.__init__`: menus, toolbar and workspace exist, so the layout can be restored."""
        window = self.window
        layout.name_window_parts(window)
        self._wrap_central()
        self.view_menu, self._toggles = install_view_menu(window, self)
        saved = layout.stored_state(window.settings) is not None
        message = layout.restore_layout(window, window.settings)
        if message:
            self.port.status(message)
        if not saved:
            for panel in self.panels.values():
                if panel.dock is not None and panel.spec.default_visible:
                    panel.dock.show()
        for panel in self.panels.values():
            if panel.spec.eager:
                self._construct(panel)
        name_tab_bars(window)

    def _wrap_central(self) -> None:
        """The notice strip sits above the workspace; `takeCentralWidget` first so that nothing is deleted."""
        central = self.window.takeCentralWidget()
        wrapper = QWidget()
        wrapper.setObjectName('workspace.wrapper')
        column = QVBoxLayout(wrapper)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(self.strip)
        if central is not None:
            column.addWidget(central, 1)
        self.window.setCentralWidget(wrapper)

    def project_changed(self) -> None:
        key = self.port.key()
        self.strip.project_changed()
        for panel in self.panels.values():
            if panel.controller is None:
                continue
            if panel.active:
                self._call(panel, 'project_changed', key)
            else:
                panel.dirty = True
        self._refresh_availability()

    def selection_changed(self, match: object) -> None:
        """`match` is the selected match (or None); delivery is debounced because arrow-key scrolling selects fast."""
        self._selected = getattr(match, 'id', None)
        self._debounce.start()

    def _flush_selection(self) -> None:
        for panel in self.panels.values():
            if panel.controller is not None and panel.active:
                self._call(panel, 'selection_changed', self._selected)

    def update_controls(self) -> None:
        busy = self.port.busy()
        if busy != self._busy:
            self._busy = busy
            for panel in self.panels.values():
                if panel.controller is not None and panel.active:
                    self._call(panel, 'busy_changed', busy)
        self._refresh_availability()

    def shutdown(self) -> None:
        """Save the layout, shut every panel down and join the workers (<= 5 s). Idempotent."""
        if self.closed:
            return
        self.closed = True
        self._debounce.stop()
        try:
            layout.save_layout(self.window, self.window.settings)
        except Exception:  # noqa: BLE001 - failing to save a layout must not stop the other shutdown work
            log.warning('PT-GUI-LAYOUT: the layout could not be saved')
        for panel in self.panels.values():
            if panel.controller is not None:
                self._call(panel, 'shutdown')
        self.tasks.shutdown()

    # ---- building and showing panels ---------------------------------------------------------------

    def controller(self, panel_id: str) -> object | None:
        """The built controller of a panel, or None while it has not been built (or failed)."""
        panel = self.panels.get(panel_id)
        return panel.controller if panel else None

    def _construct(self, panel: Panel) -> bool:
        if panel.controller is not None:
            return True
        spec = panel.spec
        panel.port = MainWindowPort(self, spec.id)
        try:
            controller = spec.factory(PanelContext(spec, panel.port, panel.port, panel.port, panel.port))
        except Exception as error:  # noqa: BLE001 - a feature's factory may raise anything; others are unaffected
            panel.failure = type(error).__name__
            log.warning('PT-GUI-FACTORY: %s: %s', spec.id, panel.failure)
            self._show_state(panel)
            return False
        panel.failure, panel.controller = None, controller
        if panel.dock is not None:
            panel.dock.show_content(controller.widget())
        self._call(panel, 'theme_changed', self.tokens)
        self._show_state(panel)
        return True

    def _activate(self, panel: Panel) -> None:
        panel.active = True
        if not self._construct(panel):
            return
        if panel.dirty:
            panel.dirty = False
            self._call(panel, 'project_changed', self.port.key())
        self._call(panel, 'busy_changed', self._busy)
        self._call(panel, 'selection_changed', self._selected)

    def _reconcile(self, *_visible: object) -> None:
        for panel in self.panels.values():
            if panel.dock is None:
                continue
            visible = panel.dock.isVisible()
            if visible and not panel.active:
                self._activate(panel)
            elif not visible:
                panel.active = False

    def _show_state(self, panel: Panel) -> None:
        """Failure, blocked or ready, in words, in the panel's dock."""
        if panel.dock is None:
            return
        spec, view = panel.spec, panel.dock.view
        if panel.failure is not None:
            model = dataclasses.replace(factory_failure(spec.title, panel.failure), actions=('retry', 'copy'),
                                        detail=f'PT-GUI-FACTORY: {panel.failure}')
            view.set_state(model)
        elif not panel.availability.enabled:
            remedy = f'Remedy: {panel.availability.remedy_command}' if panel.availability.remedy_command else ''
            view.set_state(state_model('blocked', spec.title, reason=panel.availability.reason, remedy=remedy),
                           has_content=False)
        else:
            view.set_state(state_model('ready', spec.title), has_content=panel.controller is not None)

    def _refresh_availability(self) -> None:
        for panel in self.panels.values():
            now = check(panel.spec.requires, self.capabilities)
            if now == panel.availability:
                continue
            panel.availability = now
            self._show_state(panel)
            if panel.controller is not None:
                self._call(panel, 'capabilities_changed')

    def _call(self, panel: Panel, hook: str, *args: object) -> None:
        """Call a controller hook; a hook that raises costs the panel one status line, never the window."""
        try:
            getattr(panel.controller, hook)(*args)
        except Exception as error:  # noqa: BLE001 - see above
            log.warning('panel hook failed: %s.%s: %s', panel.spec.id, hook, type(error).__name__)
            self.port.status(f'{panel.spec.title} panel error: {type(error).__name__}.')

    def _retry(self) -> None:
        for panel in self.panels.values():
            if panel.failure is not None and panel.dock is not None and panel.dock.isVisible():
                panel.failure = None
                self._activate(panel)

    def _open_setup(self) -> None:
        action = getattr(self.window, 'setup_action', None)
        if action is not None:
            action.trigger()

    # ---- commands used by the View menu, the palette and anchors ------------------------------------

    def availability(self, panel_id: str) -> Availability:
        return self.panels[panel_id].availability

    def toggle_action(self, panel_id: str) -> QAction:
        return self.panels[panel_id].dock.toggleViewAction()

    def is_shown(self, panel_id: str) -> bool:
        dock = self.panels[panel_id].dock
        return dock is not None and dock.isVisible()

    def show_panel(self, panel_id: str) -> Panel | None:
        """Show (and build) a panel's dock now rather than on the next event-loop turn."""
        panel = self.panels.get(panel_id)
        if panel is None:
            return None
        if panel.dock is not None:
            panel.dock.raise_and_show()
            if not panel.active:
                self._activate(panel)
        elif not self._construct(panel):
            return None
        return panel

    def toggle(self, panel_id: str) -> None:
        dock = self.panels[panel_id].dock
        if dock is not None and dock.isVisible():
            dock.hide()
        else:
            self.show_panel(panel_id)

    def focus_panel(self, panel_id: str) -> None:
        panel = self.show_panel(panel_id)
        if panel is not None and panel.controller is not None:
            target = panel.controller.focus_target() or (panel.dock.view if panel.dock else None)
            if target is not None:
                focus_region(target)

    def float_panel(self, panel_id: str) -> None:
        dock = self.panels[panel_id].dock
        if dock is not None:
            dock.setFloating(not dock.isFloating())
            self.show_panel(panel_id)

    def move_panel(self, panel_id: str, area: str) -> None:
        dock = self.panels[panel_id].dock
        if dock is not None:
            self.window.addDockWidget(AREAS[area], dock)
            self.show_panel(panel_id)

    def dock_area(self, panel_id: str) -> str:
        dock = self.panels[panel_id].dock
        found = self.window.dockWidgetArea(dock) if dock is not None else None
        return next((name for name, area in AREAS.items() if area == found), 'none')

    def run_command(self, run: Callable[[], None]) -> None:
        try:
            run()
        except Exception as error:  # noqa: BLE001 - a feature's command must not break the palette or the menu
            self.port.status(f'Command failed: {type(error).__name__}.')

    def reset_layout(self) -> None:
        layout.clear_layout(self.window.settings)
        docks = {panel_id: panel.dock for panel_id, panel in self.panels.items() if panel.dock is not None}
        for dock in docks.values():
            self.window.removeDockWidget(dock)
        for dock in docks.values():
            place_default(self.window, dock, docks)
            if dock.spec.default_visible:
                dock.show()
        name_tab_bars(self.window)
        self.port.status(layout.RESET_TEXT)
        self.announcer.announce(layout.RESET_TEXT)

    def open_palette(self) -> None:
        self.palette.open()

    def palette_entries(self) -> list[PaletteEntry]:
        return host_entries(self) + action_entries(self.window, self._toggles)

    def cycle_focus(self, step: int) -> None:
        """F6 and Shift+F6: navigator, code, findings, the visible panels by `focus_order`, diagnostics."""
        window = self.window
        found = {name: getattr(window, attr, None) for attr, name in _PAIR_FOCUS}
        views = getattr(window, 'views', {})
        code_target = views.get('older') or found['code']
        regions = [(found['navigator'], found['navigator']), (found['code'], code_target),
                   (found['findings'], found['findings'])]
        for panel in sorted(self.panels.values(), key=lambda p: p.spec.focus_order):
            if panel.dock is not None and panel.dock.isVisible() and panel.controller is not None:
                regions.append((panel.dock, panel.controller.focus_target() or panel.dock.view))
        regions.append((found['diagnostics'], found['diagnostics']))
        target = next_region([(box, target) for box, target in regions if box is not None and target is not None],
                             QApplication.focusWidget(), step)
        if target is not None:
            focus_region(target)

    def navigate_back(self) -> None:
        self._report(self.router.back())

    def navigate_forward(self) -> None:
        self._report(self.router.forward())

    def _report(self, result: NavResult | None) -> None:
        if result is not None and result.status != 'shown':
            self.port.status(result.message)
            self.announcer.announce(result.message)

    # ---- anchors -------------------------------------------------------------------------------------

    def _handler_for(self, kind: str) -> str | None:
        if kind in CODE_KINDS:
            return CODE_TARGET
        return next((panel_id for panel_id, panel in self.panels.items() if kind in panel.spec.anchors_in), None)

    def _show_anchor(self, target: str, anchor: AnchorRef) -> NavResult:
        if target == CODE_TARGET:
            located = locate_match(anchor, self.port.match_index())
            if isinstance(located, NavResult):
                return located
            shown = self.port.select_match(located, clear_filters=True)
            return NavResult.shown() if shown else NavResult.not_found(anchor.label or anchor.key, anchor.run_id)
        panel = self.panels[target]
        if not panel.availability.enabled:
            return NavResult.blocked(panel.spec.title, panel.availability.reason)
        if self.show_panel(target) is None or panel.controller is None:
            return NavResult.blocked(panel.spec.title, 'the panel could not be created')
        try:
            return panel.controller.show_anchor(anchor)
        except Exception as error:  # noqa: BLE001 - a feature's handler must not break navigation
            return NavResult.blocked(panel.spec.title, f'it failed to open the link ({type(error).__name__})')

    # ---- test and frozen self-check helpers ------------------------------------------------------------

    def build_all_for_test(self) -> dict[str, object]:
        """Build every built panel, blocked or not, so that tests never list panel roots by hand."""
        return {panel_id: panel.controller for panel_id, panel in self.panels.items() if self._construct(panel)}

    def self_check(self) -> list[str]:
        """The frozen `--self-test`: every manifest module imported (done at start), every panel built once.
        Returns the problems; none means the bundle carries every panel it should."""
        problems = list(self.problems)
        for panel_id, panel in self.panels.items():
            if not self._construct(panel):
                problems.append(f'{panel_id}: PT-GUI-FACTORY {panel.failure}')
        return problems

