"""Dock shells for panels (GUI plan 8.2 lifecycle, 8.3 layout persistence steps 1 and 5).

A shell is a hidden `QDockWidget` per built panel spec: it costs a fraction of a millisecond, imports nothing of
the feature, and wraps a `StateView` so that the host can show a blocked or failed panel in words. The controller's
widget joins the shell on first show. The dock's objectName is `<id>.dock` (it is also its tooltip id), which is the
name `restoreState` matches, so it never changes once shipped.
"""
from __future__ import annotations

from collections.abc import Mapping

from PySide6.QtCore import QObject, Qt
from PySide6.QtWidgets import QDockWidget, QMainWindow, QTabBar, QWidget

from ... import tooltips
from ..anchors import AnchorRef, NavResult
from ..registry import PanelSpec, accessible_name, dock_name
from ..tips import apply_tip
from .state_view import Announcer, StateView

AREAS: Mapping[str, Qt.DockWidgetArea] = {
    'left': Qt.DockWidgetArea.LeftDockWidgetArea, 'right': Qt.DockWidgetArea.RightDockWidgetArea,
    'top': Qt.DockWidgetArea.TopDockWidgetArea, 'bottom': Qt.DockWidgetArea.BottomDockWidgetArea}
_FEATURES = (QDockWidget.DockWidgetFeature.DockWidgetClosable | QDockWidget.DockWidgetFeature.DockWidgetMovable
             | QDockWidget.DockWidgetFeature.DockWidgetFloatable)
TAB_BAR_NAME = 'panels.dock_tabs'


class ControllerBase(QObject):
    """No-op hooks, so a panel controller overrides only the ones it needs. `widget()` is the panel's root widget
    (None for a panel without a dock); the host never calls a hook before `factory` has returned."""

    def __init__(self, widget: QWidget | None = None) -> None:
        super().__init__()
        self._widget = widget

    def widget(self) -> QWidget | None:
        return self._widget

    def focus_target(self) -> QWidget | None:
        return self._widget

    def project_changed(self, key: object) -> None: ...
    def selection_changed(self, match_id: str | None) -> None: ...
    def busy_changed(self, busy: bool) -> None: ...
    def capabilities_changed(self) -> None: ...
    def theme_changed(self, tokens: object) -> None: ...

    def show_anchor(self, anchor: AnchorRef) -> NavResult:
        return NavResult.blocked('This panel', f'it does not open {anchor.kind} links')

    def shutdown(self) -> None: ...


class PanelDock(QDockWidget):
    """The hidden shell of one panel."""

    def __init__(self, spec: PanelSpec, announcer: Announcer | None, parent: QMainWindow) -> None:
        super().__init__(spec.title, parent)
        self.spec = spec
        self.setObjectName(dock_name(spec.id))
        self.setAccessibleName(accessible_name(spec.title))
        self.setFeatures(_FEATURES)
        if dock_name(spec.id) in tooltips.REGISTRY:
            apply_tip(self, dock_name(spec.id))
        self.view = StateView(spec.id, spec.title, announcer)
        self.setWidget(self.view)
        self.hide()

    def show_content(self, widget: QWidget | None) -> None:
        if widget is not None:
            self.view.set_content(widget)

    def raise_and_show(self) -> None:
        self.show()
        self.raise_()


def place_default(window: QMainWindow, dock: PanelDock, groups: Mapping[str, PanelDock]) -> None:
    """Put a shell at its default area, tabbed with its group's first panel when that panel has a shell."""
    window.addDockWidget(AREAS[dock.spec.area], dock)
    target = groups.get(dock.spec.tabify_with or '')
    if target is not None and window.dockWidgetArea(target) == window.dockWidgetArea(dock):
        window.tabifyDockWidget(target, dock)
    dock.hide()


def name_tab_bars(window: QMainWindow) -> None:
    """Qt creates the dock tab bars itself and leaves them unnamed, which UI Automation reads as nothing."""
    for bar in window.findChildren(QTabBar):
        if bar.parent() is window and bar.objectName() != TAB_BAR_NAME and not bar.objectName().startswith('qt_'):
            bar.setObjectName(TAB_BAR_NAME)
            bar.setAccessibleName('Panel tabs')
            apply_tip(bar, TAB_BAR_NAME)
