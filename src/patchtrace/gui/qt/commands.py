"""The View menu, the palette's command list and the F6 focus cycle (GUI plan 8.3).

Everything a mouse can do must also be reachable from the keyboard, and the dock title buttons are not focusable,
so the host gives every panel Show/Hide, Focus, Float/Dock and Move commands here. Commands are plain data
(`PaletteEntry`) built when the palette opens, so availability is always current.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import TYPE_CHECKING

from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import QApplication, QMainWindow, QMenu, QToolBar, QWidget

from ..capabilities import Availability
from ..registry import PanelSpec, tip_prefix
from ..text import sanitize_text
from ..tips import apply_tip
from .palette import PaletteEntry

if TYPE_CHECKING:
    from .host import PanelHost

PALETTE_SHORTCUT = 'Ctrl+Shift+P'
NEXT_SHORTCUT, PREVIOUS_SHORTCUT = 'F6', 'Shift+F6'
HELP_MENU = 'menu.help'
MOVES = ('left', 'right', 'top', 'bottom')


def _availability_text(action: QAction) -> str:
    """The reason an action is off, from the Availability line of its tooltip entry."""
    for line in action.whatsThis().splitlines():
        if line.startswith('Availability:'):
            return line.removeprefix('Availability:').strip()
    return ''


def _walk(actions: Iterable[QAction], trail: str, seen: set[QAction], skip: set[QAction]) -> Iterable[tuple[QAction, str]]:
    for action in actions:
        if action in seen or action in skip or action.isSeparator():
            continue
        seen.add(action)
        text = action.text().replace('&', '').strip()
        menu = action.menu()
        if menu is not None:
            yield from _walk(menu.actions(), f'{trail}{text} > ', seen, skip)
        elif text:
            yield action, trail + text


def action_entries(window: QMainWindow, skip: set[QAction] = frozenset()) -> list[PaletteEntry]:
    """Every action in the menus and toolbars, deduplicated (the toolbar repeats menu actions)."""
    roots: list[Iterable[QAction]] = [window.menuBar().actions()]
    roots += [bar.actions() for bar in window.findChildren(QToolBar)]
    seen: set[QAction] = set()
    entries = []
    for actions in roots:
        for action, title in _walk(actions, '', seen, set(skip)):
            entries.append(PaletteEntry(
                action.objectName() or f'action:{title}', title, action.trigger,
                shortcut=action.shortcut().toString(QKeySequence.SequenceFormat.NativeText),
                enabled=action.isEnabled(), reason='' if action.isEnabled() else _availability_text(action)))
    return entries


def host_entries(host: PanelHost) -> list[PaletteEntry]:
    """Show/Hide, Focus, Float/Dock and Move for each panel that has a dock, plus the panel's own commands."""
    entries: list[PaletteEntry] = []
    for spec in host.specs.values():
        entries += panel_command_entries(spec, host)
        if spec.area == 'none':
            continue
        title = sanitize_text(spec.title)
        free = host.availability(spec.id)
        prefix = tip_prefix(spec.id)
        shown = host.is_shown(spec.id)
        entries += [
            PaletteEntry(f'{prefix}toggle', f'{"Hide" if shown else "Show"} {title} panel',
                         lambda panel=spec.id: host.toggle(panel), (title, 'panel', 'show', 'hide')),
            PaletteEntry(f'{prefix}focus', f'Focus {title} panel', lambda panel=spec.id: host.focus_panel(panel),
                         (title, 'panel'), enabled=free.enabled, reason=free.reason),
            PaletteEntry(f'{prefix}float', f'Float or dock {title} panel', lambda panel=spec.id: host.float_panel(panel),
                         (title, 'panel', 'undock', 'window')),
        ]
        entries += [PaletteEntry(f'{prefix}move_{area}', f'Move {title} panel to the {area}',
                                 lambda panel=spec.id, to=area: host.move_panel(panel, to), (title, 'panel', 'dock'))
                    for area in MOVES if area != host.dock_area(spec.id)]
    return entries


def panel_command_entries(spec: PanelSpec, host: PanelHost) -> list[PaletteEntry]:
    entries = []
    for command in spec.commands:
        try:
            state: Availability = command.enabled()
        except Exception:  # noqa: BLE001 - a feature's availability probe must not break the palette
            state = Availability(False, 'availability could not be checked')
        entries.append(PaletteEntry(command.id, command.title, lambda run=command.run: host.run_command(run),
                                    command.keywords, command.shortcut or '', state.enabled, state.reason))
    return entries


def install_view_menu(window: QMainWindow, host: PanelHost) -> tuple[QMenu, set[QAction]]:
    """The View menu, inserted before Help (found by object name, not by text). Returns it with the panel toggles,
    which the palette leaves out because the host's own commands cover them."""
    menu = QMenu('View', window)
    menu.setObjectName('menu.view.menu')
    apply_tip(menu.menuAction(), 'menu.view')
    toggles: set[QAction] = set()
    group = None
    for spec in host.specs.values():
        if spec.area == 'none':
            continue
        if spec.group != group:
            group = spec.group
            menu.addSection(sanitize_text(group, 40))
        action = host.toggle_action(spec.id)
        menu.addAction(action)
        toggles.add(action)
    if toggles:
        menu.addSeparator()
    menu.addAction(_action(window, 'Reset panel layout', host.reset_layout, None, 'gui.reset_layout'))
    menu.addAction(_action(window, 'Command palette', host.open_palette, PALETTE_SHORTCUT, 'gui.palette',
                           'gui.palette_action'))
    menu.addAction(_action(window, 'Next panel', lambda: host.cycle_focus(1), NEXT_SHORTCUT, 'gui.cycle_panels'))
    menu.addAction(_action(window, 'Previous panel', lambda: host.cycle_focus(-1), PREVIOUS_SHORTCUT,
                           'gui.cycle_panels', 'gui.cycle_previous'))
    menu.addAction(_action(window, 'Navigate back', host.navigate_back, 'Alt+Left', 'gui.navigate'))
    menu.addAction(_action(window, 'Navigate forward', host.navigate_forward, 'Alt+Right', 'gui.navigate',
                           'gui.navigate_forward'))
    bar = window.menuBar()
    before = next((a for a in bar.actions() if a.objectName() == HELP_MENU), None)
    if before is None:
        bar.addMenu(menu)
    else:
        bar.insertMenu(before, menu)
    return menu, toggles


def _action(window: QWidget, title: str, run: Callable[[], None], shortcut: str | None, tip_id: str,
            name: str | None = None) -> QAction:
    action = QAction(title, window)
    action.triggered.connect(lambda _checked=False: run())
    if shortcut:
        action.setShortcut(QKeySequence(shortcut))
    apply_tip(action, tip_id, name=name or tip_id)
    return action


# ---- F6 focus cycle -------------------------------------------------------------------------------------------


def next_region(regions: Sequence[tuple[QWidget, QWidget]], current: QWidget | None, step: int) -> QWidget | None:
    """The focus target of the region after (step 1) or before (step -1) the one holding `current`, wrapping; the
    first or last region when focus is in none of them. Each region is (container, focus target); hidden ones are
    skipped."""
    visible = [(box, target) for box, target in regions if box.isVisible()]
    if not visible:
        return None
    index = next((i for i, (box, _) in enumerate(visible)
                  if current is not None and (box is current or box.isAncestorOf(current))), None)
    if index is None:
        return visible[0][1] if step > 0 else visible[-1][1]
    return visible[(index + step) % len(visible)][1]


def focus_region(region: QWidget) -> None:
    """Focus a region; a floating dock is a window of its own and needs activating and raising first."""
    window = region.window()
    if window is not QApplication.activeWindow():
        window.activateWindow()
        window.raise_()
    region.setFocus()
