"""Tooltip registration and application for panels (GUI plan 8.2 `tips`, 8.7 R2 and R9). Pure: no Qt.

`tooltips.py` stays frozen, so this module adds what panels need on top of it: idempotent registration of a panel's
`TooltipEntry` dicts (a conflicting re-registration is `PT-GUI-TIPS`), the framework-owned `gui.*` entries, and
`apply_tip`, which also gives a control the short accessible description (the What line, at most 160 characters)
and the UIA automation id. `tooltips` is imported inside the functions so a panel spec stays cheap to import.
"""
from __future__ import annotations

import html
from collections.abc import Mapping

from .registry import DESCRIPTION_LIMIT, TIPS_CODE

GUI_TIP_IDS = ('gui.state_retry', 'gui.state_copy', 'gui.state_setup', 'gui.state_refresh', 'gui.notice',
               'gui.notice_details', 'gui.notice_dismiss', 'gui.notice_text', 'gui.palette', 'gui.palette_list', 'gui.reset_layout',
               'gui.cycle_panels', 'gui.navigate', 'panels.dock_tabs', 'menu.view')


class TipError(ValueError):
    """A tooltip registration the framework refuses; `code` is always `PT-GUI-TIPS`."""

    code = TIPS_CODE


def gui_tips() -> dict:
    """The framework-owned entries for the shared state and notice widgets (built on demand, see the module doc)."""
    from ..tooltips import TooltipEntry
    return {
        'gui.state_retry': TooltipEntry(
            'Load this panel again.', 'Recovers from a failed load without reopening the project.',
            'Starts the same load again; earlier results stay until the new one arrives.',
            availability='Shown only after a load failed.'),
        'gui.state_copy': TooltipEntry(
            'Copy the technical details of this failure as plain text.',
            'Lets you paste the error code and class into a report.',
            'Copies text to the clipboard; nothing is uploaded.', availability='Shown only after a load failed.'),
        'gui.state_setup': TooltipEntry(
            'Open the setup that this panel needs before it can show results.',
            'The panel is unavailable until its requirement is met.',
            'Opens the setup dialog; no tool is run until you choose to.',
            availability='Shown only while the panel is unavailable.'),
        'gui.state_refresh': TooltipEntry(
            'Recompute this panel for the current project state.',
            'The results shown no longer match the project, so they are for reference only.',
            'Starts a new load; the stale results stay visible until it finishes.',
            availability='Shown only while the results are stale.'),
        'gui.notice': TooltipEntry(
            'Notices that apply to the whole project, such as a pre-flight finding.',
            'Keeps an important caveat visible above every panel.',
            'Read-only; a notice never blocks work and can be dismissed.'),
        'gui.notice_details': TooltipEntry(
            'Show or hide the full text of this notice.', 'The strip shows one line; the details explain it.',
            'Expands the strip in place; nothing else changes.', availability='Shown only when a notice has details.'),
        'gui.notice_dismiss': TooltipEntry(
            'Hide this notice.', 'Removes a note you have read.',
            'The notice stays hidden for this project or session and returns only if its text changes.',
            availability='Shown only for notices that can be dismissed.'),
        'gui.notice_text': TooltipEntry(
            'The full text of the notice above the workspace.', 'Long notes do not fit on the one-line strip.',
            'Read-only; select and copy the text if you need it in a report.',
            availability='Shown only after Details is chosen.'),
        'gui.palette': TooltipEntry(
            'Search every command of the window and of the open panels by name.',
            'Reaches any command from the keyboard without hunting through menus.',
            'Typing filters the list; Enter runs the chosen command and Escape closes the palette.',
            availability='Opens with Ctrl+Shift+P.'),
        'gui.palette_list': TooltipEntry(
            'The commands that match the search text.',
            'Unavailable commands stay listed with the reason they cannot run now.',
            'Enter runs the selected command; unavailable commands only report their reason.'),
        'gui.reset_layout': TooltipEntry(
            'Put every panel back at its default place and size.',
            'Recovers a window layout that was dragged somewhere unusable.',
            'Forgets the saved panel layout; panel contents and the project are untouched.'),
        'gui.cycle_panels': TooltipEntry(
            'Move keyboard focus to the next region of the window, or the previous one with Shift.',
            'Gets between the navigator, code, findings, open panels and the log without a mouse.',
            'Changes the focused region only; nothing is edited.', availability='F6 and Shift+F6.'),
        'gui.navigate': TooltipEntry(
            'Go back to the previous place you opened from a link, or forward again.',
            'Links between panels and the code views leave a trail, like a browser history.',
            'Reopens an earlier place; nothing is edited. The trail keeps the last 50 places.',
            availability='Alt+Left and Alt+Right.'),
        'panels.dock_tabs': TooltipEntry(
            'Tabs that switch between panels docked in the same place.',
            'Several panels share one area and only one shows at a time.',
            'Choosing a tab shows that panel; nothing is closed.'),
        'menu.view': TooltipEntry(
            'Show or hide panels, reset the layout and open the command palette.',
            'Collects the window layout controls in one menu.',
            'Only changes which panels are visible; analysis results are untouched.'),
    }


def register_tips(tips: Mapping[str, object], templates: Mapping[str, object] | None = None) -> tuple[str, ...]:
    """Add entries to the tooltip registry and return the ids that are new. Registering the same text again is a
    no-op; different text under a known id, or an id used as both a tip and a template, raises `TipError`."""
    from .. import tooltips
    templates = templates or {}
    clash = sorted(set(tips) & set(templates))
    if clash:
        raise TipError(f'{TIPS_CODE}: {clash[0]} is both a tip and a template')
    added = []
    for entries, registry in ((tips, tooltips.REGISTRY), (templates, tooltips.TEMPLATES)):
        for tip_id, entry in entries.items():
            other = tooltips.TEMPLATES if registry is tooltips.REGISTRY else tooltips.REGISTRY
            if tip_id in other:
                raise TipError(f'{TIPS_CODE}: {tip_id} is already registered as the other kind')
            known = registry.get(tip_id)
            if known is None:
                registry[tip_id] = entry
                added.append(tip_id)
            elif known != entry:
                raise TipError(f'{TIPS_CODE}: {tip_id} is already registered with different text')
    return tuple(added)


def register_gui_tips() -> tuple[str, ...]:
    return register_tips(gui_tips())


def what_line(tip_id: str, **values: object) -> str:
    """The What line of a tip, cut to the accessible-description limit."""
    from .. import tooltips
    render = (tooltips.template_description(tip_id, **values) if tip_id in tooltips.TEMPLATES
              else tooltips.plain_description(tip_id))
    text = ' '.join(render.split('\n', 1)[0].removeprefix('What: ').split())  # the What line is always first
    return text if len(text) <= DESCRIPTION_LIMIT else text[:DESCRIPTION_LIMIT - 3] + '...'


def apply_tip(target: object, tip_id: str, *, accessible: str = 'what', name: str | None = None,
              **values: object) -> None:
    """Apply a registry entry to a widget or action (`tooltips.apply_tooltip` delegates here): tooltip, what's-this,
    status tip, accessible description and, only while it is still empty, the object name. With `accessible='what'`
    the description is the What line (the full text stays in what's-this and the tooltip); `'full'` keeps the old
    flattened whole text. The UIA automation id is `name` or the tip id (unique per window, which is why a state
    button passes its per-panel name). Dynamic ids (templates) take their values as keywords."""
    from .. import tooltips
    if accessible not in ('what', 'full'):
        raise ValueError(f'accessible must be "what" or "full": {accessible!r:.20}')
    if tip_id in tooltips.TEMPLATES:
        rich, plain = tooltips.template(tip_id, **values), tooltips.template_description(tip_id, **values)
    else:
        rich, plain = tooltips.tooltip(tip_id), tooltips.plain_description(tip_id)
    flat = plain.replace('\n', ' ')
    target.setToolTip(rich)
    target.setWhatsThis(plain)
    if hasattr(target, 'setStatusTip'):
        target.setStatusTip(flat)
    if hasattr(target, 'setAccessibleDescription'):
        target.setAccessibleDescription(what_line(tip_id, **values) if accessible == 'what' else flat)
    if not target.objectName():
        target.setObjectName(name or tip_id)
    if hasattr(target, 'setAccessibleIdentifier'):
        target.setAccessibleIdentifier(name or tip_id)


def escaped_tip(text: str) -> str:
    """Untrusted text as a tooltip: Qt treats a tooltip that looks like markup as rich text, so it is escaped."""
    return '<p style="white-space:pre-wrap">' + html.escape(text).replace('\n', '<br>') + '</p>'
