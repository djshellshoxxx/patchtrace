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
               'gui.notice_details', 'gui.notice_dismiss')


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
    """`tooltips.apply_tooltip` plus the accessibility contract: with `accessible='what'` the description is the
    What line (the full text stays in what's-this and the tooltip), and the UIA automation id is `name` or the tip
    id (unique per window, which is why a state button passes its per-panel name)."""
    from .. import tooltips
    if accessible not in ('what', 'full'):
        raise ValueError(f'accessible must be "what" or "full": {accessible!r:.20}')
    tooltips.apply_tooltip(target, tip_id, name=name, **values)
    if accessible == 'what' and hasattr(target, 'setAccessibleDescription'):
        target.setAccessibleDescription(what_line(tip_id, **values))
    if hasattr(target, 'setAccessibleIdentifier'):
        target.setAccessibleIdentifier(name or tip_id)


def escaped_tip(text: str) -> str:
    """Untrusted text as a tooltip: Qt treats a tooltip that looks like markup as rich text, so it is escaped."""
    return '<p style="white-space:pre-wrap">' + html.escape(text).replace('\n', '<br>') + '</p>'
