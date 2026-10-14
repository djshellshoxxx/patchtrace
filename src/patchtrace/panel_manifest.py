"""Explicit manifest of every GUI panel, built or not (GUI plan 8.2). Pure and import-cheap.

Each slot reserves the id, dock area, tab group and Ctrl+Shift shortcut of a planned panel, so a collision fails
`patchtrace panels check` before a second panel exists. A loader imports its panel module inside its own body: a
feature's code is not loaded until the host asks for it, and PyInstaller's bytecode scan still sees the import. An
absent module (or an absent package above it) means "not built yet" and is hidden from the menus; anything else a
loader raises is a defect that the check reports.

Feature builders never edit this file. They add `<package>/panel.py` exporting `PANEL` (a PanelSpec whose area,
tab group and shortcut equal its slot here); a placement change is a one-line edit by the integrator. Default
placement, hidden at first run unless a spec sets `default_visible`: right = evidence [unified and build_env
tabbed], kb [kev tabbed], rules; bottom = graph [strings and capabilities tabbed], search, series, files;
left = leads, guide.
"""
from __future__ import annotations

from .gui.registry import ManifestEntry, PanelSpec


def _evidence() -> PanelSpec:
    from .secondary.evidence_panel import PANEL
    return PANEL


def _unified() -> PanelSpec:
    from .unified.panel import PANEL
    return PANEL


def _search() -> PanelSpec:
    from .search.panel import PANEL
    return PANEL


def _graph() -> PanelSpec:
    from .callgraph.panel import PANEL
    return PANEL


def _strings() -> PanelSpec:
    from .strings.panel import PANEL
    return PANEL


def _capabilities() -> PanelSpec:
    from .intelligence.tools.capa_panel import PANEL
    return PANEL


def _build_env() -> PanelSpec:
    from .buildenv.panel import PANEL
    return PANEL


def _rules() -> PanelSpec:
    from .rules.panel import PANEL
    return PANEL


def _kb() -> PanelSpec:
    from .kbcorrelation.panel import PANEL
    return PANEL


def _kev() -> PanelSpec:
    from .kev.panel import PANEL
    return PANEL


def _leads() -> PanelSpec:
    from .pilot.panel import PANEL
    return PANEL


def _guide() -> PanelSpec:
    from .guide.panel import PANEL
    return PANEL


def _series() -> PanelSpec:
    from .nway.panel import PANEL
    return PANEL


def _files() -> PanelSpec:
    from .pe_overview.panel import PANEL
    return PANEL


MANIFEST: tuple[ManifestEntry, ...] = (
    ManifestEntry('evidence', 'patchtrace.secondary.evidence_panel', _evidence, 'right', None, 'Ctrl+Shift+E'),
    ManifestEntry('unified', 'patchtrace.unified.panel', _unified, 'right', 'evidence', 'Ctrl+Shift+U'),
    ManifestEntry('search', 'patchtrace.search.panel', _search, 'bottom', None, 'Ctrl+Shift+F'),
    ManifestEntry('graph', 'patchtrace.callgraph.panel', _graph, 'bottom', None, 'Ctrl+Shift+G'),
    ManifestEntry('strings', 'patchtrace.strings.panel', _strings, 'bottom', 'graph', 'Ctrl+Shift+T'),
    ManifestEntry('capabilities', 'patchtrace.intelligence.tools.capa_panel', _capabilities, 'bottom', 'graph',
                  'Ctrl+Shift+A'),
    ManifestEntry('build_env', 'patchtrace.buildenv.panel', _build_env, 'right', 'evidence', 'Ctrl+Shift+B'),
    ManifestEntry('rules', 'patchtrace.rules.panel', _rules, 'right', None, 'Ctrl+Shift+R'),
    ManifestEntry('kb', 'patchtrace.kbcorrelation.panel', _kb, 'right', None, 'Ctrl+Shift+K'),
    ManifestEntry('kev', 'patchtrace.kev.panel', _kev, 'right', 'kb', 'Ctrl+Shift+X'),
    ManifestEntry('leads', 'patchtrace.pilot.panel', _leads, 'left', None, 'Ctrl+Shift+L'),
    ManifestEntry('guide', 'patchtrace.guide.panel', _guide, 'left', None, 'Ctrl+Shift+H'),
    ManifestEntry('series', 'patchtrace.nway.panel', _series, 'bottom', None, None),
    ManifestEntry('files', 'patchtrace.pe_overview.panel', _files, 'bottom', None, None),
)
