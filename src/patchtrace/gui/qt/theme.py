"""Theme tokens, the three variants and their controller (GUI plan 8.6; slices F3 and F7).

``DARK`` is the existing look; ``build_stylesheet(DARK)`` must equal ``ui.DARK_STYLE`` (a golden test). ``system``
removes the stylesheet and reads tokens from the platform palette. High contrast is automatic: while the platform
asks for it, tokens come from the palette whatever variant is chosen, chip fills and hunk tints are dropped and
state is carried by text, glyph and border. ``SystemPrefs`` is the seam that tests replace with a simulated provider."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from PySide6.QtCore import QEvent, QObject, QSettings, Qt, Signal
from PySide6.QtGui import QActionGroup, QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication, QMainWindow, QMenu

from ..state import CHIP_TOKENS
from ..theme_math import NON_TEXT_CONTRAST, TEXT_CONTRAST, contrast_ratio, ensure_contrast, relative_luminance
from .theme_stylesheet import build_stylesheet

VARIANTS = ('dark', 'system')
SETTINGS_KEY = 'theme/variant'
HIGH_CONTRAST = 'high-contrast'


@dataclass(frozen=True, slots=True)
class ChipColors:
    fill: str
    edge: str


@dataclass(frozen=True, slots=True)
class ThemeTokens:
    surface: str
    surface_alt: str
    text: str
    text_muted: str
    accent: str
    focus_ring: str
    border: str
    warning: str
    disabled: str
    hunk_replace: str  # code-diff row tints; the text on them is guarded by ensure_contrast
    hunk_other: str
    chips: tuple[tuple[str, ChipColors], ...]  # a tuple, not a dict, so the tokens stay hashable
    high_contrast: bool = False

    def chip(self, token: str) -> ChipColors:
        """Colours of a chip token. ``plain`` has no fill: it is outlined text on the surface."""
        if token == 'plain':
            return ChipColors(self.surface, self.text)
        for name, colors in self.chips:
            if name == token:
                return colors
        raise KeyError(token)


DARK = ThemeTokens(
    surface='#161b22', surface_alt='#10151c', text='#d9e1ec', text_muted='#97a7ba', accent='#8be2e9',
    focus_ring='#53c6d6', border='#5f7186', warning='#ffc875', disabled='#6c7684', hunk_replace='#263a43',
    hunk_other='#33392b',
    chips=(('ok', ChipColors('#1f4d33', '#4fb87a')), ('change', ChipColors('#1f3b5c', '#5b9be0')),
           ('caution', ChipColors('#5a4310', '#e0a93b')), ('info', ChipColors('#1c4650', '#53c6d6')),
           ('muted', ChipColors('#2b3441', '#7d8da1')), ('alt', ChipColors('#46285a', '#b184d6')),
           ('error', ChipColors('#5c2326', '#e5686d'))))

def chip_text_color(tokens: ThemeTokens, token: str) -> str:
    """The text colour on a chip: the theme text, or black when a palette makes that unreadable on the fill."""
    fill = tokens.chip(token).fill
    return tokens.text if contrast_ratio(tokens.text, fill) >= TEXT_CONTRAST else '#000000'


def contrast_problems(tokens: ThemeTokens) -> list[str]:
    """Every token pair below its WCAG minimum (text 4.5:1, borders, focus ring and chip edges 3:1)."""
    checks: list[tuple[str, str, str, float]] = []
    for surface in (tokens.surface, tokens.surface_alt):
        checks += [(f'text on {surface}', tokens.text, surface, TEXT_CONTRAST),
                   (f'text_muted on {surface}', tokens.text_muted, surface, TEXT_CONTRAST),
                   (f'accent on {surface}', tokens.accent, surface, TEXT_CONTRAST),
                   (f'warning on {surface}', tokens.warning, surface, TEXT_CONTRAST),
                   (f'focus_ring on {surface}', tokens.focus_ring, surface, NON_TEXT_CONTRAST),
                   (f'border on {surface}', tokens.border, surface, NON_TEXT_CONTRAST)]
    for name in CHIP_TOKENS:
        colors = tokens.chip(name)  # plain draws its text in the edge colour, on the surface
        text = colors.edge if name == 'plain' else chip_text_color(tokens, name)
        checks.append((f'chip {name} text', text, colors.fill, TEXT_CONTRAST))
        if name != 'plain':
            checks.append((f'chip {name} edge', colors.edge, tokens.surface, NON_TEXT_CONTRAST))
    return [f'{label}: {contrast_ratio(a, b):.2f} < {minimum}' for label, a, b, minimum in checks
            if contrast_ratio(a, b) < minimum]


# ---- the system and high-contrast variants ----------------------------------------------------------------------

# Chip edges for a light surface: DARK's edges are too pale there (3:1 against white is the floor).
_LIGHT_EDGES = {'ok': '#1b7a43', 'change': '#2a62b0', 'caution': '#8a5a00', 'info': '#127383', 'muted': '#5a6878',
                'alt': '#7a46a8', 'error': '#b3282e'}
_LIGHT_WARNING = '#8a5a00'
_DARK_SURFACE_LUMINANCE = 0.18  # below this the palette is a dark one: pale edges, tinted fills


def _mix(first: str, second: str, share: float) -> str:
    """``share`` of ``first`` blended into ``second``, both #rrggbb."""
    a, b = QColor(first), QColor(second)
    channels = (round(x * share + y * (1 - share)) for x, y in ((a.red(), b.red()), (a.green(), b.green()),
                                                              (a.blue(), b.blue())))
    return '#{:02x}{:02x}{:02x}'.format(*channels)


def _keep(color: str, surfaces: tuple[str, ...], fallback: str, minimum: float) -> str:
    """``color`` when it reaches ``minimum`` on every surface, else ``fallback``."""
    for surface in surfaces:
        color = ensure_contrast(color, surface, fallback, minimum)
    return color


def system_tokens(palette: QPalette, *, high_contrast: bool = False) -> ThemeTokens:
    """Tokens from the platform palette. A colour that would fall below its WCAG floor on either surface becomes the
    palette's text colour, so a hostile palette degrades to plain text instead of unreadable text. In high contrast
    nothing is dimmed or tinted: chips are outlined text and hunks are marked by underline (see ``codediff``)."""
    role = QPalette.ColorRole
    surface = palette.color(role.Window).name()
    text = palette.color(role.WindowText).name()
    alt = palette.color(role.Base).name()
    if contrast_ratio(text, alt) < TEXT_CONTRAST:
        alt = surface
    surfaces = (surface, alt)
    ring = _keep(palette.color(role.Highlight).name(), surfaces, text, NON_TEXT_CONTRAST)
    accent = _keep(palette.color(role.Link).name(), surfaces, text, TEXT_CONTRAST)
    if high_contrast:
        outline = tuple((name, ChipColors(surface, text)) for name in CHIP_TOKENS if name != 'plain')
        return ThemeTokens(surface=surface, surface_alt=alt, text=text, text_muted=text, accent=accent, focus_ring=ring,
                           border=text, warning=text, disabled=palette.color(role.PlaceholderText).name(),
                           hunk_replace=alt, hunk_other=alt, chips=outline, high_contrast=True)
    dark = relative_luminance(surface) < _DARK_SURFACE_LUMINANCE
    edges = {name: colors.edge for name, colors in DARK.chips} if dark else _LIGHT_EDGES
    share = 0.25 if dark else 0.14
    chips = tuple((name, ChipColors(_mix(edge, surface, share), _keep(edge, surfaces, text, NON_TEXT_CONTRAST)))
                  for name, edge in edges.items())
    return ThemeTokens(
        surface=surface, surface_alt=alt, text=text,
        text_muted=_keep(_mix(text, surface, 0.7), surfaces, text, TEXT_CONTRAST), accent=accent, focus_ring=ring,
        border=_keep(_mix(text, surface, 0.55), surfaces, text, NON_TEXT_CONTRAST),
        warning=_keep(DARK.warning if dark else _LIGHT_WARNING, surfaces, text, TEXT_CONTRAST),
        disabled=_mix(text, surface, 0.45), hunk_replace=_mix(edges['change'], alt, 0.2),
        hunk_other=_mix(edges['ok'], alt, 0.2), chips=chips)


# ---- the platform seam -------------------------------------------------------------------------------------------

class SystemPrefs(Protocol):
    """What the controller asks of the platform; tests substitute a simulated provider."""

    def high_contrast(self) -> bool: ...
    def reduced_motion(self) -> bool: ...
    def palette(self) -> QPalette: ...
    def on_change(self, callback: Callable[[], None]) -> None: ...


class QtSystemPrefs(QObject):
    """The real provider: ``QStyleHints`` accessibility preferences, colour scheme and palette events."""

    def __init__(self, app: QGuiApplication, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._app = app
        self._callbacks: list[Callable[[], None]] = []
        self._hints = app.styleHints()  # both held: PySide frees the accessibility object with a dropped wrapper
        self._access = self._hints.accessibility()
        for signal in (self._access.contrastPreferenceChanged, self._access.motionPreferenceChanged,
                       self._hints.colorSchemeChanged):
            signal.connect(self._notify)
        app.installEventFilter(self)

    def high_contrast(self) -> bool:
        return self._access.contrastPreference() == Qt.ContrastPreference.HighContrast

    def reduced_motion(self) -> bool:
        return self._access.motionPreference() == Qt.MotionPreference.ReducedMotion

    def palette(self) -> QPalette:
        return self._app.palette()

    def on_change(self, callback: Callable[[], None]) -> None:
        self._callbacks.append(callback)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if event.type() in (QEvent.Type.ApplicationPaletteChange, QEvent.Type.ThemeChange):
            self._notify()
        return False

    def _notify(self, *_args: object) -> None:
        for callback in self._callbacks:
            callback()


_ANIMATED_EFFECTS = (Qt.UIEffect.UI_AnimateMenu, Qt.UIEffect.UI_FadeMenu, Qt.UIEffect.UI_AnimateCombo,
                     Qt.UIEffect.UI_AnimateTooltip, Qt.UIEffect.UI_FadeTooltip, Qt.UIEffect.UI_AnimateToolBox)


class ThemeController(QObject):
    """Owns the chosen variant (persisted), the live tokens and the window stylesheet. ``theme_changed`` carries the
    new ``ThemeTokens`` and fires only when they differ; ``motion_changed`` carries the reduced-motion flag."""

    theme_changed = Signal(object)
    motion_changed = Signal(bool)
    variant_changed = Signal(str)

    def __init__(self, window: QMainWindow, settings: QSettings, prefs: SystemPrefs | None = None,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._window = window
        self._settings = settings
        self._prefs = prefs or QtSystemPrefs(QGuiApplication.instance(), self)
        value = settings.value(SETTINGS_KEY)
        self._variant = value if value in VARIANTS else 'dark'
        self._tokens: ThemeTokens | None = None
        self._reduced: bool | None = None
        self._saved_effects: dict[Qt.UIEffect, bool] = {}
        self._prefs.on_change(self.refresh)

    @property
    def variant(self) -> str:
        return self._variant

    @property
    def effective(self) -> str:
        """``high-contrast`` while the platform asks for it, else the chosen variant."""
        return HIGH_CONTRAST if self._prefs.high_contrast() else self._variant

    @property
    def tokens(self) -> ThemeTokens:
        return self._tokens if self._tokens is not None else self._compute()

    @property
    def reduced_motion(self) -> bool:
        return bool(self._prefs.reduced_motion())

    def set_variant(self, variant: str) -> None:
        if variant not in VARIANTS:
            raise ValueError(f'unknown theme variant {variant!r}; expected one of {VARIANTS}')
        self._variant = variant
        self._settings.setValue(SETTINGS_KEY, variant)
        self.variant_changed.emit(variant)
        self.refresh()

    def refresh(self) -> None:
        """Re-read the platform, restyle the window and tell listeners what changed."""
        tokens = self._compute()
        self._window.setStyleSheet(build_stylesheet(tokens) if self.effective == 'dark' else '')
        if tokens != self._tokens:
            self._tokens = tokens
            self.theme_changed.emit(tokens)
        self._apply_motion(self.reduced_motion)

    def _compute(self) -> ThemeTokens:
        mode = self.effective
        if mode == 'dark':
            return DARK
        return system_tokens(self._prefs.palette(), high_contrast=mode == HIGH_CONTRAST)

    def _apply_motion(self, reduced: bool) -> None:
        """Menu, combo, tooltip and tool box animations are the only motion Qt widgets add by themselves."""
        if reduced == self._reduced:
            return
        self._reduced = reduced
        for effect in _ANIMATED_EFFECTS:
            if reduced:
                self._saved_effects.setdefault(effect, QApplication.isEffectEnabled(effect))
                QApplication.setEffectEnabled(effect, False)
            elif effect in self._saved_effects:
                QApplication.setEffectEnabled(effect, self._saved_effects[effect])
        self.motion_changed.emit(reduced)


_LABELS = {'dark': 'Dark', 'system': 'System'}


def install_theme_menu(menu: QMenu, controller: ThemeController) -> QMenu:
    """The View > Theme submenu: one checked variant, and a disabled note while high contrast overrides it."""
    submenu = menu.addMenu('Theme')
    submenu.setObjectName('menu.view.theme')
    group = QActionGroup(submenu)
    group.setExclusive(True)
    actions = {}
    for variant, label in _LABELS.items():
        action = submenu.addAction(label)
        action.setObjectName(f'gui.theme.{variant}')
        action.setCheckable(True)
        group.addAction(action)
        action.triggered.connect(lambda _checked=False, name=variant: controller.set_variant(name))
        actions[variant] = action
    note = submenu.addAction('High contrast is on: Windows settings decide the colours')
    note.setObjectName('gui.theme.note')
    note.setEnabled(False)

    def sync(*_args: object) -> None:
        actions[controller.variant].setChecked(True)
        note.setVisible(controller.effective == HIGH_CONTRAST)

    controller.variant_changed.connect(sync)
    controller.theme_changed.connect(sync)
    sync()
    return submenu
