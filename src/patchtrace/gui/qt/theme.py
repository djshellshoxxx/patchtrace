"""Theme tokens and the stylesheet builder (GUI plan 8.6). The dark variant is the existing look, byte for byte.

``DARK`` is the token set; ``build_stylesheet(DARK)`` must equal ``ui.DARK_STYLE`` (a golden test), so a panel can
read colours from tokens without the look of the window drifting. Only colours that custom painting or a contrast
rule needs are tokens; the decorative greys inside the template (toolbar, buttons, separators) stay literals.
Automatic high contrast and the system variant (no stylesheet, tokens from the palette) belong to slice F7."""
from __future__ import annotations

from dataclasses import dataclass
from string import Template

from ..state import CHIP_TOKENS
from ..theme_math import NON_TEXT_CONTRAST, TEXT_CONTRAST, contrast_ratio


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
    chips: tuple[tuple[str, ChipColors], ...]  # a tuple, not a dict, so the tokens stay hashable

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
    focus_ring='#53c6d6', border='#5f7186', warning='#ffc875', disabled='#6c7684',
    chips=(('ok', ChipColors('#1f4d33', '#4fb87a')), ('change', ChipColors('#1f3b5c', '#5b9be0')),
           ('caution', ChipColors('#5a4310', '#e0a93b')), ('info', ChipColors('#1c4650', '#53c6d6')),
           ('muted', ChipColors('#2b3441', '#7d8da1')), ('alt', ChipColors('#46285a', '#b184d6')),
           ('error', ChipColors('#5c2326', '#e5686d'))))

_TEMPLATE = Template("""
QWidget { background: $surface; color: $text; font-size: 12px; }
QMainWindow, QDialog { background: $surface_alt; }
QToolBar { border: none; background: #1d2530; spacing: 7px; padding: 6px; }
QPushButton, QComboBox, QSpinBox { background: #253040; border: 1px solid #3b4a5c;
 padding: 5px 8px; border-radius: 4px; min-height: 21px; }
QPushButton:hover { border-color: $focus_ring; }
QPushButton:disabled { color: $disabled; }
QLineEdit, QPlainTextEdit, QTextEdit, QListWidget { background: $surface_alt;
 border: 1px solid #303b49; border-radius: 3px; padding: 4px; }
QListWidget::item { padding: 7px 3px; }
QListWidget::item:selected { background: #21424c; color: #f1fcff; }
QLabel#brand { font-size: 20px; font-weight: 600; color: $accent; }
QLabel#muted { color: $text_muted; }
QLabel#warning { color: $warning; }
QSplitter::handle { background: #283241; }
QTabBar::tab { background: #202a36; padding: 6px 12px; }
QTabBar::tab:selected { color: $accent; }
QProgressBar { border: 1px solid #303b49; text-align: center; }
QProgressBar::chunk { background: #3c9ea9; }
QMenu { border: 1px solid #394959; }
""")


def build_stylesheet(tokens: ThemeTokens) -> str:
    return _TEMPLATE.substitute(surface=tokens.surface, surface_alt=tokens.surface_alt, text=tokens.text,
                                text_muted=tokens.text_muted, accent=tokens.accent, focus_ring=tokens.focus_ring,
                                warning=tokens.warning, disabled=tokens.disabled)


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
