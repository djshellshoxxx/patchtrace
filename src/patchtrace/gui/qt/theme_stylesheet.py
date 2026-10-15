"""The dark stylesheet template and its builder (GUI plan 8.6; slice F3, moved here by F7).

``build_stylesheet(DARK)`` must equal ``ui.DARK_STYLE`` (a golden test). Only the colours that custom painting or a
contrast rule needs are tokens; the decorative greys inside the template (toolbar, buttons, separators) stay literals.
The system and high-contrast variants use no stylesheet at all, so the platform style and palette decide."""
from __future__ import annotations

from string import Template
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .theme import ThemeTokens

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
