"""The four ports a panel talks to the main window through (GUI plan 8.2). Structural Protocols, no Qt.

Panels import these, `patchtrace.gui.qt.*` and their own package, never `MainWindow`, `ui.py` or another feature.
Everything here runs on the GUI thread. The concrete tasks, settings and theme objects live in the Qt layer, so the
shell attributes are typed `object` here; `patchtrace.gui.qt` narrows them.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path

    from ..models import ComparisonProject
    from .anchors import AnchorRef
    from .projection import MatchIndex, ProjectKey
    from .state import NoticeModel


@runtime_checkable
class ProjectPort(Protocol):
    """Read-only view of the open project."""

    def key(self) -> ProjectKey | None: ...
    def project(self) -> ComparisonProject | None: ...
    def busy(self) -> bool: ...
    def artifact_paths(self) -> tuple[Path, Path, str, str]:
        """(older path, newer path, older sha256, newer sha256)."""
        ...
    def match_index(self) -> MatchIndex:
        """Function id -> match and side, built once per key."""
        ...


@runtime_checkable
class MutationPort(Protocol):
    """The only way a panel changes the project, through `ProjectService`."""

    def annotate(self, target_id: str, text: str, kind: str = 'note') -> None: ...
    def review_match(self, match_id: str, status: str) -> None: ...


@runtime_checkable
class NavigationPort(Protocol):
    def select_match(self, match_id: str, clear_filters: bool = False) -> bool: ...
    def reveal_lines(self, function_id: str, start: int, end: int) -> object | None:
        """Show original lines `start` to `end` of a function; the function id already fixes the side."""
        ...
    def show_raw_offset(self, side: str, offset: int) -> None: ...
    def show_pair(self, older: str, newer: str, label: str) -> None: ...
    def navigate(self, anchor: AnchorRef) -> object:
        """Route an anchor; returns its NavResult."""
        ...
    def focus_panel(self, panel_id: str) -> None: ...
    def back(self) -> object | None: ...
    def forward(self) -> object | None: ...


@runtime_checkable
class ShellPort(Protocol):
    @property
    def tasks(self) -> object: ...
    @property
    def settings(self) -> object: ...
    @property
    def theme(self) -> object: ...
    def status(self, text: str) -> None: ...
    def announce(self, text: str, *, assertive: bool = False) -> None:
        """The only sender of screen-reader announcements; polite unless a blocking error."""
        ...
    def notice(self, key: str, model: NoticeModel | None) -> None:
        """Show, replace or (None) clear the window-level notice `key`."""
        ...
    def copy_text(self, text: str) -> bool:
        """Put at most 16 KiB on the clipboard; False when refused."""
        ...
    def choose_file(self, title: str, file_filter: str = '') -> Path | None: ...
    def spotlight(self, tip_id: str) -> None:
        """Reserved for the guide (E-5): outline the control that carries `tip_id`."""
        ...


@runtime_checkable
class WindowPort(ProjectPort, MutationPort, NavigationPort, ShellPort, Protocol):
    """All four, for legacy code that still takes one window object."""
