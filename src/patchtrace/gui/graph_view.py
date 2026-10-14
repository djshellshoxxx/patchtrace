"""Pure graph values for `GraphCanvas` (GUI plan 8.4, slice F6b). No Qt.

A feature lays its graph out (layout algorithms are not ours) and hands the canvas immutable node and edge views.
Labels are untrusted text: they pass `sanitize_text` here, so the canvas never sees a control character. The size
check and the keyboard and zoom rules are pure so that they are tested without a display.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from .registry import GRAPH_EDGES, GRAPH_EDGES_MAX, GRAPH_NODES, GRAPH_NODES_MAX
from .state import CHIP_TOKENS
from .text import sanitize_text

CODE_TOO_LARGE = 'PT-GUI-GRAPH-TOO-LARGE'
ZOOM_MIN = 0.05
ZOOM_MAX = 8.0
MARK_BELOW = 0.15   # below this zoom a node is a mark
LABEL_FROM = 0.5    # from this zoom a node shows its label; between the two it is a box
ANTIALIAS_ITEM_LIMIT = 200
DIRECTIONS = ('left', 'right', 'up', 'down')


class GraphTooLargeError(ValueError):
    """The graph exceeds the canvas ceilings; the panel shows the too-large state and its textual table instead."""

    code = CODE_TOO_LARGE

    def __init__(self, nodes: int, edges: int, max_nodes: int, max_edges: int) -> None:
        super().__init__(f'{CODE_TOO_LARGE}: {nodes} nodes and {edges} edges exceed the limit of {max_nodes} nodes '
                         f'and {max_edges} edges')
        self.nodes, self.edges = nodes, edges


@dataclass(frozen=True, slots=True)
class GraphNodeView:
    """`key` is the identity that survives a refresh; `x`, `y` is the centre in scene units (supplied by the
    feature's layout); `chip` is a theme chip token; `description` extends the announcement."""

    key: str
    label: str
    x: float
    y: float
    chip: str = 'plain'
    description: str = ''

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError('a graph node needs a key')
        if self.chip not in CHIP_TOKENS:
            raise ValueError(f'unknown chip token {self.chip!r}')
        object.__setattr__(self, 'label', sanitize_text(self.label))
        object.__setattr__(self, 'description', sanitize_text(self.description))


@dataclass(frozen=True, slots=True)
class GraphEdgeView:
    source: str
    target: str
    kind: str = ''


def check_ceilings(max_nodes: int, max_edges: int) -> None:
    if not (1 <= max_nodes <= GRAPH_NODES_MAX and 1 <= max_edges <= GRAPH_EDGES_MAX):
        raise ValueError(f'ceilings must be within 1..{GRAPH_NODES_MAX} nodes and 1..{GRAPH_EDGES_MAX} edges')


def validate_graph(nodes: Sequence[GraphNodeView], edges: Sequence[GraphEdgeView],
                   max_nodes: int = GRAPH_NODES, max_edges: int = GRAPH_EDGES) -> None:
    """Size first (cheap, and an oversized graph is never walked), then identity and edge endpoints."""
    if len(nodes) > max_nodes or len(edges) > max_edges:
        raise GraphTooLargeError(len(nodes), len(edges), max_nodes, max_edges)
    keys = {node.key for node in nodes}
    if len(keys) != len(nodes):
        raise ValueError('duplicate node keys')
    for edge in edges:
        if edge.source not in keys or edge.target not in keys:
            raise ValueError(f'edge {edge.source!r} -> {edge.target!r} names a missing node')


def clamp_zoom(zoom: float) -> float:
    return min(ZOOM_MAX, max(ZOOM_MIN, zoom))


def detail_level(zoom: float) -> str:
    """'mark', 'box' or 'label' by zoom."""
    return 'mark' if zoom < MARK_BELOW else 'box' if zoom < LABEL_FROM else 'label'


def antialias(item_count: int) -> bool:
    return item_count <= ANTIALIAS_ITEM_LIMIT


def adjacency(edges: Iterable[GraphEdgeView]) -> dict[str, int]:
    """Connection count per node key (both directions), for the announcement."""
    counts: dict[str, int] = {}
    for edge in edges:
        counts[edge.source] = counts.get(edge.source, 0) + 1
        counts[edge.target] = counts.get(edge.target, 0) + 1
    return counts


def first_node(points: Mapping[str, tuple[float, float]]) -> str | None:
    """Top-left reading order: the node an arrow key focuses when nothing is focused."""
    return min(points, key=lambda key: (points[key][1], points[key][0], key), default=None)


def nearest_in_direction(points: Mapping[str, tuple[float, float]], current: str, direction: str) -> str | None:
    """The nearest node strictly beyond `current` in `direction`; sideways distance counts double so that arrows
    follow rows and columns. Ties go to the smaller key. None when nothing lies that way."""
    if direction not in DIRECTIONS:
        raise ValueError(direction)
    cx, cy = points[current]
    best: tuple[float, str] | None = None
    for key, (x, y) in points.items():
        dx, dy = x - cx, y - cy
        along, across = {'left': (-dx, dy), 'right': (dx, dy), 'up': (-dy, dx), 'down': (dy, dx)}[direction]
        if key == current or along <= 0:
            continue
        candidate = (along + 2 * abs(across), key)
        if best is None or candidate < best:
            best = candidate
    return best[1] if best else None
