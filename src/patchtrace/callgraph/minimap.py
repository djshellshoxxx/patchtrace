"""Qt-free geometry of the Calls diagram minimap (docs/specs/panels/graph-inspection.md section 3).

The minimap is a read-only overview: scaled node dots and the part of the scene the canvas shows. Everything here is
plain numbers so the maths is testable without a window."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

KEY_STEP = 0.1  # fraction of the scene one arrow key press moves the viewport
GRID = 10
MAX_DOTS = 2_000
Rect = tuple[float, float, float, float]  # x, y, width, height
_DIRECTIONS = {'left': (-1, 0), 'right': (1, 0), 'up': (0, -1), 'down': (0, 1)}


@dataclass(frozen=True)
class MinimapModel:
    size: tuple[int, int]
    scene: Rect
    scale: float
    offset: tuple[float, float]
    dots: tuple[tuple[float, float], ...]
    focus_index: int | None
    viewport: Rect  # in widget coordinates
    coverage_percent: int
    description: str


def _intersect(a: Rect, b: Rect) -> Rect:
    x0, y0 = max(a[0], b[0]), max(a[1], b[1])
    x1, y1 = min(a[0] + a[2], b[0] + b[2]), min(a[1] + a[3], b[1] + b[3])
    return (x0, y0, max(0.0, x1 - x0), max(0.0, y1 - y0))


def _cell(value: float, start: float, length: float) -> int:
    return min(GRID, max(1, int((value - start) / length * GRID) + 1))


def build_minimap(points: Mapping[str, tuple[float, float]], scene: Rect, viewport: Rect, size: tuple[int, int],
                  focus: str | None = None) -> MinimapModel:
    """Fit `scene` into `size` keeping the aspect ratio and place the node dots and the viewport rectangle in it."""
    width, height = size
    if scene[2] <= 0 or scene[3] <= 0 or width <= 0 or height <= 0:
        return MinimapModel(size, scene, 0.0, (0.0, 0.0), (), None, (0.0, 0.0, 0.0, 0.0), 0,
                            'The diagram overview is empty.')
    scale = min(width / scene[2], height / scene[3])
    offset = ((width - scene[2] * scale) / 2, (height - scene[3] * scale) / 2)

    def to_widget(x: float, y: float) -> tuple[float, float]:
        return ((x - scene[0]) * scale + offset[0], (y - scene[1]) * scale + offset[1])

    keys = list(points)[:MAX_DOTS]
    dots = tuple(to_widget(*points[key]) for key in keys)
    inside = _intersect(viewport, scene)
    px, py = to_widget(inside[0], inside[1])
    coverage = round(100 * inside[2] * inside[3] / (scene[2] * scene[3]))
    cx = min(scene[0] + scene[2], max(scene[0], viewport[0] + viewport[2] / 2))
    cy = min(scene[1] + scene[3], max(scene[1], viewport[1] + viewport[3] / 2))
    text = (f'Viewport covers {coverage} percent of the diagram, centred at column {_cell(cx, scene[0], scene[2])} '
            f'of {GRID}, row {_cell(cy, scene[1], scene[3])} of {GRID}.')
    return MinimapModel(size, scene, scale, offset, dots, keys.index(focus) if focus in keys else None,
                        (px, py, inside[2] * scale, inside[3] * scale), coverage, text)


def to_scene(model: MinimapModel, x: float, y: float) -> tuple[float, float]:
    """Scene point under a widget point (clamped to the scene); the scene origin when the minimap is empty."""
    scene = model.scene
    if model.scale <= 0:
        return (scene[0], scene[1])
    sx = (x - model.offset[0]) / model.scale + scene[0]
    sy = (y - model.offset[1]) / model.scale + scene[1]
    return (min(scene[0] + scene[2], max(scene[0], sx)), min(scene[1] + scene[3], max(scene[1], sy)))


def pan_target(scene: Rect, viewport: Rect, direction: str) -> tuple[float, float]:
    """Scene point the viewport centre moves to for one arrow key press, kept inside the scene."""
    if direction not in _DIRECTIONS:
        raise ValueError(f'unknown direction {direction!r:.20}')
    dx, dy = _DIRECTIONS[direction]
    x = viewport[0] + viewport[2] / 2 + dx * scene[2] * KEY_STEP
    y = viewport[1] + viewport[3] / 2 + dy * scene[3] * KEY_STEP
    return (min(scene[0] + scene[2], max(scene[0], x)), min(scene[1] + scene[3], max(scene[1], y)))
