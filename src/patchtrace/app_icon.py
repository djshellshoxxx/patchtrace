"""The application icon: the owner's mark, rendered from the packaged SVG without Qt image plugins.

The frozen packages keep only Qt platform plugins (tools/pyinstaller_hooks/hook-PySide6.QtGui.py), so
`QIcon('mark.svg')` would be silently empty there. QtSvg's renderer paints the SVG straight into images instead,
and PNG decoding is built into QtGui. `tools/windows_icon.py` renders the Windows .exe icon with the same
function, so the window icon and the file icon cannot drift.

`resources/patchtrace-mark.svg` is a byte-identical copy of `site/assets/cdl-mark.svg` (a test enforces it).
"""
from __future__ import annotations

from importlib import resources

MARK_RESOURCE = 'resources/patchtrace-mark.svg'
MAX_SVG_BYTES = 64 * 1024
ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def mark_svg() -> bytes:
    """The packaged SVG. Raises OSError when the resource is missing, ValueError when empty or oversized."""
    data = resources.files('patchtrace').joinpath(MARK_RESOURCE).read_bytes()
    if not data or len(data) > MAX_SVG_BYTES:
        raise ValueError(f'PT-ICON: {MARK_RESOURCE} is empty or larger than {MAX_SVG_BYTES} bytes')
    return data


def render_image(svg: bytes, size: int):
    """One square, transparent-background QImage of the mark. A QGuiApplication must exist."""
    from PySide6.QtCore import QByteArray, QRectF, Qt
    from PySide6.QtGui import QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer

    if not 1 <= size <= 256:
        raise ValueError(f'PT-ICON: icon size {size} is outside 1..256')
    renderer = QSvgRenderer(QByteArray(svg))
    if not renderer.isValid():
        raise ValueError('PT-ICON: the mark is not a valid SVG')
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    try:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        renderer.render(painter, QRectF(0, 0, size, size))
    finally:
        painter.end()
    return image


def render_png(svg: bytes, size: int) -> bytes:
    """`render_image` encoded as PNG bytes (the .exe icon embeds PNG frames)."""
    from PySide6.QtCore import QBuffer, QIODevice

    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not render_image(svg, size).save(buffer, 'PNG'):
        raise ValueError('PT-ICON: PNG encoding failed')
    return bytes(buffer.data())


def app_icon():
    """The mark as a QIcon at every ICON_SIZES; an empty QIcon when it cannot be loaded (never fatal at startup)."""
    from PySide6.QtGui import QIcon, QPixmap

    try:
        svg = mark_svg()
        images = [render_image(svg, size) for size in ICON_SIZES]
    except (OSError, ValueError):
        return QIcon()
    icon = QIcon()
    for image in images:
        icon.addPixmap(QPixmap.fromImage(image))
    return icon
