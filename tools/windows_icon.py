"""Write the Windows .exe icon (PatchTrace.ico) from the packaged mark. Build tool; never shipped.

Every frame is a PNG, which Windows has read inside .ico files since Vista, so `pack_ico` only writes the
ICONDIR header and one ICONDIRENTRY per frame. Rendering reuses `patchtrace.app_icon`, so the file icon and the
window icon come from the same SVG.

    python tools/windows_icon.py --out build/windows-resources/PatchTrace.ico
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
MAX_FRAMES = 16
MAX_FRAME_BYTES = 1 << 20


def pack_ico(frames: Sequence[tuple[int, bytes]]) -> bytes:
    """An .ico holding square PNG frames given as (size in pixels, PNG bytes), in the order given."""
    if not 1 <= len(frames) <= MAX_FRAMES:
        raise ValueError(f'an icon needs 1..{MAX_FRAMES} frames, got {len(frames)}')
    sizes = [size for size, _png in frames]
    if len(set(sizes)) != len(sizes):
        raise ValueError(f'duplicate icon sizes: {sizes}')
    header = struct.pack('<HHH', 0, 1, len(frames))  # reserved, type 1 = icon, image count
    offset = len(header) + 16 * len(frames)
    entries, payload = [], []
    for size, png in frames:
        if not 1 <= size <= 256:
            raise ValueError(f'icon frame size {size} is outside 1..256')
        if not png.startswith(PNG_SIGNATURE) or len(png) > MAX_FRAME_BYTES:
            raise ValueError(f'icon frame {size}px is not a PNG of at most {MAX_FRAME_BYTES} bytes')
        side = size % 256  # 0 means 256 in ICONDIRENTRY
        entries.append(struct.pack('<BBBBHHII', side, side, 0, 0, 1, 32, len(png), offset))
        payload.append(png)
        offset += len(png)
    return header + b''.join(entries) + b''.join(payload)


def render_frames() -> list[tuple[int, bytes]]:
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtGui import QGuiApplication

    from patchtrace.app_icon import ICON_SIZES, mark_svg, render_png

    _app = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841 - painting needs a GUI application
    svg = mark_svg()
    return [(size, render_png(svg, size)) for size in ICON_SIZES]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Write the PatchTrace Windows icon from the packaged mark.')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    data = pack_ico(render_frames())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', prefix='.patchtrace-icon-', suffix='.tmp',
                                         dir=args.out.parent, delete=False) as stream:
            staged = Path(stream.name)
            stream.write(data)
        os.replace(staged, args.out)
        staged = None
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
    print(args.out)
    return 0


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
    raise SystemExit(main())
