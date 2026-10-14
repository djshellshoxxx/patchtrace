"""Shared helpers for tests/test_site_*.py (not collected as tests)."""
from __future__ import annotations

import random
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.site import build_site  # noqa: E402
from tools.site import xmr_address as xmr  # noqa: E402

SITE = ROOT / 'site'
LOGO_OUTPUTS = ('logo-512.png', 'logo-192.png', 'favicon-64.png', 'apple-touch-icon-180.png', 'og-image.png')
_RNG = random.Random(20261014)
# SYNTHETIC address: random key bytes, never a real wallet. The committed config must never contain one.
SYNTHETIC_ADDRESS = xmr.encode_address('standard', 'mainnet', _RNG.randbytes(32), _RNG.randbytes(32))


class StubQR:
    """Stands in for segno so the donation block can be tested without the optional dependency."""

    def __init__(self):
        self.payloads: list[str] = []

    def __call__(self, data: str) -> str:
        self.payloads.append(data)
        return ('<svg role="img" aria-label="stub QR" focusable="false" viewBox="0 0 3 3">'
                '<title>stub QR</title><path d="M0 0h1v1h-1z"/></svg>')


def quiet_build(out_dir: Path, **kwargs):
    logs: list[str] = []
    result = build_site.build(out_dir=out_dir, log=logs.append, **kwargs)
    return result, logs


def copy_site(destination: Path, *, drop_logo: bool = True) -> Path:
    """A private copy of site/ that a test may modify freely. By default it has no logo input and no
    generated logo assets, so results do not depend on whether the owner has uploaded the logo yet."""
    target = destination / 'site'
    shutil.copytree(SITE, target, ignore=shutil.ignore_patterns('dist', '__pycache__'))
    if drop_logo:
        (target / 'assets' / 'source' / 'logo-original.png').unlink(missing_ok=True)
        for name in LOGO_OUTPUTS:
            (target / 'assets' / name).unlink(missing_ok=True)
    return target


def make_logo(path: Path, size: tuple[int, int] = (640, 640), mode: str = 'RGB'):
    """A synthetic stand-in image (not the owner's logo)."""
    from PIL import Image, ImageDraw
    image = Image.new(mode, size, (0, 0, 0) if mode == 'RGB' else (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((size[0] // 4, size[1] // 4, size[0] * 3 // 4, size[1] * 3 // 4), outline=(120, 210, 255, 255),
                 width=max(2, size[0] // 40))
    image.save(path, format='PNG')
    return path
