#!/usr/bin/env python3
"""Make the site's logo assets from the owner's original logo (Pillow, LANCZOS resampling).

    python tools/site/make_logo_assets.py [--source PATH] [--out DIR]

Reads ``site/assets/source/logo-original.png`` (a square image; a non-square one is padded with its own
corner colour, never cropped or stretched) and writes, optimised, into ``site/assets/``:

* ``logo-512.png``, ``logo-192.png``  the hero logo (srcset pair)
* ``favicon-64.png``                  browser tab icon
* ``apple-touch-icon-180.png``        home-screen icon
* ``og-image.png`` (1200x630)         link-preview card: the logo centred on near-black ``#0e1116``

If the source file does not exist this is not an error: a clear warning is printed, nothing is written
and the exit status is 0, so the site build still succeeds and the page shows a text wordmark instead.
A source that exists but cannot be read as an image, or a missing Pillow, is an error (exit 1) so a bad
upload is never silently ignored.
"""
from __future__ import annotations

import argparse
import io
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / 'site' / 'assets' / 'source' / 'logo-original.png'
DEFAULT_OUT = ROOT / 'site' / 'assets'
SQUARE_OUTPUTS = (('logo-512.png', 512), ('logo-192.png', 192), ('favicon-64.png', 64),
                  ('apple-touch-icon-180.png', 180))
OG_NAME, OG_SIZE, OG_LOGO_SIDE = 'og-image.png', (1200, 630), 560
NEAR_BLACK = (14, 17, 22)  # #0e1116, the site background
MAX_SOURCE_PIXELS = 80_000_000  # refuse decompression bombs well above any sensible logo


class LogoError(RuntimeError):
    """The source exists but cannot be turned into site assets."""


def output_names() -> list[str]:
    return [name for name, _ in SQUARE_OUTPUTS] + [OG_NAME]


def _load_square(source: Path):
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = MAX_SOURCE_PIXELS
    try:
        with Image.open(source) as opened:
            opened.load()
            image = ImageOps.exif_transpose(opened)
    except Exception as error:  # noqa: BLE001 - PIL raises many types for bad input
        raise LogoError(f'{source} is not a readable image ({type(error).__name__}: {error})') from error
    if image.mode in ('RGBA', 'LA', 'P', 'PA'):
        rgba = image.convert('RGBA')
        flat = Image.new('RGB', rgba.size, (0, 0, 0))
        flat.paste(rgba, mask=rgba.getchannel('A'))
        image = flat
    image = image.convert('RGB')
    width, height = image.size
    side = max(width, height)
    if width != height:
        image = ImageOps.pad(image, (side, side), method=Image.Resampling.LANCZOS,
                             color=image.getpixel((0, 0)), centering=(0.5, 0.5))
    return image


def _smallest_png(image) -> bytes:
    """Lossless PNG bytes: the smallest of Pillow's optimiser and a plain level-9 and default encode."""
    best = b''
    for options in ({'optimize': True}, {'compress_level': 9}, {}):
        buffer = io.BytesIO()
        image.save(buffer, format='PNG', **options)
        if not best or buffer.tell() < len(best):
            best = buffer.getvalue()
    return best


def _save(image, path: Path):
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_bytes(_smallest_png(image))
    os.replace(temporary, path)


def generate(source: Path, out_dir: Path) -> list[Path]:
    """Write every asset into ``out_dir`` and return the paths. Raises LogoError / ImportError."""
    from PIL import Image
    square = _load_square(Path(source))
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, size in SQUARE_OUTPUTS:
        path = out_dir / name
        _save(square.resize((size, size), Image.Resampling.LANCZOS), path)
        written.append(path)
    card = Image.new('RGB', OG_SIZE, NEAR_BLACK)
    logo = square.resize((OG_LOGO_SIDE, OG_LOGO_SIDE), Image.Resampling.LANCZOS)
    card.paste(logo, ((OG_SIZE[0] - OG_LOGO_SIDE) // 2, (OG_SIZE[1] - OG_LOGO_SIDE) // 2))
    path = out_dir / OG_NAME
    _save(card, path)
    written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--source', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    if not args.source.is_file():
        print(f'WARNING: logo source not found: {args.source}\n'
              '         The site will show a text wordmark and no logo, favicon or link-preview image.\n'
              '         Put the original PNG at site/assets/source/logo-original.png and build again.',
              file=sys.stderr)
        return 0
    try:
        written = generate(args.source, args.out)
    except ImportError:
        print('ERROR: Pillow is required to make the logo assets: '
              'python -m pip install -r tools/site/requirements.txt', file=sys.stderr)
        return 1
    except LogoError as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    for path in written:
        print(f'{path.name}: {path.stat().st_size:,} bytes')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
