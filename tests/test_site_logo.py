"""tools/site/make_logo_assets.py: sizes, LANCZOS, optimisation, square padding, and graceful absence."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from site_helpers import LOGO_OUTPUTS, make_logo  # noqa: E402

from tools.site import make_logo_assets as logo  # noqa: E402

SIZES = {'logo-512.png': (512, 512), 'logo-192.png': (192, 192), 'favicon-64.png': (64, 64),
         'apple-touch-icon-180.png': (180, 180), 'og-image.png': (1200, 630)}


@pytest.fixture
def pillow():
    return pytest.importorskip('PIL', reason='Pillow is a tools/site build dependency')


def png_size(path: Path) -> tuple[int, int]:
    header = path.read_bytes()[:24]
    assert header[:8] == b'\x89PNG\r\n\x1a\n'
    return struct.unpack('>II', header[16:24])


def test_absent_source_warns_and_succeeds_without_importing_pillow(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, 'PIL', None)  # any import of Pillow would fail: it must not be needed
    assert logo.main(['--source', str(tmp_path / 'logo-original.png'), '--out', str(tmp_path / 'out')]) == 0
    err = capsys.readouterr().err
    assert 'WARNING' in err and 'text wordmark' in err and 'logo-original.png' in err
    assert not (tmp_path / 'out').exists()


def test_declared_outputs_match_the_brief():
    assert logo.output_names() == list(LOGO_OUTPUTS)
    assert logo.OG_SIZE == (1200, 630) and logo.NEAR_BLACK == (14, 17, 22)


def test_generates_every_asset_at_the_exact_size(tmp_path, pillow):
    source = make_logo(tmp_path / 'logo-original.png', (900, 900))
    out = tmp_path / 'out'
    assert logo.main(['--source', str(source), '--out', str(out)]) == 0
    assert sorted(p.name for p in out.iterdir()) == sorted(SIZES)  # nothing else, no temporary leftovers
    for name, size in SIZES.items():
        assert png_size(out / name) == size, name


def test_og_card_centres_the_logo_on_near_black(tmp_path, pillow):
    from PIL import Image
    source = make_logo(tmp_path / 'logo-original.png', (700, 700))
    logo.generate(source, tmp_path / 'out')
    card = Image.open(tmp_path / 'out' / 'og-image.png').convert('RGB')
    assert card.getpixel((5, 5)) == (14, 17, 22) and card.getpixel((1195, 625)) == (14, 17, 22)
    assert card.getpixel((600, 5)) == (14, 17, 22)  # above the 560 px logo
    assert card.getpixel((330, 315)) == (0, 0, 0)  # inside the (black) logo square, left of the ring


def test_lanczos_is_used_for_every_resize(tmp_path, monkeypatch, pillow):
    from PIL import Image
    seen = []
    original = Image.Image.resize

    def spy(self, size, resample=None, *args, **kwargs):
        seen.append(resample)
        return original(self, size, resample, *args, **kwargs)

    monkeypatch.setattr(Image.Image, 'resize', spy)
    logo.generate(make_logo(tmp_path / 'logo-original.png'), tmp_path / 'out')
    assert len(seen) >= 5 and set(seen) == {Image.Resampling.LANCZOS}


def test_outputs_are_optimised_png(tmp_path, pillow):
    from PIL import Image
    source = make_logo(tmp_path / 'logo-original.png', (1024, 1024))
    logo.generate(source, tmp_path / 'out')
    image = Image.open(tmp_path / 'out' / 'logo-512.png')
    plain = tmp_path / 'plain.png'
    image.save(plain, format='PNG', optimize=False)
    assert (tmp_path / 'out' / 'logo-512.png').stat().st_size <= plain.stat().st_size


def test_non_square_source_is_padded_not_cropped_or_stretched(tmp_path, pillow):
    from PIL import Image
    source = tmp_path / 'wide.png'
    Image.new('RGB', (800, 400), (10, 20, 30)).save(source)
    logo.generate(source, tmp_path / 'out')
    padded = Image.open(tmp_path / 'out' / 'logo-512.png').convert('RGB')
    assert padded.size == (512, 512) and padded.getpixel((0, 0)) == (10, 20, 30)
    assert padded.getpixel((256, 256)) == (10, 20, 30)


def test_transparent_source_is_flattened_onto_black(tmp_path, pillow):
    from PIL import Image
    source = make_logo(tmp_path / 'alpha.png', (400, 400), mode='RGBA')
    logo.generate(source, tmp_path / 'out')
    assert Image.open(tmp_path / 'out' / 'logo-192.png').mode == 'RGB'
    assert Image.open(tmp_path / 'out' / 'logo-192.png').getpixel((1, 1)) == (0, 0, 0)


def test_unreadable_source_is_an_error_not_a_silent_fallback(tmp_path, capsys, pillow):
    bad = tmp_path / 'logo-original.png'
    bad.write_bytes(b'GIF89a not really')
    assert logo.main(['--source', str(bad), '--out', str(tmp_path / 'out')]) == 1
    assert 'not a readable image' in capsys.readouterr().err


def test_missing_pillow_with_a_source_present_is_an_error(tmp_path, capsys, monkeypatch):
    source = tmp_path / 'logo-original.png'
    source.write_bytes(b'x')
    monkeypatch.setitem(sys.modules, 'PIL', None)
    assert logo.main(['--source', str(source), '--out', str(tmp_path / 'out')]) == 1
    assert 'Pillow is required' in capsys.readouterr().err
