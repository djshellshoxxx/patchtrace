"""Screenshots on the site are real, described and optimised; the renderer never fakes one."""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from site_helpers import SITE  # noqa: E402

from tools.site import render_screenshots as rs  # noqa: E402

SCREENS = SITE / 'assets' / 'screens'
MANIFEST = json.loads((SCREENS / 'screens.json').read_text(encoding='utf-8'))
SHOTS = MANIFEST['shots']


def png_size(path: Path) -> tuple[int, int]:
    header = path.read_bytes()[:24]
    assert header[:8] == b'\x89PNG\r\n\x1a\n'
    return struct.unpack('>II', header[16:24])


def test_manifest_declares_a_synthetic_real_gui_source():
    assert MANIFEST['schema'] == 'patchtrace-site-screens/1'
    assert 'ProjectService.sample' in MANIFEST['source'] and 'no Microsoft binaries' in MANIFEST['source']
    assert [s['id'] for s in SHOTS] == [s.id for s in rs.SHOTS]  # same set, same order as the renderer


@pytest.mark.parametrize('shot', SHOTS, ids=[s['id'] for s in SHOTS])
def test_each_screenshot_is_described_present_and_optimised(shot):
    png, webp = SCREENS / f'{shot["id"]}.png', SCREENS / f'{shot["id"]}.webp'
    assert re.fullmatch(r'[a-z0-9-]+', shot['id'])
    assert png_size(png) == (shot['width'], shot['height'])
    assert webp.read_bytes()[:4] == b'RIFF' and webp.read_bytes()[8:12] == b'WEBP'
    assert len(shot['alt']) >= 120 and len(shot['caption']) >= 40  # descriptive, not a filename
    assert png.stat().st_size <= 400_000 and webp.stat().st_size <= 260_000
    assert shot['png_bytes'] == png.stat().st_size and shot['webp_bytes'] == webp.stat().st_size


def test_manifest_text_matches_the_renderer_definitions():
    """Alt text lives in the renderer and in the manifest; they must not drift apart."""
    for definition, record in zip(rs.SHOTS, SHOTS, strict=True):
        assert (definition.id, definition.alt, definition.caption, definition.title) == (
            record['id'], record['alt'], record['caption'], record['title'])


def test_total_screenshot_weight_stays_small():
    total = sum(p.stat().st_size for p in SCREENS.iterdir() if p.is_file())
    assert total < 2_000_000


def test_manifest_and_alt_text_leak_no_local_paths():
    text = (SCREENS / 'screens.json').read_text(encoding='utf-8')
    for fragment in ('/tmp/', '/home/', 'C:\\', 'AppData', 'patchtrace-shots-', 'patchtrace-sample-'):
        assert fragment not in text


def test_renderer_failure_keeps_existing_assets_and_exits_non_zero(tmp_path, capsys):
    out = tmp_path / 'screens'
    out.mkdir()
    (out / 'keep.png').write_bytes(b'existing')
    assert rs.main(['--out', str(out), '--only', 'no-such-shot']) == 1
    assert 'FAILED' in capsys.readouterr().err
    assert [p.name for p in out.iterdir()] == ['keep.png'] and (out / 'keep.png').read_bytes() == b'existing'


def test_renderer_shot_definitions_are_complete():
    assert len({s.id for s in rs.SHOTS}) == len(rs.SHOTS)
    for shot in rs.SHOTS:
        assert len(shot.alt) >= 120 and shot.caption and callable(shot.prepare)


def test_renderer_draws_the_real_gui_offscreen(tmp_path):
    """The tool must keep working as the GUI evolves: render two states from the real MainWindow."""
    pytest.importorskip('PIL', reason='Pillow is a tools/site build dependency')
    pytest.importorskip('PySide6', reason='the app GUI is needed to render screenshots')
    import os
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    records = rs.render(tmp_path / 'out', only=['workspace', 'overview'])
    assert [r['id'] for r in records] == ['workspace', 'overview']
    for record in records:
        assert png_size(tmp_path / 'out' / f'{record["id"]}.png') == (record['width'], record['height'])
        assert record['width'] >= 900 and record['height'] >= 700
