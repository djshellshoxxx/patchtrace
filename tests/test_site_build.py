"""Build behaviour of tools/site/build_site.py: graceful without a logo or an address, the donation block
only for a valid address, fail-closed configuration, deterministic output, and the quality gate wiring.

Every build runs from a private copy of site/ without any logo, so results do not depend on whether the
owner has already uploaded the logo."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from site_helpers import LOGO_OUTPUTS, SITE, SYNTHETIC_ADDRESS, StubQR, copy_site, make_logo, quiet_build  # noqa: E402

from tools.site import build_site, checks, donate  # noqa: E402
from tools.site import xmr_address as xmr  # noqa: E402


@pytest.fixture
def bare_site(tmp_path):
    return copy_site(tmp_path)


def page(out: Path) -> str:
    return (out / 'index.html').read_text(encoding='utf-8')


def read_config(site: Path) -> dict:
    return json.loads((site / 'site-config.json').read_text(encoding='utf-8'))


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


# ---- without a logo and without an address -----------------------------------------------------------

def test_build_without_logo_and_address_succeeds_with_warnings(tmp_path, bare_site):
    result, logs = quiet_build(tmp_path / 'dist', site_dir=bare_site)
    html = page(tmp_path / 'dist')
    assert not result.logo and not result.donation
    assert any('logo source not found' in line for line in logs)
    assert any('donation block omitted' in line for line in logs)
    assert 'class="wordmark"' in html and 'class="logo"' not in html
    assert 'id="donate"' not in html and 'href="#donate"' not in html and 'monero:' not in html
    assert 'og:image' not in html and 'rel="apple-touch-icon"' not in html
    assert 'twitter:card" content="summary"' in html
    assert 'href="assets/cdl-mark.svg"' in html  # favicon falls back to the Circuit Drift Labs mark
    assert not (tmp_path / 'dist' / 'assets' / 'source').exists()  # the owner's original is never deployed


def test_committed_config_ships_no_address():
    assert read_config(SITE)['monero_address'] == ''  # supplied by the owner, never invented


def test_wordmark_fallback_text_comes_from_the_configured_name(tmp_path, bare_site):
    quiet_build(tmp_path / 'dist', site_dir=bare_site)
    assert 'CIRCUIT <b>DRIFT</b> LABS' in page(tmp_path / 'dist')


# ---- donation block ----------------------------------------------------------------------------------

def test_valid_synthetic_address_renders_the_donation_block(tmp_path, bare_site):
    qr = StubQR()
    result, _ = quiet_build(tmp_path / 'dist', site_dir=bare_site, qr=qr,
                            config_override={'monero_address': SYNTHETIC_ADDRESS})
    html = page(tmp_path / 'dist')
    assert result.donation
    assert f'<code class="xmr-address" id="xmr-address">{SYNTHETIC_ADDRESS}</code>' in html  # selectable text
    assert f'href="monero:{SYNTHETIC_ADDRESS}"' in html
    assert qr.payloads == [f'monero:{SYNTHETIC_ADDRESS}']  # the QR encodes the same URI
    assert 'class="qr"><svg' in html
    assert 'data-copy-target="xmr-address"' in html and ' hidden>Copy address</button>' in html
    assert 'href="#donate"' in html and 'id="donate"' in html
    note = html.split('class="donate-note"', 1)[1].split('</p>', 1)[0]
    for phrase in ('optional', 'not a purchase', 'no goods, services, support or priority',
                   'do not promise any feature'):
        assert phrase in note


def test_real_qr_is_inline_svg_built_at_build_time(tmp_path, bare_site):
    segno = pytest.importorskip('segno', reason='segno is a tools/site build dependency')
    quiet_build(tmp_path / 'dist', site_dir=bare_site, config_override={'monero_address': SYNTHETIC_ADDRESS})
    html = page(tmp_path / 'dist')
    svg = html.split('<div class="qr">', 1)[1].split('</div>', 1)[0]
    assert svg.startswith('<svg role="img"') and '<title>QR code' in svg and '<image' not in svg
    side = segno.make('monero:' + SYNTHETIC_ADDRESS, error='m').symbol_size(border=4)[0]
    assert f'viewBox="0 0 {side} {side}"' in svg


@pytest.mark.parametrize('bad', [
    SYNTHETIC_ADDRESS[:-1] + ('2' if SYNTHETIC_ADDRESS[-1] != '2' else '3'),
    SYNTHETIC_ADDRESS[:-1],
    'monero:' + SYNTHETIC_ADDRESS,
    xmr.encode_address('standard', 'testnet', bytes(range(32)), bytes(range(32, 64))),
    'not-an-address',
], ids=['typo', 'short', 'uri', 'testnet', 'junk'])
def test_invalid_address_fails_the_build(tmp_path, bare_site, bad):
    with pytest.raises(build_site.BuildError, match='monero_address'):
        quiet_build(tmp_path / 'dist', site_dir=bare_site, qr=StubQR(), config_override={'monero_address': bad})


def test_invalid_address_exits_with_code_2_and_writes_no_page(tmp_path, bare_site, capsys):
    config = read_config(bare_site)
    config['monero_address'] = SYNTHETIC_ADDRESS[:-3] + 'abc'
    (bare_site / 'site-config.json').write_text(json.dumps(config), encoding='utf-8')
    assert build_site.main(['--site', str(bare_site), '--out', str(tmp_path / 'dist')]) == 2
    assert 'monero_address' in capsys.readouterr().err
    assert not (tmp_path / 'dist' / 'index.html').exists()


def test_missing_segno_is_a_clear_build_error(tmp_path, bare_site, monkeypatch):
    monkeypatch.setitem(sys.modules, 'segno', None)  # import segno -> ImportError
    with pytest.raises(build_site.BuildError, match='segno'):
        quiet_build(tmp_path / 'dist', site_dir=bare_site, config_override={'monero_address': SYNTHETIC_ADDRESS})


def test_donation_block_is_empty_without_an_address():
    assert donate.render_donation_block('', number='07') == ''
    assert donate.render_donation_block(None, number='07') == ''


# ---- configuration is fail-closed --------------------------------------------------------------------

@pytest.mark.parametrize(('override', 'message'), [
    ({'surprise': 'x'}, 'unknown key'),
    ({'site_title': '  '}, 'site_title'),
    ({'repo_url': 'http://github.com/djshellshoxxx/patchtrace'}, 'repo_url'),
    ({'cdl_url': 'https://example.org/'}, 'cdl_url'),
    ({'canonical_url': 'https://djshellshoxxx.github.io/patchtrace'}, 'canonical_url'),
    ({'monero_address': 12}, 'monero_address'),
], ids=['unknown', 'blank', 'http', 'host', 'slash', 'type'])
def test_bad_configuration_is_rejected(tmp_path, bare_site, override, message):
    with pytest.raises(build_site.BuildError, match=message):
        quiet_build(tmp_path / 'dist', site_dir=bare_site, config_override=override)


@pytest.mark.parametrize(('edit', 'message'), [
    (lambda c: c['features'][0].update(status='great'), 'unknown status'),
    (lambda c: c['works_today'].append(dict(c['works_today'][0])), 'duplicate id'),
    (lambda c: c['works_today'][0].pop('evidence'), 'lacks'),
    (lambda c: c.update(roadmap=[]), 'non-empty'),
], ids=['status', 'dupe', 'lacks', 'empty'])
def test_bad_content_is_rejected(tmp_path, bare_site, edit, message):
    content = json.loads((bare_site / 'content.json').read_text(encoding='utf-8'))
    edit(content)
    (bare_site / 'content.json').write_text(json.dumps(content), encoding='utf-8')
    with pytest.raises(build_site.BuildError, match=message):
        quiet_build(tmp_path / 'dist', site_dir=bare_site)


def test_unresolved_template_placeholder_is_an_error():
    with pytest.raises(build_site.BuildError, match='no value'):
        build_site.fill('hello {{nope}}', {})


def test_refuses_to_delete_an_unrelated_directory(tmp_path, bare_site):
    victim = tmp_path / 'documents'
    victim.mkdir()
    (victim / 'thesis.txt').write_text('keep me', encoding='utf-8')
    with pytest.raises(build_site.BuildError, match='refusing'):
        quiet_build(victim, site_dir=bare_site)
    assert (victim / 'thesis.txt').read_text(encoding='utf-8') == 'keep me'


def test_rebuilding_over_a_previous_build_is_allowed(tmp_path, bare_site):
    out = tmp_path / 'dist'
    quiet_build(out, site_dir=bare_site)
    (out / 'stale.txt').write_text('old', encoding='utf-8')
    quiet_build(out, site_dir=bare_site)
    assert not (out / 'stale.txt').exists()


def test_build_is_deterministic(tmp_path, bare_site):
    first, second = tmp_path / 'a', tmp_path / 'b'
    for out in (first, second):
        quiet_build(out, site_dir=bare_site, qr=StubQR(), config_override={'monero_address': SYNTHETIC_ADDRESS})
    assert tree_digest(first) == tree_digest(second)


# ---- screenshots -------------------------------------------------------------------------------------

def test_missing_screenshot_manifest_omits_the_section(tmp_path, bare_site):
    (bare_site / 'assets' / 'screens' / 'screens.json').unlink()
    result, logs = quiet_build(tmp_path / 'dist', site_dir=bare_site)
    html = page(tmp_path / 'dist')
    assert result.screens == 0 and any('no screenshots' in line for line in logs)
    assert 'id="screens"' not in html and 'href="#screens"' not in html
    assert 'assets/screens' not in html  # nothing dangling


def test_screenshot_without_alt_or_file_is_skipped_never_published_broken(tmp_path, bare_site):
    manifest_path = bare_site / 'assets' / 'screens' / 'screens.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    manifest['shots'][0]['alt'] = ''
    (bare_site / 'assets' / 'screens' / f'{manifest["shots"][1]["id"]}.png').unlink()
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    result, logs = quiet_build(tmp_path / 'dist', site_dir=bare_site)
    assert result.screens == len(manifest['shots']) - 2
    assert sum('skipped' in line for line in logs) == 2
    assert checks.check_dist(tmp_path / 'dist', read_config(bare_site)) == []


# ---- logo pipeline inside the build ------------------------------------------------------------------

def test_logo_assets_are_generated_during_the_build(tmp_path, bare_site):
    pytest.importorskip('PIL', reason='Pillow is a tools/site build dependency')
    make_logo(bare_site / 'assets' / 'source' / 'logo-original.png')
    result, logs = quiet_build(tmp_path / 'dist', site_dir=bare_site)
    html = page(tmp_path / 'dist')
    assert result.logo and not any('logo source not found' in line for line in logs)
    for name in LOGO_OUTPUTS:
        assert (tmp_path / 'dist' / 'assets' / name).is_file()
    assert 'class="logo"' in html and 'class="wordmark"' not in html
    assert 'rel="icon" type="image/png"' in html and 'rel="apple-touch-icon"' in html
    assert 'og:image" content="https://djshellshoxxx.github.io/patchtrace/assets/og-image.png"' in html
    assert 'twitter:card" content="summary_large_image"' in html
    assert not (tmp_path / 'dist' / 'assets' / 'source').exists()


def test_unreadable_logo_fails_loudly(tmp_path, bare_site):
    pytest.importorskip('PIL', reason='Pillow is a tools/site build dependency')
    (bare_site / 'assets' / 'source' / 'logo-original.png').write_bytes(b'this is not a png')
    with pytest.raises(build_site.BuildError, match='not a readable image'):
        quiet_build(tmp_path / 'dist', site_dir=bare_site)


# ---- the quality gate stops a bad page ---------------------------------------------------------------

def test_gate_failure_exits_with_code_3(tmp_path, bare_site, monkeypatch, capsys):
    monkeypatch.setattr(checks, 'check_dist', lambda dist, config: ['synthetic problem'])
    assert build_site.main(['--site', str(bare_site), '--out', str(tmp_path / 'dist')]) == 3
    assert 'synthetic problem' in capsys.readouterr().err
