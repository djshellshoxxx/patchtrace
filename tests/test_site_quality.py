"""Quality of the built site: local links resolve, every image has alt text, no external requests except the
allow-list, semantic structure, responsive/motion/focus rules, AA contrast of the colour tokens, and that
the static checker itself rejects broken pages."""
from __future__ import annotations

import json
import re
import shutil
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from site_helpers import SITE, SYNTHETIC_ADDRESS, StubQR, copy_site, make_logo, quiet_build  # noqa: E402

from tools.site import checks  # noqa: E402

BASE = 'https://djshellshoxxx.github.io/patchtrace/'
CDL = 'https://djshellshoxxx.github.io/circuitdriftlabs/'
REPO = 'https://github.com/djshellshoxxx/patchtrace'
# Every absolute URL the page may mention at all (links, canonical and Open Graph metadata).
ALLOWED_URL_PREFIXES = (BASE, CDL, REPO)


@pytest.fixture(scope='module', params=['plain', 'full'], ids=['plain', 'full'])
def built(request, tmp_path_factory):
    """(dist, config) for a build without logo/address and one with a donation block (and a logo when
    Pillow is available)."""
    root = tmp_path_factory.mktemp(f'site-{request.param}')
    site = copy_site(root)
    kwargs = {}
    if request.param == 'full':
        kwargs.update(qr=StubQR(), config_override={'monero_address': SYNTHETIC_ADDRESS})
        try:
            make_logo(site / 'assets' / 'source' / 'logo-original.png')
        except ImportError:
            pass  # without Pillow the full variant simply has no logo
    quiet_build(root / 'dist', site_dir=site, **kwargs)
    config = json.loads((site / 'site-config.json').read_text(encoding='utf-8'))
    config.update(kwargs.get('config_override', {}))
    return root / 'dist', config


class Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    handle_startendtag = handle_starttag


def parse(dist: Path) -> Collector:
    collector = Collector()
    collector.feed((dist / 'index.html').read_text(encoding='utf-8'))
    return collector


def srcset_urls(value):
    return [part.strip().split()[0] for part in value.split(',') if part.strip()]


# ---- the checker passes the real page ----------------------------------------------------------------

def test_built_pages_pass_the_static_quality_gate(built):
    dist, config = built
    assert checks.check_dist(dist, config) == []


# ---- links, images, requests -------------------------------------------------------------------------

def test_every_local_link_and_resource_resolves(built):
    dist, _ = built
    page = parse(dist)
    ids = {attrs['id'] for _, attrs in page.tags if attrs.get('id')}
    checked = 0
    for tag, attrs in page.tags:
        values = []
        for attribute in ('href', 'src'):
            if attrs.get(attribute) is not None:
                values.append(attrs[attribute])
        if attrs.get('srcset'):
            values += srcset_urls(attrs['srcset'])
        for value in values:
            parts = urlsplit(value)
            if parts.scheme or parts.netloc:
                continue
            checked += 1
            if value.startswith('#'):
                assert value[1:] in ids, f'<{tag}> {value} points at a missing id'
            else:
                assert (dist / unquote(parts.path)).is_file(), f'<{tag}> {value} does not exist in the build'
    assert checked > 20  # the page really has local references to check


def test_every_image_has_alt_text(built):
    dist, _ = built
    images = [attrs for tag, attrs in parse(dist).tags if tag == 'img']
    assert images, 'the page should contain images (screenshots at least)'
    for attrs in images:
        decorative = attrs.get('aria-hidden') == 'true'
        if decorative:
            assert attrs.get('alt') == ''  # the brand mark: explicitly decorative
        else:
            assert len(attrs.get('alt', '').strip()) >= 40, f'weak or missing alt on {attrs.get("src")}'
        assert attrs.get('width', '').isdigit() and attrs.get('height', '').isdigit()


def test_no_external_requests_except_the_allow_list(built):
    dist, _ = built
    html = (dist / 'index.html').read_text(encoding='utf-8')
    for url in set(re.findall(r'https?://[^\s"\'<>)]+', html)):
        assert url.startswith(ALLOWED_URL_PREFIXES), f'unexpected absolute URL {url}'
    # Subresources (everything the browser fetches automatically) must be relative: zero third parties.
    for tag, attrs in parse(dist).tags:
        if tag in ('img', 'script', 'source') or (tag == 'link' and attrs.get('rel') != 'canonical'):
            for value in [attrs.get('src'), attrs.get('href'), *srcset_urls(attrs.get('srcset') or '')]:
                if value:
                    assert not urlsplit(value).scheme and not urlsplit(value).netloc, f'<{tag}> loads {value}'
    # The only schemes in links: https allow-list, #fragments, relative files and monero:
    for tag, attrs in parse(dist).tags:
        if tag == 'a':
            scheme = urlsplit(attrs['href']).scheme
            assert scheme in ('', 'https', 'monero'), attrs['href']
            if scheme == 'https':
                assert checks.allowed_external(attrs['href']), attrs['href']


def test_stylesheet_and_script_are_self_contained(built):
    dist, _ = built
    css = (dist / 'styles.css').read_text(encoding='utf-8')
    assert '@import' not in css and '@font-face' not in css
    assert not re.search(r'url\(\s*[\'"]?(https?:)?//', css)
    script = (dist / 'site.js').read_text(encoding='utf-8')
    # Negative assertions only: these are patterns the script must NOT contain; nothing here is executed.
    for banned in ('fetch(', 'XMLHttpRequest', 'sendBeacon', 'localStorage', 'sessionStorage', 'document.cookie',
                   'eval(', 'import(', 'new Image', 'WebSocket'):
        assert banned not in script, banned
    tags = parse(dist).tags
    assert [attrs['src'] for tag, attrs in tags if tag == 'script'] == ['site.js']
    assert sum(1 for tag, attrs in tags if tag == 'link' and attrs.get('rel') == 'stylesheet') == 1
    assert not {tag for tag, _ in tags} & {'iframe', 'form', 'object', 'embed', 'video', 'audio'}


# ---- structure and metadata --------------------------------------------------------------------------

def test_semantic_structure_and_head_metadata(built):
    dist, config = built
    page = parse(dist)
    tags = [tag for tag, _ in page.tags]
    for landmark in ('header', 'nav', 'main', 'footer', 'section', 'article', 'figure'):
        assert landmark in tags
    assert tags.count('h1') == 1
    html_attrs = next(attrs for tag, attrs in page.tags if tag == 'html')
    assert html_attrs['lang'] == 'en'
    metas = {(a.get('name') or a.get('property')): a.get('content') for t, a in page.tags if t == 'meta'}
    assert metas['viewport'] == 'width=device-width, initial-scale=1'
    assert 50 <= len(metas['description']) <= 200
    for key in ('og:title', 'og:description', 'og:type', 'og:url', 'og:site_name', 'twitter:card'):
        assert metas[key]
    canonical = next(a['href'] for t, a in page.tags if t == 'link' and a.get('rel') == 'canonical')
    assert canonical == BASE == config['canonical_url'] == metas['og:url']
    html = (dist / 'index.html').read_text(encoding='utf-8')
    assert re.search(r'<title>[^<]{10,}</title>', html)
    first_link = next(attrs for tag, attrs in page.tags if tag == 'a')
    assert first_link['class'] == 'skip-link' and first_link['href'] == '#main'  # first focusable element
    assert (dist / 'robots.txt').read_text(encoding='utf-8').count(f'Sitemap: {BASE}sitemap.xml') == 1
    assert f'<loc>{BASE}</loc>' in (dist / 'sitemap.xml').read_text(encoding='utf-8')


def test_open_graph_image_matches_logo_availability(built):
    dist, _ = built
    tags = parse(dist).tags
    metas = {(a.get('name') or a.get('property')): a.get('content') for t, a in tags if t == 'meta'}
    has_logo = (dist / 'assets' / 'og-image.png').is_file()
    assert ('og:image' in metas) == has_logo
    if has_logo:
        assert metas['og:image'] == f'{BASE}assets/og-image.png' and metas['og:image:alt']
    else:
        assert metas['twitter:card'] == 'summary'


def test_required_content_is_present(built):
    dist, config = built
    html = (dist / 'index.html').read_text(encoding='utf-8')
    links = {attrs['href'] for tag, attrs in parse(dist).tags if tag == 'a' and 'href' in attrs}
    assert {config['repo_url'], config['releases_url'], config['cdl_url'], config['license_url']} <= links
    for phrase in ('Alpha', 'Vibe coded', 'vibe coded', 'ordinal', 'uncalibrated', 'never runs',
                   'Design preview', 'Program E', 'Prereleases only', 'Working', 'In progress', 'Planned',
                   'Find what a patch really changed: compare the unpatched and patched binary, and the patch '
                   'itself, offline.'):
        assert phrase in html, phrase


def test_previews_are_labelled_and_never_use_screenshots(built):
    dist, _ = built
    html = (dist / 'index.html').read_text(encoding='utf-8')
    section = html.split('id="preview"', 1)[1].split('id="features"', 1)[0]
    assert section.count('Design preview · not implemented') == 10
    assert '<img' not in section and 'Illustrations, not screenshots' in section


def test_no_overclaiming_phrases(built):
    dist, _ = built
    text = re.sub(r'<[^>]+>', ' ', (dist / 'index.html').read_text(encoding='utf-8')).lower()
    for phrase in ('production ready', 'production-ready', 'guaranteed', 'zero false', 'ai-powered',
                   'enterprise-grade', 'military-grade', 'automatically finds vulnerabilities'):
        assert phrase not in text, phrase


# ---- stylesheet rules: responsive, motion, focus, theme ----------------------------------------------

def tokens(css: str) -> dict[str, str]:
    root = re.search(r':root\s*\{(.*?)\}', css, re.S).group(1)
    return dict(re.findall(r'(--[\w-]+)\s*:\s*([^;]+);', root))


def test_stylesheet_has_responsive_focus_motion_and_dark_theme_rules():
    css = (SITE / 'styles.css').read_text(encoding='utf-8')
    assert 'color-scheme: dark' in css
    assert re.search(r'@media \(max-width: 480px\)', css) and re.search(r'@media \(max-width: 760px\)', css)
    focus = re.search(r':focus-visible\s*\{([^}]*)\}', css)
    assert focus and 'outline: 2px solid' in focus.group(1) and 'outline-offset' in focus.group(1)
    reduced = re.search(r'@media \(prefers-reduced-motion: reduce\)\s*\{(.*)\}\s*$', css, re.S).group(1)
    assert 'animation: none' in reduced and 'transition: none' in reduced and 'scroll-behavior: auto' in reduced
    for forbidden in ('outline: none', 'outline: 0'):  # focus is never removed (only main's programmatic focus)
        assert css.count(forbidden) <= 1


def luminance(hex_color: str) -> float:
    value = hex_color.lstrip('#')
    channels = [int(value[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(foreground: str, background: str) -> float:
    lighter, darker = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


PAIRS = [  # (foreground token, background colour or token, minimum ratio): WCAG AA
    ('--text', '--base', 4.5), ('--text', '--surface', 4.5), ('--text', '--tint', 4.5),
    ('--body', '--base', 4.5), ('--body', '--surface', 4.5), ('--body', '--tint', 4.5),
    ('--muted', '--base', 4.5), ('--muted', '--surface', 4.5), ('--muted', '--tint', 4.5), ('--muted', '#0b0e12', 4.5), ('--muted', '#131820', 4.5),
    ('--teal', '--base', 4.5), ('--teal', '--surface', 4.5), ('--teal', '--tint', 4.5),
    ('--orange-soft', '--base', 4.5), ('--orange-soft', '--surface', 4.5), ('--orange', '--base', 4.5),
    ('--ok', '--surface', 4.5), ('--ok', '--base', 4.5), ('--warn', '--surface', 4.5), ('--warn', '--base', 4.5),
    ('--ice', '--base', 4.5), ('--neon', '--base', 4.5), ('--neon', '--surface', 4.5), ('--ice', '#131820', 4.5),
    ('--base', '--orange', 4.5),  # button label on the orange fill
    ('--base', '--teal', 4.5),
    ('--teal', '--base', 3.0),  # focus ring and UI component boundaries (WCAG 1.4.11)
]


@pytest.mark.parametrize(('foreground', 'background', 'minimum'), PAIRS, ids=[f'{i}' for i in range(len(PAIRS))])
def test_text_colour_pairs_meet_wcag_aa(foreground, background, minimum):
    palette = tokens((SITE / 'styles.css').read_text(encoding='utf-8'))
    resolve = lambda name: palette[name] if name.startswith('--') else name  # noqa: E731
    ratio = contrast(resolve(foreground), resolve(background))
    assert ratio >= minimum, f'{foreground} on {background}: {ratio:.2f} < {minimum}'


# ---- the checker really rejects broken pages ---------------------------------------------------------
# The strings below are deliberately bad page fragments (external script/font/form) used as negative test
# inputs for checks.check_dist; none of them is ever loaded or executed.

@pytest.mark.parametrize(('old', 'new', 'message'), [
    ('alt="', 'data-x="', 'no alt attribute'),
    ('<script src="site.js" defer></script>', '<script src="https://cdn.example/x.js"></script>', 'external request'),
    ('<link rel="stylesheet" href="styles.css">', '<link rel="stylesheet" href="https://fonts.example/f.css">',
     'external request'),
    ('href="#status"', 'href="#nowhere"', 'missing id'),
    ('src="assets/cdl-mark.svg"', 'src="assets/missing.svg"', 'does not resolve'),
    ('<a class="button button-primary" href="https://github.com/djshellshoxxx/patchtrace"',
     '<a class="button button-primary" href="https://evil.example/x"', 'outside the allow-list'),
    ('<link rel="canonical" href="https://djshellshoxxx.github.io/patchtrace/">', '', 'canonical link is missing'),
    ('<h1 id="hero-title">', '<h1 id="status">', 'duplicate id'),
    ('<html lang="en">', '<html>', 'lang'),
    ('<main id="main" tabindex="-1">', '<form action="https://x.example"><main id="main" tabindex="-1">', 'not allowed'),
], ids=['alt', 'script', 'font', 'frag', 'dead', 'host', 'canon', 'dupe', 'lang', 'form'])
def test_checker_rejects_broken_pages(built, tmp_path, old, new, message):
    dist, config = built
    broken = tmp_path / 'dist'
    shutil.copytree(dist, broken)
    html = (broken / 'index.html').read_text(encoding='utf-8')
    assert old in html, f'fixture text {old!r} not found; update the test with the template'
    (broken / 'index.html').write_text(html.replace(old, new, 1), encoding='utf-8')
    problems = checks.check_dist(broken, config)
    assert any(message in problem for problem in problems), problems


def test_checker_rejects_css_with_external_requests(built, tmp_path):
    dist, config = built
    broken = tmp_path / 'dist'
    shutil.copytree(dist, broken)
    css = (broken / 'styles.css').read_text(encoding='utf-8')
    (broken / 'styles.css').write_text('@import url("https://fonts.example/x.css");\nbody{background:url(https://t.example/p.png)}\n' + css,
                                       encoding='utf-8')
    problems = checks.check_dist(broken, config)
    assert any('@import' in p for p in problems) and any('external CSS url()' in p for p in problems)


def test_allow_list_rules():
    ok = [CDL, REPO, REPO + '/releases', REPO + '/blob/main/LICENSE', 'monero:4' + 'A' * 94,
          'https://djshellshoxxx.github.io/patchtrace/']
    bad = ['http://github.com/djshellshoxxx/patchtrace', 'https://github.com/djshellshoxxx/other',
           'https://github.com/djshellshoxxx/patchtrace-evil', 'https://djshellshoxxx.github.io/trackstats/',
           'https://github.com.evil.example/djshellshoxxx/patchtrace', 'https://user@github.com/djshellshoxxx/patchtrace',
           'javascript:alert(1)', 'mailto:a@b.example', 'data:text/html,hi']
    assert all(checks.allowed_external(url) for url in ok)
    assert not any(checks.allowed_external(url) for url in bad)
