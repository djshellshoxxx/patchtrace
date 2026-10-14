"""Static quality gate for the built site (standard library only).

``check_dist`` is run by ``build_site.py`` (a failing page is never deployed) and by tests/test_site_*.py.
It enforces the privacy and accessibility rules of the site brief:

* every local reference (links, images, srcset, scripts, stylesheets, CSS ``url()``) resolves to a file or id
* the only external requests are navigations to the allow-listed hosts or a ``monero:`` URI; no external
  scripts, fonts, styles, images, frames or forms
* every image has alt text (empty only for explicitly decorative images), unique ids, valid ``aria-*``
  references, one ``h1`` and no skipped heading level, ``lang``, viewport, title, description, canonical
  URL and Open Graph tags
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

# (scheme, host, path-prefixes) of the only external navigations a page may contain.
ALLOWED_LINKS = (
    ('https', 'djshellshoxxx.github.io', ('/circuitdriftlabs/', '/patchtrace/')),
    ('https', 'github.com', ('/djshellshoxxx/patchtrace',)),
)
ALLOWED_SCHEMES = ('monero',)
SUBRESOURCE_RELS = {'stylesheet', 'icon', 'shortcut', 'apple-touch-icon', 'preload', 'modulepreload', 'manifest',
                    'prefetch', 'mask-icon'}
FORBIDDEN_TAGS = {'iframe', 'frame', 'object', 'embed', 'form', 'video', 'audio', 'base'}
_CSS_URL = re.compile(r'url\(\s*([\'"]?)(.*?)\1\s*\)', re.I)
_CSS_IMPORT = re.compile(r'@import\s+(?:url\()?\s*[\'"]?([^\'")\s;]+)', re.I)


def allowed_external(url: str) -> bool:
    """True for an https link inside the allow-list or a permitted non-http scheme such as ``monero:``."""
    parts = urlsplit(url)
    if parts.scheme in ALLOWED_SCHEMES:
        return True
    for scheme, host, prefixes in ALLOWED_LINKS:
        if parts.scheme == scheme and parts.hostname == host and not parts.port and not parts.username:
            path = parts.path or '/'
            # A prefix matches itself or a sub-path, never a sibling such as /patchtrace-evil.
            if any(path == prefix.rstrip('/') or path.startswith(prefix.rstrip('/') + '/') for prefix in prefixes):
                return True
    return False


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None], int]] = []  # (tag, attrs, line)
        self.title = ''
        self._in_title = False
        self.headings: list[int] = []
        self.text_stack: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs), self.getpos()[0]))
        if tag == 'title':
            self._in_title = True
        if re.fullmatch(r'h[1-6]', tag):
            self.headings.append(int(tag[1]))

    handle_startendtag = handle_starttag

    def handle_endtag(self, tag):
        if tag == 'title':
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def _srcset_urls(value: str) -> list[str]:
    return [candidate.strip().split()[0] for candidate in value.split(',') if candidate.strip()]


def _local_target(dist: Path, url: str) -> Path | None:
    """The file a local URL points at, or None if it escapes ``dist`` or does not exist."""
    path = unquote(urlsplit(url).path)
    target = (dist / path.lstrip('/')) if path else dist / 'index.html'
    if target.is_dir():
        target = target / 'index.html'
    try:
        target.resolve().relative_to(dist.resolve())
    except ValueError:
        return None
    return target if target.is_file() else None


def _check_css(dist: Path, css_path: Path, problems: list[str]):
    text = css_path.read_text(encoding='utf-8')
    for match in _CSS_IMPORT.finditer(text):
        problems.append(f'{css_path.name}: @import {match.group(1)!r} is not allowed (one stylesheet, no external CSS)')
    for match in _CSS_URL.finditer(text):
        url = match.group(2)
        if url.startswith(('data:', '#')):
            continue
        parts = urlsplit(url)
        if parts.scheme or parts.netloc:
            problems.append(f'{css_path.name}: external CSS url() {url!r}')
        elif _local_target(css_path.parent, url) is None:
            problems.append(f'{css_path.name}: url({url!r}) does not resolve')


def check_dist(dist: Path, config: dict) -> list[str]:
    """Return a list of human-readable problems (empty when the built site passes every gate)."""
    dist = Path(dist)
    problems: list[str] = []
    index = dist / 'index.html'
    if not index.is_file():
        return [f'{index} was not written']
    page = _Page()
    page.feed(index.read_text(encoding='utf-8'))
    elements = page.elements
    ids: dict[str, int] = {}
    for _tag, attrs, line in elements:
        element_id = attrs.get('id')
        if element_id:
            if element_id in ids:
                problems.append(f'duplicate id {element_id!r} (line {line})')
            ids[element_id] = line
    base = config['canonical_url']

    def check_local(kind: str, url: str, line: int):
        if not url or url.startswith('#'):
            return
        parts = urlsplit(url)
        if parts.scheme or parts.netloc:
            problems.append(f'line {line}: {kind} {url!r} is an external request')
        elif _local_target(dist, url) is None:
            problems.append(f'line {line}: {kind} {url!r} does not resolve to a file')

    for tag, attrs, line in elements:
        if tag in FORBIDDEN_TAGS:
            problems.append(f'line {line}: <{tag}> is not allowed on this site')
        if tag == 'script':
            src = attrs.get('src')
            if not src:
                if attrs.get('type') not in ('application/ld+json',):
                    problems.append(f'line {line}: inline <script> is not allowed')
            else:
                check_local('script src', src, line)
        if tag == 'img':
            src = attrs.get('src') or ''
            check_local('img src', src, line)
            if attrs.get('srcset'):
                for url in _srcset_urls(attrs['srcset']):
                    check_local('img srcset', url, line)
            alt = attrs.get('alt')
            decorative = attrs.get('role') == 'presentation' or attrs.get('aria-hidden') == 'true'
            if alt is None:
                problems.append(f'line {line}: <img src={src!r}> has no alt attribute')
            elif not alt.strip() and not decorative:
                problems.append(f'line {line}: <img src={src!r}> has empty alt text but is not marked decorative')
            for attribute in ('width', 'height'):
                if not (attrs.get(attribute) or '').isdigit():
                    problems.append(f'line {line}: <img src={src!r}> needs a numeric {attribute} (layout stability)')
        if tag == 'source' and attrs.get('srcset'):
            for url in _srcset_urls(attrs['srcset']):
                check_local('source srcset', url, line)
        if tag == 'link':
            rels = set((attrs.get('rel') or '').lower().split())
            href = attrs.get('href') or ''
            if 'canonical' in rels:
                if href != base:
                    problems.append(f'line {line}: canonical link {href!r} != configured {base!r}')
            elif rels & SUBRESOURCE_RELS:
                check_local(f'link rel={"/".join(sorted(rels))}', href, line)
            elif href:
                problems.append(f'line {line}: <link rel={sorted(rels)}> to {href!r} is not recognised')
        if tag == 'a':
            href = attrs.get('href')
            if href is None:
                problems.append(f'line {line}: <a> without href')
                continue
            if href.startswith('#'):
                if len(href) > 1 and href[1:] not in ids and href[1:] != 'top':
                    problems.append(f'line {line}: link {href!r} points at a missing id')
            elif urlsplit(href).scheme or urlsplit(href).netloc:
                if not allowed_external(href):
                    problems.append(f'line {line}: external link {href!r} is outside the allow-list')
            else:
                check_local('a href', href, line)
            if attrs.get('target') == '_blank' and 'noopener' not in (attrs.get('rel') or ''):
                problems.append(f'line {line}: target=_blank without rel=noopener')
        for attribute in ('aria-labelledby', 'aria-describedby', 'aria-controls'):
            for reference in (attrs.get(attribute) or '').split():
                if reference not in ids:
                    problems.append(f'line {line}: {attribute}={reference!r} has no matching id')
        if attrs.get('style') and 'url(' in (attrs['style'] or '').lower():
            problems.append(f'line {line}: inline style with url() is not allowed')

    # head requirements
    html_attrs = next((attrs for tag, attrs, _ in elements if tag == 'html'), {})
    if not html_attrs.get('lang'):
        problems.append('<html> needs a lang attribute')
    metas = {(attrs.get('name') or attrs.get('property') or ''): attrs.get('content') or ''
             for tag, attrs, _ in elements if tag == 'meta'}
    if not page.title.strip():
        problems.append('<title> is empty')
    if not 50 <= len(metas.get('description', '')) <= 200:
        problems.append('meta description must be 50-200 characters')
    if 'width=device-width' not in metas.get('viewport', ''):
        problems.append('meta viewport with width=device-width is missing')
    if not any(tag == 'link' and 'canonical' in (attrs.get('rel') or '') for tag, attrs, _ in elements):
        problems.append('canonical link is missing')
    for key in ('og:title', 'og:description', 'og:type', 'og:url'):
        if not metas.get(key):
            problems.append(f'meta {key} is missing')
    if metas.get('og:url') and metas['og:url'] != base:
        problems.append(f'og:url {metas["og:url"]!r} != canonical {base!r}')
    for key in ('og:image', 'twitter:image'):
        if key in metas:
            value = metas[key]
            if not value.startswith(base):
                problems.append(f'{key} {value!r} must live under {base}')
            elif _local_target(dist, value[len(base):]) is None:
                problems.append(f'{key} {value!r} does not resolve to a built file')
    if 'og:image' in metas and not metas.get('og:image:alt'):
        problems.append('og:image needs og:image:alt')

    # structure
    if page.headings.count(1) != 1:
        problems.append(f'expected exactly one <h1>, found {page.headings.count(1)}')
    previous = 0
    for level in page.headings:
        if previous and level > previous + 1:
            problems.append(f'heading level jumps from h{previous} to h{level}')
        previous = level
    present = {tag for tag, _, _ in elements}
    for landmark in ('header', 'nav', 'main', 'footer'):
        if landmark not in present:
            problems.append(f'<{landmark}> landmark is missing')
    stylesheets = [attrs for tag, attrs, _ in elements
                   if tag == 'link' and 'stylesheet' in (attrs.get('rel') or '')]
    if len(stylesheets) != 1:
        problems.append(f'expected exactly one stylesheet, found {len(stylesheets)}')
    for attrs in stylesheets:
        css = _local_target(dist, attrs.get('href') or '')
        if css is not None:
            _check_css(dist, css, problems)
    return problems
