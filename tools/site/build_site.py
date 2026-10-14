#!/usr/bin/env python3
"""Build the PatchTrace GitHub Pages site into ``site/dist`` (the tree the Pages workflow deploys).

    python tools/site/build_site.py [--out DIR] [--write-claims] [--check-only]

Inputs live in ``site/``: ``site-config.json`` (title, URLs, optional ``monero_address``), ``content.json``
(claims, features, roadmap), ``index.template.html`` + ``partials/``, ``styles.css``, ``site.js`` and
``assets/`` (``assets/screens`` from render_screenshots.py, ``assets/source/logo-original.png`` supplied by
the owner). Nothing is fetched and the output makes no external requests.

* No logo source: a clear warning is printed and the hero shows a text wordmark (the build succeeds).
* Empty ``monero_address``: the donation block is simply not rendered. A non-empty address must be a valid
  mainnet Monero address or the build fails (exit 2).
* Every built page must pass ``checks.check_dist`` (links, alt text, privacy allow-list, structure) or the
  build fails (exit 3), so a broken page is never deployed.

Exit codes: 0 success, 2 configuration or input error, 3 the built page failed its quality gate.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.site import checks, donate, make_logo_assets, xmr_address  # noqa: E402

SITE = ROOT / 'site'
DEFAULT_OUT = SITE / 'dist'
CLAIMS_MD = ROOT / 'tests' / 'site_claims.md'
STATUSES = {'working': ('Working', '&check;', 'tag-working'),
            'in-progress': ('In progress', '&#9680;', 'tag-progress'),
            'planned': ('Planned', '&#9675;', 'tag-planned')}
REQUIRED_CONFIG = ('site_title', 'page_title', 'description', 'canonical_url', 'repo_url', 'releases_url',
                   'license_url', 'cdl_name', 'cdl_url', 'copyright_year')
OPTIONAL_CONFIG = {'monero_address': '', 'logo_alt': (
    'Circuit Drift Labs logo: a glowing glass distillation apparatus with a tilted metallic orbit ring and '
    'drifting smoke above the cracked-chrome words CIRCUIT DRIFT LABS, in ice-blue and red neon on black.')}
URL_KEYS = ('canonical_url', 'repo_url', 'releases_url', 'license_url', 'cdl_url')
TOKEN = re.compile(r'\{\{\s*([a-z_]+)\s*\}\}')
SCREENS_DIR = 'assets/screens'


class BuildError(RuntimeError):
    """A configuration/input problem (exit 2) or a failed quality gate (exit 3, ``gate=True``)."""

    def __init__(self, message: str, *, gate: bool = False):
        super().__init__(message)
        self.gate = gate


@dataclass
class BuildResult:
    out_dir: Path
    warnings: list[str] = field(default_factory=list)
    donation: bool = False
    logo: bool = False
    screens: int = 0


def esc(text: str) -> str:
    return html.escape(text, quote=True)


# ---- inputs -----------------------------------------------------------------------------------------

def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise BuildError(f'{path}: cannot read as JSON ({error})') from error
    if not isinstance(data, dict):
        raise BuildError(f'{path}: top level must be a JSON object')
    return data


def load_config(path: Path, override: dict | None = None) -> dict:
    config = {**OPTIONAL_CONFIG, **read_json(path), **(override or {})}
    unknown = sorted(set(config) - set(REQUIRED_CONFIG) - set(OPTIONAL_CONFIG))
    if unknown:
        raise BuildError(f'site-config.json: unknown key(s) {unknown}')
    for key in (*REQUIRED_CONFIG, 'logo_alt'):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise BuildError(f'site-config.json: {key!r} must be a non-empty string')
    for key in URL_KEYS:
        if not config[key].startswith('https://') or not checks.allowed_external(config[key]):
            raise BuildError(f'site-config.json: {key} {config[key]!r} must be an https URL on the allow-list '
                             '(djshellshoxxx.github.io/circuitdriftlabs, djshellshoxxx.github.io/patchtrace '
                             'or github.com/djshellshoxxx/patchtrace)')
    if not config['canonical_url'].endswith('/'):
        raise BuildError('site-config.json: canonical_url must end with "/"')
    address = config['monero_address']
    if not isinstance(address, str):
        raise BuildError('site-config.json: monero_address must be a string')
    config['monero_address'] = address.strip()
    if config['monero_address']:
        try:
            xmr_address.decode_address(config['monero_address'])
        except xmr_address.AddressError as error:
            raise BuildError(f'site-config.json: monero_address is not a valid Monero mainnet address: {error}') from error
    return config


def load_content(path: Path) -> dict:
    content = read_json(path)
    seen: set[str] = set()
    for section, required in (('works_today', ('id', 'title', 'text', 'evidence')),
                              ('features', ('id', 'name', 'role', 'status', 'note', 'evidence')),
                              ('roadmap', ('phase', 'title', 'text')),
                              ('previews', ('id', 'title', 'basis'))):
        items = content.get(section)
        if not isinstance(items, list) or not items:
            raise BuildError(f'content.json: {section!r} must be a non-empty list')
        for item in items:
            missing = [key for key in required if key not in item]
            if missing:
                raise BuildError(f'content.json: {section} entry {item.get("id", item)!r} lacks {missing}')
            if 'id' in item:
                key = f'{section}:{item["id"]}'
                if key in seen:
                    raise BuildError(f'content.json: duplicate id {key}')
                seen.add(key)
            if section == 'features' and item['status'] not in STATUSES:
                raise BuildError(f'content.json: feature {item["id"]!r} has unknown status {item["status"]!r}')
    if not isinstance(content.get('not_verified'), list):
        raise BuildError("content.json: 'not_verified' must be a list")
    return content


def load_screens(site_dir: Path, warnings: list[str]) -> list[dict]:
    """Shots from assets/screens/screens.json whose PNG and WebP files exist (never a missing image)."""
    manifest = site_dir / 'assets' / 'screens' / 'screens.json'
    if not manifest.is_file():
        warnings.append('no screenshots: site/assets/screens/screens.json is absent '
                        '(run tools/site/render_screenshots.py); the screenshots section is omitted')
        return []
    shots = []
    for shot in read_json(manifest).get('shots', []):
        name = shot.get('id', '')
        files = [site_dir / 'assets' / 'screens' / f'{name}.{ext}' for ext in ('png', 'webp')]
        if not re.fullmatch(r'[a-z0-9-]+', name) or not all(f.is_file() for f in files):
            warnings.append(f'screenshot {name!r} skipped: its files are missing')
        elif not str(shot.get('alt', '')).strip():
            warnings.append(f'screenshot {name!r} skipped: it has no alt text')
        else:
            shots.append(shot)
    return shots


# ---- rendering --------------------------------------------------------------------------------------

def fill(template: str, values: dict[str, str]) -> str:
    def replace(match: re.Match) -> str:
        key = match.group(1)
        if key not in values:
            raise BuildError(f'template placeholder {{{{{key}}}}} has no value')
        return values[key]
    return TOKEN.sub(replace, template)


def wordmark_html(name: str) -> str:
    words = name.upper().split()
    parts = [f'<b>{esc(w)}</b>' if i == 1 else esc(w) for i, w in enumerate(words)]
    return f'<p class="wordmark" translate="no">{" ".join(parts)}</p>'


def render_hero_art(config: dict, logo: bool) -> str:
    if not logo:
        return '          ' + wordmark_html(config['cdl_name'])
    return ('          <img class="logo" src="assets/logo-512.png" '
            'srcset="assets/logo-192.png 192w, assets/logo-512.png 512w" '
            'sizes="(max-width: 760px) 70vw, 380px" width="512" height="512" '
            f'alt="{esc(config["logo_alt"])}" decoding="async" fetchpriority="high">')


def render_head_extra(config: dict, logo: bool) -> str:
    base = config['canonical_url']
    lines = []
    if logo:
        lines += ['  <link rel="icon" type="image/png" sizes="64x64" href="assets/favicon-64.png">',
                  '  <link rel="apple-touch-icon" sizes="180x180" href="assets/apple-touch-icon-180.png">']
    else:
        lines.append('  <link rel="icon" type="image/svg+xml" href="assets/cdl-mark.svg">')
    title, description = esc(config['page_title']), esc(config['description'])
    lines += [f'  <meta property="og:site_name" content="{esc(config["site_title"])}">',
              '  <meta property="og:type" content="website">',
              f'  <meta property="og:title" content="{title}">',
              f'  <meta property="og:description" content="{description}">',
              f'  <meta property="og:url" content="{esc(base)}">']
    if logo:
        lines += [f'  <meta property="og:image" content="{esc(base)}assets/og-image.png">',
                  '  <meta property="og:image:width" content="1200">',
                  '  <meta property="og:image:height" content="630">',
                  f'  <meta property="og:image:alt" content="{esc(config["logo_alt"])}">',
                  '  <meta name="twitter:card" content="summary_large_image">',
                  f'  <meta name="twitter:image" content="{esc(base)}assets/og-image.png">']
    else:
        lines.append('  <meta name="twitter:card" content="summary">')
    lines += [f'  <meta name="twitter:title" content="{title}">',
              f'  <meta name="twitter:description" content="{description}">']
    return '\n'.join(lines)


def render_nav(has_screens: bool, has_donate: bool) -> str:
    items = [('#status', 'Status'), ('#works', 'Works today')]
    if has_screens:
        items.append(('#screens', 'Screenshots'))
    items += [('#preview', 'Preview'), ('#features', 'Features'), ('#roadmap', 'Roadmap')]
    if has_donate:
        items.append(('#donate', 'Donate'))
    return '\n'.join(f'        <a href="{href}">{label}</a>' for href, label in items)


def render_works(content: dict) -> str:
    rows = []
    for claim in content['works_today']:
        evidence = esc(' '.join(claim['evidence']))
        rows.append(f'          <li id="works-{esc(claim["id"])}" data-evidence="{evidence}"><h3>'
                    f'<span class="tick" aria-hidden="true">&check;</span><span>{esc(claim["title"])}</span></h3>'
                    f'<p>{esc(claim["text"])}</p></li>')
    return '\n'.join(rows)


def render_not_verified(content: dict) -> str:
    return '\n'.join(f'            <li>{esc(item)}</li>' for item in content['not_verified'])


def render_features(content: dict) -> str:
    rows = []
    for feature in content['features']:
        label, glyph, css = STATUSES[feature['status']]
        evidence = esc(' '.join(feature['evidence']))
        basis = f' data-basis="{esc(feature["basis"])}"' if feature.get('basis') else ''
        rows.append(
            f'          <tr role="row" id="feature-{esc(feature["id"])}" data-status="{feature["status"]}" '
            f'data-evidence="{evidence}"{basis}>\n'
            f'            <td role="cell">{esc(feature["name"])}</td>\n'
            f'            <td role="cell" data-label="Role">{esc(feature["role"])}</td>\n'
            f'            <td role="cell" data-label="Status"><span class="tag {css}"><span aria-hidden="true">'
            f'{glyph}</span> {label}</span></td>\n'
            f'            <td role="cell" data-label="What that means today">{esc(feature["note"])}</td>\n'
            '          </tr>')
    return ('        <table class="features" role="table">\n'
            '          <caption class="sr-only">Features and integrations with their current status</caption>\n'
            '          <thead role="rowgroup"><tr role="row"><th scope="col" role="columnheader">Feature or '
            'integration</th><th scope="col" role="columnheader">Role</th><th scope="col" '
            'role="columnheader">Status</th><th scope="col" role="columnheader">What that means today</th>'
            '</tr></thead>\n          <tbody role="rowgroup">\n' + '\n'.join(rows) + '\n          </tbody>\n'
            '        </table>')


def render_roadmap(content: dict) -> str:
    return '\n'.join(
        f'          <li><span class="phase mono">{esc(step["phase"])}</span><div>'
        f'<h3>{esc(step["title"])}</h3><p>{esc(step["text"])}</p></div></li>' for step in content['roadmap'])


def render_screens(shots: list[dict], number: str) -> str:
    if not shots:
        return ''
    figures = []
    for index, shot in enumerate(shots, 1):
        name = shot['id']
        png, webp = f'{SCREENS_DIR}/{name}.png', f'{SCREENS_DIR}/{name}.webp'
        figures.append(
            f'          <figure class="shot"><a href="{png}" title="Open the full-size image">'
            f'<picture><source type="image/webp" srcset="{webp}">'
            f'<img src="{png}" alt="{esc(shot["alt"])}" width="{int(shot["width"])}" '
            f'height="{int(shot["height"])}" loading="lazy" decoding="async"></picture></a>'
            f'<figcaption><span class="figure-label">FIG. {index:02d} / {esc(shot["title"]).upper()}</span>'
            f'{esc(shot["caption"])}</figcaption></figure>')
    return f'''      <section class="section-space" id="screens" aria-labelledby="screens-title">
        <div class="section-heading"><div><span class="kicker">{number} / REAL SCREENSHOTS</span><h2 id="screens-title">This is the actual alpha window.</h2></div><p>Select an image to open it full size.</p></div>
        <p class="shots-note">Rendered by the real PatchTrace interface, offscreen on Linux, from the bundled synthetic sample project: an authored bounds-check example with no Microsoft binaries, no Ghidra run and no AI model. Fonts and window frames differ on Windows.</p>
        <div class="shots">
{chr(10).join(figures)}
        </div>
      </section>

'''


# ---- claims document --------------------------------------------------------------------------------

def claims_markdown(content: dict) -> str:
    lines = ['# PatchTrace site: claims and evidence', '',
             'Generated by `python tools/site/build_site.py --write-claims` from `site/content.json`; '
             '`tests/test_site_claims.py` fails if this file drifts or a cited path disappears. '
             'A claim is **working** only when current repository files prove it. When unsure it is '
             '**in-progress**.', '']
    if content.get('review'):
        lines += ['## Review basis', '', content['review'], '']
    lines += ['## What works today', '', '| Claim | Evidence (repository files) |', '|---|---|']
    for claim in content['works_today']:
        lines.append(f'| **{claim["title"]}.** {claim["text"]} | ' + '<br>'.join(f'`{p}`' for p in claim['evidence']) + ' |')
    lines += ['', '## Implemented but not yet verified (shown on the page as such)', '']
    lines += [f'- {item}' for item in content['not_verified']]
    lines += ['', '## Features and integrations', '', '| Feature | Status | Caveat | Evidence or basis |', '|---|---|---|---|']
    for feature in content['features']:
        proof = '<br>'.join(f'`{p}`' for p in feature['evidence']) or feature.get('basis', '')
        if feature['evidence'] and feature.get('basis'):
            proof += f'<br>{feature["basis"]}'
        lines.append(f'| {feature["name"]} ({feature["role"]}) | {STATUSES[feature["status"]][0]} | {feature["note"]} | {proof} |')
    lines += ['', '## Design previews (illustrations with invented data, none implemented)', '',
              '| Preview | Source of the idea |', '|---|---|']
    for preview in content['previews']:
        lines.append(f'| {preview["title"]} | {preview["basis"]} |')
    return '\n'.join(lines) + '\n'


# ---- build ------------------------------------------------------------------------------------------

def prepare_out_dir(out_dir: Path) -> None:
    if out_dir.exists():
        entries = list(out_dir.iterdir())
        if entries and not ((out_dir / 'index.html').is_file() and (out_dir / 'styles.css').is_file()):
            raise BuildError(f'refusing to overwrite {out_dir}: it is not empty and does not look like a '
                             'previous site build (index.html and styles.css are missing)')
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)


def copy_assets(site_dir: Path, out_dir: Path) -> None:
    for name in ('styles.css', 'site.js'):
        shutil.copyfile(site_dir / name, out_dir / name)
    source_assets = site_dir / 'assets'
    for path in sorted(source_assets.rglob('*')):
        relative = path.relative_to(source_assets)
        if relative.parts[0] == 'source' or not path.is_file():
            continue  # the owner's original logo is an input, never deployed
        target = out_dir / 'assets' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def build(site_dir: Path = SITE, out_dir: Path = DEFAULT_OUT, *, config_override: dict | None = None,
          logo_source: Path | None = None, qr: Callable[[str], str] = donate.qr_svg,
          log: Callable[[str], None] = print) -> BuildResult:
    site_dir, out_dir = Path(site_dir), Path(out_dir)
    config = load_config(site_dir / 'site-config.json', config_override)
    content = load_content(site_dir / 'content.json')
    result = BuildResult(out_dir)
    prepare_out_dir(out_dir)
    copy_assets(site_dir, out_dir)

    # logo: generated from the owner's original; absent source -> warning + text wordmark
    source = Path(logo_source) if logo_source else site_dir / 'assets' / 'source' / 'logo-original.png'
    if source.is_file():
        try:
            make_logo_assets.generate(source, out_dir / 'assets')
        except ImportError as error:
            raise BuildError('Pillow is required to make the logo assets: '
                             'python -m pip install -r tools/site/requirements.txt') from error
        except make_logo_assets.LogoError as error:
            raise BuildError(str(error)) from error
    result.logo = all((out_dir / 'assets' / name).is_file() for name in make_logo_assets.output_names())
    if not result.logo:
        result.warnings.append(f'logo source not found ({source}); the page shows a text wordmark and has no '
                               'logo, favicon image or link-preview image. Put the original PNG at '
                               'site/assets/source/logo-original.png and build again.')

    shots = load_screens(site_dir, result.warnings)
    result.screens = len(shots)
    number = 3
    screens_number = ''
    if shots:
        screens_number, number = f'{number:02d}', number + 1
    preview_number, features_number, roadmap_number, donate_number = (f'{number + i:02d}' for i in range(4))
    try:
        donation = donate.render_donation_block(config['monero_address'], number=donate_number, qr=qr)
    except xmr_address.AddressError as error:
        raise BuildError(f'monero_address is invalid: {error}') from error
    except donate.QRUnavailable as error:
        raise BuildError(str(error)) from error
    result.donation = bool(donation)
    if not donation:
        result.warnings.append('donation block omitted: monero_address is empty in site-config.json')

    values = {key: esc(config[key]) for key in REQUIRED_CONFIG}
    values.update({
        'cdl_name_upper': esc(config['cdl_name'].upper()),
        'head_extra': render_head_extra(config, result.logo),
        'nav_links': render_nav(bool(shots), result.donation),
        'hero_art': render_hero_art(config, result.logo),
        'works_list': render_works(content),
        'not_verified_list': render_not_verified(content),
        'screens_section': render_screens(shots, screens_number),
        'previews': (site_dir / 'partials' / 'previews.html').read_text(encoding='utf-8').rstrip('\n'),
        'features_table': render_features(content),
        'roadmap_list': render_roadmap(content),
        'donate_section': donation.rstrip('\n'),
        'preview_number': preview_number, 'features_number': features_number, 'roadmap_number': roadmap_number,
    })
    page = fill((site_dir / 'index.template.html').read_text(encoding='utf-8'), values)
    if '{{' in page or '}}' in page:
        raise BuildError('unresolved template braces remain in the built page')
    (out_dir / 'index.html').write_text(page, encoding='utf-8', newline='\n')
    base = config['canonical_url']
    (out_dir / 'robots.txt').write_text(f'User-agent: *\nAllow: /\n\nSitemap: {base}sitemap.xml\n',
                                        encoding='utf-8', newline='\n')
    (out_dir / 'sitemap.xml').write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f'  <url><loc>{esc(base)}</loc></url>\n</urlset>\n', encoding='utf-8', newline='\n')

    problems = checks.check_dist(out_dir, config)
    if problems:
        raise BuildError('the built page failed its quality gate:\n  - ' + '\n  - '.join(problems), gate=True)
    for warning in result.warnings:
        log(f'WARNING: {warning}')
    log(f'built {out_dir} (logo: {"yes" if result.logo else "no"}, screenshots: {result.screens}, '
        f'donation block: {"yes" if result.donation else "no"})')
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--site', type=Path, default=SITE, help='input directory (default: site/)')
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT, help='output directory (default: site/dist)')
    parser.add_argument('--write-claims', action='store_true', help='regenerate tests/site_claims.md and exit')
    args = parser.parse_args(argv)
    try:
        if args.write_claims:
            CLAIMS_MD.write_text(claims_markdown(load_content(args.site / 'content.json')), encoding='utf-8',
                                 newline='\n')
            print(f'wrote {CLAIMS_MD}')
            return 0
        build(args.site, args.out)
    except BuildError as error:
        print(f'build_site: {"QUALITY GATE FAILED" if error.gate else "ERROR"}: {error}', file=sys.stderr)
        return 3 if error.gate else 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
