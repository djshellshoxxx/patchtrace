# PatchTrace site (GitHub Pages)

The public page for PatchTrace, in the Circuit Drift Labs style. It is a static site: one HTML page, one
stylesheet, one small optional script, no frameworks, no external fonts, scripts or trackers. The built
tree is `site/dist/`, deployed by `.github/workflows/pages.yml`. Canonical URL:
<https://djshellshoxxx.github.io/patchtrace/>.

## Three things only the owner can do

1. **Enable Pages with the GitHub Actions source** (one time; repository settings cannot be changed from
   code). Repository **Settings -> Pages -> Build and deployment -> Source: GitHub Actions**. After that,
   every push to `main` that touches `site/**` or `tools/site/**` deploys, and **Actions -> GitHub Pages ->
   Run workflow** deploys on demand.
2. **Upload the logo.** Save the original square logo as `site/assets/source/logo-original.png` and
   commit it. The build turns it into `logo-512.png`, `logo-192.png`, `favicon-64.png`,
   `apple-touch-icon-180.png` and a 1200x630 `og-image.png` (Pillow, LANCZOS). The original itself is never
   deployed. Until it exists, the page shows a text wordmark and the build prints a warning. The image's
   alt text is `logo_alt` in `site-config.json`; it was written from your description of the logo, so
   adjust it to match the real image.
3. **Add the Monero address.** Paste your **mainnet** address (the bare address, not a `monero:` link)
   into `monero_address` in `site/site-config.json`, or tell the assistant. Check it first with
   `python tools/site/xmr_address.py YOUR_ADDRESS`. The build refuses an invalid address (typo, wrong
   network, wrong length), so a mistyped address can never go live. While the field is empty the donation
   block is not rendered at all. After the first deploy, compare the address on the live page with your
   wallet before announcing it.

## Build and preview locally

```powershell
python -m pip install -r tools/site/requirements.txt   # Pillow and segno; site tools only
python tools/site/build_site.py                         # writes site/dist, prints warnings
python tools/site/build_site.py --write-claims          # regenerates tests/site_claims.md after content edits
python -m pytest -q tests/test_site_*.py
```

Open `site/dist/index.html` in a browser. Exit codes: 0 built, 2 configuration or input error (for example
an invalid address), 3 the built page failed its quality gate. The gate (`tools/site/checks.py`) fails the
build, and therefore the deployment, on a dead local link, an image without alt text, an external script,
font, style or image, a link outside the allow-list (this site, Circuit Drift Labs, the PatchTrace GitHub
repository, and the `monero:` URI), duplicate ids or a skipped heading level.

## What is where

| Path | Purpose |
|---|---|
| `site-config.json` | Title, description, canonical URL, links, `monero_address`, `logo_alt` |
| `content.json` | Claims ("works today"), features table, roadmap and preview list; every claim cites repository files |
| `index.template.html`, `partials/previews.html` | Page template and the ten design-preview illustrations |
| `styles.css`, `site.js` | The one stylesheet; the optional copy-to-clipboard enhancement |
| `assets/screens/` | Real screenshots (`screens.json` holds the alt text); regenerate with `QT_QPA_PLATFORM=offscreen python tools/site/render_screenshots.py` |
| `assets/cdl-mark.svg` | The Circuit Drift Labs mark, copied from the Circuit Drift Labs site |
| `assets/source/` | Where `logo-original.png` goes (input only) |
| `../tools/site/` | `build_site.py`, `make_logo_assets.py`, `render_screenshots.py`, `xmr_address.py`, `donate.py`, `checks.py` |
| `../tests/test_site_*.py`, `../tests/site_claims.md` | Tests and the generated claim-to-evidence table |

## Editing rules

* **Every statement of fact is a claim.** Put it in `content.json` with repository evidence. When unsure,
  use status `in-progress`, never `working`; `tests/test_site_claims.py` checks that cited files exist and
  that `tests/site_claims.md` matches.
* The design previews are illustrations with invented data, labelled "Design preview, not implemented".
  They must never use a screenshot or real CVE identifiers.
* Screenshots come only from `render_screenshots.py` (the real GUI on the bundled synthetic sample). If it
  fails, the page ships without the missing image; nothing is drawn by hand.
* No new external request of any kind. Links are limited to the allow-list in `tools/site/checks.py`.

## Licences and trademarks

The repository code, including this site's HTML, CSS and tooling, is MIT-licensed (see `LICENSE`). The
Circuit Drift Labs logo, mark and name are the owner's brand material and the MIT licence does not extend
to them; `assets/cdl-mark.svg` is copied unchanged from the Circuit Drift Labs site (same owner) as the
brand mark of the theme this page follows.

## Status of this tooling

Verified locally on Linux: the build, the quality gate, the logo pipeline (with a stand-in image), the QR
code (with a synthetic address) and the screenshot renderer. **Not yet verified:** the first run of the
Pages workflow on GitHub (it needs step 1 above), rendering in Windows and Safari browsers, and screen-reader
behaviour. The action versions are pinned to the majors `configure-pages@v5`, `upload-pages-artifact@v3`
and `deploy-pages@v4`.
