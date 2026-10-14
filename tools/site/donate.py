"""Donation block for the site build.

Rendered only when ``site-config.json`` carries a non-empty ``monero_address``: the address as selectable
text, a copy button (hidden until ``site.js`` confirms the clipboard API), a ``monero:`` URI link, a QR code
drawn at build time as inline SVG, and a short honest note. The address is validated first
(:mod:`tools.site.xmr_address`); an invalid one raises ``AddressError`` and the build fails.
"""
from __future__ import annotations

import html
from collections.abc import Callable

from . import xmr_address

QR_TITLE = 'QR code containing the Monero address as a monero: link'


class QRUnavailable(RuntimeError):
    """segno is not installed; it is a build-time dependency of tools/site only."""


def qr_svg(data: str, *, title: str = QR_TITLE) -> str:
    """Inline SVG of a QR code (error correction M, 4-module quiet zone, black on white for scanners)."""
    try:
        import segno
    except ImportError as error:
        raise QRUnavailable('segno is required to draw the donation QR code: '
                            'python -m pip install -r tools/site/requirements.txt') from error
    code = segno.make(data, error='m', micro=False)
    svg = code.svg_inline(scale=1, border=4, dark='#000000', light='#ffffff', title=title,
                          svgclass='qr-svg', omitsize=True)
    label = html.escape(title, quote=True)
    return svg.replace('<svg ', f'<svg role="img" aria-label="{label}" focusable="false" ', 1)


def render_donation_block(address: str | None, *, number: str,
                          qr: Callable[[str], str] = qr_svg) -> str:
    """The donation section, or '' when no address is configured (nothing placeholder-like is shipped)."""
    address = (address or '').strip()
    if not address:
        return ''
    uri = xmr_address.monero_uri(address)  # raises AddressError unless a valid mainnet address
    safe = html.escape(address, quote=True)
    return f'''      <section class="section-space donate" id="donate" aria-labelledby="donate-title">
        <div class="section-heading"><div><span class="kicker">{html.escape(number)} / SUPPORT</span><h2 id="donate-title">Donate, if you want to.</h2></div><p>Optional, and never expected.</p></div>
        <div class="donate-card">
          <div class="qr">{qr(uri)}</div>
          <div>
            <span class="donate-label">Monero (XMR) address</span>
            <code class="xmr-address" id="xmr-address">{safe}</code>
            <div class="donate-actions">
              <button class="button" type="button" data-copy-target="xmr-address" data-copy-status="copy-status" hidden>Copy address</button>
              <a class="text-link" href="{html.escape(uri, quote=True)}">Open in a Monero wallet <span aria-hidden="true">&nearr;</span></a>
            </div>
            <p class="copy-status" id="copy-status" role="status" aria-live="polite"></p>
            <p class="donate-note">Donations are optional. They are not a purchase: they buy no goods, services, support or priority, and they do not promise any feature or release date. Monero payments cannot be reversed, so check the address in your wallet before you send.</p>
          </div>
        </div>
      </section>
'''
