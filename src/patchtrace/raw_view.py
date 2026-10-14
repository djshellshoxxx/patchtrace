"""Pure composition of raw byte views for the comparison viewer (SPEC-26 B, alpha).

Responsibility: turn (verified reader, PE overview, selected function entry
address, scope choice, page) into a rendered Hex/Binary/Base64 page for one
side, and compute which displayed lines differ between the two sides at equal
logical byte offsets. No Qt; the desktop only displays the returned text.

Scopes offered in the alpha:

* ``whole``  - the whole artifact file.
* ``entry``  - file bytes starting at the selected function's entry point. The
  entry address is translated to a file offset through the PE section map.
  The function's extent is NOT claimed: upstream Ghidriff records carry an
  entry address but no verified contiguous body range, so the view pages
  forward from the entry offset and says so. Unmappable or ambiguous entries
  are reported unavailable; no range is guessed.

Error contract: :func:`build_side` never raises for missing inputs; it returns
``RawSide`` with ``rendered=None`` and a ``message`` explaining why. Byte-read
failures (``ArtifactBytesError``) are converted into a message with their code.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from .artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from .pe_overview import PeOverview
from .representations import (
    DEFAULT_PAGE_SIZE,
    ByteScope,
    PageBytes,
    RenderedPage,
    Representation,
    byte_diff_mask,
    file_range,
    page_count,
    read_page,
    render_page,
    whole_file,
)

SCOPES = ('whole', 'entry')
BYTES_PER_LINE = {Representation.HEX: 16, Representation.BINARY: 8}


@dataclass(frozen=True, slots=True)
class RawSide:
    side: str
    scope: ByteScope | None
    page: PageBytes | None
    rendered: RenderedPage | None
    pages: int
    message: str = ''


def parse_entry_rva(address: str | None, image_base: int | None) -> int | None:
    """Return the RVA of a Ghidriff virtual address string, or None when unsafe.

    Accepts hexadecimal with or without ``0x``. A value below the image base is
    rejected rather than reinterpreted, because its address space is unknown.
    """
    if not address or image_base is None:
        return None
    text = address.strip().lower().removeprefix('0x')
    if not text or len(text) > 16 or any(ch not in '0123456789abcdef' for ch in text):
        return None
    value = int(text, 16)
    if value < image_base or value - image_base > 0xFFFFFFFF:
        return None
    return value - image_base


def entry_scope(overview: PeOverview | None, size: int, address: str | None) -> tuple[ByteScope | None, str]:
    if overview is None or overview.image_base is None:
        return None, 'Function entry unavailable: PE headers of this artifact could not be inspected.'
    rva = parse_entry_rva(address, overview.image_base)
    if rva is None:
        return None, (f'Function entry unavailable: address {address or "(none)"} is not a virtual address '
                      'inside this image.')
    offset = overview.section_map().rva_to_offset(rva)
    if offset is None:
        return None, (f'Function entry unavailable: RVA 0x{rva:x} is not backed by file bytes or maps '
                      'ambiguously (virtual-only, gap or overlapping sections). No range is guessed.')
    scope = file_range(size, offset, size - offset)
    label = (f'File bytes from function entry RVA 0x{rva:x} (file offset 0x{offset:x}); '
             'function extent not determined')
    return dataclasses.replace(scope, label=label, rva=rva), ''


def build_scope(choice: str, reader: VerifiedArtifactReader, overview: PeOverview | None,
                address: str | None) -> tuple[ByteScope | None, str]:
    if choice == 'whole':
        return whole_file(reader.size), ''
    if choice == 'entry':
        return entry_scope(overview, reader.size, address)
    raise ValueError(f'unknown raw scope {choice!r}')


def build_side(side: str, reader: VerifiedArtifactReader | None, overview: PeOverview | None,
               address: str | None, choice: str, representation: Representation, page_index: int,
               page_size: int = DEFAULT_PAGE_SIZE) -> RawSide:
    if reader is None:
        return RawSide(side, None, None, None, 0, 'Verified artifact bytes are unavailable for this side.')
    scope, message = build_scope(choice, reader, overview, address)
    if scope is None:
        return RawSide(side, None, None, None, 0, message)
    pages = page_count(scope, page_size)
    if pages == 0:
        return RawSide(side, scope, None, None, 0, 'Selected scope contains no bytes.')
    index = max(0, min(page_index, pages - 1))
    try:
        page = read_page(reader, scope, index, page_size)
    except ArtifactBytesError as exc:
        return RawSide(side, scope, None, None, pages, f'Byte read failed ({exc.code}); nothing is shown.')
    return RawSide(side, scope, page, render_page(page, representation), pages)


def differing_lines(older: RawSide, newer: RawSide, representation: Representation) -> tuple[int, ...]:
    """Zero-based display line numbers (excluding segment headers) with differing bytes.

    Only meaningful for contiguous single-chunk pages in Hex or Binary; returns
    an empty tuple otherwise (Base64 lines do not align to byte boundaries).
    """
    per_line = BYTES_PER_LINE.get(representation)
    if per_line is None or older.page is None or newer.page is None:
        return ()
    if len(older.page.chunks) != 1 or len(newer.page.chunks) != 1:
        return ()
    mask = byte_diff_mask(older.page.data, newer.page.data)
    return tuple(sorted({index // per_line for index in mask}))
