"""SPEC-31 addressing (06 s1, D-17): VA <-> RVA per side, per-SET basis detection, external keys. Pure.

The basis rule is C3's `secondary.binexport_identity.detect_address_basis` (reused, never re-implemented): all
addresses inside [image_base, image_base + size_of_image) -> VA; all below size_of_image -> RVA; anything else is
`not-comparable` for the whole set, which the adapter reports as a limitation (fixes R01 s3 limit 1, where an
image-base mismatch silently became "absent"). The C3 function reads the FIRST and LAST element, so its input is
sorted here.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from ..enrichment.identity import parse_address
from ..secondary.binexport_identity import PeLayout, detect_address_basis
from .limits import UnifiedError

Side = Literal['older', 'newer']
Basis = Literal['va', 'rva']
SetBasis = Literal['va', 'rva', 'not-comparable']
__all__ = ['AddressMap', 'PeLayout', 'detect_address_basis', 'is_external_key', 'layout_from_reader', 'parse_va_text']

# Ghidra's placeholder for an imported location: an index into its external space, not an import name (D-17).
# Same shape as nway/graph.py `_is_external` (private there, so restated).
_EXTERNAL = re.compile(r'EXTERNAL:[0-9A-Fa-f]+')


def is_external_key(text: object) -> bool:
    return isinstance(text, str) and _EXTERNAL.fullmatch(text.strip()) is not None


def parse_va_text(text: object) -> int | None:
    """Ghidriff hex text (with or without 0x) to an int; external keys and junk are None."""
    if not isinstance(text, str) or not text.strip() or is_external_key(text):
        return None
    return parse_address(text)


def layout_from_reader(reader) -> PeLayout:
    """ImageBase/SizeOfImage from the artifact's own verified bytes (`pe_overview`), never from an engine."""
    from ..pe_overview.headers import read_image_layout
    layout = read_image_layout(reader)
    if layout is None:
        raise UnifiedError('PT-UNIFIED-INPUT', 'The artifact has no readable PE image layout',
                           reason='pe-layout-unavailable')
    return PeLayout(image_base=layout[0], size_of_image=layout[1])


@dataclass(frozen=True)
class AddressMap:
    """The two PE layouts of a run; converts an engine's addresses to RVAs (identity of a function across tools
    is (artifact SHA-256, RVA), D-17)."""
    older: PeLayout
    newer: PeLayout

    def layout(self, side: Side) -> PeLayout:
        return self.older if side == 'older' else self.newer

    def side_basis(self, side: Side, addresses: Iterable[int]) -> str:
        return detect_address_basis(sorted(set(addresses)), self.layout(side))

    def set_basis(self, older_addresses: Iterable[int], newer_addresses: Iterable[int]) -> SetBasis:
        """One basis for a whole engine set. A side without addresses does not decide; unknown on a side, or VA on
        one side and RVA on the other, makes the set not comparable."""
        found = set()
        for side, addresses in (('older', older_addresses), ('newer', newer_addresses)):
            values = sorted(set(addresses))
            if values:
                found.add(detect_address_basis(values, self.layout(side)))
        if not found:
            return 'va'
        return found.pop() if len(found) == 1 and next(iter(found)) in ('va', 'rva') else 'not-comparable'

    def to_rva(self, side: Side, value: int, basis: Basis) -> int | None:
        """The RVA of `value`, or None when it lies outside the image (the adapter drops and counts it)."""
        layout = self.layout(side)
        rva = value - layout.image_base if basis == 'va' else value
        return rva if 0 <= rva < layout.size_of_image else None
