"""IDA effective address -> image-relative RVA, per side (SPEC-DA-01 "Diaphora output mapping"). Pure.

Result addresses are text EAs. They are mapped independently for the older and the newer binary from that PE's own
image base and size. Anything that cannot be mapped with certainty stays visible as `external-ea-only` or
`ambiguous` and is never counted as agreeing with Ghidriff; there is no name-only linking.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .contracts import DiaphoraError

_HEX = re.compile(r'(?:0[xX])?([0-9a-fA-F]{1,16})')


def parse_ea(text: object, label: str = 'address') -> int:
    """Diaphora writes EAs as hexadecimal text (optionally `0x`-prefixed); everything else is rejected."""
    if not isinstance(text, str):
        raise DiaphoraError('PT-DIAPHORA-INPUT', f'{label} is not text')
    match = _HEX.fullmatch(text.strip())
    if match is None:
        raise DiaphoraError('PT-DIAPHORA-INPUT', f'{label} {text[:40]!r} is not a hexadecimal address')
    return int(match.group(1), 16)


@dataclass(frozen=True)
class ImageMap:
    """What is known about one side's image. `image_base`/`size` None means the PE could not be read."""
    image_base: int | None
    size_of_image: int | None

    def rva(self, ea: int) -> tuple[int | None, str]:
        """(rva, status). `verified-rva`: inside [base, base+size). `ambiguous`: base/size unknown, or the EA is
        small enough to also be an RVA of a database exported at base 0. `external-ea-only`: elsewhere."""
        if self.image_base is None or self.size_of_image is None or self.size_of_image <= 0:
            return None, 'ambiguous'
        offset = ea - self.image_base
        if 0 <= offset < self.size_of_image:
            if self.image_base != 0 and ea < self.size_of_image:
                return None, 'ambiguous'        # also a valid RVA: base-0 export or rebased database
            return offset, 'verified-rva'
        if 0 <= ea < self.size_of_image:
            return None, 'ambiguous'
        return None, 'external-ea-only'


def combine(older: str, newer: str) -> str:
    """One status for a two-sided row: verified only when both sides are."""
    if older == newer == 'verified-rva':
        return 'verified-rva'
    return 'ambiguous' if 'ambiguous' in (older, newer) else 'external-ea-only'
