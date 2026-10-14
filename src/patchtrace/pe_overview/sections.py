"""Section table parsing, entropy and conservative packer hints."""
from __future__ import annotations

import struct

from ._common import Ctx, clean_text
from .entropy import entropy_of_range
from .models import PackerHint, SectionInfo

SECTION_FLAGS = {
    0x20: 'CODE', 0x40: 'INITIALIZED_DATA', 0x80: 'UNINITIALIZED_DATA', 0x02000000: 'DISCARDABLE',
    0x04000000: 'NOT_CACHED', 0x08000000: 'NOT_PAGED', 0x10000000: 'SHARED', 0x20000000: 'EXECUTE',
    0x40000000: 'READ', 0x80000000: 'WRITE',
}
SCN_MEM_EXECUTE = 0x20000000
SCN_CNT_CODE = 0x20
HIGH_ENTROPY = 7.2
MIN_ENTROPY_BYTES = 4096


def parse_sections(ctx: Ctx, table_offset: int, count: int) -> tuple[SectionInfo, ...]:
    lim = ctx.limits
    if count > lim.max_sections:
        ctx.warn('section_count_over_cap', f'{count} sections declared; reading the first {lim.max_sections}')
        count = lim.max_sections
    raw = ctx.read(table_offset, count * 40) if count else b''
    if len(raw) < count * 40:
        ctx.warn('section_table_truncated', 'section table extends beyond the end of the file')
    out = []
    for i in range(len(raw) // 40):
        ctx.check()
        name_raw, vsize, va, rsize, roff, _p, _l, _n, _m, chars = struct.unpack_from('<8sIIIIIIHHI', raw, i * 40)
        ent, measured, sampled = entropy_of_range(ctx, roff, rsize)
        flags = tuple(n for bit, n in SECTION_FLAGS.items() if chars & bit)
        out.append(SectionInfo(clean_text(name_raw.rstrip(b'\0')), va, vsize, roff, rsize, chars, flags,
                               ent, measured, sampled))
    return tuple(out)


def last_raw_end(sections: tuple[SectionInfo, ...]) -> int:
    return max((s.raw_offset + s.raw_size for s in sections if s.raw_size), default=0)


_NAME_HINTS = {
    'UPX0': 'UPX', 'UPX1': 'UPX', 'UPX2': 'UPX', '.UPX0': 'UPX', '.UPX1': 'UPX',
    '.aspack': 'ASPack', '.adata': 'ASPack', '.petite': 'Petite', 'MPRESS1': 'MPRESS',
    'MPRESS2': 'MPRESS', '.themida': 'Themida', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect',
    '.enigma1': 'Enigma Protector', '.nsp0': 'NsPack', '.nsp1': 'NsPack',
}


def packer_hints(sections: tuple[SectionInfo, ...]) -> tuple[PackerHint, ...]:
    hints: list[PackerHint] = []
    names = {s.name for s in sections}
    by_name = {s.name: s for s in sections}
    if 'UPX0' in names and 'UPX1' in names:
        upx0 = by_name['UPX0']
        if upx0.raw_size == 0 and upx0.virtual_size > 0:
            hints.append(PackerHint(
                'UPX', 'medium',
                'UPX0 has no raw data but reserves virtual space, UPX1 is present (typical UPX layout); '
                'section names can be edited, so this is not proof'))
    seen = {h.name for h in hints}
    for sec in sections:
        packer = _NAME_HINTS.get(sec.name)
        if packer and packer not in seen:
            seen.add(packer)
            hints.append(PackerHint(packer, 'low', f'section named {sec.name!r}; names are easily forged'))
    for sec in sections:
        if (sec.flags and (sec.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE)) and sec.entropy is not None
                and sec.entropy >= HIGH_ENTROPY and sec.entropy_bytes >= MIN_ENTROPY_BYTES):
            hints.append(PackerHint(
                'high-entropy executable section', 'low',
                f'section {sec.name!r} entropy {sec.entropy:.2f} bits/byte over {sec.entropy_bytes} bytes; '
                'may be compressed or encrypted, but entropy alone does not establish packing'))
    return tuple(hints)
