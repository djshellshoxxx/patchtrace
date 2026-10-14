"""Certificate table (Security directory) structure. Presence only, never validity."""
from __future__ import annotations

import struct

from ._common import Ctx
from .models import CertificateEntry, CertificateTable


def parse_certificate_table(ctx: Ctx, file_offset: int, size: int) -> CertificateTable:
    """The Security directory 'RVA' is a file offset. Entries are 8-byte aligned WIN_CERTIFICATE headers."""
    present = file_offset != 0 and size != 0
    if not present:
        return CertificateTable(False, file_offset, size, ())
    file_size = ctx.reader.size
    end = file_offset + size
    if file_offset >= file_size or end > file_size:
        ctx.warn('certificate_table_out_of_file', 'certificate table extends beyond the end of the file')
    end = min(end, file_size)
    entries: list[CertificateEntry] = []
    pos = file_offset
    while pos + 8 <= end and len(entries) < ctx.limits.max_certificates:
        ctx.check()
        head = ctx.read(pos, 8)
        if len(head) < 8:
            break
        length, revision, ctype = struct.unpack('<IHH', head)
        if length < 8 or pos + length > end:
            ctx.warn('certificate_entry_invalid', f'certificate entry at {pos:#x} has invalid length {length}')
            break
        entries.append(CertificateEntry(pos, length, revision, ctype))
        pos += (length + 7) & ~7
    return CertificateTable(True, file_offset, size, tuple(entries))
