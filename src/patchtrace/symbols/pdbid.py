"""Bounded stdlib reader for the identity (GUID, age) of an MSF 7.0 PDB (SPEC-53 GHR-1).

Reads only the superblock, the stream directory (at most 4 MiB), the PDB info stream header and, if present,
the DBI header. Hostile input surfaces only as `SymbolError('PT-SYMBOL-PDB-INVALID')`. No symbol data is parsed.
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

from .modes import SymbolError

MAGIC = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00'
MAX_DIRECTORY = 4 * 1024 * 1024
_BAD = 'PT-SYMBOL-PDB-INVALID'


@dataclass(frozen=True)
class PdbIdentity:
    guid: str      # lowercase hyphenated, as the PE CodeView record prints it
    age: int       # DBI age when a DBI stream exists (the value the PE records), else the info-stream age


def _invalid(why: str) -> SymbolError:
    return SymbolError(_BAD, f'not a usable PDB ({why})')


def read_pdb_identity(path: Path) -> PdbIdentity:
    try:
        with open(path, 'rb') as f:
            return _read(f)
    except OSError as exc:
        raise SymbolError(_BAD, f'PDB is unreadable ({exc.strerror or "I/O error"})') from None
    except (struct.error, ValueError, OverflowError, IndexError):
        raise _invalid('malformed') from None


def _read(f) -> PdbIdentity:
    head = f.read(56)
    if len(head) < 56 or head[:32] != MAGIC:
        raise _invalid('bad magic')
    block, _free, blocks, dir_bytes, _unk, map_addr = struct.unpack_from('<6I', head, 32)
    if block not in (512, 1024, 2048, 4096, 8192, 16384, 32768) or not 0 < dir_bytes <= MAX_DIRECTORY:
        raise _invalid('bad geometry')
    f.seek(0, 2)
    size = f.tell()
    if blocks * block != size or map_addr >= blocks:
        raise _invalid('size does not match the superblock')

    def read_blocks(indices, length):
        parts = []
        for i in indices:
            if i >= blocks:
                raise _invalid('block out of range')
            f.seek(i * block)
            parts.append(f.read(block))
        return b''.join(parts)[:length]

    n_dir = -(-dir_bytes // block)
    f.seek(map_addr * block)
    table = f.read(n_dir * 4)
    if len(table) != n_dir * 4:
        raise _invalid('truncated block map')
    directory = read_blocks(struct.unpack(f'<{n_dir}I', table), dir_bytes)
    if len(directory) != dir_bytes:
        raise _invalid('truncated directory')
    n_streams = struct.unpack_from('<I', directory, 0)[0]
    if n_streams < 2 or 4 + 4 * n_streams > dir_bytes:
        raise _invalid('bad stream count')
    sizes = struct.unpack_from(f'<{n_streams}I', directory, 4)
    pos = 4 + 4 * n_streams
    locations: list[tuple[int, ...]] = []
    for s in sizes:
        n = 0 if s == 0xFFFFFFFF else -(-s // block)
        if pos + 4 * n > dir_bytes:
            raise _invalid('truncated directory')
        locations.append(struct.unpack_from(f'<{n}I', directory, pos))
        pos += 4 * n
    if sizes[1] < 28:
        raise _invalid('no PDB info stream')
    info = read_blocks(locations[1][:1], 28)
    _version, _signature, info_age = struct.unpack_from('<III', info, 0)
    guid = str(uuid.UUID(bytes_le=info[12:28]))
    age = info_age
    if n_streams > 3 and 12 <= sizes[3] != 0xFFFFFFFF:
        dbi = read_blocks(locations[3][:1], 12)
        age = struct.unpack_from('<I', dbi, 8)[0]
    return PdbIdentity(guid, age)
