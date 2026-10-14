"""Synthetic inputs for the Tier-W tests (SPEC-33 s13). No Microsoft data: Winbindex-shaped documents are made
up here (except the committed, trimmed afd.sys fixture), MSF files are written by `build_msf`, and PE images come
from tests/pe_builder.py or the self-made fixtures in tests/fixtures/tier_w/."""
from __future__ import annotations

import gzip
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures'
TIER_W_FIXTURES = FIXTURES / 'tier_w'
AFD = FIXTURES / 'winbindex' / 'afd.sys.json'


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def gz(doc) -> bytes:
    return gzip.compress(json.dumps(doc).encode(), mtime=0)


def wb_entry(key: str, *, size: int = 4096, ts: int = 1, vsize: int | None = 0x3000, version: str | None = None,
             lines: dict | None = None, machine: int = 34404, last: tuple[int, int] | None = None) -> tuple[str, dict]:
    """One Winbindex entry. `lines` = {line: [(kb, date, release, heading), ...]}."""
    digest = sha(key)
    info = {'sha256': digest, 'size': size, 'machineType': machine, 'timestamp': ts}
    if version:
        info['version'] = version
    if vsize:
        info['virtualSize'] = vsize
    if last:
        info['lastSectionVirtualAddress'], info['lastSectionPointerToRawData'] = last
    wv = {line: {kb: {'assemblies': {}, 'updateInfo': {'releaseDate': d, 'releaseVersion': rv, 'heading': h}}
                 for kb, d, rv, h in kbs} for line, kbs in (lines or {}).items()}
    return digest, {'fileInfo': info, 'windowsVersions': wv}


def wb_doc(*entries) -> dict:
    return dict(entries)


def monthly_line(prefix: str, line: str, build: int, n: int, *, start_month: int = 1, year: int = 2024,
                 shared: dict | None = None) -> list[tuple[str, dict]]:
    """n builds of one line released monthly; returns Winbindex entries keyed by `<prefix><i>`."""
    out = []
    for i in range(n):
        month = start_month + i
        date = f'{year + (month - 1) // 12}-{(month - 1) % 12 + 1:02d}-09'
        kbs = [(f'KB{build}{i:02d}', date, f'{build}.{100 + i}', f'{date} KB (OS Build {build}.{100 + i})')]
        lines = {line: kbs}
        if shared and i in shared:
            lines.update(shared[i])
        out.append(wb_entry(f'{prefix}{i}', ts=1000 + i, version=f'10.0.{build}.{100 + i} (WinBuild.1)', lines=lines))
    return out


# ---- MSF 7.00 writer (test-only) ---------------------------------------------------------------------------------

MSF_MAGIC = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'


def build_msf(streams: list[bytes | None], block_size: int = 512) -> bytes:
    """Minimal MSF 7.00 container: superblock, one FPM block pair, directory, stream blocks. `None` = nil stream."""
    blocks: list[bytes] = [b'', b'\0' * block_size, b'\0' * block_size]  # 0 superblock, 1-2 free page maps

    def place(data: bytes) -> list[int]:
        ids = []
        for off in range(0, len(data), block_size):
            ids.append(len(blocks))
            blocks.append(data[off:off + block_size].ljust(block_size, b'\0'))
        return ids
    stream_blocks = [place(s) if s else [] for s in streams]
    directory = struct.pack('<I', len(streams))
    directory += b''.join(struct.pack('<I', 0xFFFFFFFF if s is None else len(s)) for s in streams)
    directory += b''.join(struct.pack('<I', i) for ids in stream_blocks for i in ids)
    dir_ids = place(directory)
    map_id = place(b''.join(struct.pack('<I', i) for i in dir_ids))[0]
    blocks[0] = (MSF_MAGIC + struct.pack('<IIIIII', block_size, 1, len(blocks), len(directory), 0, map_id)
                 ).ljust(block_size, b'\0')
    return b''.join(blocks)


def pdb_info_stream(guid_le: bytes, age: int, signature: int = 0x12345678) -> bytes:
    return struct.pack('<III', 20000404, signature, age) + guid_le + b'\0' * 8


def sym_record(kind: int, payload: bytes) -> bytes:
    body = struct.pack('<H', kind) + payload
    body += b'\0' * ((-(len(body) + 2)) % 4)
    return struct.pack('<H', len(body)) + body


def pub32(name: str, offset: int, segment: int = 1, flags: int = 2) -> bytes:
    return sym_record(0x110E, struct.pack('<IIH', flags, offset, segment) + name.encode() + b'\0')


def gproc32(name: str, offset: int, size: int, segment: int = 1, kind: int = 0x1110) -> bytes:
    return sym_record(kind, struct.pack('<IIIIIIIIHB', 0, 0, 0, size, 0, 0, 0, offset, segment, 0)
                      + name.encode() + b'\0')


def section_header(name: bytes, vsize: int, va: int) -> bytes:
    return struct.pack('<8sIIIIIIHHI', name.ljust(8, b'\0'), vsize, va, 0, 0, 0, 0, 0, 0, 0x60000020)


def dbi_stream(*, age: int, sym_stream: int, modules: list[tuple[int, int, str]] = (), flags: int = 0,
               opt_dbg: dict[int, int] | None = None, machine: int = 0x8664) -> bytes:
    """DBI header + module info (sym stream, sym byte size, name) + optional debug header."""
    mods = b''
    for stream, size, name in modules:
        entry = struct.pack('<I', 0) + b'\0' * 28 + struct.pack('<HHIIIHHIII', 0, stream, size, 0, 0, 0, 0, 0, 0, 0)
        entry += name.encode() + b'\0' + name.encode() + b'\0'
        entry += b'\0' * ((-len(entry)) % 4)
        mods += entry
    dbg = [0xFFFF] * 11
    for index, stream in (opt_dbg or {}).items():
        dbg[index] = stream
    opt = b''.join(struct.pack('<H', v) for v in dbg)
    header = struct.pack('<iIIHHHHHHiiiiiIiiHHI', -1, 19990903, age, 0xFFFF, 0, 0xFFFF, 0, sym_stream, 0,
                         len(mods), 0, 0, 0, 0, 0, len(opt), 0, flags, machine, 0)
    return header + mods + opt


def module_stream(records: bytes) -> bytes:
    return struct.pack('<I', 4) + records
