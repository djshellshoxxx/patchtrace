"""Stdlib reader for MSF 7.00 PDB files (SPEC-33 s5.4). Read-only, never executes anything.

Gives the PDB identity (GUID from the PDB info stream, age from the DBI stream, as the PE CodeView record
references them), the DBI flags (bit 1 = private symbols stripped), public symbols (S_PUB32 in the symbol
record stream), private procedures and thunks from module streams, the section header stream and OMAP. Every
count, offset and length is bounded; any problem raises `MsfError(code, message)` and nothing else.
Format reference: LLVM "The PDB File Format" documentation (MSF, PDB info, DBI, module and symbol streams).
"""
from __future__ import annotations

import bisect
import os
import struct
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

MAGIC = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'
MAGIC_V2 = b'Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0'
BLOCK_SIZES = frozenset({512, 1024, 2048, 4096, 8192, 16384, 32768})
MAX_FILE = 2 * 1024 ** 3
MAX_DIRECTORY = 64 * 1024 * 1024
MAX_STREAMS = 65535
MAX_STREAM = 512 * 1024 * 1024
MAX_RECORDS = 5_000_000
MAX_NAME = 4096
MAX_MODULES = 100_000
MAX_SECTIONS = 4096
MAX_WARNINGS = 200
STREAM_PDB, STREAM_DBI = 1, 3
NIL = 0xFFFFFFFF
NO_STREAM = 0xFFFF
S_PUB32, S_THUNK32 = 0x110E, 0x1102
PROC_KINDS = frozenset({0x1110, 0x110F, 0x1147, 0x1146, 0x1155, 0x1156})
DBG_OMAP_FROM_SRC, DBG_SECTION_HDR, DBG_SECTION_HDR_ORIG = 4, 5, 10
FLAG_STRIPPED = 0x2


class MsfError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code


@dataclass(frozen=True)
class PdbInfo:
    guid: str          # lowercase hyphenated, as uuid.UUID(bytes_le=...) prints it (same as pe_overview CodeView)
    age: int           # DBI age: the value the PE CodeView record and the symbol server key use
    info_age: int      # PDB info stream age (may be higher after rewrites)
    signature: int
    stripped: bool
    machine: int
    omap: bool

    @property
    def guid_age(self) -> str:
        return uuid.UUID(self.guid).hex.upper() + f'{self.age:X}'


@dataclass(frozen=True)
class PdbSymbol:
    name: str
    segment: int
    offset: int
    rva: int | None
    kind: str          # 'public' | 'private'
    is_function: bool
    size: int | None
    thunk: bool = False


@dataclass(frozen=True)
class PdbFunction:
    rva: int
    name: str
    aliases: int
    kind: str          # 'public' | 'private'
    size: int | None
    thunk: bool
    public_names: tuple[str, ...]


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int


@dataclass(frozen=True)
class PdbIndex:
    info: PdbInfo
    publics: tuple[PdbSymbol, ...]
    procedures: tuple[PdbSymbol, ...]
    sections: tuple[Section, ...]
    warnings: tuple[str, ...]

    def functions(self) -> list[PdbFunction]:
        """Union of function publics and private procedures, one entry per RVA (SPEC-33 s5.3 merge rule)."""
        publics: dict[int, set[str]] = {}
        procs: dict[int, list[PdbSymbol]] = {}
        for sym in self.publics:
            if sym.is_function and sym.rva is not None:
                publics.setdefault(sym.rva, set()).add(sym.name)
        for sym in self.procedures:
            if sym.rva is not None:
                procs.setdefault(sym.rva, []).append(sym)
        out = []
        for rva in sorted(set(publics) | set(procs)):
            names = tuple(sorted(publics.get(rva, ())))
            here = procs.get(rva, [])
            proc_names = sorted({p.name for p in here})
            if names:
                name, aliases = names[0], len(names) - 1
            else:
                name, aliases = proc_names[0], len(proc_names) - 1
            sizes = [p.size for p in here if p.size is not None]
            out.append(PdbFunction(rva=rva, name=name, aliases=aliases, kind='private' if here else 'public',
                                   size=max(sizes) if sizes else None, thunk=any(p.thunk for p in here),
                                   public_names=names))
        return out


class _Warnings(list):
    def add(self, text: str) -> None:
        if len(self) < MAX_WARNINGS:
            self.append(text)


class MsfFile:
    """Superblock + stream directory; streams are read block by block from the open handle."""

    def __init__(self, path: Path, cancel: Callable[[], bool] | None = None):
        self.path = Path(path)
        self.cancel = cancel
        try:
            self.handle = open(self.path, 'rb')  # noqa: SIM115 - closed by close()/context manager
        except OSError as exc:
            raise MsfError('unreadable', f'cannot open PDB: {exc.strerror or exc}') from None
        try:
            self._parse_header()
        except BaseException:
            self.handle.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        self.handle.close()

    def _check_cancel(self) -> None:
        if self.cancel is not None and self.cancel():
            raise MsfError('cancelled', 'PDB parsing cancelled')

    def _read_at(self, offset: int, length: int) -> bytes:
        self.handle.seek(offset)
        data = self.handle.read(length)
        if len(data) != length:
            raise MsfError('truncated', 'PDB file ends inside a block')
        return data

    def _parse_header(self) -> None:
        size = os.fstat(self.handle.fileno()).st_size
        if size > MAX_FILE:
            raise MsfError('limit', f'PDB is larger than {MAX_FILE} bytes')
        head = self.handle.read(56)
        if head.startswith(MAGIC_V2[:32]):
            raise MsfError('unsupported-version', 'MSF 2.00 PDBs are not supported')
        if len(head) < 56 or head[:32] != MAGIC:
            raise MsfError('not-msf', 'missing the MSF 7.00 signature')
        bs, fpm, nblocks, dir_bytes, _unknown, map_addr = struct.unpack_from('<IIIIII', head, 32)
        if bs not in BLOCK_SIZES:
            raise MsfError('bad-superblock', f'block size {bs} is not supported')
        if fpm not in (1, 2):
            raise MsfError('bad-superblock', 'free block map block must be 1 or 2')
        if nblocks < 3 or nblocks * bs > -(-size // bs) * bs:
            raise MsfError('bad-superblock', 'block count does not match the file size')
        if not 4 <= dir_bytes <= MAX_DIRECTORY:
            raise MsfError('bad-superblock', 'directory size out of range')
        if not 1 <= map_addr < nblocks:
            raise MsfError('bad-superblock', 'block map address out of range')
        self.block_size, self.num_blocks = bs, nblocks
        dir_blocks = -(-dir_bytes // bs)
        if dir_blocks > bs // 4:
            raise MsfError('bad-directory', 'too many directory blocks')
        indices = struct.unpack_from(f'<{dir_blocks}I', self._block(map_addr))
        directory = b''.join(self._block(self._index(i)) for i in indices)[:dir_bytes]
        (count,) = struct.unpack_from('<I', directory, 0)
        if count > MAX_STREAMS or 4 + 4 * count > dir_bytes:
            raise MsfError('bad-directory', 'stream count out of range')
        sizes = struct.unpack_from(f'<{count}I', directory, 4)
        pos = 4 + 4 * count
        self.streams: list[tuple[int, tuple[int, ...]]] = []
        for stream_size in sizes:
            if stream_size == NIL:
                self.streams.append((0, ()))
                continue
            if stream_size > MAX_STREAM:
                raise MsfError('limit', f'a stream of {stream_size} bytes exceeds the cap')
            need = -(-stream_size // bs)
            if pos + 4 * need > dir_bytes:
                raise MsfError('bad-directory', 'stream block list runs past the directory')
            blocks = tuple(self._index(i) for i in struct.unpack_from(f'<{need}I', directory, pos))
            pos += 4 * need
            self.streams.append((stream_size, blocks))

    def _index(self, block: int) -> int:
        if not 1 <= block < self.num_blocks:
            raise MsfError('bad-block', f'block index {block} out of range')
        return block

    def _block(self, block: int) -> bytes:
        return self._read_at(self._index(block) * self.block_size, self.block_size)

    def stream(self, index: int) -> bytes:
        if not 0 <= index < len(self.streams):
            raise MsfError('bad-stream', f'stream {index} does not exist')
        size, blocks = self.streams[index]
        parts = []
        for block in blocks:
            self._check_cancel()
            parts.append(self._block(block))
        return b''.join(parts)[:size]


def _cstring(data: bytes, start: int, end: int, warn: _Warnings) -> str:
    stop = data.find(b'\0', start, end)
    if stop < 0:
        raise MsfError('bad-record', 'symbol name is not NUL-terminated inside its record')
    raw = data[start:stop]
    if not raw or len(raw) > MAX_NAME:
        raise MsfError('bad-record', 'symbol name empty or longer than 4096 bytes')
    text = raw.decode('utf-8', errors='replace')
    if '�' in text:
        warn.add('a symbol name is not valid UTF-8; invalid bytes replaced')
    return text


def _records(data: bytes, start: int, end: int, budget: list[int], check: Callable[[], None]):
    """Yield (kind, payload_start, record_end) for CodeView records in data[start:end]."""
    off = start
    while off + 4 <= end:
        (length,) = struct.unpack_from('<H', data, off)
        if length < 2:
            raise MsfError('bad-record', 'symbol record shorter than its kind field')
        rec_end = off + 2 + length
        if rec_end > end:
            raise MsfError('bad-record', 'symbol record runs past its stream')
        budget[0] -= 1
        if budget[0] < 0:
            raise MsfError('limit', f'more than {MAX_RECORDS} symbol records')
        if budget[0] % 4096 == 0:
            check()
        (kind,) = struct.unpack_from('<H', data, off + 2)
        yield kind, off + 4, rec_end
        off = rec_end


@dataclass(frozen=True)
class _Dbi:
    age: int
    sym_stream: int
    flags: int
    machine: int
    modules: tuple[tuple[int, int], ...]  # (stream, sym byte size)
    dbg: tuple[int, ...]


def _parse_dbi(data: bytes, warn: _Warnings) -> _Dbi:
    if len(data) < 64:
        raise MsfError('bad-dbi', 'DBI stream shorter than its header')
    fields = struct.unpack_from('<iIIHHHHHHiiiiiIiiHHI', data, 0)
    signature, _ver, age = fields[0], fields[1], fields[2]
    sym_stream = fields[7]
    mod_size, sc_size, sm_size, fi_size, ts_size = fields[9:14]
    dbg_size, ec_size, flags, machine = fields[15], fields[16], fields[17], fields[18]
    if signature != -1:
        raise MsfError('bad-dbi', 'unsupported DBI version signature')
    sizes = (mod_size, sc_size, sm_size, fi_size, ts_size, ec_size, dbg_size)
    if any(s < 0 for s in sizes) or 64 + sum(sizes) > len(data):
        raise MsfError('bad-dbi', 'DBI substreams run past the stream')
    modules, pos, end = [], 64, 64 + mod_size
    while pos + 64 <= end:
        if len(modules) >= MAX_MODULES:
            raise MsfError('limit', f'more than {MAX_MODULES} modules')
        stream, sym_bytes = struct.unpack_from('<HI', data, pos + 34)
        name_end = data.find(b'\0', pos + 64, min(end, pos + 64 + MAX_NAME + 1))
        obj_end = data.find(b'\0', name_end + 1, min(end, name_end + 1 + MAX_NAME + 1)) if name_end >= 0 else -1
        if obj_end < 0:
            raise MsfError('bad-dbi', 'module record names are not terminated')
        modules.append((stream, sym_bytes))
        pos = obj_end + 1
        pos += (-pos) % 4
    dbg_start = 64 + mod_size + sc_size + sm_size + fi_size + ts_size + ec_size
    count = dbg_size // 2
    dbg = struct.unpack_from(f'<{count}H', data, dbg_start) if count else ()
    if end - pos >= 4:
        warn.add('module info substream has trailing bytes')
    return _Dbi(age, sym_stream, flags, machine, tuple(modules), tuple(dbg))


def _sections(data: bytes) -> tuple[Section, ...]:
    count = len(data) // 40
    if count > MAX_SECTIONS:
        raise MsfError('limit', f'more than {MAX_SECTIONS} section headers')
    out = []
    for i in range(count):
        raw_name, vsize, va = struct.unpack_from('<8sII', data, i * 40)
        out.append(Section(raw_name.rstrip(b'\0').decode('latin-1'), va, vsize))
    return tuple(out)


class Omap:
    """OMAP-from-source table: maps original RVAs to final image RVAs (to == 0 means unmapped)."""

    def __init__(self, data: bytes):
        count = len(data) // 8
        pairs = [struct.unpack_from('<II', data, i * 8) for i in range(count)]
        if any(a[0] > b[0] for a, b in zip(pairs, pairs[1:], strict=False)):
            raise MsfError('bad-omap', 'OMAP table is not sorted')
        self.froms = [p[0] for p in pairs]
        self.tos = [p[1] for p in pairs]

    def map(self, rva: int) -> int | None:
        i = bisect.bisect_right(self.froms, rva) - 1
        if i < 0 or self.tos[i] == 0:
            return None
        return self.tos[i] + (rva - self.froms[i])


def _stream_or_none(msf: MsfFile, dbg: tuple[int, ...], slot: int) -> bytes | None:
    if slot >= len(dbg) or dbg[slot] == NO_STREAM:
        return None
    data = msf.stream(dbg[slot])
    return data or None


def _identity(msf: MsfFile, warn: _Warnings) -> tuple[PdbInfo, _Dbi]:
    if len(msf.streams) <= STREAM_DBI:
        raise MsfError('bad-pdb', 'PDB has no DBI stream')
    info = msf.stream(STREAM_PDB)
    if len(info) < 28:
        raise MsfError('bad-pdb', 'PDB info stream is too short')
    _version, signature, info_age = struct.unpack_from('<III', info, 0)
    guid = str(uuid.UUID(bytes_le=info[12:28]))
    dbi = _parse_dbi(msf.stream(STREAM_DBI), warn)
    omap = DBG_OMAP_FROM_SRC < len(dbi.dbg) and dbi.dbg[DBG_OMAP_FROM_SRC] != NO_STREAM
    return PdbInfo(guid=guid, age=dbi.age, info_age=info_age, signature=signature,
                   stripped=bool(dbi.flags & FLAG_STRIPPED), machine=dbi.machine, omap=omap), dbi


def _guarded(fn):
    """Fault boundary: hostile input may only surface as MsfError (never struct.error, IndexError, ...)."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except MsfError:
            raise
        except (struct.error, ValueError, IndexError, OverflowError, UnicodeError) as exc:
            raise MsfError('bad-pdb', f'malformed PDB ({type(exc).__name__})') from None
    wrapper.__name__, wrapper.__doc__ = fn.__name__, fn.__doc__
    return wrapper


@_guarded
def read_identity(path: Path, cancel: Callable[[], bool] | None = None) -> PdbInfo:
    with MsfFile(path, cancel) as msf:
        return _identity(msf, _Warnings())[0]


@_guarded
def read_pdb(path: Path, cancel: Callable[[], bool] | None = None,
             fallback_sections: tuple[Section, ...] = ()) -> PdbIndex:
    """Full index. `fallback_sections` (from the PE) map segments when the PDB has no section header stream."""
    warn = _Warnings()
    with MsfFile(path, cancel) as msf:
        info, dbi = _identity(msf, warn)
        current = _stream_or_none(msf, dbi.dbg, DBG_SECTION_HDR)
        original = _stream_or_none(msf, dbi.dbg, DBG_SECTION_HDR_ORIG)
        omap_data = _stream_or_none(msf, dbi.dbg, DBG_OMAP_FROM_SRC)
        omap = Omap(omap_data) if omap_data else None
        sections = _sections(current) if current else tuple(fallback_sections)
        if not current:
            warn.add('PDB has no section header stream; segments mapped through the PE section table'
                     if fallback_sections else 'PDB has no section header stream; RVAs unknown')
        base = _sections(original) if omap and original else sections
        if omap and not original:
            warn.add('OMAP present without original section headers; mapping through current sections')

        def rva_of(segment: int, offset: int) -> int | None:
            if not 1 <= segment <= len(base):
                return None
            rva = base[segment - 1].virtual_address + offset
            return omap.map(rva) if omap else rva
        budget = [MAX_RECORDS]
        check = msf._check_cancel
        publics = []
        if dbi.sym_stream != NO_STREAM:
            data = msf.stream(dbi.sym_stream)
            for kind, start, end in _records(data, 0, len(data), budget, check):
                if kind != S_PUB32:
                    continue
                if end - start < 11:
                    raise MsfError('bad-record', 'S_PUB32 record too short')
                flags, offset, segment = struct.unpack_from('<IIH', data, start)
                name = _cstring(data, start + 10, end, warn)
                publics.append(PdbSymbol(name, segment, offset, rva_of(segment, offset), 'public',
                                         bool(flags & 0x3), None))
        procedures = []
        for stream, sym_bytes in dbi.modules:
            if stream == NO_STREAM or sym_bytes < 4:
                continue
            data = msf.stream(stream)
            limit = min(sym_bytes, len(data))
            (signature,) = struct.unpack_from('<I', data, 0) if len(data) >= 4 else (0,)
            if signature not in (1, 2, 4):
                warn.add(f'module stream {stream}: unknown symbol signature {signature}; skipped')
                continue
            for kind, start, end in _records(data, 4, limit, budget, check):
                if kind in PROC_KINDS:
                    if end - start < 36:
                        raise MsfError('bad-record', 'procedure record too short')
                    code_size, = struct.unpack_from('<I', data, start + 12)
                    offset, segment = struct.unpack_from('<IH', data, start + 28)
                    name = _cstring(data, start + 35, end, warn)
                    procedures.append(PdbSymbol(name, segment, offset, rva_of(segment, offset), 'private', True,
                                                code_size))
                elif kind == S_THUNK32:
                    if end - start < 22:
                        raise MsfError('bad-record', 'thunk record too short')
                    offset, segment, length = struct.unpack_from('<IHH', data, start + 12)
                    name = _cstring(data, start + 21, end, warn)
                    procedures.append(PdbSymbol(name, segment, offset, rva_of(segment, offset), 'private', True,
                                                length, thunk=True))
        unmapped = sum(1 for s in publics + procedures if s.rva is None)
        if unmapped:
            warn.add(f'{unmapped} symbols have a segment outside the section table (no RVA)')
        return PdbIndex(info, tuple(publics), tuple(procedures), sections, tuple(warn))


def is_pdb_magic(head: bytes) -> bool:
    return head.startswith(MAGIC[:24]) or head.startswith(MAGIC_V2[:30])
