"""Identity facts for CSAF applicability (SPEC-28 section G), taken from verified bytes only.

Facts: the SHA-256 verified on the read handle, the VS_FIXEDFILEINFO file and product versions of the RT_VERSION
resource, and the CodeView PDB name/GUID/age from ``pe_overview``. The file name is never an identity fact.
A Windows file version describes the file, not the operating-system build an advisory names; applicability
treats a version-based mapping as a candidate, never as verified.

The resource walk is bounded: three directory levels (type, name, language), at most 64 entries per directory,
every offset inside the resource directory's declared size, data at most 64 KiB. Malformed resources yield a
note, never an exception.
"""
from __future__ import annotations

import re
import struct
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ...artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from ...pe_overview.inspect import inspect_pe
from ...pe_overview.models import PeOverview
from ..contracts import ArtifactIdentity, IntelError, PdbIdentity

RT_VERSION = 16
MAX_DIR_ENTRIES = 64
MAX_VERSION_BYTES = 64 * 1024
VS_SIGNATURE = 0xFEEF04BD
_KEY = 'VS_VERSION_INFO\0'.encode('utf-16-le')


@dataclass(frozen=True)
class VersionInfo:
    file_version: str | None
    product_version: str | None
    note: str | None = None


class _Bad(Exception):
    pass


def _version(ms: int, ls: int) -> str:
    return f'{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}'


def read_version_info(reader: VerifiedArtifactReader, overview: PeOverview) -> VersionInfo:
    """VS_FIXEDFILEINFO versions of the first RT_VERSION resource (lowest name id, lowest language id)."""
    directory = overview.directory('Resource')
    if directory is None or not directory.present:
        return VersionInfo(None, None, 'no resource directory')
    smap = overview.section_map()
    base, limit = directory.rva, directory.size

    def read_rva(rva: int, length: int) -> bytes:
        ranges = smap.rva_to_file_ranges(rva, length)
        if not ranges:
            raise _Bad('resource bytes are not backed by the file')
        data = b''.join(reader.read(r.file_offset, r.length, clip=False) for r in ranges)
        if len(data) != length:
            raise _Bad('short resource read')
        return data

    def read_dir(offset: int, length: int) -> bytes:
        if offset < 0 or offset + length > limit:
            raise _Bad('resource offset outside the resource directory')
        return read_rva(base + offset, length)

    def entries(offset: int) -> list[tuple[int | None, int, bool]]:
        named, ids = struct.unpack_from('<HH', read_dir(offset, 16), 12)
        count = min(named + ids, MAX_DIR_ENTRIES)
        raw = read_dir(offset + 16, 8 * count) if count else b''
        out = []
        for i in range(count):
            name, target = struct.unpack_from('<II', raw, 8 * i)
            out.append((None if name & 0x80000000 else name & 0xFFFF, target & 0x7FFFFFFF, bool(target & 0x80000000)))
        return out

    def pick(items: list[tuple[int | None, int, bool]], want_dir: bool) -> int:
        usable = sorted((ident, target) for ident, target, is_dir in items if ident is not None and is_dir == want_dir)
        if not usable:
            raise _Bad('no usable resource entry')
        return usable[0][1]

    try:
        types = [(ident, target, is_dir) for ident, target, is_dir in entries(0) if ident == RT_VERSION]
        if not types:
            return VersionInfo(None, None, 'no version resource')
        names = pick(types, True)
        languages = pick(entries(names), True)
        data_entry = pick(entries(languages), False)
        data_rva, size = struct.unpack_from('<II', read_dir(data_entry, 16), 0)
        if size < 92:
            raise _Bad('version resource too small')
        blob = read_rva(data_rva, min(size, MAX_VERSION_BYTES))
        _length, value_length, _type = struct.unpack_from('<HHH', blob, 0)
        if blob[6:6 + len(_KEY)] != _KEY:
            raise _Bad('VS_VERSION_INFO key missing')
        if value_length < 52:
            return VersionInfo(None, None, 'version resource has no fixed file info')
        signature, _struc, fms, fls, pms, pls = struct.unpack_from('<IIIIII', blob, 40)
        if signature != VS_SIGNATURE:
            raise _Bad('VS_FIXEDFILEINFO signature mismatch')
        return VersionInfo(_version(fms, fls), _version(pms, pls))
    except (_Bad, struct.error) as exc:
        return VersionInfo(None, None, f'version resource unusable: {exc}')


def _pdb(overview: PeOverview) -> PdbIdentity | None:
    info = overview.codeview
    if info is None:
        return None
    name = re.split(r'[\\/]', info.pdb_path)[-1].strip().replace('\0', '')[:260]
    guid = re.sub(r'[^0-9A-Fa-f]', '', info.guid).upper()
    if not name or len(guid) != 32:
        return None
    return PdbIdentity(name=name, guid=guid, age=info.age)


def identity_from_reader(side: str, reader: VerifiedArtifactReader, *, asserted_product_ids: Sequence[str] = (),
                         cancel: threading.Event | None = None) -> ArtifactIdentity:
    overview = inspect_pe(reader, cancel=(lambda: cancel.is_set()) if cancel is not None else None)
    if overview.status == 'cancelled':
        raise IntelError('PT-INTEL-CANCEL', 'identity inspection cancelled', recoverable=True)
    notes = []
    try:
        version = read_version_info(reader, overview)
    except ArtifactBytesError as exc:
        version = VersionInfo(None, None, f'version resource unreadable ({exc.code})')
    if version.note:
        notes.append(version.note)
    pdb = _pdb(overview)
    if pdb is None:
        notes.append('no CodeView PDB identity')
    return ArtifactIdentity(side=side, sha256=reader.sha256, file_version=version.file_version,
                            product_version=version.product_version, pdb_identity=pdb,
                            asserted_product_ids=tuple(sorted(set(asserted_product_ids))),
                            facts_state='verified-bytes', notes=tuple(notes))


def record_only(side: str, sha256: str, note: str, *, asserted_product_ids: Sequence[str] = ()) -> ArtifactIdentity:
    return ArtifactIdentity(side=side, sha256=sha256, asserted_product_ids=tuple(sorted(set(asserted_product_ids))),
                            facts_state='record-only', notes=(note,))


def project_identities(artifacts, root: Path, asserted: dict[str, Sequence[str]] | None = None,
                       cancel: threading.Event | None = None) -> tuple[ArtifactIdentity, ArtifactIdentity]:
    """(older, newer) identities of a project's two artifacts. Bytes that fail verification degrade one side to
    its recorded SHA-256 (``record-only``); they never stop the other side."""
    asserted = asserted or {}
    out = {}
    for artifact in artifacts:
        claims = asserted.get(artifact.side, ())
        try:
            with VerifiedArtifactReader.open_artifact(artifact, Path(root),
                                                      cancel=(lambda: cancel.is_set()) if cancel else None) as reader:
                out[artifact.side] = identity_from_reader(artifact.side, reader, asserted_product_ids=claims,
                                                          cancel=cancel)
        except ArtifactBytesError as exc:
            if exc.code == 'cancelled':
                raise IntelError('PT-INTEL-CANCEL', 'identity inspection cancelled', recoverable=True) from None
            out[artifact.side] = record_only(artifact.side, artifact.sha256,
                                             f'artifact bytes not verified ({exc.code}); only the recorded SHA-256 '
                                             'is available', asserted_product_ids=claims)
    if set(out) != {'older', 'newer'}:
        raise IntelError('PT-INTEL-INPUT', 'the project must have one older and one newer artifact')
    return out['older'], out['newer']
