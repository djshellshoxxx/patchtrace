"""Synthetic PE resource (.rsrc) writer for tests. Bytes only, never executed.

The layout follows what resource compilers emit (directories, then name strings, then data entries, then the
data), so parsers see realistic offsets. Nodes are laid out by identity, which is what makes hostile shapes
expressible with the same primitives: a directory that lists itself (cycle), two entries that share one child
(DAG), a fan of thousands of entries, literal offsets no layout would produce, lying sizes and lying counts.
`version_blob` writes VS_VERSIONINFO nodes through one `node` helper so tests can corrupt single fields.
"""
from __future__ import annotations

import hashlib
import importlib.util
import struct
from collections import deque
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path

from pe_builder import RDATA, SECTION_ALIGN, PeSpec, SectionSpec, align, build_pe_ex

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, PeOverview, SectionMap, inspect_pe
from patchtrace.pe_overview._common import Ctx
from patchtrace.pe_overview.models import DataDirectory

RT_ICON = 3
RT_RCDATA = 10
RT_VERSION = 16
RT_MANIFEST = 24
LANG_EN_US = 0x409
HIGH = 0x80000000
DEFAULT_LIMITS = Limits()


@dataclass(eq=False)
class Data:
    """A resource leaf. `size` and `rva` override the declared Size and OffsetToData to make them lie."""

    payload: bytes = b''
    codepage: int = 0
    size: int | None = None
    rva: int | None = None


@dataclass(frozen=True)
class Name:
    """A string-named entry whose declared Length can differ from the characters actually written."""

    text: str
    length: int | None = None


@dataclass(frozen=True)
class Raw:
    """A literal entry target, for offsets no layout would produce."""

    offset: int
    directory: bool = False


@dataclass(eq=False)
class Dir:
    """A resource directory. `entries` are (id | str | Name, Dir | Data | Raw) pairs.

    Entries are written as a compiler would (names first, then ids ascending) unless `keep_order` is set;
    `named` and `ids` override the two declared counts.
    """

    entries: list = field(default_factory=list)
    named: int | None = None
    ids: int | None = None
    keep_order: bool = False


def tree(spec: dict) -> Dir:
    """{type: {name: {lang: bytes | Data}}} to a Dir; any depth, bytes become Data."""
    def child(value):
        if isinstance(value, dict):
            return tree(value)
        return Data(value) if isinstance(value, bytes) else value
    return Dir([(key, child(value)) for key, value in spec.items()])


def _is_name(key) -> bool:
    return isinstance(key, (str, Name))


def _text(key) -> str:
    return key.text if isinstance(key, Name) else key


def _ordered(directory: Dir) -> list:
    if directory.keep_order:
        return list(directory.entries)
    named = sorted((e for e in directory.entries if _is_name(e[0])), key=lambda e: _text(e[0]).lower())
    ids = sorted((e for e in directory.entries if not _is_name(e[0])), key=lambda e: e[0])
    return named + ids


def _collect(root: Dir) -> list[Dir]:
    seen = {id(root)}
    order = [root]
    queue = deque([root])
    while queue:
        for _key, target in queue.popleft().entries:
            if isinstance(target, Dir) and id(target) not in seen:
                seen.add(id(target))
                order.append(target)
                queue.append(target)
    return order


def serialize(root: Dir, base_rva: int) -> bytes:
    """Lay out every node reachable from `root`; `base_rva` is where the blob will sit in the image."""
    dirs = _collect(root)
    offsets: dict[int, int] = {}
    cursor = 0
    for directory in dirs:
        offsets[id(directory)] = cursor
        cursor += 16 + 8 * len(directory.entries)
    names: dict[str, tuple[int, int]] = {}  # text -> (offset, declared Length)
    for directory in dirs:
        for key, _target in directory.entries:
            if _is_name(key) and _text(key) not in names:
                declared = key.length if isinstance(key, Name) and key.length is not None else len(_text(key))
                names[_text(key)] = (cursor, declared)
                cursor = align(cursor + 2 + 2 * len(_text(key)), 2)
    cursor = align(cursor, 4)
    unique = list({id(t): t for d in dirs for _k, t in d.entries if isinstance(t, Data)}.values())
    entry_at = {id(item): cursor + 16 * i for i, item in enumerate(unique)}
    cursor += 16 * len(unique)
    payload_at: dict[int, int] = {}
    for item in unique:
        cursor = align(cursor, 8)
        payload_at[id(item)] = cursor
        cursor += len(item.payload)

    out = bytearray(align(cursor, 4))
    for directory in dirs:
        pos = offsets[id(directory)]
        entries = _ordered(directory)
        named_count = sum(_is_name(k) for k, _ in entries)
        struct.pack_into('<IIHHHH', out, pos, 0, 0, 0, 0,
                         directory.named if directory.named is not None else named_count,
                         directory.ids if directory.ids is not None else len(entries) - named_count)
        for i, (key, target) in enumerate(entries):
            first = (HIGH | names[_text(key)][0]) if _is_name(key) else key
            if isinstance(target, Dir):
                second = HIGH | offsets[id(target)]
            elif isinstance(target, Raw):
                second = (HIGH if target.directory else 0) | target.offset
            else:
                second = entry_at[id(target)]
            struct.pack_into('<II', out, pos + 16 + 8 * i, first, second)
    for text, (pos, declared) in names.items():
        struct.pack_into('<H', out, pos, declared)
        out[pos + 2:pos + 2 + 2 * len(text)] = text.encode('utf-16-le', 'surrogatepass')
    for item in unique:
        rva = item.rva if item.rva is not None else base_rva + payload_at[id(item)]
        size = item.size if item.size is not None else len(item.payload)
        struct.pack_into('<IIII', out, entry_at[id(item)], rva, size, item.codepage, 0)
        out[payload_at[id(item)]:payload_at[id(item)] + len(item.payload)] = item.payload
    return bytes(out)


def next_section_rva(spec: PeSpec) -> int:
    """RVA `build_pe_ex` gives a section appended after those already in `spec`."""
    rva = SECTION_ALIGN
    for section in spec.sections:
        vsize = section.virtual_size if section.virtual_size is not None else len(section.data)
        rva += align(max(vsize, 1), SECTION_ALIGN)
    return rva


def rsrc_pe(root: Dir | bytes, *, spec: PeSpec | None = None, declared_size: int | None = None,
            declared_rva: int | None = None) -> tuple[bytes, dict]:
    """A PE whose last explicit section is `.rsrc` and whose Resource directory points at it.

    `root` may be a Dir or an already built blob. `declared_size` and `declared_rva` make the data directory lie.
    """
    base = spec or PeSpec()
    rva = next_section_rva(base)
    blob = root if isinstance(root, bytes) else serialize(root, rva)
    built = replace(base, sections=[*base.sections, SectionSpec('.rsrc', blob, RDATA)],
                    extra_directories={**base.extra_directories, 2: (
                        declared_rva if declared_rva is not None else rva,
                        declared_size if declared_size is not None else len(blob))})
    data, info = build_pe_ex(built)
    name, srva, _vsize, soff, _rsize = info['sections'][len(built.sections) - 1]
    assert (name, srva) == ('.rsrc', rva), 'builder RVA prediction drifted from pe_builder'
    return data, {**info, 'rsrc_rva': rva, 'rsrc_off': soff, 'rsrc_size': len(blob)}


def leaf_file_offset(info: dict, rva: int) -> int:
    return info['rsrc_off'] + (rva - info['rsrc_rva'])


def real_launchers() -> list[Path]:
    """Real MSVC-built Windows executables that ship inside pip (distlib's script launchers). Never copied into
    the repository; the tests that use them skip when pip carries none."""
    spec = importlib.util.find_spec('pip')
    folder = Path(spec.origin).parent / '_vendor' / 'distlib' if spec is not None and spec.origin else None
    return sorted(folder.glob('*.exe')) if folder is not None and folder.is_dir() else []


@dataclass
class Opened:
    reader: VerifiedArtifactReader
    ctx: Ctx
    overview: PeOverview
    smap: SectionMap
    resource: DataDirectory | None

    def codes(self) -> set[str]:
        return {w.code for w in self.ctx.warnings}


@contextmanager
def open_pe(tmp_path: Path, data: bytes, *, limits: Limits = DEFAULT_LIMITS, cancel=None,
            name: str = 'sample.bin') -> Iterator[Opened]:
    path = tmp_path / name
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        overview = inspect_pe(reader)
        yield Opened(reader, Ctx(reader, cancel, limits), overview, overview.section_map(),
                     overview.directory('Resource'))


def noise(count: int, seed: bytes = b'seed') -> bytes:
    """Deterministic pseudo-random bytes for mutation tests."""
    out = bytearray()
    block = 0
    while len(out) < count:
        out += hashlib.sha256(seed + struct.pack('<I', block)).digest()
        block += 1
    return bytes(out[:count])


def mutate(data: bytes, seed: int, flips: int = 12, start: int = 0, end: int | None = None) -> bytes:
    """Overwrite `flips` positions inside [start, end) with deterministic noise."""
    end = len(data) if end is None else end
    rnd = noise(flips * 4, b'mut%d' % seed)
    out = bytearray(data)
    for i in range(flips):
        pos = start + int.from_bytes(rnd[i * 4:i * 4 + 3], 'little') % max(1, end - start)
        out[pos] = rnd[i * 4 + 3]
    return bytes(out)


# -- VS_VERSIONINFO -------------------------------------------------------------------------------------------


def pad4(length: int) -> bytes:
    return b'\0' * (-length % 4)


def utf16z(text: str) -> bytes:
    return (text + '\0').encode('utf-16-le', 'surrogatepass')


def node(key: str | bytes, value: bytes = b'', *, wtype: int = 1, value_length: int | None = None,
         children: Sequence[bytes] = ()) -> bytes:
    """One version node: header, key, padding, value, then DWORD-aligned children.

    wLength excludes the padding that follows the node, as the format requires; a parent adds that padding
    between siblings. `key` may be raw bytes to write a malformed key.
    """
    body = bytearray(struct.pack('<HHH', 0, len(value) if value_length is None else value_length, wtype))
    body += key if isinstance(key, bytes) else utf16z(key)
    body += pad4(len(body)) + value
    for child in children:
        body += pad4(len(body)) + child
    struct.pack_into('<H', body, 0, len(body))
    return bytes(body)


def fixed_file_info(file_version=(1, 0, 0, 1), product_version=None, *, mask=0x3F, flags=0, file_os=0x40004,
                    file_type=1, subtype=0, signature=0xFEEF04BD) -> bytes:
    product = product_version or file_version

    def pair(quad):
        return (quad[0] << 16 | quad[1], quad[2] << 16 | quad[3])
    return struct.pack('<13I', signature, 0x10000, *pair(file_version), *pair(product), mask, flags, file_os,
                       file_type, subtype, 0, 0)


def string_node(key: str, value: str) -> bytes:
    return node(key, utf16z(value), value_length=len(value) + 1)


def string_table(lang_codepage: str, strings: dict[str, str]) -> bytes:
    return node(lang_codepage, children=[string_node(k, v) for k, v in strings.items()])


def var_node(translations: Sequence[tuple[int, int]]) -> bytes:
    value = b''.join(struct.pack('<HH', lang, codepage) for lang, codepage in translations)
    return node('Translation', value, wtype=0)


def version_blob(file_version=(1, 0, 0, 1), product_version=None, *, strings: dict[str, dict[str, str]] | None = None,
                 translations: Sequence[tuple[int, int]] | None = ((LANG_EN_US, 0x4B0),), fixed: bool = True,
                 root_key: str | bytes = 'VS_VERSION_INFO', **fixed_kw) -> bytes:
    """A well-formed VS_VERSIONINFO unless a keyword says otherwise; `strings` maps table key to its strings."""
    children = []
    if strings is not None:
        children.append(node('StringFileInfo', children=[string_table(k, v) for k, v in strings.items()]))
    if translations is not None:
        children.append(node('VarFileInfo', children=[var_node(translations)]))
    value = fixed_file_info(file_version, product_version, **fixed_kw) if fixed else b''
    return node(root_key, value, wtype=0, children=children)


def standard_strings(version: str = '1.0.0.1') -> dict[str, dict[str, str]]:
    return {'040904B0': {'CompanyName': 'Example Corp', 'FileDescription': 'Example', 'FileVersion': version,
                         'InternalName': 'example', 'OriginalFilename': 'example.dll',
                         'ProductName': 'Example Product', 'ProductVersion': version}}
