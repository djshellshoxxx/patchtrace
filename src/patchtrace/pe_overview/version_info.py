"""VS_VERSIONINFO reader for RT_VERSION resources (WBQ S1; format facts in SPEC-26 D2).

A version resource is a tree of length-prefixed nodes: the root holds VS_FIXEDFILEINFO and its children
StringFileInfo (tables of strings, one per language and code page) and VarFileInfo (the Translation list). Each
node is `wLength, wValueLength, wType, szKey, padding, value, padding, children` with DWORD alignment relative to
the start of the resource, and `wLength` excludes the padding that follows the node.

Every length in the file is untrusted. A node that claims more than its parent holds is clamped and flagged, a node
shorter than its header ends the level, siblings are located only by `wLength` (so a bad key or value cannot
desynchronise them), and the walk always advances, so it terminates. Strings are decoded leniently and cleaned of
control and bidirectional characters. All blocks are kept; the block with the lowest name then language is the
primary one (the same pick as the CSAF identity reader), and facts that disagree are listed, never reconciled.
A file version describes the file, not the Windows build or the file's authenticity.
"""
from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from ._common import Ctx
from .models import SectionMap
from .resources import (
    DEFAULT_RESOURCE_LIMITS,
    RT_VERSION,
    ResourceInventory,
    ResourceLeaf,
    ResourceLimits,
    decode_utf16,
    leaves_of_type,
    read_leaf,
)

_HEADER = 6
_FIXED_SIZE = 52
_SIGNATURE = 0xFEEF04BD
_ROOT_KEY = 'VS_VERSION_INFO'
_TABLE_KEY = re.compile(r'[0-9A-Fa-f]{8}')
_LEADING_VERSION = re.compile(r'\s*(\d+(?:\s*[.,]\s*\d+){0,3})')
_MESSAGES = {
    'version_block_malformed': 'a version resource has an inconsistent length, key or value; the readable part is kept',
    'version_over_cap': 'a version resource exceeded a size or count limit; the values shown are partial',
    'version_key_mismatch': 'a version resource key is not the documented one',
}

Quad = tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class FixedFileInfo:
    file_version: Quad
    product_version: Quad
    flags_mask: int
    flags: int
    os: int
    type: int
    subtype: int


@dataclass(frozen=True, slots=True)
class VersionString:
    lang_codepage: str
    key: str
    value: str
    truncated: bool


@dataclass(frozen=True, slots=True)
class VersionBlock:
    """One RT_VERSION leaf. `status` is ok | partial | malformed | unreadable; `warnings` are warning codes."""

    leaf: ResourceLeaf
    fixed: FixedFileInfo | None
    strings: tuple[VersionString, ...]
    translations: tuple[str, ...]
    status: str
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VersionInfoSet:
    """Blocks ordered by (name, language); `contradictions` are stable codes such as fixed_disagree:file_version."""

    blocks: tuple[VersionBlock, ...]
    primary_index: int | None
    contradictions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Node:
    end: int
    value_length: int
    key: str
    key_cut: bool
    value_start: int


def version_text(quad: Quad) -> str:
    return '.'.join(str(part) for part in quad)


def parse_version_info(ctx: Ctx, smap: SectionMap, inventory: ResourceInventory,
                       limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS) -> VersionInfoSet:
    """Every RT_VERSION leaf of the inventory (at most `max_version_blocks`) as a block; none gives an empty set."""
    leaves = leaves_of_type(inventory, RT_VERSION)
    if len(leaves) > limits.max_version_blocks:
        ctx.warn('version_over_cap', f'more than {limits.max_version_blocks} version resources; the rest are not read')
        leaves = leaves[:limits.max_version_blocks]
    blocks = tuple(_block(ctx, smap, leaf, limits) for leaf in leaves)
    return VersionInfoSet(blocks, 0 if blocks else None, _contradictions(blocks))


def _block(ctx: Ctx, smap: SectionMap, leaf: ResourceLeaf, limits: ResourceLimits) -> VersionBlock:
    ctx.check()
    data = read_leaf(ctx, smap, leaf, limits.max_version_bytes)
    if not data and leaf.size:
        ctx.warn('version_block_malformed', 'version data is not backed by file bytes')
        return VersionBlock(leaf, None, (), (), 'unreadable', ('version_block_malformed',))
    parser = _Parser(data, leaf.size > limits.max_version_bytes, limits)
    usable = parser.run()
    if parser.capped:
        parser.flag('version_over_cap')
    for code in parser.warnings:
        ctx.warn(code, _MESSAGES[code])
    status = 'malformed' if not usable else 'partial' if parser.warnings else 'ok'
    return VersionBlock(leaf, parser.fixed, tuple(parser.strings), tuple(parser.translations), status,
                        tuple(parser.warnings))


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _quad(high: int, low: int) -> Quad:
    return (high >> 16, high & 0xFFFF, low >> 16, low & 0xFFFF)


def _find_nul(data: bytes, start: int, end: int) -> int:
    """Offset of the first UTF-16 NUL unit in [start, end), -1 when there is none."""
    position = start
    while True:
        found = data.find(b'\0\0', position, end)
        if found < 0 or (found - start) % 2 == 0:
            return found
        position = found + 1


class _Parser:
    def __init__(self, data: bytes, capped: bool, limits: ResourceLimits):
        self.data, self.capped, self.limits = data, capped, limits
        self.warnings: list[str] = []
        self.fixed: FixedFileInfo | None = None
        self.strings: list[VersionString] = []
        self.translations: list[str] = []

    def flag(self, code: str) -> None:
        if code not in self.warnings:
            self.warnings.append(code)

    def run(self) -> bool:
        """Read the root and its children; False when the root itself is unusable."""
        root = self._node(0, len(self.data))
        if root is None:
            return False
        if root.key != _ROOT_KEY:
            self.flag('version_key_mismatch')
            return False
        value_end = root.value_start + root.value_length
        if root.value_length:
            if root.value_length < _FIXED_SIZE:
                self.flag('version_block_malformed')
                return False
            if value_end > root.end:
                self._overrun(root.end)
                return False
            self._fixed(root.value_start)
        pos = _align4(value_end)
        while pos + _HEADER <= root.end:
            child = self._node(pos, root.end)
            if child is None:
                break
            kind = child.key.casefold()
            if kind == 'stringfileinfo':
                self._string_file_info(child)
            elif kind == 'varfileinfo':
                self._var_file_info(child)
            pos = _align4(child.end)
        return True

    def _overrun(self, limit: int) -> None:
        """A node reaches past `limit`: the byte cap if `limit` is the end of the data we read, else a bad length."""
        self.flag('version_over_cap' if self.capped and limit >= len(self.data) else 'version_block_malformed')

    def _node(self, pos: int, limit: int) -> _Node | None:
        """The node whose header starts at `pos`, or None (flagged) when no node can start there."""
        if limit - pos < _HEADER:
            self._overrun(limit)
            return None
        length, value_length, _kind = struct.unpack_from('<HHH', self.data, pos)
        if length < _HEADER:
            self.flag('version_block_malformed')
            return None
        end = pos + length
        if end > limit:
            self._overrun(limit)
            end = limit
        terminator = _find_nul(self.data, pos + _HEADER, end)
        if terminator < 0:
            self.flag('version_block_malformed')
            return None
        key, cut = decode_utf16(self.data[pos + _HEADER:terminator], self.limits.max_name_chars)
        return _Node(end, value_length, key, cut, min(_align4(terminator + 2), end))

    def _fixed(self, start: int) -> None:
        values = struct.unpack_from('<13I', self.data, start)
        if values[0] != _SIGNATURE:
            self.flag('version_block_malformed')
            return
        _sig, _struct_version, fms, fls, pms, pls, mask, flags, file_os, file_type, subtype, _dms, _dls = values
        self.fixed = FixedFileInfo(_quad(fms, fls), _quad(pms, pls), mask, flags, file_os, file_type, subtype)

    def _children(self, parent: _Node) -> Iterator[_Node]:
        """The child nodes of `parent`, stopping at the first one that cannot be read."""
        pos = parent.value_start
        while pos + _HEADER <= parent.end:
            child = self._node(pos, parent.end)
            if child is None:
                return
            yield child
            pos = _align4(child.end)

    def _string_file_info(self, node: _Node) -> None:
        for table in self._children(node):
            self._string_table(table)

    def _string_table(self, table: _Node) -> None:
        lang_codepage = table.key
        if _TABLE_KEY.fullmatch(lang_codepage):
            lang_codepage = lang_codepage.upper()
        else:
            self.flag('version_key_mismatch')
        for count, item in enumerate(self._children(table)):
            if count >= self.limits.max_version_keys:
                self.flag('version_over_cap')
                return
            value, cut = self._string_value(item)
            self.strings.append(VersionString(lang_codepage, item.key, value, cut or item.key_cut))

    def _string_value(self, item: _Node) -> tuple[str, bool]:
        end = _find_nul(self.data, item.value_start, item.end)
        return decode_utf16(self.data[item.value_start:item.end if end < 0 else end], self.limits.max_value_chars)

    def _var_file_info(self, node: _Node) -> None:
        for var in self._children(node):
            if var.key.casefold() == 'translation':
                self._translation(var)

    def _translation(self, var: _Node) -> None:
        raw = self.data[var.value_start:min(var.value_start + var.value_length, var.end)]
        pairs = len(raw) // 4
        if pairs > self.limits.max_version_keys:
            self.flag('version_over_cap')
            pairs = self.limits.max_version_keys
        for index in range(pairs):
            language, codepage = struct.unpack_from('<HH', raw, 4 * index)
            self.translations.append(f'{language:04X}{codepage:04X}')


def _leading_version(text: str) -> Quad | None:
    """The version a string starts with ('1, 0, 0, 1', '10.0.19041.1 (build)'), padded with zeros, else None."""
    match = _LEADING_VERSION.match(text)
    if match is None:
        return None
    parts = [int(part) for part in re.findall(r'\d+', match.group(1))] + [0, 0, 0]
    return (parts[0], parts[1], parts[2], parts[3])


def _contradictions(blocks: tuple[VersionBlock, ...]) -> tuple[str, ...]:
    found: set[str] = set()
    fixed = [block.fixed for block in blocks if block.fixed is not None]
    for name in ('file_version', 'product_version'):
        if len({getattr(item, name) for item in fixed}) > 1:
            found.add(f'fixed_disagree:{name}')
    for key in ('FileVersion', 'ProductVersion'):
        if len({item.value for block in blocks for item in block.strings if item.key == key}) > 1:
            found.add(f'string_disagree:{key}')
    for block in blocks:
        if block.fixed is None:
            continue
        for key, quad in (('FileVersion', block.fixed.file_version), ('ProductVersion', block.fixed.product_version)):
            for item in block.strings:
                if item.key == key and _leading_version(item.value) not in (None, quad):
                    found.add(f'fixed_vs_string:{key}')
    return tuple(sorted(found))
