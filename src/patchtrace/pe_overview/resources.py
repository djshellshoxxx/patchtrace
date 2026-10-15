"""Bounded reader for the PE resource tree (Type / Name / Language) over verified bytes.

Windows finds a resource by walking nested directories from the root. The format allows any depth but tools use
three levels (Type, Name, Language), so the reader follows up to four directory levels, the root being the first.
It lists every leaf without trusting the file: the walk is iterative, each directory is read once (a cycle or a
shared subtree is reported and skipped, never re-walked), counts, depth, names and nodes are capped, every read
is clipped to the bytes the section map backs, and a monotonic budget plus the cancel hook bound the time.
Structure (directories, names, data entries) must lie inside the declared directory size; leaf data is only
bound by the section map. An entry is a name or an id by the high bit of its first dword, as pefile and the CSAF
identity reader decide. It reports facts and does not interpret leaves: the version and manifest readers do.
Rules: docs/specs/program-e/WBQ-integration-plan.md sections 6 and 7. Text from the file is untrusted: control
and bidirectional characters are dropped.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from ._common import Ctx
from .models import FileRange, SectionMap

RT_VERSION = 16
RT_MANIFEST = 24
TYPE_LABELS = {
    1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU', 5: 'RT_DIALOG', 6: 'RT_STRING', 7: 'RT_FONTDIR',
    8: 'RT_FONT', 9: 'RT_ACCELERATOR', 10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE', 12: 'RT_GROUP_CURSOR',
    14: 'RT_GROUP_ICON', 16: 'RT_VERSION', 17: 'RT_DLGINCLUDE', 19: 'RT_PLUGPLAY', 20: 'RT_VXD',
    21: 'RT_ANICURSOR', 22: 'RT_ANIICON', 23: 'RT_HTML', 24: 'RT_MANIFEST',
}
# Types with a defined structure; the others (RCDATA, HTML, named and unknown types) can carry any payload.
_STRUCTURED_TYPES = frozenset(set(TYPE_LABELS) - {10, 23})
_DIR_HEADER = 16
_ENTRY = 8
_DATA_ENTRY = 16
_HIGH = 0x80000000
_LOW31 = 0x7FFFFFFF
_RVA_SPAN = 1 << 32
_MIN_EMBEDDED = 0x40
_BIDI_CONTROLS = (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
_DROPPED = {cp: None for cp in (*range(0x20), *range(0x7F, 0xA0), 0x2028, 0x2029, *_BIDI_CONTROLS)}


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Caps for the resource, version and manifest readers (and the Rich and export readers that share them)."""

    max_nodes: int = 20_000
    max_depth: int = 4
    max_dir_entries: int = 4_096
    max_name_chars: int = 256
    max_version_bytes: int = 65_536
    max_version_blocks: int = 16
    max_value_chars: int = 1_024
    max_version_keys: int = 64
    max_manifest_bytes: int = 2_097_152
    max_manifests: int = 16
    max_hash_bytes: int = 16_777_216
    max_rich_entries: int = 256
    max_exports: int = 20_000
    time_budget_s: float = 2.0


DEFAULT_RESOURCE_LIMITS = ResourceLimits()


@dataclass(frozen=True, slots=True)
class ResourceLeaf:
    """One resource. `name` and `lang` are numeric ids or cleaned string names, None when the tree is shallower.

    `size` is the declared size. `offset` is the file offset of the first data byte, None when that RVA is not
    backed by file data.
    """

    type_id: int | None
    type_label: str
    name: int | str | None
    lang: int | str | None
    rva: int
    size: int
    codepage: int
    offset: int | None


@dataclass(frozen=True, slots=True)
class ResourceInventory:
    """Leaves ordered by (type, name, language); `by_type` is (label, leaf count, declared bytes)."""

    leaves: tuple[ResourceLeaf, ...]
    by_type: tuple[tuple[str, int, int], ...]
    embedded_pe: tuple[ResourceLeaf, ...]
    truncated: bool


def sanitize_text(text: str) -> str:
    """Drop C0/C1 controls, line and paragraph separators and bidirectional controls from untrusted text."""
    return text.translate(_DROPPED)


def decode_utf16(raw: bytes, max_chars: int) -> tuple[str, bool]:
    """Lenient UTF-16LE: bad units become U+FFFD, a stray last byte is ignored, at most `max_chars` units are decoded.

    The flag says the input held more than that.
    """
    usable = len(raw) // 2 * 2
    kept = raw[:min(usable, 2 * max_chars)]
    return sanitize_text(kept.decode('utf-16-le', errors='replace')), usable > 2 * max_chars


def backed_ranges(smap: SectionMap, rva: int, want: int) -> tuple[FileRange, ...]:
    """File ranges of the longest prefix of [rva, rva + want) that the section map backs (empty if none)."""
    want = min(want, _RVA_SPAN - rva)
    if want <= 0:
        return ()
    whole = smap.rva_to_file_ranges(rva, want)
    if whole:
        return whole
    low, high = 0, want - 1  # `low` bytes are backed (zero trivially); `high + 1` or more are not
    while low < high:
        mid = (low + high + 1) // 2
        if smap.rva_to_file_ranges(rva, mid) is not None:
            low = mid
        else:
            high = mid - 1
    return smap.rva_to_file_ranges(rva, low) or ()


def read_leaf(ctx: Ctx, smap: SectionMap, leaf: ResourceLeaf, max_bytes: int) -> bytes:
    """The leaf's bytes, clipped to `max_bytes` and to what the file backs (shorter than asked means clipped)."""
    pieces: list[bytes] = []
    for span in backed_ranges(smap, leaf.rva, min(leaf.size, max_bytes)):
        position, remaining = span.file_offset, span.length
        while remaining > 0:
            ctx.check()
            piece = ctx.read(position, remaining)
            if not piece:
                return b''.join(pieces)
            pieces.append(piece)
            position += len(piece)
            remaining -= len(piece)
    return b''.join(pieces)


def leaves_of_type(inventory: ResourceInventory, type_id: int) -> tuple[ResourceLeaf, ...]:
    return tuple(leaf for leaf in inventory.leaves if leaf.type_id == type_id)


def parse_resources(ctx: Ctx, smap: SectionMap, rva: int, size: int,
                    limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS) -> ResourceInventory | None:
    """Inventory of the resource directory at `rva` (declared `size`), or None when it is not readable at all."""
    started = time.monotonic()
    spans = backed_ranges(smap, rva, size)
    if not spans or spans[0].length < _DIR_HEADER:
        ctx.warn('resource_dir_unreadable', 'the resource directory is not backed by file data')
        return None
    walk = _Walk(ctx, smap, _Tree(ctx, rva, spans[0].file_offset, spans[0].length), limits, started)
    walk.run()
    leaves = tuple(sorted(walk.leaves, key=_leaf_key))
    embedded = walk.sniff(leaves)
    return ResourceInventory(leaves, _by_type(leaves), embedded, walk.truncated)


@dataclass(frozen=True, slots=True)
class _Tree:
    """The file-backed window holding the directory structures; offsets are relative to the directory RVA."""

    ctx: Ctx
    rva: int
    file_offset: int
    limit: int

    def read(self, offset: int, length: int) -> bytes:
        """Up to `length` bytes at `offset`, never past the window."""
        if offset < 0 or length <= 0 or offset >= self.limit:
            return b''
        return self.ctx.read(self.file_offset + offset, min(length, self.limit - offset))


def _ident_key(value: int | str | None) -> tuple[int, int, str]:
    if value is None:
        return (0, 0, '')
    return (1, value, '') if isinstance(value, int) else (2, 0, value)


def _leaf_key(leaf: ResourceLeaf) -> tuple:
    return (leaf.type_id is None, leaf.type_id or 0, leaf.type_label, _ident_key(leaf.name), _ident_key(leaf.lang))


def _by_type(leaves: tuple[ResourceLeaf, ...]) -> tuple[tuple[str, int, int], ...]:
    totals: dict[tuple[bool, int, str], list[int]] = {}
    for leaf in leaves:
        entry = totals.setdefault((leaf.type_id is None, leaf.type_id or 0, leaf.type_label), [0, 0])
        entry[0] += 1
        entry[1] += leaf.size
    return tuple((key[2], count, total) for key, (count, total) in sorted(totals.items()))


class _Walk:
    def __init__(self, ctx: Ctx, smap: SectionMap, tree: _Tree, limits: ResourceLimits, started: float):
        self.ctx, self.smap, self.tree, self.limits, self.started = ctx, smap, tree, limits, started
        self.leaves: list[ResourceLeaf] = []
        self.truncated = False
        self._visited = {0}
        self._nodes = 0
        self._names: dict[int, str] = {}

    def run(self) -> None:
        if not self._take_node():
            return
        stack = [(0, 1, ())]  # (directory offset, depth with the root at 1, identities leading here)
        while stack and self._tick():
            offset, depth, path = stack.pop()
            self._directory(offset, depth, path, stack)

    def sniff(self, leaves: tuple[ResourceLeaf, ...]) -> tuple[ResourceLeaf, ...]:
        """Leaves of payload-carrying types whose data starts with MZ (a lexical hint, not a parse)."""
        found = []
        for leaf in leaves:
            if leaf.type_id in _STRUCTURED_TYPES or leaf.size < _MIN_EMBEDDED or leaf.offset is None:
                continue
            if not self._tick():
                break
            if self.ctx.read(leaf.offset, 2) == b'MZ':
                found.append(leaf)
        return tuple(found)

    def _tick(self) -> bool:
        """Poll cancellation and the time budget; False means stop and keep what was read."""
        self.ctx.check()
        if time.monotonic() - self.started >= self.limits.time_budget_s:
            self._stop('metadata_time_budget', f'resource reading stopped after {self.limits.time_budget_s} s')
            return False
        return True

    def _stop(self, code: str, message: str) -> None:
        self.ctx.warn(code, message)
        self.truncated = True

    def _take_node(self) -> bool:
        if self._nodes >= self.limits.max_nodes:
            self._stop('resource_nodes_over_cap', f'more than {self.limits.max_nodes} resource nodes; stopped')
            return False
        self._nodes += 1
        return True

    def _directory(self, offset: int, depth: int, path: tuple, stack: list) -> None:
        header = self.tree.read(offset, _DIR_HEADER)
        if len(header) < _DIR_HEADER:
            self._stop('resource_dir_unreadable', 'a resource directory is not backed by file data')
            return
        named, ids = struct.unpack_from('<HH', header, 12)
        declared = named + ids
        wanted = min(declared, self.limits.max_dir_entries)
        if declared > wanted:
            self._stop('resource_nodes_over_cap',
                       f'a resource directory declares {declared} entries; reading {wanted}')
        room = max(0, (self.tree.limit - offset - _DIR_HEADER) // _ENTRY)
        if room < wanted:
            self._stop('resource_dir_unreadable', 'a resource directory runs past the bytes the file backs')
        raw = self.tree.read(offset + _DIR_HEADER, _ENTRY * min(wanted, room))
        for name_field, target in struct.iter_unpack('<II', raw[:len(raw) // _ENTRY * _ENTRY]):
            if not self._tick():
                return
            here = (*path, self._identity(name_field))
            if target & _HIGH:
                self._subdirectory(target & _LOW31, depth, here, stack)
            else:
                self._data_entry(target, here)

    def _subdirectory(self, offset: int, depth: int, path: tuple, stack: list) -> None:
        if depth >= self.limits.max_depth:
            self._stop('resource_depth_over_cap', f'resource directories nested deeper than {self.limits.max_depth}')
        elif offset in self._visited:
            self._stop('resource_cycle_skipped', 'a resource directory was reached twice (cycle or shared); skipped')
        elif self._take_node():
            self._visited.add(offset)
            stack.append((offset, depth + 1, path))

    def _data_entry(self, offset: int, path: tuple) -> None:
        if not self._take_node():
            return
        raw = self.tree.read(offset, _DATA_ENTRY)
        if len(raw) < _DATA_ENTRY:
            self._stop('resource_dir_unreadable', 'a resource data entry is not backed by file data')
            return
        rva, size, codepage, _reserved = struct.unpack('<IIII', raw)
        kind = path[0]
        self.leaves.append(ResourceLeaf(
            kind if isinstance(kind, int) else None, _type_label(kind), path[1] if len(path) > 1 else None,
            path[2] if len(path) > 2 else None, rva, size, codepage, self._file_offset(rva)))

    def _file_offset(self, rva: int) -> int | None:
        tree = self.tree
        if tree.rva <= rva < tree.rva + tree.limit:
            return tree.file_offset + rva - tree.rva
        spans = self.smap.rva_to_file_ranges(rva, 1)
        return spans[0].file_offset if spans else None

    def _identity(self, name_field: int) -> int | str:
        if name_field & _HIGH:
            return self._name(name_field & _LOW31)
        return name_field & 0xFFFF

    def _name(self, offset: int) -> str:
        if offset in self._names:
            return self._names[offset]
        cap = self.limits.max_name_chars
        head = self.tree.read(offset, 2)
        if len(head) < 2:
            self._stop('resource_dir_unreadable', 'a resource name is not backed by file data')
            text = f'<unreadable name @ {offset:#x}>'
        else:
            (declared,) = struct.unpack('<H', head)
            want = min(declared, cap)
            raw = self.tree.read(offset + 2, 2 * want)
            text = decode_utf16(raw, cap)[0]
            if declared > cap or len(raw) < 2 * want:
                self.ctx.warn('resource_name_truncated', f'a resource name was cut at {cap} characters')
        self._names[offset] = text
        return text


def _type_label(kind: int | str) -> str:
    if isinstance(kind, str):
        return f'name:{kind}'
    return TYPE_LABELS.get(kind, f'#{kind}')
