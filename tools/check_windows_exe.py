"""Check a built PatchTrace.exe carries the intended version resource and an icon (SPEC-52 WIN-1 gate).

Reads the file with PatchTrace's own bounded PE reader (`patchtrace.pe_overview`, no Qt) and never executes it.
Exit 0 only for complete, consistent PE/version evidence with the exact label, source commit and numeric
file/product quad, plus nonempty icon groups whose language-bound resources contain valid generated RGBA PNG
frames. CRC, dimensions, bounded zlib data and pixel-row filters are checked; this is a generated-build gate,
not a general PNG decoder. Exit 3 with a PT-REL-* code otherwise. Prints one JSON object.

    python tools/check_windows_exe.py dist/PatchTrace/PatchTrace.exe --label 0.1.0-beta.7 --commit <40-hex-sha> --build 7
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import zlib
from collections.abc import Sequence
from pathlib import Path

RT_GROUP_ICON = 14


def _png_valid(data: bytes, width: int, height: int) -> bool:
    """Validate the bounded RGBA PNG frames produced by windows_icon, without importing Qt."""
    if not 1 <= width <= 256 or not 1 <= height <= 256 or len(data) > 1 << 20:
        return False
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return False
    pos, chunks, compressed = 8, [], bytearray()
    while pos + 12 <= len(data):
        size, = struct.unpack_from('>I', data, pos)
        end = pos + 12 + size
        if end > len(data):
            return False
        kind, body = data[pos + 4:pos + 8], data[pos + 8:end - 4]
        if kind not in {b'IHDR', b'IDAT', b'IEND'} and not kind[0] & 0x20:
            return False  # unknown critical PNG chunk
        crc, = struct.unpack_from('>I', data, end - 4)
        if zlib.crc32(kind + body) != crc:
            return False
        chunks.append(kind)
        if len(chunks) == 1:
            if kind != b'IHDR' or size != 13:
                return False
            if struct.unpack('>IIBBBBB', body) != (width, height, 8, 6, 0, 0, 0):
                return False
        elif kind == b'IHDR':
            return False
        if kind == b'IDAT':
            compressed.extend(body)
        if kind == b'IEND':
            if size or end != len(data) or not compressed:
                return False
            try:
                decoder = zlib.decompressobj()
                expected = height * (1 + 4 * width)
                pixels = decoder.decompress(compressed, expected + 1)
                return (len(pixels) == expected and decoder.eof and not decoder.unused_data
                        and all(pixels[y * (1 + 4 * width)] <= 4 for y in range(height)))
            except zlib.error:
                return False
        pos = end
    return False


def _valid_icon_group(ctx, smap, inventory, group) -> bool:
    from patchtrace.pe_overview.resources import leaves_of_type, read_leaf

    if group.size > 6 + 14 * 16:
        return False
    data = read_leaf(ctx, smap, group, 6 + 14 * 16)
    if len(data) != group.size or len(data) < 6:
        return False
    reserved, kind, count = struct.unpack_from('<HHH', data)
    if reserved or kind != 1 or not 1 <= count <= 16 or len(data) != 6 + 14 * count:
        return False
    seen = set()
    for index in range(count):
        width, height, colors, reserved, planes, bits, size, ident = struct.unpack_from(
            '<BBBBHHIH', data, 6 + 14 * index)
        if reserved or colors or planes != 1 or bits != 32 or not 1 <= size <= 1 << 20 or ident in seen:
            return False
        seen.add(ident)
        leaves = [leaf for leaf in leaves_of_type(inventory, 3)
                  if leaf.name == ident and leaf.lang == group.lang]
        if len(leaves) != 1 or leaves[0].size != size:
            return False
        png = read_leaf(ctx, smap, leaves[0], 1 << 20)
        if len(png) != size or not _png_valid(png, width or 256, height or 256):
            return False
    return True


def read_resources(path: Path) -> dict:
    """Return bounded resource evidence; incomplete evidence cannot pass problems()."""
    from patchtrace.artifact_bytes import VerifiedArtifactReader
    from patchtrace.pe_overview import Limits, inspect_pe
    from patchtrace.pe_overview._common import Ctx
    from patchtrace.pe_overview.resources import DEFAULT_RESOURCE_LIMITS, leaves_of_type, parse_resources
    from patchtrace.pe_overview.version_info import parse_version_info, version_text

    with VerifiedArtifactReader.open_path(path) as reader:
        overview = inspect_pe(reader)
        empty = {'status': overview.status, 'strings': {}, 'file_version': None, 'product_version': None,
                 'icon_groups': 0, 'invalid_icon_groups': 0, 'resource_truncated': True,
                 'version_statuses': [], 'version_warnings': [], 'contradictions': [],
                 'version_shape_valid': False}
        directory = overview.directory('Resource')
        if directory is None or not directory.present:
            return empty
        ctx = Ctx(reader, None, Limits())
        smap = overview.section_map()
        inventory = parse_resources(ctx, smap, directory.rva, directory.size, DEFAULT_RESOURCE_LIMITS)
        if inventory is None:
            return empty
        info = parse_version_info(ctx, smap, inventory, DEFAULT_RESOURCE_LIMITS)
        block = info.blocks[info.primary_index] if info.primary_index is not None else None
        # Our generator emits one version resource and one language/codepage with unique keys.
        # Refuse alternate/duplicate identity before a last-wins dictionary can hide it.
        keys = [s.key for s in block.strings] if block else []
        shape_valid = (len(leaves_of_type(inventory, 16)) == 1 and len(info.blocks) == 1 and block is not None
                       and len({s.lang_codepage for s in block.strings}) == 1
                       and len(keys) == len(set(keys)) and not any(s.truncated for s in block.strings))
        groups = leaves_of_type(inventory, RT_GROUP_ICON)
        # A generated build has one group. Bound alternate languages/resources before payload reads.
        invalid_groups = (len(groups) if len(groups) > 16 else
                          sum(not _valid_icon_group(ctx, smap, inventory, group) for group in groups))
        return {
            'status': overview.status,
            'strings': {s.key: s.value for s in block.strings} if block else {},
            'file_version': version_text(block.fixed.file_version) if block and block.fixed else None,
            'product_version': version_text(block.fixed.product_version) if block and block.fixed else None,
            'icon_groups': len(groups),
            'invalid_icon_groups': invalid_groups,
            'resource_truncated': inventory.truncated,
            'version_shape_valid': shape_valid,
            'version_statuses': [b.status for b in info.blocks],
            'version_warnings': [w.code for w in ctx.warnings] + [w for b in info.blocks for w in b.warnings],
            'contradictions': list(info.contradictions),
        }


def problems(found: dict, label: str, commit: str, quad: tuple[int, int, int, int]) -> list[str]:
    strings = found['strings']
    issues = []
    # The generic inspector compares a numeric three-part prefix padded with .0;
    # prerelease labels intentionally differ from the four-part CI build number.
    # Validate both exact representations below, retaining every other contradiction.
    contradictions = [c for c in found['contradictions']
                      if c not in {'fixed_vs_string:FileVersion', 'fixed_vs_string:ProductVersion'}]
    if (found['status'] != 'ok' or found['resource_truncated'] or not found['version_shape_valid']
            or not found['version_statuses']
            or any(s != 'ok' for s in found['version_statuses']) or found['version_warnings']
            or contradictions):
        issues.append('PT-REL-RESOURCE: incomplete or contradictory PE/version evidence')
    expected_fixed = '.'.join(str(n) for n in quad)
    for key in ('file_version', 'product_version'):
        if found[key] != expected_fixed:
            issues.append(f'PT-REL-VERSION: fixed {key} is {found[key]!r}, expected {expected_fixed!r}')
    for key, expected in (('ProductVersion', label), ('FileVersion', label), ('OriginalFilename', 'PatchTrace.exe')):
        if strings.get(key) != expected:
            issues.append(f'PT-REL-VERSION: {key} is {strings.get(key)!r}, expected {expected!r}')
    if strings.get('Comments') != f'Unsigned build of commit {commit}':
        issues.append(f'PT-REL-COMMIT: Comments is {strings.get("Comments")!r}, expected commit {commit}')
    if 'CompanyName' in strings:
        issues.append('PT-REL-PUBLISHER: unsigned builds must not carry a CompanyName (SPEC-52)')
    if not found['icon_groups']:
        issues.append('PT-REL-ICON: no RT_GROUP_ICON resource')
    elif found['invalid_icon_groups']:
        issues.append('PT-REL-ICON: empty, malformed or unreadable icon group/payload')
    return issues


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Check the version resource and icon of a built PatchTrace.exe.')
    parser.add_argument('exe', type=Path)
    parser.add_argument('--label', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--build', type=int, default=0, help='expected fixed build/run number (default: 0)')
    args = parser.parse_args(argv)
    found = read_resources(args.exe)
    from windows_version_info import make_fields

    try:
        fields = make_fields(args.label, args.commit, args.build, 'Copyright (c) 2026 PatchTrace')
    except ValueError as exc:
        parser.error(str(exc))
    issues = problems(found, fields.label, fields.commit, fields.quad)
    print(json.dumps({**found, 'problems': issues}, indent=2, sort_keys=True))
    return 3 if issues else 0


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
    raise SystemExit(main())
