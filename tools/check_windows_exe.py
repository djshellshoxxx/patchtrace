"""Check a built PatchTrace.exe carries the intended version resource and an icon (SPEC-52 WIN-1 gate).

Reads the file with PatchTrace's own bounded PE reader (`patchtrace.pe_overview`, no Qt) and never executes it.
Exit 0 when the first RT_VERSION block names the expected label and commit and an RT_GROUP_ICON exists;
exit 3 with a PT-REL-* code otherwise. Prints one JSON object.

    python tools/check_windows_exe.py dist/PatchTrace/PatchTrace.exe --label 0.1.0-alpha.1 --commit <sha>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

RT_GROUP_ICON = 14


def read_resources(path: Path) -> dict:
    """{'status', 'strings', 'file_version', 'icon_groups'} for the PE at `path`."""
    from patchtrace.artifact_bytes import VerifiedArtifactReader
    from patchtrace.pe_overview import Limits, inspect_pe
    from patchtrace.pe_overview._common import Ctx
    from patchtrace.pe_overview.resources import DEFAULT_RESOURCE_LIMITS, leaves_of_type, parse_resources
    from patchtrace.pe_overview.version_info import parse_version_info, version_text

    with VerifiedArtifactReader.open_path(path) as reader:
        overview = inspect_pe(reader)
        directory = overview.directory('Resource')
        if directory is None or not directory.present:
            return {'status': overview.status, 'strings': {}, 'file_version': None, 'icon_groups': 0}
        ctx = Ctx(reader, None, Limits())
        smap = overview.section_map()
        inventory = parse_resources(ctx, smap, directory.rva, directory.size, DEFAULT_RESOURCE_LIMITS)
        info = parse_version_info(ctx, smap, inventory, DEFAULT_RESOURCE_LIMITS)
        block = info.blocks[info.primary_index] if info.primary_index is not None else None
        return {
            'status': overview.status,
            'strings': {s.key: s.value for s in block.strings} if block else {},
            'file_version': version_text(block.fixed.file_version) if block and block.fixed else None,
            'icon_groups': len(leaves_of_type(inventory, RT_GROUP_ICON)),
        }


def problems(found: dict, label: str, commit: str) -> list[str]:
    strings = found['strings']
    issues = []
    for key, expected in (('ProductVersion', label), ('FileVersion', label), ('OriginalFilename', 'PatchTrace.exe')):
        if strings.get(key) != expected:
            issues.append(f'PT-REL-VERSION: {key} is {strings.get(key)!r}, expected {expected!r}')
    if strings.get('Comments') != f'Unsigned build of commit {commit}':
        issues.append(f'PT-REL-COMMIT: Comments is {strings.get("Comments")!r}, expected commit {commit}')
    if 'CompanyName' in strings:
        issues.append('PT-REL-PUBLISHER: unsigned builds must not carry a CompanyName (SPEC-52)')
    if not found['icon_groups']:
        issues.append('PT-REL-ICON: no RT_GROUP_ICON resource')
    return issues


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Check the version resource and icon of a built PatchTrace.exe.')
    parser.add_argument('exe', type=Path)
    parser.add_argument('--label', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args(argv)
    found = read_resources(args.exe)
    issues = problems(found, args.label, args.commit)
    print(json.dumps({**found, 'problems': issues}, indent=2, sort_keys=True))
    return 3 if issues else 0


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
    raise SystemExit(main())
