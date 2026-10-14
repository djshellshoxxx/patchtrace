"""Regenerate the committed SYNTHETIC BinExport2 goldens and their PROVENANCE.json (SPEC-10b §10.1).

usage: gen_binexport_fixtures.py [--check]

The exports are built with tests/binexport_builder.py (runtime class from the checked-in descriptor, serialized
deterministically). They are bound to project-owned synthetic PEs (`patchtrace.sample.synthetic_pe(variant)`):
`executable_id` is that PE's SHA-256 (or its MD5 for the IDA-style case). They are NOT plugin output and are
never live-compatibility evidence; real Ghidra/IDA goldens are a separate, manual step (README.md).
`--check` regenerates in memory and exits 1 if any committed byte differs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'tests' / 'fixtures' / 'binexport'
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]

from binexport_builder import valid  # noqa: E402

from patchtrace.sample import synthetic_pe  # noqa: E402

IMAGE_BASE, SIZE_OF_IMAGE = 0x180000000, 0x2000  # synthetic_pe() OptionalHeader values
TIMESTAMP = 1_760_400_000  # fixed (2025-10-14) so regeneration is byte-identical

# name -> (pe variant, functions, base address, id kind, expected address basis)
CASES = {
    'synthetic-older.BinExport': (0, 3, IMAGE_BASE + 0x1000, 'sha256', 'va'),
    'synthetic-newer.BinExport': (1, 4, IMAGE_BASE + 0x1000, 'sha256', 'va'),
    'synthetic-newer-rva.BinExport': (1, 4, 0x1000, 'sha256', 'rva'),
    'synthetic-older-md5id.BinExport': (0, 3, IMAGE_BASE + 0x1000, 'md5', 'va'),
}


def build() -> tuple[dict[str, bytes], list[dict]]:
    files, records = {}, []
    for name, (variant, functions, base, kind, basis) in CASES.items():
        pe = synthetic_pe(variant)
        source_sha = hashlib.sha256(pe).hexdigest()
        ident = source_sha if kind == 'sha256' else hashlib.md5(pe).hexdigest()  # noqa: S324 - mimics IDA id
        msg = valid(ident, base=base, timestamp=TIMESTAMP, functions=functions)
        msg.meta_information.executable_name = f'synthetic-{variant}.dll'
        data = msg.SerializeToString(deterministic=True)
        files[name] = data
        records.append({
            'file': name, 'file_sha256': hashlib.sha256(data).hexdigest(), 'file_size': len(data),
            'source_sha256': source_sha,
            'source_origin': f'patchtrace.sample.synthetic_pe({variant}) (project-owned synthetic PE, never executed)',
            'tool': 'synthetic: tests/binexport_builder.py via tools/gen_binexport_fixtures.py (NOT a BinExport plugin)',
            'options': ['Subtract Imagebase'] if basis == 'rva' else [],
            'produced_on': 'regenerable; first generated 2026-10-14 on Linux (CPython 3.13, protobuf 7.36.2 upb)',
            'produced_by': 'C3 builder (Claude Code session)',
            'license': 'test fixture derived from project-owned source; no third-party content',
            'architecture_name': msg.meta_information.architecture_name,
            'observed_executable_id': ident, 'id_binding': kind, 'address_basis': basis,
            'functions': functions, 'image_base': IMAGE_BASE, 'size_of_image': SIZE_OF_IMAGE,
            'live_compatibility_evidence': False,
        })
    return files, records


def provenance_text(records: list[dict]) -> str:
    return json.dumps({'contract': 'binexport-fixture-provenance/1', 'fixtures': records}, indent=2,
                      sort_keys=True) + '\n'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    files, records = build()
    wanted = {**files, 'PROVENANCE.json': provenance_text(records).encode('utf-8')}
    if args.check:
        drift = [n for n, data in wanted.items() if not (OUT / n).is_file() or (OUT / n).read_bytes() != data]
        print('fixtures up to date' if not drift else f'fixture DRIFT: {drift}')
        return 1 if drift else 0
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in wanted.items():
        (OUT / name).write_bytes(data)
    print(f'wrote {len(files)} fixtures + PROVENANCE.json to {OUT}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
