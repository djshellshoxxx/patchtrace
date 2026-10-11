"""Package an already assembled private Windows backend for offline delivery.

This tool DOES NOT fetch dependencies or prove that the supplied Python/Ghidriff
runtime is portable or licensed for distribution. Verify the full stack on
a clean offline Windows machine before publishing.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from patchtrace.offline_bundle import build_offline_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description='Create a verified PatchTrace offline backend ZIP')
    parser.add_argument('--payload', required=True, type=Path,
                        help='Directory containing python/, ghidra/, jdk/ and LICENSES/')
    parser.add_argument('--out', required=True, type=Path, help='New ZIP filename (refuses overwrite)')
    parser.add_argument('--runtime-id', required=True)
    parser.add_argument('--python-version', required=True)
    parser.add_argument('--ghidra-version', required=True)
    parser.add_argument('--jdk-version', required=True)
    parser.add_argument('--ghidriff-revision', required=True)
    args = parser.parse_args()
    versions = {
        'python': args.python_version,
        'ghidra': args.ghidra_version,
        'jdk': args.jdk_version,
        'ghidriff_revision': args.ghidriff_revision,
    }
    archive = build_offline_bundle(args.payload, args.runtime_id, versions, args.out)
    digest = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
    sidecar = archive.with_suffix(archive.suffix + '.sha256')
    sidecar.write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(f'Packed {archive.name} SHA-256 {digest}')
    print('Not a full runtime acceptance test; test in fresh disconnected Windows first.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
