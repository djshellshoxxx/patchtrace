"""Package an already assembled private Windows backend for offline delivery.

This tool DOES NOT fetch dependencies or prove that the supplied Python/Ghidriff
runtime is portable or licensed for distribution. Verify the full stack on
a clean offline Windows machine before publishing.
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


def _builder():
    """The shared module (tools/ is not a package): one packaging path for both entry points."""
    name = 'build_backend_bundle'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(name + '.py'))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


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
    archive, digest = _builder().package_payload(args.payload, args.out, args.runtime_id, versions)
    print(f'Packed {archive.name} SHA-256 {digest}')
    print('Not a full runtime acceptance test; test in fresh disconnected Windows first.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
