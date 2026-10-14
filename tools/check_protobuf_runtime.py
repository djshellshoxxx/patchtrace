"""CI/dev guard (SPEC-10b §9.5): the installed protobuf equals the pyproject pin and runs the upb backend.

usage: check_protobuf_runtime.py        exits 0 when both hold, 1 otherwise (prints one line either way)
The pure-Python protobuf fallback is refused by the product (85x memory); a drifted version means the
descriptor/golden-field-table tests no longer describe what runs.
"""
from __future__ import annotations

import importlib.metadata
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def pinned_version() -> str:
    dependencies = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']['dependencies']
    for item in dependencies:
        match = re.fullmatch(r'protobuf==([0-9][0-9A-Za-z.]*)', item.replace(' ', ''))
        if match:
            return match.group(1)
    raise SystemExit('pyproject.toml does not pin protobuf with ==')


def main() -> int:
    pin, installed = pinned_version(), importlib.metadata.version('protobuf')
    from google.protobuf.internal import api_implementation
    backend = api_implementation.Type()
    print(f'protobuf pin={pin} installed={installed} backend={backend}')
    if installed != pin or backend != 'upb':
        print('FAIL: protobuf must equal the pin and use the upb backend', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
