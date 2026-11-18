"""Generate only local-package/1 schemas; deterministic, offline and Qt-free."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'local-package'
NAMES = ('PackageLimits', 'PackageFileIdentity', 'PackageSource', 'PackageDecoder', 'PackageCapability',
         'PackagePart', 'PackageContainer', 'PackageDiagnostic', 'PackageInventory', 'PackageSelection',
         'PackageUsage')


def render() -> dict[str, str]:
    from patchtrace.acquisition import package_contracts
    result = {}
    for name in NAMES:
        schema = getattr(package_contracts, name).model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/local-package/1/{name}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        result[name + '.json'] = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return result


def main(argv: list[str]) -> int:
    if argv not in ([], ['--check']):
        raise SystemExit('usage: generate_package_schemas.py [--check]')
    stale = []
    for name, text in render().items():
        path = OUT / name
        if argv:
            if not path.is_file() or path.read_text(encoding='utf-8') != text:
                stale.append(name)
        else:
            OUT.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
    for name in stale:
        print(f'stale: {name}', file=sys.stderr)
    return 1 if stale else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
