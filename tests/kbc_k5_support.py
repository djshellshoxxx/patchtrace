"""Shared builders for the K5 tests: synthetic Winbindex records to index rows and a product scope."""
from __future__ import annotations

import json
from pathlib import Path

from patchtrace.acquisition import winbindex as wb
from patchtrace.kbcorrelation.contracts import ProductScope
from patchtrace.kbcorrelation.lineage import IndexRow, index_rows

FIXTURES = Path(__file__).parent / 'fixtures' / 'kbcorrelation' / 'winbindex'
SHA = {name: ch * 64 for name, ch in {'A': 'a', 'X': 'b', 'Y': 'c', 'Z': 'd', 'V': 'f'}.items()}


def record(name: str = 'exampledrv.sys') -> dict:
    return json.loads((FIXTURES / f'{name}.json').read_text(encoding='utf-8'))


def rows_of(doc: dict, name: str = 'exampledrv.sys') -> tuple[tuple[IndexRow, ...], int]:
    parsed = wb.parse_rows(json.dumps(doc).encode('utf-8'), name, '2099-02-12', compressed=False)
    rows, rejected = index_rows((r.as_mapping() for r in parsed.rows), file_name=name)
    assert rejected == 0
    return rows, parsed.skipped


def scope(key: str | None = '11-24H2', family: str = 'windows-client', arch: str = 'amd64') -> ProductScope:
    return ProductScope(scope_id=('1' if key == '11-24H2' else '2') * 64, family=family, architecture=arch,
                        display_name='Example OS', winbindex_key=key, mapping='candidate', alias_catalog_version=1)
