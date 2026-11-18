"""Regenerate the corrections-exchange/1 JSON Schema (docs/specs/manual-corrections-exchange.md section 3).

Run from the repository root:

    PYTHONPATH=src python tools/generate_corrections_schemas.py          # write
    PYTHONPATH=src python tools/generate_corrections_schemas.py --check  # exit 1 on drift

Output, deterministic and offline: ``docs/schemas/corrections/CorrectionsExchange.json``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'corrections'
SCHEMA_BASE = 'https://patchtrace.local/schemas/corrections-exchange/1/'


def render() -> dict[Path, str]:
    from patchtrace.corrections_exchange import CorrectionsExchange
    schema = CorrectionsExchange.model_json_schema()
    schema['$id'] = f'{SCHEMA_BASE}CorrectionsExchange.json'
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    return {OUT / 'CorrectionsExchange.json': json.dumps(schema, indent=2, sort_keys=True) + '\n'}


def main(argv: list[str]) -> int:
    rendered = render()
    if '--check' in argv:
        stale = [p for p, text in rendered.items() if not p.is_file() or p.read_text(encoding='utf-8') != text]
        for path in stale:
            print(f'stale: {path.relative_to(ROOT)}', file=sys.stderr)
        return 1 if stale else 0
    OUT.mkdir(parents=True, exist_ok=True)
    for path, text in rendered.items():
        path.write_text(text, encoding='utf-8', newline='\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
