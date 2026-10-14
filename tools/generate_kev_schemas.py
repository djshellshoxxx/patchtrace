"""Regenerate the kev/1 artefacts (KEV-integration-plan sections 7 and 9, slice K1a).

Run from the repository root:

    PYTHONPATH=src python tools/generate_kev_schemas.py          # write
    PYTHONPATH=src python tools/generate_kev_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/kev/`` (top level only; ``upstream/`` holds CISA's own schema):
one JSON Schema per stored contract plus ``examples.json`` (one valid and several invalid examples per contract). The
examples derive from the SYNTHETIC fixture ``tests/fixtures/kev/kev-synthetic-2099.json``, never from live data.
"""
from __future__ import annotations

import copy
import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'kev'
FIXTURE = ROOT / 'tests' / 'fixtures' / 'kev' / 'kev-synthetic-2099.json'

CONTRACTS = ('KevEntry', 'KevEntrySlim', 'KevCatalogMeta', 'KevCatalog', 'KevLookup', 'KevContext', 'KevDelta',
             'KevPlan')
NOW = datetime.datetime(2099, 3, 2, 12, 0, tzinfo=datetime.UTC)


def _bad(valid: dict, why: str, *path_and_value) -> dict:
    """A copy of ``valid`` with one nested value replaced; ``path_and_value`` is (key, key, ..., value)."""
    example = copy.deepcopy(valid)
    *path, value = path_and_value
    target = example
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return {'why': why, 'example': example}


def build_examples() -> dict:
    from patchtrace.kev.contracts import KevPlan
    from patchtrace.kev.join import diff, lookup, make_context
    from patchtrace.kev.parse import parse_catalog

    raw = FIXTURE.read_bytes()
    catalog = parse_catalog(raw, source='local-import', retrieved_at='2099-03-01T13:00:00Z',
                            file_name='kev-synthetic-2099.json')
    changed = json.loads(raw)
    changed['vulnerabilities'][0]['knownRansomwareCampaignUse'] = 'Unknown'
    newer = parse_catalog(json.dumps(changed).encode('utf-8'), source='local-import',
                          retrieved_at='2099-03-02T13:00:00Z')
    entry = catalog.entries[0]
    valid = {
        'KevEntry': entry, 'KevEntrySlim': entry.slim(), 'KevCatalogMeta': catalog.meta, 'KevCatalog': catalog,
        'KevLookup': lookup(catalog, [entry.cve_id], NOW)[0],
        'KevContext': make_context(catalog, [entry.cve_id, 'CVE-2099-99999'], NOW),
        'KevDelta': diff(catalog, newer), 'KevPlan': KevPlan.for_source('cisa-github'),
    }
    dumps = {name: json.loads(model.model_dump_json()) for name, model in valid.items()}
    invalid = {
        'KevEntry': [_bad(dumps['KevEntry'], 'fullwidth CVE ID', 'cve_id', 'CVE-２０９９-１０００１'),
                     _bad(dumps['KevEntry'], 'due date before added', 'due_date', '2099-01-01'),
                     _bad(dumps['KevEntry'], 'unknown field', 'extra', 1)],
        'KevEntrySlim': [_bad(dumps['KevEntrySlim'], 'bad CWE token', 'cwes', ['CWE-x']),
                         _bad(dumps['KevEntrySlim'], 'wrong contract', 'contract', 'kev/2')],
        'KevCatalogMeta': [_bad(dumps['KevCatalogMeta'], 'counts do not add up', 'skipped_entries', 3),
                           _bad(dumps['KevCatalogMeta'], 'path in file name', 'file_name', 'a/b.json')],
        'KevCatalog': [_bad(dumps['KevCatalog'], 'entry count differs from metadata', 'meta', 'entry_count', 3)],
        'KevLookup': [_bad(dumps['KevLookup'], 'listed without entry', 'entry', None),
                      _bad(dumps['KevLookup'], 'unknown status', 'status', 'maybe')],
        'KevContext': [_bad(dumps['KevContext'], 'identity does not match CVEs', 'context_id', 'f' * 64)],
        'KevDelta': [_bad(dumps['KevDelta'], 'negative count', 'added_count', -1)],
        'KevPlan': [_bad(dumps['KevPlan'], 'host is not the fixed host', 'host', 'example.invalid'),
                    _bad(dumps['KevPlan'], 'unknown method', 'method', 'POST')],
    }
    return {name: {'valid': dumps[name], 'invalid': invalid[name]} for name in CONTRACTS}


def render_contract_schemas() -> dict[str, str]:
    from patchtrace.kev import contracts
    out = {}
    for name in CONTRACTS:
        schema = getattr(contracts, name).model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/kev/1/{name}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        out[f'{name}.json'] = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return out


def render() -> dict[Path, str]:
    """Every generated file and its exact text (a pure function of the repository contents)."""
    files = {OUT / name: text for name, text in render_contract_schemas().items()}
    files[OUT / 'examples.json'] = json.dumps(build_examples(), indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return files


def main(argv: list[str]) -> int:
    check = '--check' in argv
    drift = []
    for path, text in render().items():
        if check:
            current = path.read_text(encoding='utf-8') if path.is_file() else None
            if current != text:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
    for item in drift:
        print(f'stale: {item}', file=sys.stderr)
    return 1 if drift else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
