"""Regenerate the kev/1 artefacts (KEV-integration-plan section 7).

Run from the repository root:

    PYTHONPATH=src python tools/generate_kev_schemas.py          # write
    PYTHONPATH=src python tools/generate_kev_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/kev/``: one JSON Schema per persisted contract plus
``examples.json`` (one valid and several invalid examples per contract). Every example is built from the SYNTHETIC
catalog ``tests/fixtures/kev/kev-synthetic-2099.json``; nothing is fetched. ``docs/schemas/kev/upstream/`` belongs to
slice K0 (CISA's own schema, vendored byte for byte) and is never written here.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'kev'
FIXTURE = ROOT / 'tests' / 'fixtures' / 'kev' / 'kev-synthetic-2099.json'

CONTRACTS = ('KevEntry', 'KevEntrySlim', 'KevCatalogMeta', 'KevLookup', 'KevContext', 'KevDelta', 'KevPlan',
             'KevCurrent')
STAMP = '2099-03-02T08:00:00Z'
NOW = datetime(2099, 3, 2, 8, 0, 0, tzinfo=UTC)
SHA = 'a' * 64


def valid_records() -> dict:
    """One valid SYNTHETIC record per contract."""
    from patchtrace.enrichment.identity import domain_id
    from patchtrace.kev import contracts as c
    from patchtrace.kev.join import diff, lookup
    from patchtrace.kev.parse import parse_catalog

    raw = FIXTURE.read_bytes()
    catalog = parse_catalog(raw, source='local-import', retrieved_at=STAMP, file_name=FIXTURE.name)
    document = json.loads(raw)
    document['vulnerabilities'] = [row for row in document['vulnerabilities'] if row['cveID'] != 'CVE-2099-10009']
    document['vulnerabilities'][1]['knownRansomwareCampaignUse'] = 'Known'
    document['count'] = len(document['vulnerabilities'])
    newer = parse_catalog(json.dumps(document).encode('utf-8'), source='local-import', retrieved_at=STAMP)
    entry = catalog.by_cve['CVE-2099-10001']
    answers = lookup(catalog, ['CVE-2099-10001', 'CVE-2099-10002'], NOW)
    row_lookups = tuple(item.model_copy(update={'entry': item.entry.slim() if item.entry else None})
                        for item in answers)
    context = c.KevContext(
        context_id=domain_id('kev-context', 1, {'snapshot_id': catalog.meta.snapshot_id,
                                                 'cves': ['CVE-2099-10001', 'CVE-2099-10002'], 'join_version': 1}),
        created_at=STAMP, snapshot_id=catalog.meta.snapshot_id, catalog_version=catalog.meta.catalog_version,
        date_released=catalog.meta.date_released, content_digest=catalog.meta.content_digest, source='local-import',
        lookups=row_lookups, kb='KB5000001', release_date='2099-02-11', orientation_verified=True)
    return {'KevEntry': entry, 'KevEntrySlim': entry.slim(), 'KevCatalogMeta': catalog.meta, 'KevLookup': answers[0],
            'KevContext': context, 'KevDelta': diff(catalog, newer), 'KevPlan': c.plan_for('cisa-site'),
            'KevCurrent': c.KevCurrent(snapshot_id=catalog.meta.snapshot_id, raw_sha256=catalog.meta.raw_sha256,
                                       date_released=catalog.meta.date_released, set_at=STAMP)}


SPECIFIC_INVALID = {
    'KevEntry': ({'cve_id': 'CVE-２０９９-10001'}, 'CVE IDs are ASCII digits only'),
    'KevEntrySlim': ({'due_date': '2099-02-09'}, 'the due date cannot be before the date added'),
    'KevCatalogMeta': ({'authenticity': 'tls-allowlisted-host'}, 'a local import is unverified-local-file'),
    'KevLookup': ({'status': 'not-listed'}, 'a not-listed lookup carries no entry'),
    'KevContext': ({'lookups': []}, 'a row needs at least one lookup'),
    'KevDelta': ({'removed_count': 0}, 'a count below the length of its list'),
    'KevPlan': ({'url': 'https://www.cisa.gov/other.json'}, 'a plan names only the fixed URL of its source'),
    'KevCurrent': ({'raw_sha256': 'not-a-hash'}, 'a SHA-256 is 64 lower-case hex digits'),
}


def build_examples() -> dict:
    out = {}
    for name, record in valid_records().items():
        valid = json.loads(record.model_dump_json())
        invalid = [{'example': valid | {'unexpected_field': 1}, 'reason': 'extra fields are forbidden'},
                   {'example': valid | {'contract': 'kev/2'}, 'reason': 'unsupported future contract version'}]
        patch, reason = SPECIFIC_INVALID[name]
        invalid.append({'example': valid | patch, 'reason': reason})
        out[name] = {'valid': valid, 'invalid': invalid}
    return out


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
