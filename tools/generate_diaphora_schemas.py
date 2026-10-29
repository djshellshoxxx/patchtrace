"""Regenerate the diaphora/1 artefacts (SPEC-DA-01).

    PYTHONPATH=src python tools/generate_diaphora_schemas.py          # write
    PYTHONPATH=src python tools/generate_diaphora_schemas.py --check  # exit 1 on drift

Deterministic and offline, in ``docs/schemas/diaphora/``: one JSON Schema per persisted contract plus ``examples.json``.
Every example is SYNTHETIC (a made-up pair of builds and addresses); none comes from Diaphora or a real binary.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'diaphora'
CONTRACTS = ('DiaphoraMatch', 'DiaphoraUnmatched', 'DiaphoraMatchSet', 'DiaphoraDiffManifest')
OLDER, NEWER, RESULT = 'a' * 64, 'b' * 64, 'c' * 64


def valid_records() -> dict:
    from patchtrace.diaphora import contracts as c
    match = c.DiaphoraMatch(
        index=0, category='best', older_ea_text='180001000', newer_ea_text='180001010', older_ea=0x180001000,
        newer_ea=0x180001010, older_rva=0x1000, newer_rva=0x1010, older_name='sub_old', newer_name='sub_new',
        ratio_text='0.980', ratio_milli=980, ratio_transform='direct', older_nodes=5, newer_nodes=6,
        heuristic='Same name', address_status='verified-rva')
    unmatched = c.DiaphoraUnmatched(index=0, source_side='primary', side='older', ea_text='180001800',
                                    ea=0x180001800, rva=0x1800, name='sub_only_old', address_status='verified-rva')
    return {'DiaphoraMatch': match, 'DiaphoraUnmatched': unmatched,
            'DiaphoraMatchSet': c.DiaphoraMatchSet(engine_version='3.4.3', older_sha256=OLDER, newer_sha256=NEWER,
                                                   result_sha256=RESULT, trust='manifest-bound', matches=(match,),
                                                   unmatched=(unmatched,)),
            'DiaphoraDiffManifest': c.DiaphoraDiffManifest(
                contract='diaphora-diff/1', orientation='older->newer', older_binary_sha256=OLDER,
                newer_binary_sha256=NEWER, result_sha256=RESULT, diaphora_version='3.4.3')}


SPECIFIC_INVALID = {
    'DiaphoraMatch': ({'category': 'great'}, 'only best, partial, unreliable and multimatch exist'),
    'DiaphoraUnmatched': ({'side': 'both'}, 'a side is older or newer'),
    'DiaphoraMatchSet': ({'trust': 'verified'}, 'trust is manifest-bound or user-attested'),
    'DiaphoraDiffManifest': ({'result_sha256': 'XYZ'}, 'a SHA-256 is 64 lower-case hex digits'),
}


def build_examples() -> dict:
    out = {}
    for name, record in valid_records().items():
        valid = json.loads(record.model_dump_json())
        invalid = [{'example': valid | {'unexpected_field': 1}, 'reason': 'extra fields are forbidden'}]
        patch, reason = SPECIFIC_INVALID[name]
        invalid.append({'example': valid | patch, 'reason': reason})
        out[name] = {'valid': valid, 'invalid': invalid}
    return out


def render() -> dict[Path, str]:
    from patchtrace.diaphora import contracts
    files = {}
    for name in CONTRACTS:
        schema = getattr(contracts, name).model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/diaphora/1/{name}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        files[OUT / f'{name}.json'] = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    files[OUT / 'examples.json'] = json.dumps(build_examples(), indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return files


def main(argv: list[str]) -> int:
    check = '--check' in argv
    drift = []
    for path, text in render().items():
        if check:
            if not path.is_file() or path.read_text(encoding='utf-8') != text:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
    for item in drift:
        print(f'stale: {item}', file=sys.stderr)
    return 1 if drift else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
