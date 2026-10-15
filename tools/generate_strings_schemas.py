"""Regenerate the strings-* JSON Schemas and examples (WB3-S0).

Run from the repository root:

    PYTHONPATH=src python tools/generate_strings_schemas.py          # write
    PYTHONPATH=src python tools/generate_strings_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/strings/``: one JSON Schema per contract plus
``examples.json`` (valid and invalid SYNTHETIC examples).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'strings'

CONTRACTS = ('StringBasis', 'StringLink', 'StringChange', 'StringsDelta', 'StringAnchorHit', 'SearchRow')
A, B, C = 'a' * 64, 'b' * 64, 'c' * 64
SCHEMA_BASE = 'https://patchtrace.local/schemas/strings/1/'


def _models() -> dict:
    from patchtrace.strings import contracts
    return {name: getattr(contracts, name) for name in CONTRACTS}


def valid_records() -> dict:
    from patchtrace.strings import contracts as c
    part = c.BasisPart(source='floss', semantics_id=c.STATIC_SEMANTICS_ID, source_version='3.1.1', run_id='run-1',
                       raw_sha256=B, types=('static',), config_digest=C)
    basis = c.StringBasis(artifact_sha256=A, side='older', min_length=4, rows_seen=2, rows_kept=2,
                          stages={'static': c.StageState(state='complete'), 'stack': c.StageState(state='not-run')},
                          parts=(part,))
    link = c.StringLink(tier='L1', function=c.FunctionRef(side='newer', rva=0x1030, name='sub_1030'),
                        pair_status='modified', lineage_group='bytes:' + A, evidence_ref='run-1#0')
    change = c.StringChange(id=B, value_sha256=A, display='hello', length=5, status='only-newer',
                            newer=c.SideObservation(types=('static',), encodings=('ASCII',), offsets=(0x600,),
                                                    rvas=(0x2000,), region='.rdata'),
                            links=(link,), cues=('message',), review_tier=1, reasons=('pair-modified',))
    delta = c.StringsDelta(older_basis_digest=A, newer_basis_digest=B, comparable=True,
                           harmonized=c.Harmonized(min_length=4, types=('static',)), counts={'only-newer': 1},
                           changes=(change,), pairing=c.PairingInfo(available=True))
    hit = c.StringAnchorHit(anchor_id='anchor-1', kind='api-name', match='exact', string_id=A, presence_older=False,
                            presence_newer=True, links=(link,), lineage_group='bytes:' + A)
    row = c.SearchRow(doc_key='strings:' + A, text='hello', title='hello', side='newer', status='only-newer',
                      function_ids=('rva:0x1030',), offsets=(0x600,), coverage='changed and linked')
    return {'StringBasis': basis, 'StringLink': link, 'StringChange': change, 'StringsDelta': delta,
            'StringAnchorHit': hit, 'SearchRow': row}


def _invalid(valid: dict) -> dict:
    basis = valid['StringBasis'].model_dump(mode='json')
    change = valid['StringChange'].model_dump(mode='json')
    delta = valid['StringsDelta'].model_dump(mode='json')
    return {
        'StringBasis': [
            {'label': 'extra field', 'value': {**basis, 'surprise': 1}},
            {'label': 'more kept than seen', 'value': {**basis, 'rows_kept': 3}},
            {'label': 'no parts', 'value': {**basis, 'parts': []}}],
        'StringChange': [
            {'label': 'only-newer observed on the older side', 'value': {**change, 'older': change['newer']}},
            {'label': 'cue outside the vocabulary', 'value': {**change, 'cues': ['scary']}},
            {'label': 'review tier 8', 'value': {**change, 'review_tier': 8}}],
        'StringsDelta': [
            {'label': 'value gate claims validation', 'value': {**delta, 'value_gate': 'validated'}},
            {'label': 'not comparable but carries changes', 'value': {**delta, 'comparable': False}}],
        'StringAnchorHit': [
            {'label': 'strength above anchor', 'value': {**valid['StringAnchorHit'].model_dump(mode='json'),
                                                         'strength': 'confirmed'}}]}


def render() -> dict[Path, str]:
    models = _models()
    out: dict[Path, str] = {}
    for name in CONTRACTS:
        schema = models[name].model_json_schema()
        schema['$id'] = f'{SCHEMA_BASE}{name}.json'
        out[OUT / f'{name}.json'] = json.dumps(schema, indent=2, sort_keys=True) + '\n'
    valid = valid_records()
    invalid = _invalid(valid)
    examples = {name: {'valid': [record.model_dump(mode='json')], 'invalid': invalid.get(name, [])}
                for name, record in valid.items()}
    out[OUT / 'examples.json'] = json.dumps(examples, indent=2, sort_keys=True) + '\n'
    return out


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
