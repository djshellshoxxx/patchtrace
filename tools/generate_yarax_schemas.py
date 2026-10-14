"""Regenerate the yara-rules/1 JSON Schemas and examples (slice R0).

Run from the repository root:

    PYTHONPATH=src python tools/generate_yarax_schemas.py          # write
    PYTHONPATH=src python tools/generate_yarax_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/yarax/``: one JSON Schema per contract plus
``examples.json`` (valid and invalid SYNTHETIC examples).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'yarax'

CONTRACTS = ('EngineStamp', 'PairSource', 'RuleCandidate', 'RuleDecision', 'RuleVersion', 'TargetRef', 'CellResult',
             'MatrixRun', 'ExportRecord', 'WorkerRequest', 'WorkerResult')
A, B, C = 'a' * 64, 'b' * 64, 'c' * 64
SCHEMA_BASE = 'https://patchtrace.local/schemas/yarax/1/'
RULE_TEXT = 'rule PT_aaaaaaaaaaaa_older : patchtrace older_side\n{\n  condition:\n    uint16(0) == 0x5A4D\n}\n'


def _models() -> dict:
    from patchtrace.yarax import contracts
    return {name: getattr(contracts, name) for name in CONTRACTS}


def valid_records() -> dict:
    from patchtrace.yarax import contracts as c
    engine = c.EngineStamp(version='1.21.0', version_source='metadata', decoder='iced-x86', decoder_version='1.21.0')
    pair = c.PairSource(project_id='proj-1', revision=3, run_id='run-1', older_sha256=A, newer_sha256=B,
                        match_id='m-1', category='removed', materiality='material',
                        older=c.FunctionRef(rva=0x104D, size=96, extent='pdata'))
    pin = c.CallPin(disp_offset=3, end_offset=7, dll='kernel32.dll', name='TerminateProcess')
    pattern = ' '.join(['48', '8B', '??', '??'] * 4)
    feature = c.BytesFeature(side='older', window_rva=0x104D, length=16, pattern=pattern, literal=8, longest_run=1,
                             mask=('rip-disp',), mask_source='iced-x86', pins=(pin,), source_hits=1, other_hits=0,
                             separation='older-only')
    candidate = c.RuleCandidate(
        candidate_id=A, lineage_id=C.replace('c', 'a'), direction='older', source=pair, features=(feature,),
        rule_name='PT_aaaaaaaaaaaa_older', rule_text=RULE_TEXT, rule_sha256=c.text_sha256(RULE_TEXT),
        gates=(c.Gate(gate_id='sep', state='pass', measured=1),), engine=engine)
    decision = c.RuleDecision(decision_id=B, candidate_id=A, action='accept', analyst_label='older-build removal',
                              cve=('CVE-2026-0001',), kb=('KB5000001',), cwe=('CWE-416',),
                              decided_at='2026-01-02T03:04:05Z')
    version = c.RuleVersion(version_id=C, lineage_id=A, version=1, candidate_id=A, decision_id=B, rule_text=RULE_TEXT,
                            rule_sha256=c.text_sha256(RULE_TEXT), source=pair, engine=engine,
                            created_at='2026-01-02T03:04:06Z')
    target = c.TargetRef(target_id='t-1', label='older anchor', role='older-anchor', sha256=A, size=4096,
                         expect='hit')
    cell = c.CellResult(rule_name='PT_aaaaaaaaaaaa_older', target_id='t-1', state='hit', hits=1, offsets=(0x44D,),
                        rvas=(0x104D,), elapsed_ms=12, verdict='as-expected')
    run = c.MatrixRun(run_id='run-2', cache_key=B, engine=engine, status='complete', targets=(target,),
                      cells=(cell,), limits={'cells': 105000})
    export = c.ExportRecord(export_id=A, version_id=C, basename='PT_aaaaaaaaaaaa_older.yar', sha256=B,
                            exported_at='2026-01-02T03:04:07Z')
    request = c.WorkerRequest(op='scan', rules=(c.RuleText(name='PT_aaaaaaaaaaaa_older', text=RULE_TEXT),),
                              targets=(c.WorkerTarget(target_id='t-1', path='sample.bin', sha256=A, size=4096),),
                              limits={'target_timeout_s': 30}, result='result.json')
    result = c.WorkerResult(kind='ok', engine=engine, cells=(cell,))
    return {'EngineStamp': engine, 'PairSource': pair, 'RuleCandidate': candidate, 'RuleDecision': decision,
            'RuleVersion': version, 'TargetRef': target, 'CellResult': cell, 'MatrixRun': run,
            'ExportRecord': export, 'WorkerRequest': request, 'WorkerResult': result}


def _invalid(valid: dict) -> dict:
    dump = {name: record.model_dump(mode='json') for name, record in valid.items()}
    return {
        'PairSource': [
            {'label': 'extra field', 'value': {**dump['PairSource'], 'surprise': 1}},
            {'label': 'unreviewed pair', 'value': {**dump['PairSource'], 'review': 'pending'}},
            {'label': 'removed pair with a newer body', 'value': {**dump['PairSource'], 'newer': dump['PairSource']['older']}}],
        'RuleCandidate': [
            {'label': 'rule text does not match its hash', 'value': {**dump['RuleCandidate'], 'rule_sha256': B}},
            {'label': 'rule name for the other direction', 'value': {**dump['RuleCandidate'], 'direction': 'newer'}}],
        'RuleDecision': [
            {'label': 'accept without a label', 'value': {**dump['RuleDecision'], 'analyst_label': ''}},
            {'label': 'malformed CVE', 'value': {**dump['RuleDecision'], 'cve': ['CVE-26-1']}}],
        'RuleVersion': [
            {'label': 'first version with a predecessor', 'value': {**dump['RuleVersion'], 'supersedes': A}}],
        'CellResult': [
            {'label': 'timeout carrying a verdict', 'value': {**dump['CellResult'], 'state': 'timeout', 'hits': 0,
                                                              'offsets': [], 'rvas': []}},
            {'label': 'hit without hits', 'value': {**dump['CellResult'], 'hits': 0}}],
        'WorkerResult': [
            {'label': 'ok without an engine stamp', 'value': {**dump['WorkerResult'], 'engine': None}},
            {'label': 'error without a code', 'value': {'kind': 'error'}}]}


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
