"""Regenerate the tool-evidence/1 artefacts (SPEC-29 tools T2).

Run from the repository root:

    PYTHONPATH=src python tools/generate_intel_tools_schemas.py          # write
    PYTHONPATH=src python tools/generate_intel_tools_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/intel-tools/``: one JSON Schema per contract plus
``examples.json`` (valid and invalid SYNTHETIC examples).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'intel-tools'

CONTRACTS = ('ToolManifest', 'ToolRun', 'EvidenceLink', 'CapabilityEvidence', 'StringEvidence', 'EnvironmentEvidence',
             'ToolEvidenceSet', 'ToolDelta')
A, B, C = 'a' * 64, 'b' * 64, 'c' * 64
SCHEMA_BASE = 'https://patchtrace.local/schemas/intel-tools/1/'


def _models():
    from patchtrace.intelligence.tools import common, delta
    return {'ToolManifest': common.ToolManifest, 'ToolRun': common.ToolRun, 'EvidenceLink': common.EvidenceLink,
            'CapabilityEvidence': common.CapabilityEvidence, 'StringEvidence': common.StringEvidence,
            'EnvironmentEvidence': common.EnvironmentEvidence, 'ToolEvidenceSet': common.ToolEvidenceSet,
            'ToolDelta': delta.ToolDelta}


def valid_records() -> dict:
    from patchtrace.intelligence.tools import common as c
    manifest = c.ToolManifest(engine='capa', version='9.4.0', version_text='capa 9.4.0', cli_path='/opt/capa/capa',
                              executable_sha256=A, capabilities=('backend:vivisect', 'json'), license='Apache-2.0',
                              rules_source='embedded', backend='vivisect', supported=True, pin_status='pinned')
    run = c.ToolRun(run_id='run-1', engine='capa', side='older', input_artifact_hash=B, config_digest=C, cache_key=C,
                    started_at='2099-01-01T00:00:00+00:00', elapsed=1200, status='ok', returncode=0, stdout_digest=A,
                    evidence_count=1, profile='basic', options={'argv': 'capa/1'}, manifest=manifest)
    link = c.EvidenceLink(tool_run_id='run-1', artifact_sha256=B, function_id='rva:0x1030', rva=0x1030,
                          attribution='function-start')
    capability = c.CapabilityEvidence(rule_id='get hostname', rule_sha256=A, namespace='host-interaction/os/hostname',
                                      scope='function', address_space='absolute', address=0x140001030, location=link,
                                      kind='capability', source_run_id='run-1')
    text = c.StringEvidence(value_hash=A, length=5, display_value='hello', encoding='ASCII', type='static',
                            source_location=c.EvidenceLink(tool_run_id='run-1', artifact_sha256=B, rva=0x2000,
                                                           file_offset=0x600),
                            confidence_class='verified-bytes', extraction_method='floss-static',
                            source_run_id='run-1')
    env = c.EnvironmentEvidence(category='compiler', toolchain='Example C 1.0', detector_rule='Example C',
                                heuristic=False, certainty='signature', source_run_id='run-1')
    evidence = c.ToolEvidenceSet(run_id='run-1', engine='capa', side='older', artifact_sha256=B, cache_key=C,
                                 config_digest=C, image_base=0x140000000, capabilities=(capability,),
                                 counts={'capabilities': 1})
    from patchtrace.intelligence.tools import delta
    return {'ToolManifest': manifest, 'ToolRun': run, 'EvidenceLink': link, 'CapabilityEvidence': capability,
            'StringEvidence': text, 'EnvironmentEvidence': env, 'ToolEvidenceSet': evidence,
            'ToolDelta': delta.ToolDelta(engine='capa', older_run_id='run-1', newer_run_id='run-2', comparable=False,
                                         reasons=('no stored run for the newer artifact',))}


def _invalid(valid: dict) -> dict:
    run = valid['ToolRun'].model_dump(mode='json')
    return {
        'ToolRun': [
            {'label': 'extra field', 'value': {**run, 'surprise': 1}},
            {'label': 'unknown status', 'value': {**run, 'status': 'done'}},
            {'label': 'failure without an error code', 'value': {**run, 'status': 'failed'}},
            {'label': 'none-found with evidence', 'value': {**run, 'status': 'none-found'}}],
        'EvidenceLink': [
            {'label': 'localized without an RVA',
             'value': {'tool_run_id': 'r', 'artifact_sha256': A, 'attribution': 'function-start'}},
            {'label': 'file offset beyond 2^40', 'value': {'tool_run_id': 'r', 'artifact_sha256': A,
                                                           'file_offset': 2 ** 41}}],
        'ToolManifest': [
            {'label': 'supported without a digest', 'value': {'engine': 'capa', 'license': 'MIT', 'supported': True}}]}


def render() -> dict[Path, str]:
    models = _models()
    out: dict[Path, str] = {}
    for name in CONTRACTS:
        schema = models[name].model_json_schema()
        schema['$id'] = f'{SCHEMA_BASE}{name}.json'
        out[OUT / f'{name}.json'] = json.dumps(schema, indent=2, sort_keys=True) + '\n'
    valid = valid_records()
    examples = {name: {'valid': [record.model_dump(mode='json')], 'invalid': _invalid(valid).get(name, [])}
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
