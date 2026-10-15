"""Regenerate the build-environment/1 JSON Schemas and examples (DIE slice D3).

Run from the repository root:

    PYTHONPATH=src python tools/generate_buildenv_schemas.py          # write
    PYTHONPATH=src python tools/generate_buildenv_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/build-environment/``: one JSON Schema per contract plus
``examples.json`` (valid and invalid SYNTHETIC examples).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'build-environment'

CONTRACTS = ('PeBuildFacts', 'BuildFact', 'DieSummary', 'BuildFingerprint', 'BuildChange', 'PreflightWarning',
             'NoiseReason', 'BuildEnvDelta', 'BuildFactAnchor', 'TeachHook')
A, B, C = 'a' * 64, 'b' * 64, 'c' * 64
SCHEMA_BASE = 'https://patchtrace.local/schemas/build-environment/1/'


def _models() -> dict:
    from patchtrace.buildenv import contracts
    return {name: getattr(contracts, name) for name in CONTRACTS}


def _pe(c):
    rich = c.RichFacts(offset=0x80, key=0x1234, checksum_ok=True, entries=(c.RichEntry(product_id=261, build=33134, count=12),),
                       truncated=False, signature=C)
    return c.PeBuildFacts(
        linker_field=(14, 36), os_field=(6, 0), image_field=(0, 0), subsystem_field=(6, 0), subsystem='WINDOWS_CUI',
        dll_characteristics=('DYNAMIC_BASE',), guard_flags=None, security_cookie_set=None, debug_entry_types=(2,),
        repro=False, rich=rich, clr=None, runtime_families=('msvc-crt-14',), entropy_exec_max=5.5, overlay_size=0,
        overlay_entropy=None, sampled=False, anomalies=())


def valid_records() -> dict:
    from patchtrace.buildenv import contracts as c
    from patchtrace.buildenv.anchors import anchors_for
    from patchtrace.buildenv.copy import TEACH
    from patchtrace.buildenv.delta import compute_delta
    die = c.DieSummary(status='ok', run_id='run-1', tool_version='3.21', db_label='3.21 linux deb', db_sha256=B,
                       argv_version='diec/1', heuristics=False, cache_key=C)
    compiler = c.BuildFact(key='compiler', value='Microsoft Visual C/C++', version='19.38', source='diec',
                           certainty='signature', ref='run-1', raw=(('raw_type', 'compiler'),))
    linker = c.BuildFact(key='linker_field', value='14.36', source='pe-header', certainty='exact-field')
    pe = _pe(c)

    def fingerprint(side, sha, name):
        fact = compiler.model_copy(update={'value': name})
        return c.BuildFingerprint(artifact_sha256=sha, side=side, pe=pe, die=die, facts=(fact, linker),
                                  anomalies=(), built_from=c.BuiltFrom(pe_facts_version=pe.facts_version,
                                                                      die_cache_key=C))
    older, newer = fingerprint('older', A, 'Microsoft Visual C/C++'), fingerprint('newer', B, 'MinGW')
    delta = compute_delta(older, newer)
    return {'PeBuildFacts': pe, 'BuildFact': compiler, 'DieSummary': die, 'BuildFingerprint': older,
            'BuildChange': delta.changes[0], 'PreflightWarning': delta.preflight[0], 'NoiseReason': delta.noise[0],
            'BuildEnvDelta': delta, 'BuildFactAnchor': anchors_for(older)[0],
            'TeachHook': TEACH['build.toolchain_differs']}


def _invalid(valid: dict) -> dict:
    def dump(name):
        return valid[name].model_dump(mode='json')
    delta, fact, die = dump('BuildEnvDelta'), dump('BuildFact'), dump('DieSummary')
    return {
        'BuildFact': [
            {'label': 'extra field', 'value': {**fact, 'surprise': 1}},
            {'label': 'key outside the closed set', 'value': {**fact, 'key': 'verdict'}},
            {'label': 'certainty outside the vocabulary', 'value': {**fact, 'certainty': 'certain'}}],
        'DieSummary': [{'label': 'unknown status', 'value': {**die, 'status': 'passed'}}],
        'BuildChange': [{'label': 'unchanged with different values', 'value': {**dump('BuildChange'),
                                                                             'change': 'unchanged'}}],
        'PreflightWarning': [{'label': 'severity outside the vocabulary',
                              'value': {**dump('PreflightWarning'), 'severity': 'alarm'}}],
        'BuildEnvDelta': [
            {'label': 'verdict without comparable inputs', 'value': {**delta, 'comparable': False}},
            {'label': 'noise attribution without a difference', 'value': {**delta, 'toolchain': 'same'}},
            {'label': 'wrong orientation', 'value': {**delta, 'orientation': 'newer->older'}}]}


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
