"""Shared builders of the rule-candidate tests: SYNTHETIC pairs only (tests/test_intel_tools_pe.py images and the
committed real-tool goldens captured on them). Nothing here runs a tool or touches a Microsoft binary."""
from __future__ import annotations

from intel_tools_support import FIXTURES, golden

from patchtrace.intelligence.tools import delta, floss
from patchtrace.intelligence.tools.capa_pairs import PairCapabilityDelta
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolManifest, ToolRun
from patchtrace.pe_overview import inspect_pe
from patchtrace.yarax.contracts import EngineStamp, FunctionRef, PairSource

ENGINE = EngineStamp(version='1.21.0', version_source='pin', decoder='iced-x86', decoder_version='1.21.0')
BASE = 0x140000000


def pair_source(images, pair: str, *, match_id: str, category: str, materiality: str = 'material',
                confirmed: bool = False, rva: int = 0x1000) -> PairSource:
    sizes = {side: images(pair, side)[0] for side in ('older', 'newer')}
    ref = FunctionRef(name='fn', rva=rva, size=32, extent='pdata')
    return PairSource(
        project_id='proj-1', revision=1, run_id='run-1', older_sha256=sizes['older'].sha256,
        newer_sha256=sizes['newer'].sha256, match_id=match_id, category=category, materiality=materiality,
        analyst_confirmed_material=confirmed, older=None if category == 'added' else ref,
        newer=None if category == 'removed' else ref)


def capa_pairs_golden() -> PairCapabilityDelta:
    return PairCapabilityDelta.model_validate_json((FIXTURES / 'expected-pairs-capa-api.json').read_bytes())


def floss_delta(images, pair: str = 'floss-static'):
    """(ToolDelta, readers) of the committed FLOSS static goldens of `pair`."""
    sets, readers = {}, {}
    for side in ('older', 'newer'):
        copy, reader, pe = images(pair, side)
        ctx = floss.ParseContext(f'r-{side}', side, copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'], False)
        sets[side] = floss.parse(golden(f'floss/{pair}-{side}.static.json'), ctx)
        readers[side] = reader
    manifest = ToolManifest(engine='floss', version='3.1.1', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    runs = {side: ToolRun(run_id=s.run_id, engine='floss', side=side, input_artifact_hash=s.artifact_sha256,
                          config_digest='d' * 64, cache_key=s.cache_key, started_at='t', elapsed=0, status='ok',
                          evidence_count=s.evidence_count(), profile='context', manifest=manifest)
            for side, s in sets.items()}
    return delta.compute(runs['older'], sets['older'], runs['newer'], sets['newer']), readers


def overviews(images, pair: str):
    return tuple(inspect_pe(images(pair, side)[1]) for side in ('older', 'newer'))


def fake_writer(pair, *, direction, rule_name, features) -> str:
    """Stands in for the closed-grammar synthesizer (R1): deterministic, depends on the included features only."""
    body = ' '.join(f'{f.kind}' for f in features)
    return f'rule {rule_name} {{ condition: true /* {direction} {body} */ }}\n'
